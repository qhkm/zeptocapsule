//! Supervisor — manages capsules, drives the job lifecycle, enforces timeouts.

use std::collections::HashMap;
use std::time::Duration;

use tracing::{info, warn};

use crate::backend::{Backend, BackendError, CapsuleHandle};
use crate::capsule::Capsule;
use zk_proto::{CapsuleState, GuestEvent, HostCommand, JobSpec, PROTOCOL_VERSION};

/// Outcome of a supervised job execution.
#[derive(Debug)]
pub enum JobOutcome {
    Completed {
        job_id: String,
        output_artifact_ids: Vec<String>,
        summary: String,
    },
    Failed {
        job_id: String,
        error: String,
        retryable: bool,
    },
    Cancelled {
        job_id: String,
    },
}

/// Errors from the supervisor lifecycle.
#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("backend error: {0}")]
    Backend(#[from] BackendError),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("timeout during {phase}")]
    Timeout { phase: String },
}

/// The host-side supervisor that owns all active capsules.
pub struct Supervisor {
    capsules: HashMap<String, Capsule>,
}

impl Supervisor {
    pub fn new() -> Self {
        Self {
            capsules: HashMap::new(),
        }
    }

    pub fn register(&mut self, capsule: Capsule) {
        self.capsules.insert(capsule.job_id.clone(), capsule);
    }

    pub fn get(&self, job_id: &str) -> Option<&Capsule> {
        self.capsules.get(job_id)
    }

    pub fn get_mut(&mut self, job_id: &str) -> Option<&mut Capsule> {
        self.capsules.get_mut(job_id)
    }

    pub fn remove(&mut self, job_id: &str) -> Option<Capsule> {
        self.capsules.remove(job_id)
    }

    /// Return job IDs of capsules that have exceeded their heartbeat timeout.
    pub fn stale_capsules(&self, heartbeat_timeout_sec: u64) -> Vec<String> {
        let timeout = Duration::from_secs(heartbeat_timeout_sec);
        self.capsules
            .iter()
            .filter(|(_, c)| {
                c.state == CapsuleState::Running
                    && c.elapsed_since_heartbeat()
                        .map(|d| d > timeout)
                        .unwrap_or(false)
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn active_count(&self) -> usize {
        self.capsules
            .values()
            .filter(|c| {
                matches!(
                    c.state,
                    CapsuleState::Initializing
                        | CapsuleState::Ready
                        | CapsuleState::Running
                        | CapsuleState::Waiting
                )
            })
            .count()
    }

    /// Run a single job through its full lifecycle:
    /// spawn → handshake → start_job → event loop → cleanup.
    pub async fn run_job<B: Backend>(
        &mut self,
        backend: &B,
        spec: &JobSpec,
        worker_binary: &str,
    ) -> Result<JobOutcome, SupervisorError> {
        let job_id = &spec.job_id;

        // Phase A: Spawn capsule
        info!(job_id, "spawning capsule");
        let handle = backend.spawn(spec, worker_binary).await?;
        let capsule_id = handle.id();
        info!(job_id, capsule_id, "capsule spawned");

        let mut capsule = Capsule::new(
            spec.job_id.clone(),
            spec.run_id.clone(),
            spec.role.clone(),
        );
        self.register(capsule.clone());

        // Phase A2: Wait for Ready
        let event = recv_timeout(&handle, Duration::from_secs(10), "ready").await?;
        match event {
            GuestEvent::Ready => {
                info!(job_id, "guest ready");
            }
            other => {
                return Err(SupervisorError::Protocol(format!(
                    "expected Ready, got {:?}",
                    std::mem::discriminant(&other)
                )));
            }
        }

        // Phase B: Handshake
        handle
            .send(HostCommand::Handshake {
                protocol_version: PROTOCOL_VERSION,
                worker_profile: spec.role.clone(),
            })
            .await?;

        let event = recv_timeout(&handle, Duration::from_secs(10), "handshake_ack").await?;
        match event {
            GuestEvent::HandshakeAck {
                guest_id,
                protocol_version,
                ..
            } => {
                info!(job_id, guest_id, protocol_version, "handshake complete");
                capsule.complete_handshake(guest_id);
            }
            other => {
                return Err(SupervisorError::Protocol(format!(
                    "expected HandshakeAck, got {:?}",
                    std::mem::discriminant(&other)
                )));
            }
        }

        // Phase C: Start job
        handle.send(HostCommand::StartJob(spec.clone())).await?;

        let event = recv_timeout(&handle, Duration::from_secs(30), "started").await?;
        match event {
            GuestEvent::Started { .. } => {
                info!(job_id, "job started");
                capsule.state = CapsuleState::Running;
                capsule.record_heartbeat();
            }
            // Guest might complete instantly (placeholder impl)
            GuestEvent::Completed {
                job_id: jid,
                output_artifact_ids,
                summary,
            } => {
                capsule.state = CapsuleState::Completed;
                self.update_capsule(&capsule);
                cleanup(&handle).await;
                self.remove(&jid);
                return Ok(JobOutcome::Completed {
                    job_id: jid,
                    output_artifact_ids,
                    summary,
                });
            }
            GuestEvent::Failed {
                job_id: jid,
                error,
                retryable,
            } => {
                capsule.state = CapsuleState::Failed;
                self.update_capsule(&capsule);
                cleanup(&handle).await;
                self.remove(&jid);
                return Ok(JobOutcome::Failed {
                    job_id: jid,
                    error,
                    retryable,
                });
            }
            other => {
                return Err(SupervisorError::Protocol(format!(
                    "expected Started, got {:?}",
                    std::mem::discriminant(&other)
                )));
            }
        }
        self.update_capsule(&capsule);

        // Phase D: Event loop with heartbeat + wall clock timeout
        let wall_timeout = Duration::from_secs(spec.limits.timeout_sec);
        let hb_timeout = Duration::from_secs(spec.limits.heartbeat_timeout_sec);
        let wall_deadline = tokio::time::Instant::now() + wall_timeout;
        let mut last_heartbeat = tokio::time::Instant::now();

        let outcome = loop {
            let hb_remaining = hb_timeout.saturating_sub(last_heartbeat.elapsed());
            let wall_remaining = wall_deadline.saturating_duration_since(tokio::time::Instant::now());

            // Pick the nearest deadline
            let next_timeout = hb_remaining.min(wall_remaining);
            let is_wall = wall_remaining <= hb_remaining;

            tokio::select! {
                result = handle.recv() => {
                    match result {
                        Ok(event) => {
                            match event {
                                GuestEvent::Heartbeat { .. }
                                | GuestEvent::Progress { .. }
                                | GuestEvent::Waiting { .. } => {
                                    last_heartbeat = tokio::time::Instant::now();
                                    capsule.record_heartbeat();
                                    if matches!(event, GuestEvent::Waiting { .. }) {
                                        capsule.state = CapsuleState::Waiting;
                                    }
                                }
                                GuestEvent::ArtifactProduced { ref artifact, .. } => {
                                    last_heartbeat = tokio::time::Instant::now();
                                    capsule.record_heartbeat();
                                    info!(job_id, artifact_id = %artifact.artifact_id, "artifact produced");
                                }
                                GuestEvent::Completed { job_id: jid, output_artifact_ids, summary } => {
                                    capsule.state = CapsuleState::Completed;
                                    info!(job_id = %jid, "job completed");
                                    break JobOutcome::Completed { job_id: jid, output_artifact_ids, summary };
                                }
                                GuestEvent::Failed { job_id: jid, error, retryable } => {
                                    capsule.state = CapsuleState::Failed;
                                    capsule.exit_reason = Some(error.clone());
                                    warn!(job_id = %jid, error, "job failed");
                                    break JobOutcome::Failed { job_id: jid, error, retryable };
                                }
                                GuestEvent::Cancelled { job_id: jid } => {
                                    capsule.state = CapsuleState::Cancelled;
                                    info!(job_id = %jid, "job cancelled");
                                    break JobOutcome::Cancelled { job_id: jid };
                                }
                                _ => {
                                    // Pong, Ready, HandshakeAck during job — ignore
                                }
                            }
                        }
                        Err(e) => {
                            // Guest process died unexpectedly
                            capsule.state = CapsuleState::Failed;
                            capsule.exit_reason = Some(e.to_string());
                            warn!(job_id, error = %e, "guest connection lost");
                            break JobOutcome::Failed {
                                job_id: job_id.to_string(),
                                error: e.to_string(),
                                retryable: true,
                            };
                        }
                    }
                }
                _ = tokio::time::sleep(next_timeout) => {
                    let reason = if is_wall { "wall clock timeout" } else { "heartbeat timeout" };
                    warn!(job_id, reason, "timeout — cancelling job");

                    // Try graceful cancel
                    let _ = handle.send(HostCommand::CancelJob { job_id: job_id.to_string() }).await;
                    match tokio::time::timeout(Duration::from_secs(10), handle.recv()).await {
                        Ok(Ok(GuestEvent::Cancelled { .. } | GuestEvent::Failed { .. })) => {}
                        _ => {
                            let _ = handle.terminate().await;
                        }
                    }

                    capsule.state = CapsuleState::Failed;
                    capsule.exit_reason = Some(reason.into());
                    break JobOutcome::Failed {
                        job_id: job_id.to_string(),
                        error: reason.into(),
                        retryable: !is_wall,
                    };
                }
            }
        };

        // Phase E: Cleanup
        self.update_capsule(&capsule);
        cleanup(&handle).await;
        self.remove(job_id);

        Ok(outcome)
    }

    fn update_capsule(&mut self, capsule: &Capsule) {
        if let Some(c) = self.capsules.get_mut(&capsule.job_id) {
            c.state = capsule.state;
            c.last_heartbeat = capsule.last_heartbeat;
            c.exit_reason = capsule.exit_reason.clone();
            c.guest_id = capsule.guest_id.clone();
            c.handshake_done = capsule.handshake_done;
        }
    }
}

/// Receive an event with a timeout.
async fn recv_timeout(
    handle: &impl CapsuleHandle,
    timeout: Duration,
    phase: &str,
) -> Result<GuestEvent, SupervisorError> {
    tokio::time::timeout(timeout, handle.recv())
        .await
        .map_err(|_| SupervisorError::Timeout {
            phase: phase.to_string(),
        })?
        .map_err(SupervisorError::Backend)
}

/// Send shutdown and terminate the capsule.
async fn cleanup(handle: &impl CapsuleHandle) {
    let _ = handle.send(HostCommand::Shutdown).await;
    // Give guest a moment to exit cleanly
    match tokio::time::timeout(Duration::from_secs(3), handle.recv()).await {
        _ => {} // Don't care about the result
    }
    let _ = handle.terminate().await;
}
