//! Guest agent — the control loop running inside the capsule.
//!
//! Reads HostCommands from the control channel, launches the worker
//! binary, and forwards GuestEvents back to the host.
//!
//! Transport-agnostic: accepts any AsyncBufRead/AsyncWrite pair.
//! - Dev mode: stdin/stdout
//! - Namespace mode: Unix socket
//! - MicroVM mode: vsock ports 7000 (control) / 7001 (events)

use std::time::Duration;

use tokio::io::AsyncBufReadExt;
use tokio::time::interval;
use zk_proto::{GuestEvent, HostCommand, JobSpec, PROTOCOL_VERSION};

use crate::worker::{WorkerHandle, launch_worker, write_job_spec};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// Run the guest agent control loop.
pub async fn run_agent<R, W>(reader: R, mut writer: W)
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // Signal readiness
    send_event(&mut writer, &GuestEvent::Ready).await;

    let mut active_job: Option<ActiveJob> = None;
    let mut lines = reader.lines();

    loop {
        if let Some(ref mut job) = active_job {
            // While a job is running, multiplex: host commands, worker stdout, heartbeat timer
            let finished = run_job_select_loop(job, &mut lines, &mut writer).await;
            if finished {
                active_job = None;
                // Continue the outer loop to read the next host command
            }
        } else {
            // No active job — just wait for the next host command
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if let Some(job) = handle_command_line(&line, &mut writer).await {
                        active_job = Some(job);
                    }
                }
                _ => break,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Active job state
// ---------------------------------------------------------------------------

struct ActiveJob {
    spec: JobSpec,
    worker: WorkerHandle,
    heartbeat: tokio::time::Interval,
    /// PID of the worker child, stored separately for signal sending.
    child_pid: Option<u32>,
    /// Cancellation in progress: SIGTERM sent, waiting for exit.
    cancelling: bool,
    cancel_deadline: Option<tokio::time::Instant>,
}

// ---------------------------------------------------------------------------
// Job select loop — runs while a worker is active
// ---------------------------------------------------------------------------

/// Drive the job to completion (or cancellation/failure).
/// Returns `true` when the job is done and the caller should clear `active_job`.
/// Consumes host commands that arrive while the job is running.
async fn run_job_select_loop<R, W>(
    job: &mut ActiveJob,
    host_lines: &mut tokio::io::Lines<R>,
    writer: &mut W,
) -> bool
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            // --- Host command arrived ---
            line_result = host_lines.next_line() => {
                match line_result {
                    Ok(Some(line)) => {
                        let done = handle_host_command_during_job(&line, job, writer).await;
                        if done { return true; }
                    }
                    _ => return true, // EOF or error: treat as shutdown
                }
            }

            // --- Worker emitted an event on stdout ---
            worker_line = job.worker.stdout.next_line() => {
                match worker_line {
                    Ok(Some(line)) => {
                        forward_worker_line(&line, &job.spec.job_id, writer).await;
                    }
                    // Worker stdout closed — worker exited (or pipe broken)
                    _ => {
                        handle_worker_exit(job, writer).await;
                        return true;
                    }
                }
            }

            // --- Heartbeat tick ---
            _ = job.heartbeat.tick() => {
                let phase = if job.cancelling { "cancelling" } else { "running" };
                send_event(writer, &GuestEvent::Heartbeat {
                    job_id: job.spec.job_id.clone(),
                    phase: phase.into(),
                    message: None,
                    memory_used_mib: None,
                })
                .await;

                // If we are in the SIGKILL grace period, check the deadline
                if job.cancelling {
                    if let Some(deadline) = job.cancel_deadline {
                        if tokio::time::Instant::now() >= deadline {
                            sigkill_worker(job);
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Host command handling during an active job
// ---------------------------------------------------------------------------

async fn handle_host_command_during_job<W: tokio::io::AsyncWrite + Unpin>(
    line: &str,
    job: &mut ActiveJob,
    writer: &mut W,
) -> bool {
    let cmd: HostCommand = match zk_proto::decode_line(line) {
        Ok(c) => c,
        Err(_) => return false,
    };

    match cmd {
        HostCommand::CancelJob { job_id } if job_id == job.spec.job_id => {
            sigterm_worker(job);
            job.cancelling = true;
            // SIGKILL after 10 seconds if still alive
            job.cancel_deadline =
                Some(tokio::time::Instant::now() + Duration::from_secs(10));
            false
        }
        HostCommand::Ping { seq } => {
            send_event(writer, &GuestEvent::Pong { seq }).await;
            false
        }
        HostCommand::Shutdown => {
            sigterm_worker(job);
            true // break outer loop after we return
        }
        // Reject a second job while one is already active
        HostCommand::StartJob(spec) => {
            send_event(
                writer,
                &GuestEvent::Failed {
                    job_id: spec.job_id,
                    error: "guest already running a job".into(),
                    retryable: false,
                },
            )
            .await;
            false
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Worker stdout forwarding
// ---------------------------------------------------------------------------

async fn forward_worker_line<W: tokio::io::AsyncWrite + Unpin>(
    line: &str,
    job_id: &str,
    writer: &mut W,
) {
    // Try to parse the line as a GuestEvent to forward it.
    // Only non-terminal events are forwarded: the guest agent is responsible
    // for emitting Started, Completed, Failed, and Cancelled.
    match zk_proto::decode_line::<GuestEvent>(line) {
        Ok(event) => {
            match &event {
                GuestEvent::Heartbeat { job_id: jid, .. }
                | GuestEvent::Progress { job_id: jid, .. }
                | GuestEvent::Waiting { job_id: jid, .. }
                | GuestEvent::ArtifactProduced { job_id: jid, .. }
                    if jid == job_id =>
                {
                    send_event(writer, &event).await;
                }
                _ => {
                    // Terminal events or wrong job_id: let the guest agent handle them
                    tracing::debug!("worker emitted event (not forwarding): {:?}", line);
                }
            }
        }
        Err(_) => {
            // Malformed line — log and ignore
            tracing::debug!("worker emitted non-JSON line: {:?}", line);
        }
    }
}

// ---------------------------------------------------------------------------
// Worker exit handling
// ---------------------------------------------------------------------------

async fn handle_worker_exit<W: tokio::io::AsyncWrite + Unpin>(
    job: &mut ActiveJob,
    writer: &mut W,
) {
    let status = job.worker.child.wait().await;
    let job_id = job.spec.job_id.clone();

    if job.cancelling {
        // Cancellation wins regardless of exit code
        send_event(writer, &GuestEvent::Cancelled { job_id }).await;
        return;
    }

    match status {
        Ok(s) if s.success() => {
            send_event(
                writer,
                &GuestEvent::Completed {
                    job_id,
                    output_artifact_ids: vec![],
                    summary: String::new(),
                },
            )
            .await;
        }
        Ok(s) => {
            #[cfg(unix)]
            let retryable = {
                use std::os::unix::process::ExitStatusExt;
                s.signal().is_some()
            };
            #[cfg(not(unix))]
            let retryable = false;

            let code = s.code().unwrap_or(-1);
            send_event(
                writer,
                &GuestEvent::Failed {
                    job_id,
                    error: format!("worker exited with code {}", code),
                    retryable,
                },
            )
            .await;
        }
        Err(e) => {
            send_event(
                writer,
                &GuestEvent::Failed {
                    job_id,
                    error: format!("failed to wait for worker: {}", e),
                    retryable: false,
                },
            )
            .await;
        }
    }
}

// ---------------------------------------------------------------------------
// Signal helpers
// ---------------------------------------------------------------------------

fn sigterm_worker(job: &mut ActiveJob) {
    if let Some(pid) = job.child_pid {
        send_signal(pid, libc_sigterm());
    }
}

fn sigkill_worker(job: &mut ActiveJob) {
    if let Some(pid) = job.child_pid {
        send_signal(pid, libc_sigkill());
    }
    job.cancel_deadline = None;
}

fn send_signal(pid: u32, sig: i32) {
    #[cfg(unix)]
    unsafe {
        libc::kill(pid as libc::pid_t, sig);
    }
    #[cfg(not(unix))]
    {
        let _ = (pid, sig);
    }
}

fn libc_sigterm() -> i32 {
    #[cfg(unix)]
    return libc::SIGTERM;
    #[cfg(not(unix))]
    return 15;
}

fn libc_sigkill() -> i32 {
    #[cfg(unix)]
    return libc::SIGKILL;
    #[cfg(not(unix))]
    return 9;
}

// ---------------------------------------------------------------------------
// No-active-job command dispatch
// ---------------------------------------------------------------------------

/// Handle a command when no job is running.
/// Returns `Some(ActiveJob)` if a job was started, `None` otherwise.
async fn handle_command_line<W: tokio::io::AsyncWrite + Unpin>(
    line: &str,
    writer: &mut W,
) -> Option<ActiveJob> {
    let cmd: HostCommand = match zk_proto::decode_line(line) {
        Ok(c) => c,
        Err(_) => return None,
    };

    match cmd {
        HostCommand::Handshake {
            protocol_version,
            worker_profile,
        } => {
            send_event(
                writer,
                &GuestEvent::HandshakeAck {
                    protocol_version: protocol_version.min(PROTOCOL_VERSION),
                    guest_id: format!("guest-{}", std::process::id()),
                    capabilities: vec![worker_profile],
                },
            )
            .await;
            None
        }
        HostCommand::StartJob(spec) => start_job(spec, writer).await,
        HostCommand::CancelJob { job_id } => {
            // No active job — acknowledge cancel gracefully
            send_event(writer, &GuestEvent::Cancelled { job_id }).await;
            None
        }
        HostCommand::Ping { seq } => {
            send_event(writer, &GuestEvent::Pong { seq }).await;
            None
        }
        HostCommand::Shutdown => None, // Caller will break the loop on next iteration
    }
}

async fn start_job<W: tokio::io::AsyncWrite + Unpin>(
    spec: JobSpec,
    writer: &mut W,
) -> Option<ActiveJob> {
    // Write job spec to workspace
    let workspace = &spec.workspace.guest_path;
    let _ = std::fs::create_dir_all(workspace);

    let spec_path = match write_job_spec(&spec, workspace) {
        Ok(p) => p,
        Err(e) => {
            send_event(
                writer,
                &GuestEvent::Failed {
                    job_id: spec.job_id.clone(),
                    error: format!("failed to write job spec: {}", e),
                    retryable: false,
                },
            )
            .await;
            return None;
        }
    };

    // Determine worker binary: /zeptoclaw/worker by default, configurable via env
    let worker_binary = std::env::var("ZEPTOCLAW_BINARY")
        .unwrap_or_else(|_| "/zeptoclaw/worker".to_string());

    send_event(

        writer,
        &GuestEvent::Started {
            job_id: spec.job_id.clone(),
        },
    )
    .await;

    match launch_worker(&spec, &spec_path, &worker_binary).await {
        Ok(worker) => {
            let child_pid = worker.child.id();
            let mut heartbeat = interval(HEARTBEAT_INTERVAL);
            heartbeat.tick().await; // consume the immediate first tick
            Some(ActiveJob {
                spec,
                worker,
                heartbeat,
                child_pid,
                cancelling: false,
                cancel_deadline: None,
            })
        }
        Err(e) => {
            send_event(
                writer,
                &GuestEvent::Failed {
                    job_id: spec.job_id.clone(),
                    error: format!("failed to launch worker: {}", e),
                    retryable: false,
                },
            )
            .await;
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Event serialisation
// ---------------------------------------------------------------------------

async fn send_event<W: tokio::io::AsyncWrite + Unpin>(writer: &mut W, event: &GuestEvent) {
    use tokio::io::AsyncWriteExt;

    if let Ok(line) = zk_proto::encode_line(event) {
        let _ = writer.write_all(line.as_bytes()).await;
        let _ = writer.flush().await;
    }
}
