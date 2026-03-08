//! ZeptoKernel protocol — shared types between host supervisor and guest agent.
//!
//! All host↔guest communication uses JSON-line messages over a transport
//! (Unix socket in namespace mode, vsock in microVM mode).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Host → Guest commands
// ---------------------------------------------------------------------------

/// Commands sent from the host supervisor to the guest agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostCommand {
    /// Start a job inside the capsule.
    StartJob(JobSpec),
    /// Cancel a running job.
    CancelJob { job_id: String },
    /// Ping the guest agent (health check).
    Ping { seq: u64 },
    /// Shut down the guest cleanly.
    Shutdown,
}

/// Full job specification delivered to the guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSpec {
    pub job_id: String,
    pub run_id: String,
    pub role: String,
    pub profile_id: String,
    pub instruction: String,
    pub input_artifacts: Vec<ArtifactRef>,
    pub env: HashMap<String, String>,
    pub limits: ResourceLimits,
    pub workspace: WorkspaceConfig,
}

/// Reference to an input artifact (path inside the guest).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub artifact_id: String,
    pub guest_path: PathBuf,
    pub kind: String,
}

/// Resource limits enforced by the kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Wall clock timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_sec: u64,
    /// Memory limit in MiB.
    #[serde(default)]
    pub memory_mib: Option<u64>,
    /// CPU quota as fraction (e.g. 1.0 = one core).
    #[serde(default)]
    pub cpu_quota: Option<f64>,
    /// Max number of processes in the capsule.
    #[serde(default)]
    pub max_pids: Option<u32>,
    /// Whether outbound network is allowed.
    #[serde(default)]
    pub network: bool,
    /// Heartbeat timeout — kill if no heartbeat for this many seconds.
    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout_sec: u64,
}

fn default_timeout() -> u64 {
    300
}
fn default_heartbeat_timeout() -> u64 {
    60
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            timeout_sec: default_timeout(),
            memory_mib: None,
            cpu_quota: None,
            max_pids: None,
            network: false,
            heartbeat_timeout_sec: default_heartbeat_timeout(),
        }
    }
}

/// Workspace configuration for the guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    /// Path inside the guest where the workspace is mounted.
    #[serde(default = "default_workspace_path")]
    pub guest_path: PathBuf,
    /// Size limit in MiB for the workspace tmpfs.
    #[serde(default)]
    pub size_mib: Option<u64>,
}

fn default_workspace_path() -> PathBuf {
    PathBuf::from("/workspace")
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self {
            guest_path: default_workspace_path(),
            size_mib: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Guest → Host events
// ---------------------------------------------------------------------------

/// Events sent from the guest agent back to the host supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GuestEvent {
    /// Guest agent is ready to accept jobs.
    Ready,
    /// Pong response to a Ping.
    Pong { seq: u64 },
    /// Job has started executing.
    Started { job_id: String },
    /// Periodic heartbeat while job is running.
    Heartbeat {
        job_id: String,
        #[serde(default)]
        memory_used_mib: Option<u64>,
    },
    /// Progress update from the worker.
    Progress {
        job_id: String,
        phase: String,
        message: String,
    },
    /// Worker is waiting (e.g. for LLM API response).
    Waiting {
        job_id: String,
        reason: String,
    },
    /// Worker produced an artifact.
    ArtifactProduced {
        job_id: String,
        artifact_id: String,
        kind: String,
        guest_path: PathBuf,
        summary: String,
    },
    /// Job completed successfully.
    Completed {
        job_id: String,
        output_artifact_ids: Vec<String>,
    },
    /// Job failed.
    Failed {
        job_id: String,
        error: String,
        retryable: bool,
    },
    /// Job was cancelled.
    Cancelled { job_id: String },
}

impl GuestEvent {
    /// Extract the job_id from events that carry one.
    pub fn job_id(&self) -> Option<&str> {
        match self {
            Self::Ready | Self::Pong { .. } => None,
            Self::Started { job_id }
            | Self::Heartbeat { job_id, .. }
            | Self::Progress { job_id, .. }
            | Self::Waiting { job_id, .. }
            | Self::ArtifactProduced { job_id, .. }
            | Self::Completed { job_id, .. }
            | Self::Failed { job_id, .. }
            | Self::Cancelled { job_id } => Some(job_id),
        }
    }
}

// ---------------------------------------------------------------------------
// Capsule lifecycle states (tracked by host)
// ---------------------------------------------------------------------------

/// Lifecycle state of an execution capsule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleState {
    Initializing,
    Ready,
    Running,
    Waiting,
    Completed,
    Failed,
    Cancelled,
    CleanupFailed,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Protocol-level errors.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("invalid message: {0}")]
    InvalidMessage(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("timeout: {0}")]
    Timeout(String),
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

/// Serialize a message to a JSON line (with trailing newline).
pub fn encode_line<T: Serialize>(msg: &T) -> Result<String, ProtoError> {
    serde_json::to_string(msg)
        .map(|s| format!("{}\n", s))
        .map_err(|e| ProtoError::InvalidMessage(e.to_string()))
}

/// Deserialize a JSON line into a message.
pub fn decode_line<'a, T: Deserialize<'a>>(line: &'a str) -> Result<T, ProtoError> {
    serde_json::from_str(line.trim()).map_err(|e| ProtoError::InvalidMessage(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_host_command() {
        let cmd = HostCommand::StartJob(JobSpec {
            job_id: "j1".into(),
            run_id: "r1".into(),
            role: "researcher".into(),
            profile_id: "researcher".into(),
            instruction: "Research competitors".into(),
            input_artifacts: vec![],
            env: HashMap::new(),
            limits: ResourceLimits::default(),
            workspace: WorkspaceConfig::default(),
        });
        let line = encode_line(&cmd).unwrap();
        let decoded: HostCommand = decode_line(&line).unwrap();
        match decoded {
            HostCommand::StartJob(spec) => assert_eq!(spec.job_id, "j1"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_guest_event() {
        let event = GuestEvent::Completed {
            job_id: "j1".into(),
            output_artifact_ids: vec!["art_1".into()],
        };
        let line = encode_line(&event).unwrap();
        let decoded: GuestEvent = decode_line(&line).unwrap();
        assert_eq!(decoded.job_id(), Some("j1"));
    }

    #[test]
    fn default_limits() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.timeout_sec, 300);
        assert!(!limits.network);
        assert_eq!(limits.heartbeat_timeout_sec, 60);
    }

    #[test]
    fn guest_event_job_id_extraction() {
        assert_eq!(GuestEvent::Ready.job_id(), None);
        assert_eq!(
            GuestEvent::Progress {
                job_id: "j2".into(),
                phase: "searching".into(),
                message: "done".into(),
            }
            .job_id(),
            Some("j2")
        );
    }
}
