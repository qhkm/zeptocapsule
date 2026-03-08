//! ZeptoKernel protocol — shared types between host supervisor and guest agent.
//!
//! All host↔guest communication uses newline-delimited JSON over a transport:
//! - Dev/namespace mode: Unix socket or stdin/stdout
//! - MicroVM mode: virtio-vsock (port 7000 control, port 7001 events)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Transport constants
// ---------------------------------------------------------------------------

/// Vsock port for host→guest control commands.
pub const VSOCK_PORT_CONTROL: u32 = 7000;
/// Vsock port for guest→host event stream.
pub const VSOCK_PORT_EVENTS: u32 = 7001;
/// Current protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

// ---------------------------------------------------------------------------
// Wire envelope
// ---------------------------------------------------------------------------

/// Envelope wrapping all messages for version tracking and request correlation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub version: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub payload: T,
}

impl<T> Envelope<T> {
    pub fn new(payload: T) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id: None,
            payload,
        }
    }

    pub fn with_request_id(payload: T, id: impl Into<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id: Some(id.into()),
            payload,
        }
    }
}

// ---------------------------------------------------------------------------
// Host → Guest commands
// ---------------------------------------------------------------------------

/// Commands sent from the host supervisor to the guest agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostCommand {
    /// Protocol handshake — sent immediately after vsock connection.
    Handshake {
        protocol_version: u16,
        worker_profile: String,
    },
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

/// Reference to an input artifact available inside the guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub artifact_id: String,
    pub guest_path: PathBuf,
    pub kind: String,
    #[serde(default)]
    pub summary: String,
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
    /// Max total output bytes across all artifacts.
    #[serde(default)]
    pub max_output_bytes: Option<u64>,
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
            max_output_bytes: None,
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
    /// Protocol handshake acknowledgment.
    HandshakeAck {
        protocol_version: u16,
        guest_id: String,
        capabilities: Vec<String>,
    },
    /// Guest agent is ready to accept jobs.
    Ready,
    /// Pong response to a Ping.
    Pong { seq: u64 },
    /// Job has started executing.
    Started { job_id: String },
    /// Periodic heartbeat while job is running.
    Heartbeat {
        job_id: String,
        phase: String,
        #[serde(default)]
        message: Option<String>,
        #[serde(default)]
        memory_used_mib: Option<u64>,
    },
    /// Progress update from the worker.
    Progress {
        job_id: String,
        phase: String,
        message: String,
        #[serde(default)]
        percent: Option<f32>,
    },
    /// Worker is waiting (e.g. for LLM API response).
    Waiting { job_id: String, reason: String },
    /// Worker produced an artifact.
    ArtifactProduced {
        job_id: String,
        artifact: ProducedArtifact,
    },
    /// Job completed successfully.
    Completed {
        job_id: String,
        output_artifact_ids: Vec<String>,
        #[serde(default)]
        summary: String,
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

/// Metadata for a produced artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProducedArtifact {
    pub artifact_id: String,
    pub kind: String,
    pub path: PathBuf,
    pub summary: String,
    pub size_bytes: u64,
}

impl GuestEvent {
    /// Extract the job_id from events that carry one.
    pub fn job_id(&self) -> Option<&str> {
        match self {
            Self::Ready | Self::Pong { .. } | Self::HandshakeAck { .. } => None,
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

/// Serialize a message inside an envelope.
pub fn encode_envelope<T: Serialize>(msg: &T) -> Result<String, ProtoError> {
    let envelope = Envelope::new(msg);
    encode_line(&envelope)
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
            summary: "done".into(),
        };
        let line = encode_line(&event).unwrap();
        let decoded: GuestEvent = decode_line(&line).unwrap();
        assert_eq!(decoded.job_id(), Some("j1"));
    }

    #[test]
    fn roundtrip_handshake() {
        let cmd = HostCommand::Handshake {
            protocol_version: PROTOCOL_VERSION,
            worker_profile: "researcher".into(),
        };
        let line = encode_line(&cmd).unwrap();
        let decoded: HostCommand = decode_line(&line).unwrap();
        match decoded {
            HostCommand::Handshake {
                protocol_version,
                worker_profile,
            } => {
                assert_eq!(protocol_version, PROTOCOL_VERSION);
                assert_eq!(worker_profile, "researcher");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_handshake_ack() {
        let event = GuestEvent::HandshakeAck {
            protocol_version: 1,
            guest_id: "g1".into(),
            capabilities: vec!["researcher".into()],
        };
        let line = encode_line(&event).unwrap();
        let decoded: GuestEvent = decode_line(&line).unwrap();
        match decoded {
            GuestEvent::HandshakeAck {
                guest_id,
                capabilities,
                ..
            } => {
                assert_eq!(guest_id, "g1");
                assert_eq!(capabilities, vec!["researcher"]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_artifact_produced() {
        let event = GuestEvent::ArtifactProduced {
            job_id: "j1".into(),
            artifact: ProducedArtifact {
                artifact_id: "art_1".into(),
                kind: "markdown".into(),
                path: PathBuf::from("/workspace/output.md"),
                summary: "Research results".into(),
                size_bytes: 4096,
            },
        };
        let line = encode_line(&event).unwrap();
        let decoded: GuestEvent = decode_line(&line).unwrap();
        match decoded {
            GuestEvent::ArtifactProduced { artifact, .. } => {
                assert_eq!(artifact.size_bytes, 4096);
                assert_eq!(artifact.artifact_id, "art_1");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_envelope() {
        let cmd = HostCommand::Ping { seq: 42 };
        let envelope = Envelope::with_request_id(&cmd, "req-1");
        let line = encode_line(&envelope).unwrap();
        let decoded: Envelope<HostCommand> = decode_line(&line).unwrap();
        assert_eq!(decoded.version, PROTOCOL_VERSION);
        assert_eq!(decoded.request_id.as_deref(), Some("req-1"));
    }

    #[test]
    fn default_limits() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.timeout_sec, 300);
        assert!(!limits.network);
        assert_eq!(limits.heartbeat_timeout_sec, 60);
        assert!(limits.max_output_bytes.is_none());
    }

    #[test]
    fn guest_event_job_id_extraction() {
        assert_eq!(GuestEvent::Ready.job_id(), None);
        assert_eq!(
            GuestEvent::HandshakeAck {
                protocol_version: 1,
                guest_id: "g".into(),
                capabilities: vec![],
            }
            .job_id(),
            None
        );
        assert_eq!(
            GuestEvent::Progress {
                job_id: "j2".into(),
                phase: "searching".into(),
                message: "done".into(),
                percent: Some(0.5),
            }
            .job_id(),
            Some("j2")
        );
    }

    #[test]
    fn vsock_port_constants() {
        assert_eq!(VSOCK_PORT_CONTROL, 7000);
        assert_eq!(VSOCK_PORT_EVENTS, 7001);
    }
}
