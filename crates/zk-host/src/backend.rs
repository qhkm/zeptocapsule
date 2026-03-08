//! Isolation backend trait and implementations.
//!
//! The `Backend` trait abstracts the isolation mechanism.
//! V1: namespace sandbox (Linux namespaces + cgroups + seccomp)
//! Future: Firecracker microVM, unikernel

use zk_proto::{GuestEvent, HostCommand, JobSpec};

/// Result type for backend operations.
pub type BackendResult<T> = Result<T, BackendError>;

/// Backend errors.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("spawn failed: {0}")]
    SpawnFailed(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("cleanup failed: {0}")]
    CleanupFailed(String),
    #[error("not supported: {0}")]
    NotSupported(String),
}

/// A running capsule instance returned by a backend.
///
/// Provides the control interface for host↔guest communication.
pub trait CapsuleHandle: Send + Sync {
    /// Send a command to the guest agent.
    fn send(
        &self,
        cmd: HostCommand,
    ) -> impl std::future::Future<Output = BackendResult<()>> + Send;

    /// Receive the next event from the guest agent.
    fn recv(&self) -> impl std::future::Future<Output = BackendResult<GuestEvent>> + Send;

    /// Terminate the capsule (SIGTERM → SIGKILL escalation).
    fn terminate(&self) -> impl std::future::Future<Output = BackendResult<()>> + Send;

    /// Get the capsule's PID (or VM ID).
    fn id(&self) -> String;
}

/// Isolation backend — creates capsules.
pub trait Backend: Send + Sync {
    type Handle: CapsuleHandle;

    /// Spawn a new execution capsule for the given job.
    fn spawn(
        &self,
        spec: &JobSpec,
        worker_binary: &str,
    ) -> impl std::future::Future<Output = BackendResult<Self::Handle>> + Send;
}
