use std::collections::HashMap;
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::types::{CapsuleReport, CapsuleSpec, Signal};

pub type KernelResult<T> = Result<T, KernelError>;

#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("spawn failed: {0}")]
    SpawnFailed(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("cleanup failed: {0}")]
    CleanupFailed(String),
    #[error("invalid state: {0}")]
    InvalidState(String),
    #[error("not supported: {0}")]
    NotSupported(String),
}

pub type CapsuleStdin = Pin<Box<dyn AsyncWrite + Send>>;
pub type CapsuleStdout = Pin<Box<dyn AsyncRead + Send>>;

pub struct CapsuleChild {
    pub stdin: CapsuleStdin,
    pub stdout: CapsuleStdout,
    pub pid: u32,
}

pub trait CapsuleHandle: Send {
    fn spawn(
        &mut self,
        binary: &str,
        args: &[&str],
        env: HashMap<String, String>,
    ) -> KernelResult<CapsuleChild>;

    fn kill(&mut self, signal: Signal) -> KernelResult<()>;

    fn destroy(self: Box<Self>) -> KernelResult<CapsuleReport>;
}

pub trait Backend: Send + Sync {
    fn create(&self, spec: CapsuleSpec) -> KernelResult<Box<dyn CapsuleHandle>>;
}
