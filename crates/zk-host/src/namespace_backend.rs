//! Namespace sandbox backend — isolates each worker in Linux namespaces.
//!
//! Uses nix::sched::clone() with CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS
//! | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNET.
//!
//! Control channel: stdin/stdout pipe pair (same as ProcessBackend).
//! cgroup v2 enforces memory, CPU, and PID limits.

#[allow(unused_imports)]
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;

#[allow(unused_imports)]
use nix::sched::CloneFlags;
#[allow(unused_imports)]
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter, Lines};
use tokio::sync::Mutex;

use zk_proto::{GuestEvent, HostCommand, JobSpec};

use crate::backend::{Backend, BackendError, BackendResult, CapsuleHandle};
use crate::cgroup::Cgroup;

// ---------------------------------------------------------------------------
// NamespaceHandle — wraps a pipe pair to the guest process
// ---------------------------------------------------------------------------

pub struct NamespaceHandle {
    child_pid: Pid,
    stdin: Mutex<BufWriter<tokio::fs::File>>,
    stdout: Mutex<Lines<BufReader<tokio::fs::File>>>,
    _cgroup: Cgroup,
    _stack: Vec<u8>,
}

impl CapsuleHandle for NamespaceHandle {
    async fn send(&self, cmd: HostCommand) -> BackendResult<()> {
        let line = zk_proto::encode_line(&cmd)
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        let mut stdin = self.stdin.lock().await;
        stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|e| BackendError::Transport(format!("stdin write: {e}")))?;
        stdin
            .flush()
            .await
            .map_err(|e| BackendError::Transport(format!("stdin flush: {e}")))?;
        Ok(())
    }

    async fn recv(&self) -> BackendResult<GuestEvent> {
        let mut stdout = self.stdout.lock().await;
        match stdout.next_line().await {
            Ok(Some(line)) => zk_proto::decode_line(&line)
                .map_err(|e| BackendError::Transport(format!("decode: {e}"))),
            Ok(None) => Err(BackendError::Transport("guest closed stdout (EOF)".into())),
            Err(e) => Err(BackendError::Transport(format!("stdout read: {e}"))),
        }
    }

    async fn terminate(&self) -> BackendResult<()> {
        unsafe {
            libc::kill(self.child_pid.as_raw(), libc::SIGKILL);
        }
        let _ = nix::sys::wait::waitpid(self.child_pid, None);
        Ok(())
    }

    fn id(&self) -> String {
        format!("namespace-{}", self.child_pid.as_raw())
    }
}

// ---------------------------------------------------------------------------
// NamespaceBackend
// ---------------------------------------------------------------------------

pub struct NamespaceBackend {
    guest_binary: PathBuf,
}

impl NamespaceBackend {
    pub fn new(guest_binary: impl Into<PathBuf>) -> Self {
        Self {
            guest_binary: guest_binary.into(),
        }
    }
}

impl Backend for NamespaceBackend {
    type Handle = NamespaceHandle;

    async fn spawn(&self, spec: &JobSpec, _worker_binary: &str) -> BackendResult<NamespaceHandle> {
        do_clone(&self.guest_binary, spec)
            .map_err(|e| BackendError::SpawnFailed(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Clone implementation — stub, filled in Task 5
// ---------------------------------------------------------------------------

fn do_clone(
    _guest_binary: &PathBuf,
    _spec: &JobSpec,
) -> Result<NamespaceHandle, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "not yet implemented",
    ))
}
