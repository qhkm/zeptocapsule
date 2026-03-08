//! Process backend — spawns `zk-guest` as a child process with stdin/stdout IPC.
//!
//! No isolation. Same protocol. Used for development and testing on macOS/Linux.

use std::path::PathBuf;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::Mutex;

use zk_proto::{GuestEvent, HostCommand, JobSpec};

use crate::backend::{Backend, BackendError, BackendResult, CapsuleHandle};

/// A running guest process.
pub struct ProcessHandle {
    child: Mutex<Child>,
    stdin: Mutex<BufWriter<ChildStdin>>,
    stdout: Mutex<Lines<BufReader<ChildStdout>>>,
    pid: u32,
}

impl CapsuleHandle for ProcessHandle {
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
            Ok(Some(line)) => {
                zk_proto::decode_line(&line)
                    .map_err(|e| BackendError::Transport(format!("decode: {e}")))
            }
            Ok(None) => Err(BackendError::Transport("guest closed stdout (EOF)".into())),
            Err(e) => Err(BackendError::Transport(format!("stdout read: {e}"))),
        }
    }

    async fn terminate(&self) -> BackendResult<()> {
        let mut child = self.child.lock().await;

        // Try SIGTERM first (Unix only)
        #[cfg(unix)]
        if let Some(pid) = child.id() {
            unsafe { libc::kill(pid as i32, libc::SIGTERM) };
            // Wait up to 5s for graceful exit
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                child.wait(),
            )
            .await
            {
                Ok(Ok(_)) => return Ok(()),
                _ => {} // Fall through to SIGKILL
            }
        }

        // SIGKILL
        child
            .kill()
            .await
            .map_err(|e| BackendError::CleanupFailed(format!("kill: {e}")))?;
        child
            .wait()
            .await
            .map_err(|e| BackendError::CleanupFailed(format!("wait: {e}")))?;
        Ok(())
    }

    fn id(&self) -> String {
        format!("process-{}", self.pid)
    }
}

/// Backend that spawns `zk-guest` as a child process. No isolation.
pub struct ProcessBackend {
    guest_binary: PathBuf,
}

impl ProcessBackend {
    pub fn new(guest_binary: impl Into<PathBuf>) -> Self {
        Self {
            guest_binary: guest_binary.into(),
        }
    }
}

impl Backend for ProcessBackend {
    type Handle = ProcessHandle;

    async fn spawn(&self, _spec: &JobSpec, _worker_binary: &str) -> BackendResult<ProcessHandle> {
        use tokio::process::Command;

        let mut child = Command::new(&self.guest_binary)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                BackendError::SpawnFailed(format!(
                    "failed to spawn {:?}: {e}",
                    self.guest_binary
                ))
            })?;

        let pid = child.id().unwrap_or(0);
        let child_stdin = child.stdin.take().ok_or_else(|| {
            BackendError::SpawnFailed("failed to capture child stdin".into())
        })?;
        let child_stdout = child.stdout.take().ok_or_else(|| {
            BackendError::SpawnFailed("failed to capture child stdout".into())
        })?;

        // Drain stderr in background so it doesn't block
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::debug!(target: "zk_guest_stderr", "{}", line);
                }
            });
        }

        Ok(ProcessHandle {
            child: Mutex::new(child),
            stdin: Mutex::new(BufWriter::new(child_stdin)),
            stdout: Mutex::new(BufReader::new(child_stdout).lines()),
            pid,
        })
    }
}
