use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::process::{Child, Command};
use tokio::sync::oneshot;

use crate::backend::{Backend, CapsuleChild, CapsuleHandle, KernelError, KernelResult};
use crate::types::{CapsuleReport, CapsuleSpec, ResourceViolation, Signal};

pub struct ProcessBackend;

impl Backend for ProcessBackend {
    fn create(&self, spec: CapsuleSpec) -> KernelResult<Box<dyn CapsuleHandle>> {
        Ok(Box::new(ProcessCapsule::new(spec)))
    }
}

struct ProcessState {
    child: Option<Child>,
    exit_code: Option<i32>,
    exit_signal: Option<i32>,
    killed_by: Option<ResourceViolation>,
}

pub struct ProcessCapsule {
    spec: CapsuleSpec,
    started_at: Instant,
    state: Arc<Mutex<ProcessState>>,
    timeout_cancel: Option<oneshot::Sender<()>>,
}

impl ProcessCapsule {
    fn new(spec: CapsuleSpec) -> Self {
        Self {
            spec,
            started_at: Instant::now(),
            state: Arc::new(Mutex::new(ProcessState {
                child: None,
                exit_code: None,
                exit_signal: None,
                killed_by: None,
            })),
            timeout_cancel: None,
        }
    }

    fn install_timeout_watchdog(&mut self, pid: u32) {
        let timeout_sec = self.spec.limits.timeout_sec;
        if timeout_sec == 0 {
            return;
        }

        let state = Arc::clone(&self.state);
        let (tx, rx) = oneshot::channel();
        self.timeout_cancel = Some(tx);

        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(timeout_sec)) => {
                    #[cfg(unix)]
                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = pid;
                    }
                    if let Ok(mut locked) = state.lock() {
                        if locked.killed_by.is_none() {
                            locked.killed_by = Some(ResourceViolation::WallClock);
                        }
                    }
                }
                _ = rx => {}
            }
        });
    }

    fn signal_number(signal: Signal) -> i32 {
        match signal {
            Signal::Terminate => libc::SIGTERM,
            Signal::Kill => libc::SIGKILL,
        }
    }
}

impl CapsuleHandle for ProcessCapsule {
    fn spawn(
        &mut self,
        binary: &str,
        args: &[&str],
        env: HashMap<String, String>,
    ) -> KernelResult<CapsuleChild> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| KernelError::CleanupFailed("capsule state poisoned".into()))?;
        if state.child.is_some() {
            return Err(KernelError::InvalidState(
                "capsule already has a running child".into(),
            ));
        }

        let mut cmd = Command::new(binary);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for (key, value) in env {
            cmd.env(key, value);
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| KernelError::SpawnFailed(format!("failed to spawn {binary}: {e}")))?;
        let pid = child.id().ok_or_else(|| {
            KernelError::SpawnFailed(format!("spawned process {binary} missing pid"))
        })?;
        let stdin = child.stdin.take().ok_or_else(|| {
            KernelError::SpawnFailed(format!("failed to capture stdin for {binary}"))
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            KernelError::SpawnFailed(format!("failed to capture stdout for {binary}"))
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            KernelError::SpawnFailed(format!("failed to capture stderr for {binary}"))
        })?;

        state.child = Some(child);
        drop(state);
        self.install_timeout_watchdog(pid);

        Ok(CapsuleChild {
            stdin: Box::pin(stdin),
            stdout: Box::pin(stdout),
            stderr: Box::pin(stderr),
            pid,
        })
    }

    fn kill(&mut self, signal: Signal) -> KernelResult<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| KernelError::CleanupFailed("capsule state poisoned".into()))?;
        let pid = state
            .child
            .as_ref()
            .and_then(tokio::process::Child::id)
            .ok_or_else(|| KernelError::InvalidState("capsule has no child to kill".into()))?;
        #[cfg(unix)]
        unsafe {
            libc::kill(pid as i32, Self::signal_number(signal));
        }
        #[cfg(not(unix))]
        {
            let _ = signal;
            let _ = pid;
        }
        Ok(())
    }

    fn destroy(mut self: Box<Self>) -> KernelResult<CapsuleReport> {
        if let Some(cancel) = self.timeout_cancel.take() {
            let _ = cancel.send(());
        }

        let mut state = self
            .state
            .lock()
            .map_err(|_| KernelError::CleanupFailed("capsule state poisoned".into()))?;

        if let Some(mut child) = state.child.take() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    state.exit_code = status.code();
                    state.exit_signal = exit_signal(&status);
                }
                Ok(None) => {
                    #[cfg(unix)]
                    unsafe {
                        libc::kill(child.id().unwrap_or_default() as i32, libc::SIGKILL);
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = child.start_kill();
                    }
                    for _ in 0..20 {
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                state.exit_code = status.code();
                                state.exit_signal = exit_signal(&status);
                                break;
                            }
                            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(25)),
                            Err(error) => {
                                return Err(KernelError::CleanupFailed(format!(
                                    "failed to inspect child status: {error}"
                                )));
                            }
                        }
                    }
                }
                Err(e) => {
                    return Err(KernelError::CleanupFailed(format!(
                        "failed to inspect child status: {e}"
                    )));
                }
            }
        }

        Ok(CapsuleReport {
            exit_code: state.exit_code,
            exit_signal: state.exit_signal,
            killed_by: state.killed_by,
            wall_time: self.started_at.elapsed(),
            peak_memory_mib: None,
        })
    }
}

#[cfg(unix)]
fn exit_signal(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;

    status.signal()
}

#[cfg(not(unix))]
fn exit_signal(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}
