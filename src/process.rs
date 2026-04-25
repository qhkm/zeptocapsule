use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::process::{Child, Command};
use tokio::sync::oneshot;

use crate::backend::{Backend, CapsuleChild, CapsuleHandle, KernelError, KernelResult};
use crate::egress::ca::CapsuleCa;
use crate::egress::judge::JudgeClient;
use crate::egress::proxy::{self, ProxyConfig, ProxyHandle};
use crate::egress::rules::CompiledPolicy;
use crate::types::{CapsuleReport, CapsuleSpec, ResourceViolation, Signal};

pub struct ProcessBackend;

impl Backend for ProcessBackend {
    fn create(&self, spec: CapsuleSpec) -> KernelResult<Box<dyn CapsuleHandle>> {
        ProcessCapsule::new(spec).map(|c| Box::new(c) as Box<dyn CapsuleHandle>)
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
    egress: Option<EgressRuntime>,
}

/// Per-capsule egress runtime: the proxy, the CA cert temp file path, and
/// the env-var bundle injected into the child process.
struct EgressRuntime {
    proxy: ProxyHandle,
    ca_cert_path: PathBuf,
    env: Vec<(String, String)>,
}

impl ProcessCapsule {
    fn new(spec: CapsuleSpec) -> KernelResult<Self> {
        let egress = match &spec.egress {
            Some(policy) => Some(start_egress(policy)?),
            None => None,
        };
        Ok(Self {
            spec,
            started_at: Instant::now(),
            state: Arc::new(Mutex::new(ProcessState {
                child: None,
                exit_code: None,
                exit_signal: None,
                killed_by: None,
            })),
            timeout_cancel: None,
            egress,
        })
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
                    let _ = pid;
                    if let Ok(mut locked) = state.lock() && locked.killed_by.is_none() {
                        locked.killed_by = Some(ResourceViolation::WallClock);
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
        // Inject egress env first so callers can override individual vars.
        if let Some(ref e) = self.egress {
            for (k, v) in &e.env {
                cmd.env(k, v);
            }
        }
        for (key, value) in env {
            cmd.env(key, value);
        }

        #[cfg(unix)]
        if matches!(self.spec.security, crate::types::SecurityProfile::Dev) {
            let rlimits = crate::types::RLimits::from(&self.spec.limits);
            unsafe {
                cmd.pre_exec(move || {
                    if let Some(mem) = rlimits.max_memory_bytes {
                        let rlim = libc::rlimit {
                            rlim_cur: mem,
                            rlim_max: mem,
                        };
                        libc::setrlimit(libc::RLIMIT_AS, &rlim);
                    }
                    if let Some(cpu) = rlimits.max_cpu_seconds {
                        let rlim = libc::rlimit {
                            rlim_cur: cpu,
                            rlim_max: cpu,
                        };
                        libc::setrlimit(libc::RLIMIT_CPU, &rlim);
                    }
                    if let Some(fsize) = rlimits.max_file_size_bytes {
                        let rlim = libc::rlimit {
                            rlim_cur: fsize,
                            rlim_max: fsize,
                        };
                        libc::setrlimit(libc::RLIMIT_FSIZE, &rlim);
                    }
                    Ok(())
                });
            }
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

        let egress_log = match self.egress.take() {
            Some(e) => {
                let log = e.proxy.drain_audit_log();
                e.proxy.shutdown();
                if let Err(err) = std::fs::remove_file(&e.ca_cert_path) {
                    tracing::debug!(
                        "failed to remove CA cert temp file at {}: {err}",
                        e.ca_cert_path.display()
                    );
                }
                log
            }
            None => Vec::new(),
        };

        Ok(CapsuleReport {
            exit_code: state.exit_code,
            exit_signal: state.exit_signal,
            killed_by: state.killed_by,
            wall_time: self.started_at.elapsed(),
            peak_memory_mib: None,
            init_error: None,
            actual_isolation: Some(crate::types::Isolation::Process),
            actual_security: Some(crate::types::SecurityProfile::Dev),
            egress_log,
        })
    }
}

/// Build and start the per-capsule proxy + CA cert temp file. Errors here
/// fail capsule creation; we'd rather surface a setup failure than start a
/// capsule that thinks it has an egress gate but actually doesn't.
fn start_egress(policy: &crate::egress::EgressPolicy) -> KernelResult<EgressRuntime> {
    let compiled = CompiledPolicy::compile(policy)
        .map_err(|e| KernelError::InvalidState(format!("egress policy compile failed: {e}")))?;
    let ca = CapsuleCa::generate()
        .map_err(|e| KernelError::SpawnFailed(format!("egress CA generation failed: {e}")))?;

    let judge = match &policy.judge {
        Some(cfg) => Some(
            JudgeClient::new(cfg.clone())
                .map_err(|e| KernelError::InvalidState(format!("egress judge init failed: {e}")))?,
        ),
        None => None,
    };

    let cfg = ProxyConfig {
        policy: compiled,
        ca,
        block_private_networks: policy.block_private_networks,
        default_action: policy.default_action,
        judge,
    };
    let pem = cfg.ca.ca_cert_pem().to_owned();
    let proxy = proxy::spawn(cfg)
        .map_err(|e| KernelError::SpawnFailed(format!("egress proxy bind failed: {e}")))?;

    let ca_cert_path = write_ca_cert_temp(&pem)?;
    let proxy_url = format!("http://{}", proxy.addr);
    let cert_path_str = ca_cert_path.to_string_lossy().into_owned();
    let env = vec![
        ("HTTP_PROXY".to_owned(), proxy_url.clone()),
        ("http_proxy".to_owned(), proxy_url.clone()),
        ("HTTPS_PROXY".to_owned(), proxy_url.clone()),
        ("https_proxy".to_owned(), proxy_url.clone()),
        ("ALL_PROXY".to_owned(), proxy_url.clone()),
        ("all_proxy".to_owned(), proxy_url),
        ("SSL_CERT_FILE".to_owned(), cert_path_str.clone()),
        ("REQUESTS_CA_BUNDLE".to_owned(), cert_path_str.clone()),
        ("NODE_EXTRA_CA_CERTS".to_owned(), cert_path_str.clone()),
        ("CURL_CA_BUNDLE".to_owned(), cert_path_str),
    ];

    Ok(EgressRuntime {
        proxy,
        ca_cert_path,
        env,
    })
}

fn write_ca_cert_temp(pem: &str) -> KernelResult<PathBuf> {
    let mut path = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    path.push(format!("zk-egress-ca-{}-{nanos}.pem", std::process::id()));
    std::fs::write(&path, pem)
        .map_err(|e| KernelError::SpawnFailed(format!("write CA temp file: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
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
