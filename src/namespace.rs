use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use nix::sched::CloneFlags;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use tokio::sync::oneshot;

use crate::backend::{Backend, CapsuleChild, CapsuleHandle, KernelError, KernelResult};
use crate::cgroup::Cgroup;
use crate::types::{CapsuleReport, CapsuleSpec, ResourceViolation, Signal};

static NEXT_CAPSULE_ID: AtomicU64 = AtomicU64::new(1);

pub struct NamespaceBackend;

impl Backend for NamespaceBackend {
    fn create(&self, spec: CapsuleSpec) -> KernelResult<Box<dyn CapsuleHandle>> {
        Ok(Box::new(NamespaceCapsule::new(spec)))
    }
}

struct NamespaceState {
    child_pid: Option<Pid>,
    cgroup: Option<Cgroup>,
    killed_by: Option<ResourceViolation>,
    stack: Option<Vec<u8>>,
    staged_init: Option<PathBuf>,
    diag_read: Option<RawFd>,
}

pub struct NamespaceCapsule {
    spec: CapsuleSpec,
    started_at: Instant,
    state: Arc<Mutex<NamespaceState>>,
    timeout_cancel: Option<oneshot::Sender<()>>,
}

impl NamespaceCapsule {
    fn new(spec: CapsuleSpec) -> Self {
        Self {
            spec,
            started_at: Instant::now(),
            state: Arc::new(Mutex::new(NamespaceState {
                child_pid: None,
                cgroup: None,
                killed_by: None,
                stack: None,
                staged_init: None,
                diag_read: None,
            })),
            timeout_cancel: None,
        }
    }

    fn install_timeout_watchdog(&mut self, pid: Pid) {
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
                    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
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

    fn signal_number(signal: Signal) -> nix::sys::signal::Signal {
        match signal {
            Signal::Terminate => nix::sys::signal::Signal::SIGTERM,
            Signal::Kill => nix::sys::signal::Signal::SIGKILL,
        }
    }
}

impl CapsuleHandle for NamespaceCapsule {
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
        if state.child_pid.is_some() {
            return Err(KernelError::InvalidState(
                "capsule already has a running child".into(),
            ));
        }

        let spawn = do_clone(&self.spec, binary, args, env)
            .map_err(|e| KernelError::SpawnFailed(e.to_string()))?;

        state.child_pid = Some(spawn.child_pid);
        state.cgroup = Some(spawn.cgroup);
        state.stack = Some(spawn.stack);
        state.staged_init = Some(spawn.staged_init);
        state.diag_read = Some(spawn.diag_read);
        drop(state);

        self.install_timeout_watchdog(spawn.child_pid);

        Ok(CapsuleChild {
            stdin: Box::pin(spawn.stdin),
            stdout: Box::pin(spawn.stdout),
            stderr: Box::pin(spawn.stderr),
            pid: spawn.child_pid.as_raw() as u32,
        })
    }

    fn kill(&mut self, signal: Signal) -> KernelResult<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| KernelError::CleanupFailed("capsule state poisoned".into()))?;
        let pid = state
            .child_pid
            .ok_or_else(|| KernelError::InvalidState("capsule has no child to kill".into()))?;
        nix::sys::signal::kill(pid, Self::signal_number(signal))
            .map_err(|e| KernelError::CleanupFailed(format!("kill {} failed: {e}", pid)))?;
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

        let mut exit_code = None;
        let mut exit_signal = None;
        if let Some(pid) = state.child_pid.take() {
            match waitpid(pid, Some(WaitPidFlag::WNOHANG))
                .map_err(|e| KernelError::CleanupFailed(format!("waitpid {pid}: {e}")))?
            {
                WaitStatus::StillAlive => {
                    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
                    match waitpid(pid, None)
                        .map_err(|e| KernelError::CleanupFailed(format!("waitpid {pid}: {e}")))?
                    {
                        WaitStatus::Exited(_, code) => exit_code = Some(code),
                        WaitStatus::Signaled(_, signal, _) => exit_signal = Some(signal as i32),
                        _ => {}
                    }
                }
                WaitStatus::Exited(_, code) => exit_code = Some(code),
                WaitStatus::Signaled(_, signal, _) => exit_signal = Some(signal as i32),
                _ => {}
            }
        }

        let init_error = if let Some(diag_fd) = state.diag_read.take() {
            let mut buf = [0u8; 4096];
            let n = nix::unistd::read(diag_fd, &mut buf).unwrap_or(0);
            let _ = nix::unistd::close(diag_fd);
            if n > 0 {
                Some(String::from_utf8_lossy(&buf[..n]).into_owned())
            } else {
                None
            }
        } else {
            None
        };

        let peak_memory_mib = state.cgroup.as_ref().and_then(Cgroup::peak_memory_mib);
        if state.killed_by.is_none() {
            state.killed_by = state.cgroup.as_ref().and_then(Cgroup::detect_violation);
        }
        let killed_by = state.killed_by;
        let _ = state.cgroup.take();
        let _ = state.stack.take();
        if let Some(staged) = state.staged_init.take() {
            let _ = std::fs::remove_file(&staged);
        }

        Ok(CapsuleReport {
            exit_code,
            exit_signal,
            killed_by,
            wall_time: self.started_at.elapsed(),
            peak_memory_mib,
            init_error,
            actual_isolation: Some(crate::types::Isolation::Namespace),
            actual_security: Some(self.spec.security),
        })
    }
}

struct NamespaceSpawn {
    child_pid: Pid,
    stdin: tokio::fs::File,
    stdout: tokio::fs::File,
    stderr: tokio::fs::File,
    cgroup: Cgroup,
    stack: Vec<u8>,
    staged_init: PathBuf,
    diag_read: RawFd,
}

struct StagedInitGuard(Option<PathBuf>);

impl StagedInitGuard {
    fn new(path: PathBuf) -> Self {
        Self(Some(path))
    }

    fn into_inner(mut self) -> PathBuf {
        self.0.take().expect("staged init path missing")
    }
}

impl Drop for StagedInitGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn do_clone(
    spec: &CapsuleSpec,
    binary: &str,
    args: &[&str],
    env: HashMap<String, String>,
) -> Result<NamespaceSpawn, std::io::Error> {
    let init_binary = resolve_init_binary(spec)?;

    // Copy init binary to a world-accessible temp path. Inside a user
    // namespace the process loses CAP_DAC_OVERRIDE in the parent namespace,
    // so it cannot traverse directories like /home/user (mode 700).
    let init_binary = stage_init_binary(&init_binary)?;
    let staged_init = StagedInitGuard::new(init_binary.clone());
    let (child_stdin_r_owned, host_stdin_w_owned) =
        nix::unistd::pipe().map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    let child_stdin_r = child_stdin_r_owned.into_raw_fd();
    let host_stdin_w = host_stdin_w_owned.into_raw_fd();

    let (host_stdout_r_owned, child_stdout_w_owned) =
        nix::unistd::pipe().map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    let host_stdout_r = host_stdout_r_owned.into_raw_fd();
    let child_stdout_w = child_stdout_w_owned.into_raw_fd();

    let (host_stderr_r_owned, child_stderr_w_owned) =
        nix::unistd::pipe().map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    let host_stderr_r = host_stderr_r_owned.into_raw_fd();
    let child_stderr_w = child_stderr_w_owned.into_raw_fd();

    let (sync_r_owned, sync_w_owned) =
        nix::unistd::pipe().map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    let sync_r = sync_r_owned.into_raw_fd();
    let sync_w = sync_w_owned.into_raw_fd();

    let (diag_r_owned, diag_w_owned) =
        nix::unistd::pipe().map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    let diag_r = diag_r_owned.into_raw_fd();
    let diag_w = diag_w_owned.into_raw_fd();

    let workspace = spec.workspace.guest_path.clone();
    let workspace_host = spec.workspace.host_path.clone();
    let workspace_size = spec.workspace.size_mib.unwrap_or(128);
    if let Some(host_workspace) = workspace_host.as_ref() {
        std::fs::create_dir_all(host_workspace)?;
    } else {
        std::fs::create_dir_all(&workspace)?;
    }

    let security = spec.security;

    let worker_binary = binary.to_owned();
    let worker_args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    let mut env = env.into_iter().collect::<Vec<_>>();
    env.push((
        "ZK_INIT_WORKSPACE_PATH".into(),
        workspace.to_string_lossy().into_owned(),
    ));
    if let Some(host_workspace) = workspace_host.as_ref() {
        env.push((
            "ZK_INIT_WORKSPACE_HOST_PATH".into(),
            host_workspace.to_string_lossy().into_owned(),
        ));
    }
    env.push((
        "ZK_INIT_WORKSPACE_SIZE".into(),
        format!("{workspace_size}m"),
    ));
    env.push(("ZK_INIT_TMP_SIZE".into(), "64m".into()));
    if matches!(security, crate::types::SecurityProfile::Hardened) {
        env.push(("ZK_ROOTFS_READY".into(), "1".into()));
    }

    let mut stack = vec![0_u8; 8 * 1024 * 1024];
    let clone_flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWIPC
        | CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWNET;

    let child_pid = unsafe {
        nix::sched::clone(
            Box::new(|| {
                child_main(
                    &init_binary,
                    &worker_binary,
                    &worker_args,
                    &env,
                    sync_r,
                    child_stdin_r,
                    child_stdout_w,
                    child_stderr_w,
                    diag_w,
                    security,
                    &workspace,
                    workspace_host.as_deref(),
                )
            }),
            &mut stack,
            clone_flags,
            Some(libc::SIGCHLD),
        )
    }
    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;

    let _ = nix::unistd::close(child_stdin_r);
    let _ = nix::unistd::close(child_stdout_w);
    let _ = nix::unistd::close(child_stderr_w);
    let _ = nix::unistd::close(sync_r);
    let _ = nix::unistd::close(diag_w);

    if let Err(error) = write_uid_gid_maps(child_pid) {
        unsafe { libc::write(sync_w, [1_u8].as_ptr().cast(), 1) };
        let _ = nix::unistd::close(sync_w);
        let _ = nix::unistd::close(diag_r);
        let _ = nix::sys::signal::kill(child_pid, nix::sys::signal::Signal::SIGKILL);
        let _ = waitpid(child_pid, None);
        return Err(error);
    }

    let capsule_id = format!(
        "capsule-{}",
        NEXT_CAPSULE_ID.fetch_add(1, Ordering::Relaxed)
    );
    let cgroup_required = spec.security_overrides.cgroup_required.unwrap_or(matches!(
        spec.security,
        crate::types::SecurityProfile::Hardened
    ));

    let cgroup = match Cgroup::create(&capsule_id) {
        Ok(cgroup) => {
            let _ = cgroup.add_pid(child_pid.as_raw() as u32);
            let _ = cgroup.apply_limits(&spec.limits);
            cgroup
        }
        Err(error) => {
            if cgroup_required {
                unsafe { libc::write(sync_w, [1_u8].as_ptr().cast(), 1) };
                let _ = nix::unistd::close(sync_w);
                let _ = nix::unistd::close(diag_r);
                let _ = nix::sys::signal::kill(child_pid, nix::sys::signal::Signal::SIGKILL);
                let _ = waitpid(child_pid, None);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("cgroup setup required but failed: {error}"),
                ));
            }
            tracing::warn!("cgroup setup failed for {}: {}", capsule_id, error);
            Cgroup::dummy()
        }
    };

    unsafe { libc::write(sync_w, [1_u8].as_ptr().cast(), 1) };
    let _ = nix::unistd::close(sync_w);

    let stdin = unsafe { tokio::fs::File::from_raw_fd(host_stdin_w) };
    let stdout = unsafe { tokio::fs::File::from_raw_fd(host_stdout_r) };
    let stderr = unsafe { tokio::fs::File::from_raw_fd(host_stderr_r) };

    Ok(NamespaceSpawn {
        child_pid,
        stdin,
        stdout,
        stderr,
        cgroup,
        stack,
        staged_init: staged_init.into_inner(),
        diag_read: diag_r,
    })
}

/// Copy init binary to /tmp with world-readable+executable permissions.
/// Inside a user namespace the child loses CAP_DAC_OVERRIDE in the parent
/// namespace, so paths under user home directories (mode 700) are inaccessible.
fn stage_init_binary(src: &std::path::Path) -> std::io::Result<PathBuf> {
    static STAGE_COUNTER: AtomicU64 = AtomicU64::new(0);
    let name = format!(
        "zk-init-{}-{}",
        std::process::id(),
        STAGE_COUNTER.fetch_add(1, Ordering::Relaxed),
    );
    let dest = std::env::temp_dir().join(name);
    std::fs::copy(src, &dest)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(dest)
}

/// Write a diagnostic message to the diag pipe and return -1 (child exit).
fn child_bail(diag_fd: RawFd, msg: &str) -> isize {
    let bytes = msg.as_bytes();
    unsafe { libc::write(diag_fd, bytes.as_ptr().cast(), bytes.len()) };
    -1
}

fn child_main(
    init_binary: &PathBuf,
    worker_binary: &str,
    worker_args: &[String],
    env: &[(String, String)],
    sync_read: RawFd,
    stdin_fd: RawFd,
    stdout_fd: RawFd,
    stderr_fd: RawFd,
    diag_fd: RawFd,
    security: crate::types::SecurityProfile,
    workspace_guest: &std::path::Path,
    workspace_host: Option<&std::path::Path>,
) -> isize {
    let mut sync_byte = [0_u8; 1];
    unsafe { libc::read(sync_read, sync_byte.as_mut_ptr().cast(), 1) };
    unsafe { libc::close(sync_read) };

    unsafe { libc::fcntl(diag_fd, libc::F_SETFD, libc::FD_CLOEXEC) };

    unsafe {
        libc::dup2(stdin_fd, libc::STDIN_FILENO);
        libc::dup2(stdout_fd, libc::STDOUT_FILENO);
        libc::dup2(stderr_fd, libc::STDERR_FILENO);
        libc::close(stdin_fd);
        libc::close(stdout_fd);
        libc::close(stderr_fd);
    }

    // Hardened: pivot_root + capabilities drop + seccomp.
    // After pivot_root the original /tmp path is inaccessible, so stage the
    // init binary inside the new rootfs before pivoting.
    let init_binary_path: std::path::PathBuf =
        if matches!(security, crate::types::SecurityProfile::Hardened) {
            let new_root =
                std::path::PathBuf::from(format!("/tmp/zk-rootfs-{}", std::process::id()));
            if let Err(e) = std::fs::create_dir_all(&new_root) {
                return child_bail(diag_fd, &format!("rootfs: mkdir {}: {e}", new_root.display()));
            }
            let staged = new_root.join("zk-init");
            if let Err(e) = std::fs::copy(init_binary, &staged) {
                return child_bail(diag_fd, &format!("rootfs: copy zk-init: {e}"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755));
            }

            if let Err(e) = crate::rootfs::setup_and_pivot(&new_root, workspace_guest, workspace_host) {
                return child_bail(diag_fd, &format!("rootfs: pivot: {e}"));
            }

            // Drop all capabilities from bounding set
            unsafe {
                for cap in 0..=40 {
                    libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0);
                }
            }

            // Install seccomp filter (must be after PR_SET_NO_NEW_PRIVS)
            if let Err(e) = crate::seccomp::install_seccomp_filter() {
                return child_bail(diag_fd, &format!("seccomp: {e}"));
            }

            // After pivot, the staged binary is at /zk-init
            std::path::PathBuf::from("/zk-init")
        } else {
            init_binary.clone()
        };

    let init_binary = match CString::new(init_binary_path.to_string_lossy().as_bytes()) {
        Ok(binary) => binary,
        Err(_) => return child_bail(diag_fd, "init binary path contains NUL"),
    };

    let worker_binary = match CString::new(worker_binary) {
        Ok(binary) => binary,
        Err(_) => return child_bail(diag_fd, "worker binary path contains NUL"),
    };
    let worker_args = worker_args
        .iter()
        .map(|arg| CString::new(arg.as_str()))
        .collect::<Result<Vec<_>, _>>();
    let worker_args = match worker_args {
        Ok(args) => args,
        Err(_) => return child_bail(diag_fd, "worker arg contains NUL"),
    };

    let argv_cstrings = std::iter::once(init_binary.clone())
        .chain(std::iter::once(worker_binary))
        .chain(worker_args)
        .collect::<Vec<_>>();
    let argv = argv_cstrings
        .iter()
        .map(|arg| arg.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect::<Vec<_>>();

    let env_cstrings = env
        .iter()
        .filter_map(|(key, value)| CString::new(format!("{key}={value}")).ok())
        .collect::<Vec<_>>();
    let envp = env_cstrings
        .iter()
        .map(|entry| entry.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect::<Vec<_>>();

    unsafe { libc::execve(init_binary.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    child_bail(
        diag_fd,
        &format!(
            "execve {}: {}",
            init_binary_path.display(),
            std::io::Error::last_os_error()
        ),
    )
}

fn resolve_init_binary(spec: &CapsuleSpec) -> Result<PathBuf, std::io::Error> {
    let path = if let Some(path) = &spec.init_binary {
        path.clone()
    } else {
        crate::default_init_binary()
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::NotFound, error.to_string()))?
    };

    if path.exists() {
        Ok(path)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("zk-init binary not found at {}", path.display()),
        ))
    }
}

fn write_uid_gid_maps(child_pid: Pid) -> std::io::Result<()> {
    let pid = child_pid.as_raw();
    let uid = nix::unistd::getuid().as_raw();
    let gid = nix::unistd::getgid().as_raw();

    std::fs::write(format!("/proc/{pid}/uid_map"), format!("0 {uid} 1\n"))?;
    std::fs::write(format!("/proc/{pid}/setgroups"), "deny\n")?;
    std::fs::write(format!("/proc/{pid}/gid_map"), format!("0 {gid} 1\n"))?;
    Ok(())
}
