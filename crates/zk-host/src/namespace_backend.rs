//! Namespace sandbox backend — isolates each worker in Linux namespaces.
//!
//! Uses nix::sched::clone() with CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS
//! | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNET.
//!
//! Control channel: stdin/stdout pipe pair (same as ProcessBackend).
//! cgroup v2 enforces memory, CPU, and PID limits.

use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::path::PathBuf;

use nix::sched::CloneFlags;
use nix::unistd::Pid;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter, Lines};
use tokio::sync::Mutex;

use zk_proto::{GuestEvent, HostCommand, JobSpec};

use crate::backend::{Backend, BackendError, BackendResult, CapsuleHandle};
use crate::cgroup::Cgroup;

// ---------------------------------------------------------------------------
// NamespaceHandle
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
// do_clone — core namespace spawn
// ---------------------------------------------------------------------------

fn do_clone(
    guest_binary: &PathBuf,
    spec: &JobSpec,
) -> Result<NamespaceHandle, std::io::Error> {
    // nix 0.29: pipe() returns (OwnedFd, OwnedFd) — (read_end, write_end).
    // We call into_raw_fd() immediately so the OwnedFd doesn't auto-close.

    // Pipe pair 1: host writes commands → child stdin (guest reads)
    let (guest_stdin_r_owned, host_stdin_w_owned) = nix::unistd::pipe()
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    let guest_stdin_r: RawFd = guest_stdin_r_owned.into_raw_fd();
    let host_stdin_w: RawFd = host_stdin_w_owned.into_raw_fd();

    // Pipe pair 2: child stdout (guest writes) → host reads events
    let (host_stdout_r_owned, guest_stdout_w_owned) = nix::unistd::pipe()
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    let host_stdout_r: RawFd = host_stdout_r_owned.into_raw_fd();
    let guest_stdout_w: RawFd = guest_stdout_w_owned.into_raw_fd();

    // Sync pipe: parent signals child after writing UID/GID maps
    let (sync_r_owned, sync_w_owned) = nix::unistd::pipe()
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    let sync_r: RawFd = sync_r_owned.into_raw_fd();
    let sync_w: RawFd = sync_w_owned.into_raw_fd();

    // Workspace directory must exist as a mount point before clone
    let workspace = spec.workspace.guest_path.clone();
    let workspace_size = spec.workspace.size_mib.unwrap_or(128);
    std::fs::create_dir_all(&workspace)?;

    let guest_binary = guest_binary.clone();

    // 8 MiB stack for the child thread
    let mut stack = vec![0u8; 8 * 1024 * 1024];

    let clone_flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWIPC
        | CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWNET;

    // nix 0.29: clone() takes Option<c_int> for the exit signal, not Option<Signal>
    let child_pid = unsafe {
        nix::sched::clone(
            Box::new(|| {
                child_main(
                    &guest_binary,
                    &workspace,
                    workspace_size,
                    sync_r,
                    guest_stdin_r,
                    guest_stdout_w,
                )
            }),
            &mut stack,
            clone_flags,
            Some(libc::SIGCHLD),
        )
    }
    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;

    // Parent: close child-side fds — these are now in the child's fd table
    let _ = nix::unistd::close(guest_stdin_r);
    let _ = nix::unistd::close(guest_stdout_w);
    let _ = nix::unistd::close(sync_r);

    // Write UID/GID maps — must happen before signalling child so the child
    // has the correct namespace capabilities when it tries to mount.
    if let Err(e) = write_uid_gid_maps(child_pid) {
        // Unblock child before killing so it doesn't hang on the sync read
        unsafe { libc::write(sync_w, [1u8].as_ptr() as *const libc::c_void, 1) };
        let _ = nix::unistd::close(sync_w);
        unsafe { libc::kill(child_pid.as_raw(), libc::SIGKILL) };
        let _ = nix::sys::wait::waitpid(child_pid, None);
        return Err(e);
    }

    // Create cgroup and apply resource limits (best-effort — don't fail spawn)
    let cgroup = match Cgroup::create(&spec.job_id) {
        Ok(cg) => {
            let _ = cg.add_pid(child_pid.as_raw() as u32);
            let _ = cg.apply_limits(&spec.limits);
            cg
        }
        Err(e) => {
            tracing::warn!("cgroup setup failed for job {}: {}", spec.job_id, e);
            Cgroup::dummy()
        }
    };

    // Signal child to proceed (write any byte)
    unsafe { libc::write(sync_w, [1u8].as_ptr() as *const libc::c_void, 1) };
    let _ = nix::unistd::close(sync_w);

    // Wrap raw fds as tokio async files
    let stdin_file = unsafe { tokio::fs::File::from_raw_fd(host_stdin_w) };
    let stdout_file = unsafe { tokio::fs::File::from_raw_fd(host_stdout_r) };

    Ok(NamespaceHandle {
        child_pid,
        stdin: Mutex::new(BufWriter::new(stdin_file)),
        stdout: Mutex::new(BufReader::new(stdout_file).lines()),
        _cgroup: cgroup,
        _stack: stack,
    })
}

// ---------------------------------------------------------------------------
// child_main — runs inside the new namespaces
// ---------------------------------------------------------------------------

fn child_main(
    guest_binary: &PathBuf,
    workspace: &PathBuf,
    workspace_size_mib: u64,
    sync_read: RawFd,
    stdin_fd: RawFd,
    stdout_fd: RawFd,
) -> isize {
    // 1. Wait for parent to write UID/GID maps
    let mut buf = [0u8; 1];
    unsafe { libc::read(sync_read, buf.as_mut_ptr() as *mut libc::c_void, 1) };
    unsafe { libc::close(sync_read) };

    // 2. Mount /proc so the child sees its own process tree
    let _ = nix::mount::mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        nix::mount::MsFlags::empty(),
        None::<&str>,
    );

    // 3. Mount workspace as tmpfs
    let _ = std::fs::create_dir_all(workspace);
    let opts = format!("size={}m,mode=0755", workspace_size_mib);
    let ok = nix::mount::mount(
        Some("tmpfs"),
        workspace.as_os_str(),
        Some("tmpfs"),
        nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV,
        Some(opts.as_str()),
    )
    .is_ok();
    if !ok {
        return -1;
    }

    // 4. Redirect stdin/stdout to our pipe pair
    unsafe {
        libc::dup2(stdin_fd, libc::STDIN_FILENO);
        libc::dup2(stdout_fd, libc::STDOUT_FILENO);
        libc::close(stdin_fd);
        libc::close(stdout_fd);
    }

    // 5. Exec zk-guest — this replaces the child process image
    let path = match std::ffi::CString::new(
        guest_binary.to_str().unwrap_or("/zk-guest"),
    ) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    let args: &[*const libc::c_char] = &[path.as_ptr(), std::ptr::null()];
    unsafe { libc::execv(path.as_ptr(), args.as_ptr()) };

    // If execv returns, it failed
    -1
}

// ---------------------------------------------------------------------------
// write_uid_gid_maps — enable root-inside-namespace → current-user-outside
// ---------------------------------------------------------------------------

fn write_uid_gid_maps(child_pid: Pid) -> std::io::Result<()> {
    let pid = child_pid.as_raw();
    let uid = nix::unistd::getuid().as_raw();
    let gid = nix::unistd::getgid().as_raw();

    // uid_map: map uid 0 (root) inside namespace → current uid outside
    std::fs::write(
        format!("/proc/{}/uid_map", pid),
        format!("0 {} 1\n", uid),
    )?;

    // Must write "deny" to setgroups before gid_map (kernel security requirement)
    std::fs::write(format!("/proc/{}/setgroups", pid), "deny\n")?;

    // gid_map: map gid 0 inside namespace → current gid outside
    std::fs::write(
        format!("/proc/{}/gid_map", pid),
        format!("0 {} 1\n", gid),
    )?;

    Ok(())
}
