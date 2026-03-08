//! Firecracker microVM backend.
//!
//! Implements `Backend` and `CapsuleHandle` for `Isolation::Firecracker`.
//! VM lifecycle: create state_dir -> spawn (boot VM) -> kill (signal worker) -> destroy (teardown).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::net::UnixStream;
use tokio::sync::oneshot;

use crate::backend::{Backend, CapsuleChild, CapsuleHandle, KernelError, KernelResult};
use crate::types::{CapsuleReport, CapsuleSpec, FirecrackerConfig, ResourceViolation, Signal};

const WORKER_GUEST_PATH: &str = "/run/zeptokernel/worker";
const GUEST_INIT_PATH: &str = "/sbin/init";
const WORKER_PATH_FILE: &str = "/run/zeptokernel/worker.path";
const WORKER_ARGS_FILE: &str = "/run/zeptokernel/worker.args";
const WORKER_ENV_FILE: &str = "/run/zeptokernel/worker.env";
const WORKSPACE_DEVICE_FILE: &str = "/run/zeptokernel/workspace.device";
const WORKSPACE_PATH_FILE: &str = "/run/zeptokernel/workspace.path";
const TMP_SIZE_FILE: &str = "/run/zeptokernel/tmp.size";
const MODE_MARKER_FILE: &str = "/run/zeptokernel/firecracker.mode";
const TERMINATE_GRACE_SECS: u64 = 5;

fn rootfs_copy_path(state_dir: &Path) -> PathBuf {
    state_dir.join("rootfs.ext4")
}

fn serial_log_path(state_dir: &Path) -> PathBuf {
    state_dir.join("serial.log")
}

fn api_socket_path(state_dir: &Path) -> PathBuf {
    state_dir.join("api.sock")
}

fn vsock_socket_path(state_dir: &Path) -> PathBuf {
    state_dir.join("fc.vsock")
}

fn wait_for_socket(path: &Path) -> KernelResult<()> {
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err(KernelError::SpawnFailed(format!(
        "timeout waiting for socket: {}",
        path.display()
    )))
}

fn build_boot_args() -> String {
    "console=ttyS0 reboot=k panic=1 root=/dev/vda rw init=/sbin/init".to_string()
}

fn write_nul_delimited_strings(path: &Path, values: &[String]) -> KernelResult<()> {
    let mut bytes = Vec::new();
    for value in values {
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
    }
    std::fs::write(path, bytes)
        .map_err(|e| KernelError::SpawnFailed(format!("write {}: {e}", path.display())))
}

fn mount_loop_image(image: &Path, mount_point: &Path) -> KernelResult<()> {
    std::fs::create_dir_all(mount_point)
        .map_err(|e| KernelError::SpawnFailed(format!("mkdir {}: {e}", mount_point.display())))?;

    let output = std::process::Command::new("mount")
        .args(["-o", "loop"])
        .arg(image)
        .arg(mount_point)
        .output()
        .map_err(|e| KernelError::SpawnFailed(format!("mount {}: {e}", image.display())))?;

    if !output.status.success() {
        return Err(KernelError::SpawnFailed(format!(
            "mount {} failed: {}",
            image.display(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

fn unmount_path(path: &Path) {
    let _ = std::process::Command::new("umount").arg(path).output();
}

fn stage_firecracker_payload(
    binary: &str,
    args: &[&str],
    env: &HashMap<String, String>,
    init_binary: &Path,
    guest_workspace_path: &Path,
    rootfs_image: &Path,
    state_dir: &Path,
) -> KernelResult<()> {
    let mount_point = state_dir.join("rootfs_mount");
    mount_loop_image(rootfs_image, &mount_point)?;

    let result = (|| -> KernelResult<()> {
        let stage_dir = mount_point.join("run/zeptokernel");
        std::fs::create_dir_all(&stage_dir)
            .map_err(|e| KernelError::SpawnFailed(format!("mkdir {}: {e}", stage_dir.display())))?;

        // If the binary already exists in the rootfs (e.g. /bin/cat from busybox),
        // use it directly to avoid glibc/musl mismatch from copying host binaries.
        // Use symlink_metadata to avoid following symlinks that resolve to absolute
        // paths outside the mount point (e.g. /bin/cat -> /bin/busybox).
        let guest_worker_path = {
            let rootfs_binary = mount_point.join(binary.trim_start_matches('/'));
            if std::fs::symlink_metadata(&rootfs_binary).is_ok() {
                binary.to_string()
            } else {
                let worker_dest = stage_dir.join("worker");
                std::fs::copy(binary, &worker_dest)
                    .map_err(|e| KernelError::SpawnFailed(format!("copy worker binary: {e}")))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(
                        &worker_dest,
                        std::fs::Permissions::from_mode(0o755),
                    )
                    .map_err(|e| {
                        KernelError::SpawnFailed(format!("chmod {}: {e}", worker_dest.display()))
                    })?;
                }
                WORKER_GUEST_PATH.to_string()
            }
        };

        let init_dest = mount_point.join("sbin/init");
        if let Some(parent) = init_dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                KernelError::SpawnFailed(format!("mkdir {}: {e}", parent.display()))
            })?;
        }
        // Remove existing symlink (e.g. Alpine /sbin/init -> /bin/busybox)
        // to avoid overwriting the symlink target instead of replacing /sbin/init.
        let _ = std::fs::remove_file(&init_dest);
        std::fs::copy(init_binary, &init_dest)
            .map_err(|e| KernelError::SpawnFailed(format!("copy zk-init: {e}")))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&init_dest, std::fs::Permissions::from_mode(0o755)).map_err(
                |e| KernelError::SpawnFailed(format!("chmod {}: {e}", init_dest.display())),
            )?;
        }

        std::fs::write(
            stage_dir.join("worker.path"),
            format!("{guest_worker_path}\n"),
        )
        .map_err(|e| KernelError::SpawnFailed(format!("write {}: {e}", WORKER_PATH_FILE)))?;
        write_nul_delimited_strings(
            &stage_dir.join("worker.args"),
            &args
                .iter()
                .map(|arg| (*arg).to_string())
                .collect::<Vec<_>>(),
        )?;
        write_nul_delimited_strings(
            &stage_dir.join("worker.env"),
            &env.iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>(),
        )?;
        std::fs::write(stage_dir.join("workspace.device"), b"/dev/vdb\n").map_err(|e| {
            KernelError::SpawnFailed(format!("write {}: {e}", WORKSPACE_DEVICE_FILE))
        })?;
        std::fs::write(
            stage_dir.join("workspace.path"),
            format!("{}\n", guest_workspace_path.display()),
        )
        .map_err(|e| KernelError::SpawnFailed(format!("write {}: {e}", WORKSPACE_PATH_FILE)))?;
        std::fs::write(stage_dir.join("tmp.size"), b"64m\n")
            .map_err(|e| KernelError::SpawnFailed(format!("write {}: {e}", TMP_SIZE_FILE)))?;
        std::fs::write(stage_dir.join("firecracker.mode"), b"1\n")
            .map_err(|e| KernelError::SpawnFailed(format!("write {}: {e}", MODE_MARKER_FILE)))?;

        Ok(())
    })();

    unmount_path(&mount_point);
    result
}

fn control_message(signal: Signal) -> String {
    match signal {
        Signal::Terminate => "TERMINATE\n".to_string(),
        Signal::Kill => "KILL\n".to_string(),
    }
}

enum ControlStatus {
    Exited(i32),
    Signaled(i32),
    Unknown,
}

fn parse_exit_status(line: &str) -> ControlStatus {
    if let Some(value) = line.trim().strip_prefix("EXIT ") {
        if let Ok(code) = value.trim().parse::<i32>() {
            return ControlStatus::Exited(code);
        }
    }
    if let Some(value) = line.trim().strip_prefix("SIGNAL ") {
        if let Ok(signal) = value.trim().parse::<i32>() {
            return ControlStatus::Signaled(signal);
        }
    }
    ControlStatus::Unknown
}

async fn read_control_line(
    stream: &mut UnixStream,
    timeout: std::time::Duration,
) -> KernelResult<Option<String>> {
    use tokio::io::AsyncReadExt;

    tokio::time::timeout(timeout, async {
        let mut bytes = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            let read = stream
                .read(&mut byte)
                .await
                .map_err(|e| KernelError::Transport(format!("control read: {e}")))?;
            if read == 0 {
                break;
            }
            if byte[0] == b'\n' {
                break;
            }
            bytes.push(byte[0]);
        }

        if bytes.is_empty() {
            Ok(None)
        } else {
            String::from_utf8(bytes)
                .map(Some)
                .map_err(|e| KernelError::Transport(format!("control utf8: {e}")))
        }
    })
    .await
    .map_err(|_| KernelError::Transport("control channel timeout".into()))?
}

pub struct FirecrackerBackend;

impl Backend for FirecrackerBackend {
    fn create(&self, spec: CapsuleSpec) -> KernelResult<Box<dyn CapsuleHandle>> {
        let config = spec
            .firecracker
            .as_ref()
            .ok_or_else(|| {
                KernelError::NotSupported(
                    "Firecracker isolation requires firecracker config".into(),
                )
            })?
            .clone();

        validate_prerequisites(&config)?;

        let state_dir = create_state_dir()?;

        Ok(Box::new(FirecrackerCapsule {
            spec,
            config,
            state_dir,
            fc_process: None,
            control: None,
            started_at: Instant::now(),
            killed_by: Arc::new(Mutex::new(None)),
            timeout_cancel: None,
        }))
    }
}

pub struct FirecrackerCapsule {
    spec: CapsuleSpec,
    config: FirecrackerConfig,
    state_dir: PathBuf,
    fc_process: Option<std::process::Child>,
    control: Option<UnixStream>,
    started_at: Instant,
    killed_by: Arc<Mutex<Option<ResourceViolation>>>,
    timeout_cancel: Option<oneshot::Sender<()>>,
}

impl FirecrackerCapsule {
    fn kill_fc_process(&mut self) -> KernelResult<()> {
        if let Some(ref mut child) = self.fc_process {
            child
                .kill()
                .map_err(|e| KernelError::Transport(format!("kill firecracker: {e}")))?;
        }
        Ok(())
    }
}

impl CapsuleHandle for FirecrackerCapsule {
    fn spawn(
        &mut self,
        binary: &str,
        args: &[&str],
        env: HashMap<String, String>,
    ) -> KernelResult<CapsuleChild> {
        use crate::firecracker_api as api;
        use crate::vsock;
        use crate::workspace_image;

        let api_socket = api_socket_path(&self.state_dir);
        let vsock_socket = vsock_socket_path(&self.state_dir);
        let serial_log = serial_log_path(&self.state_dir);
        let rootfs_copy = rootfs_copy_path(&self.state_dir);

        std::fs::copy(&self.config.rootfs_path, &rootfs_copy)
            .map_err(|e| KernelError::SpawnFailed(format!("copy rootfs: {e}")))?;

        let init_binary = self
            .spec
            .init_binary
            .clone()
            .map(Ok)
            .unwrap_or_else(crate::default_init_binary)?;
        stage_firecracker_payload(
            binary,
            args,
            &env,
            &init_binary,
            &self.spec.workspace.guest_path,
            &rootfs_copy,
            &self.state_dir,
        )?;

        let ws_image = workspace_image::image_path(&self.state_dir);
        let ws_size = workspace_image::default_size_mib(self.spec.workspace.size_mib);
        workspace_image::create_image(&ws_image, ws_size)?;

        if let Some(ref host_path) = self.spec.workspace.host_path {
            let mount_point = self.state_dir.join("ws_mount");
            workspace_image::seed_from_host(&ws_image, host_path, &mount_point)?;
        }

        // Firecracker requires the log file to exist before starting.
        std::fs::write(&serial_log, b"").map_err(|e| {
            KernelError::SpawnFailed(format!("create log file {}: {e}", serial_log.display()))
        })?;

        let fc_child = std::process::Command::new(&self.config.firecracker_bin)
            .args(["--api-sock", &api_socket.to_string_lossy()])
            .arg("--log-path")
            .arg(&serial_log)
            .arg("--level")
            .arg("Warning")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| KernelError::SpawnFailed(format!("start firecracker: {e}")))?;
        self.fc_process = Some(fc_child);

        wait_for_socket(&api_socket)?;

        let vcpus = self.config.effective_vcpus(&self.spec.limits);
        let memory_mib = self.config.effective_memory_mib(&self.spec.limits);

        // Run async Firecracker API calls on a dedicated thread to avoid
        // "cannot block_on from within a runtime" when called from async context.
        let kernel_path = self.config.kernel_path.to_string_lossy().to_string();
        let enable_network = self.config.enable_network;
        let tap_name = self.config.tap_name.clone();
        let rootfs_str = rootfs_copy.to_string_lossy().to_string();
        let ws_str = ws_image.to_string_lossy().to_string();
        let vsock_str = vsock_socket.to_string_lossy().to_string();
        let api_sock = api_socket.clone();

        let configure_result: Result<_, KernelError> = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| KernelError::SpawnFailed(format!("create runtime: {e}")))?;
            rt.block_on(async {
                api::put_expect_ok(
                    &api_sock,
                    "/machine-config",
                    &api::machine_config_json(vcpus, memory_mib),
                )
                .await?;

                api::put_expect_ok(
                    &api_sock,
                    "/boot-source",
                    &api::boot_source_json(&kernel_path, &build_boot_args()),
                )
                .await?;

                api::put_expect_ok(
                    &api_sock,
                    "/drives/rootfs",
                    &api::drive_json("rootfs", &rootfs_str, true, false),
                )
                .await?;

                api::put_expect_ok(
                    &api_sock,
                    "/drives/workspace",
                    &api::drive_json("workspace", &ws_str, false, false),
                )
                .await?;

                api::put_expect_ok(
                    &api_sock,
                    "/vsock",
                    &api::vsock_json("vsock0", &vsock_str, vsock::GUEST_CID),
                )
                .await?;

                if enable_network {
                    if let Some(ref tap) = tap_name {
                        api::put_expect_ok(
                            &api_sock,
                            "/network-interfaces/eth0",
                            &api::network_interface_json("eth0", tap),
                        )
                        .await?;
                    }
                }

                api::put_expect_ok(&api_sock, "/actions", &api::action_json("InstanceStart"))
                    .await?;
                Ok::<(), KernelError>(())
            })
        })
        .join()
        .map_err(|_| KernelError::SpawnFailed("configure thread panicked".into()))?;
        configure_result?;

        wait_for_socket(&vsock_socket)?;

        let vsock_sock2 = vsock_socket.clone();
        let connect_result = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| KernelError::SpawnFailed(format!("create runtime: {e}")))?;
            rt.block_on(async {
                let stdin = vsock::connect(&vsock_sock2, vsock::PORT_STDIN).await?;
                let stdout = vsock::connect(&vsock_sock2, vsock::PORT_STDOUT).await?;
                let stderr = vsock::connect(&vsock_sock2, vsock::PORT_STDERR).await?;
                let mut control = vsock::connect(&vsock_sock2, vsock::PORT_CONTROL).await?;

                // Read READY on same runtime where the streams were created.
                let ready = read_control_line(
                    &mut control,
                    std::time::Duration::from_secs(30),
                )
                .await?;

                // Convert tokio streams to raw fds for cross-runtime use.
                use std::os::fd::IntoRawFd;
                let to_fd = |s: UnixStream| -> KernelResult<i32> {
                    s.into_std()
                        .map(|s| s.into_raw_fd())
                        .map_err(|e| KernelError::Transport(format!("into_std: {e}")))
                };
                let stdin_fd = to_fd(stdin)?;
                let stdout_fd = to_fd(stdout)?;
                let stderr_fd = to_fd(stderr)?;
                let control_fd = to_fd(control)?;

                Ok::<_, KernelError>((stdin_fd, stdout_fd, stderr_fd, control_fd, ready))
            })
        })
        .join()
        .map_err(|_| KernelError::SpawnFailed("connect thread panicked".into()))?;
        let (stdin_fd, stdout_fd, stderr_fd, control_fd, ready) = connect_result?;

        // Re-wrap raw fds as tokio UnixStreams on whatever runtime is available.
        use std::os::fd::FromRawFd;
        let map_io = |e: std::io::Error| KernelError::Transport(format!("from_std: {e}"));
        let stdin_stream = unsafe {
            UnixStream::from_std(std::os::unix::net::UnixStream::from_raw_fd(stdin_fd))
                .map_err(map_io)?
        };
        let stdout_stream = unsafe {
            UnixStream::from_std(std::os::unix::net::UnixStream::from_raw_fd(stdout_fd))
                .map_err(map_io)?
        };
        let stderr_stream = unsafe {
            UnixStream::from_std(std::os::unix::net::UnixStream::from_raw_fd(stderr_fd))
                .map_err(map_io)?
        };
        let control_stream = unsafe {
            UnixStream::from_std(std::os::unix::net::UnixStream::from_raw_fd(control_fd))
                .map_err(map_io)?
        };
        if ready.as_deref() != Some("READY") {
            return Err(KernelError::SpawnFailed(format!(
                "zk-init sent unexpected readiness: {}",
                ready.unwrap_or_default()
            )));
        }
        self.control = Some(control_stream);

        let killed_by = Arc::clone(&self.killed_by);
        let timeout_sec = self.spec.limits.timeout_sec;
        let fc_pid = self.fc_process.as_ref().map(|child| child.id());
        if timeout_sec > 0 {
            let (tx, mut rx) = oneshot::channel::<()>();
            self.timeout_cancel = Some(tx);
            std::thread::spawn(move || {
                let deadline = Instant::now() + std::time::Duration::from_secs(timeout_sec);
                loop {
                    if rx.try_recv().is_ok() || Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
                if Instant::now() >= deadline {
                    *killed_by.lock().unwrap() = Some(ResourceViolation::WallClock);
                    if let Some(pid) = fc_pid {
                        unsafe {
                            libc::kill(pid as i32, libc::SIGKILL);
                        }
                    }
                }
            });
        }

        let (stdout_read, _) = tokio::io::split(stdout_stream);
        let (stderr_read, _) = tokio::io::split(stderr_stream);
        let (_, stdin_write) = tokio::io::split(stdin_stream);
        let pid = self
            .fc_process
            .as_ref()
            .map(|child| child.id())
            .unwrap_or_default();

        Ok(CapsuleChild {
            stdin: Box::pin(stdin_write),
            stdout: Box::pin(stdout_read),
            stderr: Box::pin(stderr_read),
            pid,
        })
    }

    fn kill(&mut self, signal: Signal) -> KernelResult<()> {
        let message = control_message(signal);

        let control_result = if let Some(mut control) = self.control.take() {
            let result = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| KernelError::Transport(format!("create runtime: {e}")))?;
                let write_result = rt.block_on(async {
                    use tokio::io::AsyncWriteExt;
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        control.write_all(message.as_bytes()),
                    )
                    .await
                    {
                        Ok(result) => result
                            .map_err(|e| KernelError::Transport(format!("control write: {e}"))),
                        Err(_) => {
                            Err(KernelError::Transport("control channel timeout".into()))
                        }
                    }
                });
                Ok::<_, KernelError>((write_result, control))
            })
            .join()
            .map_err(|_| KernelError::Transport("kill thread panicked".into()))?;
            match result {
                Ok((write_result, control)) => {
                    self.control = Some(control);
                    write_result
                }
                Err(e) => Err(e),
            }
        } else {
            Err(KernelError::InvalidState(
                "firecracker control channel is not connected".into(),
            ))
        };

        match signal {
            Signal::Terminate => {
                if control_result.is_err() {
                    tracing::warn!(
                        "control channel failed for TERMINATE, escalating to process kill"
                    );
                    self.kill_fc_process()?;
                } else {
                    std::thread::sleep(std::time::Duration::from_secs(TERMINATE_GRACE_SECS));
                }
            }
            Signal::Kill => {
                if let Err(error) = control_result {
                    tracing::warn!("control channel failed for KILL: {error}");
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
                self.kill_fc_process()?;
            }
        }

        Ok(())
    }

    fn destroy(mut self: Box<Self>) -> KernelResult<CapsuleReport> {
        if let Some(cancel) = self.timeout_cancel.take() {
            let _ = cancel.send(());
        }

        let mut exit_code = None;
        let mut exit_signal = None;
        if let Some(mut control) = self.control.take() {
            let line_result = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| KernelError::Transport(format!("create runtime: {e}")))?;
                rt.block_on(read_control_line(
                    &mut control,
                    std::time::Duration::from_secs(2),
                ))
            })
            .join()
            .map_err(|_| KernelError::Transport("destroy read thread panicked".into()))?;
            if let Some(line) = line_result? {
                match parse_exit_status(&line) {
                    ControlStatus::Exited(code) => exit_code = Some(code),
                    ControlStatus::Signaled(signal) => exit_signal = Some(signal),
                    ControlStatus::Unknown => {}
                }
            }
        }

        if let Some(ref mut child) = self.fc_process {
            let _ = child.kill();
            let _ = child.wait();
        }

        let wall_time = self.started_at.elapsed();
        let killed_by = self.killed_by.lock().unwrap().take();

        if let Some(ref host_path) = self.spec.workspace.host_path {
            use crate::workspace_image;
            let ws_image = workspace_image::image_path(&self.state_dir);
            if ws_image.exists() {
                let mount_point = self.state_dir.join("ws_export_mount");
                if let Err(error) =
                    workspace_image::export_to_host(&ws_image, host_path, &mount_point)
                {
                    tracing::warn!("workspace export failed: {error}");
                }
            }
        }

        let serial = serial_log_path(&self.state_dir);
        let serial_hint = if serial.exists() {
            std::fs::read_to_string(&serial)
                .ok()
                .and_then(|log| extract_serial_hint(&log))
        } else {
            None
        };

        if let Some(ref hint) = serial_hint {
            tracing::debug!("serial log hints: {hint}");
        }

        if self.state_dir.exists() {
            let _ = std::fs::remove_dir_all(&self.state_dir);
        }

        Ok(CapsuleReport {
            exit_code,
            exit_signal,
            killed_by,
            wall_time,
            peak_memory_mib: None,
        })
    }
}

fn validate_prerequisites(config: &FirecrackerConfig) -> KernelResult<()> {
    if !config.firecracker_bin.exists() {
        return Err(KernelError::NotSupported(format!(
            "firecracker binary not found: {}",
            config.firecracker_bin.display()
        )));
    }
    if !config.kernel_path.exists() {
        return Err(KernelError::NotSupported(format!(
            "kernel image not found: {}",
            config.kernel_path.display()
        )));
    }
    if !config.rootfs_path.exists() {
        return Err(KernelError::NotSupported(format!(
            "rootfs image not found: {}",
            config.rootfs_path.display()
        )));
    }

    let kvm = Path::new("/dev/kvm");
    if !kvm.exists() {
        return Err(KernelError::NotSupported(
            "/dev/kvm not available — KVM required for Firecracker".into(),
        ));
    }

    Ok(())
}

fn create_state_dir() -> KernelResult<PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = format!(
        "zk-fc-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
    );
    let dir = std::env::temp_dir().join(&id);
    std::fs::create_dir_all(&dir)
        .map_err(|e| KernelError::SpawnFailed(format!("create state_dir: {e}")))?;
    Ok(dir)
}

/// Extract a diagnostic hint from the serial log if boot/runtime errors are present.
/// Returns at most a few lines of relevant context, not the full log.
fn extract_serial_hint(log: &str) -> Option<String> {
    let error_patterns = ["panic", "error", "failed", "fatal", "Oops"];
    let mut hints = Vec::new();

    for line in log.lines() {
        let lower = line.to_lowercase();
        if error_patterns.iter().any(|p| lower.contains(p)) {
            hints.push(line.to_string());
            if hints.len() >= 5 {
                break;
            }
        }
    }

    if hints.is_empty() {
        None
    } else {
        Some(hints.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn test_spec() -> CapsuleSpec {
        CapsuleSpec {
            isolation: Isolation::Firecracker,
            security: SecurityProfile::Standard,
            firecracker: Some(FirecrackerConfig {
                firecracker_bin: PathBuf::from("/nonexistent/firecracker"),
                kernel_path: PathBuf::from("/nonexistent/vmlinux"),
                rootfs_path: PathBuf::from("/nonexistent/rootfs.ext4"),
                vcpus: None,
                memory_mib: None,
                enable_network: false,
                tap_name: None,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn create_rejects_missing_firecracker_config() {
        let backend = FirecrackerBackend;
        let spec = CapsuleSpec {
            isolation: Isolation::Firecracker,
            security: SecurityProfile::Standard,
            ..Default::default()
        };
        let result = backend.create(spec);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(matches!(err, KernelError::NotSupported(_)));
    }

    #[test]
    fn create_rejects_missing_firecracker_binary() {
        let backend = FirecrackerBackend;
        let err = backend.create(test_spec()).err().expect("expected error");
        let msg = format!("{err}");
        assert!(
            msg.contains("firecracker")
                || msg.contains("not found")
                || msg.contains("not supported"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn create_state_dir_unique() {
        let dir1 = create_state_dir().unwrap();
        // Small delay to ensure different timestamp
        std::thread::sleep(std::time::Duration::from_millis(2));
        let dir2 = create_state_dir().unwrap();
        assert_ne!(dir1, dir2);
        let _ = std::fs::remove_dir_all(&dir1);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn rootfs_copy_path_in_state_dir() {
        let state_dir = PathBuf::from("/tmp/zk-fc-test");
        let rootfs = rootfs_copy_path(&state_dir);
        assert_eq!(rootfs, PathBuf::from("/tmp/zk-fc-test/rootfs.ext4"));
    }

    #[test]
    fn worker_guest_path_is_fixed() {
        assert_eq!(WORKER_GUEST_PATH, "/run/zeptokernel/worker");
    }

    #[test]
    fn guest_init_path_is_fixed() {
        assert_eq!(GUEST_INIT_PATH, "/sbin/init");
    }

    #[test]
    fn boot_args_include_root_and_init() {
        let boot_args = build_boot_args();
        assert!(boot_args.contains("root=/dev/vda"));
        assert!(boot_args.contains("init=/sbin/init"));
    }

    #[test]
    fn serial_log_path_in_state_dir() {
        let state_dir = PathBuf::from("/tmp/zk-fc-test");
        let serial = serial_log_path(&state_dir);
        assert_eq!(serial, PathBuf::from("/tmp/zk-fc-test/serial.log"));
    }

    #[test]
    fn api_socket_path_in_state_dir() {
        let state_dir = PathBuf::from("/tmp/zk-fc-test");
        let socket = api_socket_path(&state_dir);
        assert_eq!(socket, PathBuf::from("/tmp/zk-fc-test/api.sock"));
    }

    #[test]
    fn vsock_socket_path_in_state_dir() {
        let state_dir = PathBuf::from("/tmp/zk-fc-test");
        let vsock = vsock_socket_path(&state_dir);
        assert_eq!(vsock, PathBuf::from("/tmp/zk-fc-test/fc.vsock"));
    }

    #[test]
    fn control_message_terminate() {
        assert_eq!(control_message(Signal::Terminate), "TERMINATE\n");
    }

    #[test]
    fn control_message_kill() {
        assert_eq!(control_message(Signal::Kill), "KILL\n");
    }

    #[test]
    fn parse_exit_code_message() {
        match parse_exit_status("EXIT 7") {
            ControlStatus::Exited(code) => assert_eq!(code, 7),
            _ => panic!("expected exit status"),
        }
    }

    #[test]
    fn parse_signal_message() {
        match parse_exit_status("SIGNAL 15") {
            ControlStatus::Signaled(signal) => assert_eq!(signal, 15),
            _ => panic!("expected signal status"),
        }
    }

    #[test]
    fn extract_serial_hint_finds_panic() {
        let log = "booting kernel...\nKernel panic - not syncing: VFS\nend trace\n";
        let hint = extract_serial_hint(log);
        assert!(hint.is_some());
        assert!(hint.unwrap().contains("panic"));
    }

    #[test]
    fn extract_serial_hint_empty_log() {
        let hint = extract_serial_hint("");
        assert!(hint.is_none());
    }

    #[test]
    fn extract_serial_hint_no_errors() {
        let log = "booting kernel...\nStarting zk-init\nREADY\n";
        let hint = extract_serial_hint(log);
        assert!(hint.is_none());
    }
}
