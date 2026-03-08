//! Firecracker microVM backend.
//!
//! Implements `Backend` and `CapsuleHandle` for `Isolation::Firecracker`.
//! VM lifecycle: create state_dir -> spawn (boot VM) -> kill (signal worker) -> destroy (teardown).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::backend::{Backend, CapsuleChild, CapsuleHandle, KernelError, KernelResult};
use crate::types::{
    CapsuleReport, CapsuleSpec, FirecrackerConfig, ResourceViolation, Signal,
};

const WORKER_GUEST_PATH: &str = "/run/zeptokernel/worker";
const DEFAULT_BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1 quiet";
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

fn stage_worker_binary(
    binary: &str,
    rootfs_image: &Path,
    state_dir: &Path,
) -> KernelResult<()> {
    let mount_point = state_dir.join("rootfs_mount");
    std::fs::create_dir_all(&mount_point)
        .map_err(|e| KernelError::SpawnFailed(format!("mkdir rootfs_mount: {e}")))?;

    let output = std::process::Command::new("mount")
        .args(["-o", "loop"])
        .arg(rootfs_image)
        .arg(&mount_point)
        .output()
        .map_err(|e| KernelError::SpawnFailed(format!("mount rootfs: {e}")))?;

    if !output.status.success() {
        return Err(KernelError::SpawnFailed(format!(
            "mount rootfs failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let worker_dir = mount_point.join("run/zeptokernel");
    std::fs::create_dir_all(&worker_dir)
        .map_err(|e| KernelError::SpawnFailed(format!("mkdir worker dir: {e}")))?;

    let worker_dest = worker_dir.join("worker");
    std::fs::copy(binary, &worker_dest)
        .map_err(|e| KernelError::SpawnFailed(format!("copy worker binary: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&worker_dest, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| KernelError::SpawnFailed(format!("chmod worker: {e}")))?;
    }

    let _ = std::process::Command::new("umount")
        .arg(&mount_point)
        .output();

    Ok(())
}

fn control_message(signal: Signal) -> String {
    match signal {
        Signal::Terminate => "TERMINATE\n".to_string(),
        Signal::Kill => "KILL\n".to_string(),
    }
}

pub struct FirecrackerBackend;

impl Backend for FirecrackerBackend {
    fn create(&self, spec: CapsuleSpec) -> KernelResult<Box<dyn CapsuleHandle>> {
        let config = spec
            .firecracker
            .as_ref()
            .ok_or_else(|| {
                KernelError::NotSupported("Firecracker isolation requires firecracker config".into())
            })?
            .clone();

        validate_prerequisites(&config)?;

        let state_dir = create_state_dir()?;

        Ok(Box::new(FirecrackerCapsule {
            spec,
            config,
            state_dir,
            fc_process: None,
            started_at: Instant::now(),
            killed_by: Arc::new(Mutex::new(None)),
        }))
    }
}

pub struct FirecrackerCapsule {
    spec: CapsuleSpec,
    config: FirecrackerConfig,
    state_dir: PathBuf,
    fc_process: Option<std::process::Child>,
    started_at: Instant,
    killed_by: Arc<Mutex<Option<ResourceViolation>>>,
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
        _args: &[&str],
        _env: HashMap<String, String>,
    ) -> KernelResult<CapsuleChild> {
        use crate::firecracker_api as api;
        use crate::vsock;
        use crate::workspace_image;

        let api_socket = api_socket_path(&self.state_dir);
        let vsock_socket = vsock_socket_path(&self.state_dir);
        let serial_log = serial_log_path(&self.state_dir);
        let rootfs_copy = rootfs_copy_path(&self.state_dir);

        // 1. Copy rootfs to writable overlay
        std::fs::copy(&self.config.rootfs_path, &rootfs_copy)
            .map_err(|e| KernelError::SpawnFailed(format!("copy rootfs: {e}")))?;

        // 2. Stage worker binary into rootfs
        stage_worker_binary(binary, &rootfs_copy, &self.state_dir)?;

        // 3. Prepare workspace image
        let ws_image = workspace_image::image_path(&self.state_dir);
        let ws_size = workspace_image::default_size_mib(self.spec.workspace.size_mib);
        workspace_image::create_image(&ws_image, ws_size)?;

        if let Some(ref host_path) = self.spec.workspace.host_path {
            let mount_point = self.state_dir.join("ws_mount");
            workspace_image::seed_from_host(&ws_image, host_path, &mount_point)?;
        }

        // 4. Start Firecracker process
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

        // 5. Wait for API socket to appear
        wait_for_socket(&api_socket)?;

        // 6. Configure VM over REST API
        let vcpus = self.config.effective_vcpus(&self.spec.limits);
        let memory_mib = self.config.effective_memory_mib(&self.spec.limits);

        let rt = tokio::runtime::Handle::try_current()
            .map_err(|e| KernelError::SpawnFailed(format!("no tokio runtime: {e}")))?;

        rt.block_on(async {
            api::put_expect_ok(
                &api_socket,
                "/machine-config",
                &api::machine_config_json(vcpus, memory_mib),
            )
            .await?;

            api::put_expect_ok(
                &api_socket,
                "/boot-source",
                &api::boot_source_json(
                    &self.config.kernel_path.to_string_lossy(),
                    DEFAULT_BOOT_ARGS,
                ),
            )
            .await?;

            api::put_expect_ok(
                &api_socket,
                "/drives/rootfs",
                &api::drive_json("rootfs", &rootfs_copy.to_string_lossy(), true, false),
            )
            .await?;

            api::put_expect_ok(
                &api_socket,
                "/drives/workspace",
                &api::drive_json(
                    "workspace",
                    &ws_image.to_string_lossy(),
                    false,
                    false,
                ),
            )
            .await?;

            api::put_expect_ok(
                &api_socket,
                "/vsock",
                &api::vsock_json(
                    "vsock0",
                    &vsock_socket.to_string_lossy(),
                    vsock::GUEST_CID,
                ),
            )
            .await?;

            if self.config.enable_network {
                if let Some(ref tap) = self.config.tap_name {
                    api::put_expect_ok(
                        &api_socket,
                        "/network-interfaces/eth0",
                        &api::network_interface_json("eth0", tap),
                    )
                    .await?;
                }
            }

            api::put_expect_ok(
                &api_socket,
                "/actions",
                &api::action_json("InstanceStart"),
            )
            .await?;

            Ok::<(), KernelError>(())
        })?;

        // 7. Wait for vsock socket to appear
        wait_for_socket(&vsock_socket)?;

        // 8. Connect vsock streams
        let (stdin_stream, stdout_stream, stderr_stream) = rt.block_on(async {
            let stdin = vsock::connect(&vsock_socket, vsock::PORT_STDIN).await?;
            let stdout =
                vsock::connect(&vsock_socket, vsock::PORT_STDOUT).await?;
            let stderr =
                vsock::connect(&vsock_socket, vsock::PORT_STDERR).await?;
            Ok::<_, KernelError>((stdin, stdout, stderr))
        })?;

        // 9. Wait for control channel readiness
        rt.block_on(async {
            let mut ctrl =
                vsock::connect(&vsock_socket, vsock::PORT_CONTROL).await?;
            let mut buf = [0u8; 16];
            use tokio::io::AsyncReadExt;
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                ctrl.read(&mut buf),
            )
            .await
            .map_err(|_| {
                KernelError::SpawnFailed(
                    "zk-init readiness timeout (30s)".into(),
                )
            })?
            .map_err(|e| {
                KernelError::Transport(format!("control read: {e}"))
            })?;

            let msg = std::str::from_utf8(&buf[..n]).unwrap_or("");
            if !msg.starts_with("READY") {
                return Err(KernelError::SpawnFailed(format!(
                    "zk-init sent unexpected readiness: {msg}"
                )));
            }
            Ok(())
        })?;

        // 10. Start timeout watchdog
        let killed_by = Arc::clone(&self.killed_by);
        let timeout_sec = self.spec.limits.timeout_sec;
        let fc_pid = self.fc_process.as_ref().map(|c| c.id());

        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(timeout_sec))
                .await;
            *killed_by.lock().unwrap() =
                Some(ResourceViolation::WallClock);
            if let Some(pid) = fc_pid {
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
            }
        });

        // Split streams into CapsuleChild
        let (stdout_read, _) = tokio::io::split(stdout_stream);
        let (stderr_read, _) = tokio::io::split(stderr_stream);
        let (_, stdin_write) = tokio::io::split(stdin_stream);

        let pid =
            self.fc_process.as_ref().map(|c| c.id()).unwrap_or(0);

        Ok(CapsuleChild {
            stdin: Box::pin(stdin_write),
            stdout: Box::pin(stdout_read),
            stderr: Box::pin(stderr_read),
            pid,
        })
    }

    fn kill(&mut self, signal: Signal) -> KernelResult<()> {
        let vsock_socket = vsock_socket_path(&self.state_dir);

        let rt = tokio::runtime::Handle::try_current()
            .map_err(|e| {
                KernelError::Transport(format!("no tokio runtime: {e}"))
            })?;

        let msg = control_message(signal);

        let control_result = rt.block_on(async {
            match tokio::time::timeout(
                std::time::Duration::from_secs(2),
                async {
                    use crate::vsock;
                    let mut ctrl = vsock::connect(
                        &vsock_socket,
                        vsock::PORT_CONTROL,
                    )
                    .await?;
                    use tokio::io::AsyncWriteExt;
                    ctrl.write_all(msg.as_bytes())
                        .await
                        .map_err(|e| {
                            KernelError::Transport(format!(
                                "control write: {e}"
                            ))
                        })?;
                    Ok::<(), KernelError>(())
                },
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(KernelError::Transport(
                    "control channel timeout".into(),
                )),
            }
        });

        match signal {
            Signal::Terminate => {
                if control_result.is_err() {
                    tracing::warn!(
                        "control channel failed for TERMINATE, \
                         escalating to process kill"
                    );
                    self.kill_fc_process()?;
                }
            }
            Signal::Kill => {
                if let Err(e) = control_result {
                    tracing::warn!(
                        "control channel failed for KILL: {e}"
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(
                    500,
                ));
                self.kill_fc_process()?;
            }
        }

        Ok(())
    }

    fn destroy(mut self: Box<Self>) -> KernelResult<CapsuleReport> {
        // 1. Kill Firecracker process if running
        if let Some(ref mut child) = self.fc_process {
            let _ = child.kill();
            let _ = child.wait();
        }

        let wall_time = self.started_at.elapsed();
        let killed_by = self.killed_by.lock().unwrap().take();

        // 2. Export workspace back to host if configured
        if let Some(ref host_path) = self.spec.workspace.host_path {
            use crate::workspace_image;
            let ws_image = workspace_image::image_path(&self.state_dir);
            if ws_image.exists() {
                let mount_point = self.state_dir.join("ws_export_mount");
                if let Err(e) = workspace_image::export_to_host(&ws_image, host_path, &mount_point) {
                    tracing::warn!("workspace export failed: {e}");
                }
            }
        }

        // 3. Read serial log for diagnostics
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

        // 4. Clean up state directory
        if self.state_dir.exists() {
            let _ = std::fs::remove_dir_all(&self.state_dir);
        }

        Ok(CapsuleReport {
            exit_code: None,
            exit_signal: None,
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
    let id = format!("zk-fc-{}-{}", std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis());
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
        let err = backend.create(spec).unwrap_err();
        assert!(matches!(err, KernelError::NotSupported(_)));
    }

    #[test]
    fn create_rejects_missing_firecracker_binary() {
        let backend = FirecrackerBackend;
        let err = backend.create(test_spec()).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("firecracker") || msg.contains("not found") || msg.contains("not supported"),
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
