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

impl CapsuleHandle for FirecrackerCapsule {
    fn spawn(
        &mut self,
        _binary: &str,
        _args: &[&str],
        _env: HashMap<String, String>,
    ) -> KernelResult<CapsuleChild> {
        Err(KernelError::NotSupported(
            "Firecracker spawn not yet implemented".into(),
        ))
    }

    fn kill(&mut self, _signal: Signal) -> KernelResult<()> {
        Err(KernelError::NotSupported(
            "Firecracker kill not yet implemented".into(),
        ))
    }

    fn destroy(mut self: Box<Self>) -> KernelResult<CapsuleReport> {
        if let Some(ref mut child) = self.fc_process {
            let _ = child.kill();
            let _ = child.wait();
        }

        let wall_time = self.started_at.elapsed();
        let killed_by = self.killed_by.lock().unwrap().take();

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
}
