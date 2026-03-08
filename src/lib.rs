mod backend;
mod init_shim;
mod process;
mod types;

#[cfg(target_os = "linux")]
mod cgroup;
#[cfg(target_os = "linux")]
mod firecracker;
#[cfg(target_os = "linux")]
mod firecracker_api;
#[cfg(target_os = "linux")]
mod namespace;
mod rootfs;
#[cfg(target_os = "linux")]
mod seccomp;
#[cfg(target_os = "linux")]
mod vsock;
#[cfg(target_os = "linux")]
mod workspace_image;

use backend::{Backend, CapsuleHandle, KernelResult};
use std::collections::HashMap;
use std::path::PathBuf;

pub use backend::{CapsuleChild, CapsuleStderr};
pub use init_shim::{
    FcInitConfig, MountConfig, is_firecracker_mode, is_init, parse_fc_init_config, run_init_shim,
    setup_guest_fs,
};
pub use types::{
    CapsuleReport, CapsuleSpec, FirecrackerConfig, Isolation, RLimits, ResourceLimits,
    ResourceViolation, SecurityOverrides, SecurityProfile, Signal, WorkspaceConfig,
};

pub struct Capsule {
    inner: Box<dyn CapsuleHandle>,
}

pub fn default_init_binary() -> KernelResult<PathBuf> {
    let path = if let Some(path) = std::env::var_os("ZEPTOKERNEL_INIT_BINARY") {
        PathBuf::from(path)
    } else {
        let mut path = std::env::current_exe()
            .map_err(|e| KernelError::NotSupported(format!("current_exe failed: {e}")))?;
        path.set_file_name("zk-init");
        path
    };

    if path.exists() {
        Ok(path)
    } else {
        Err(KernelError::NotSupported(format!(
            "zk-init binary not found at {}",
            path.display()
        )))
    }
}

pub fn create(spec: CapsuleSpec) -> KernelResult<Capsule> {
    spec.validate().map_err(KernelError::InvalidState)?;
    let backend: Box<dyn Backend> = match spec.isolation {
        types::Isolation::Process => Box::new(process::ProcessBackend),
        types::Isolation::Namespace => {
            #[cfg(target_os = "linux")]
            {
                Box::new(namespace::NamespaceBackend)
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(KernelError::NotSupported(
                    "namespace isolation requires Linux".into(),
                ));
            }
        }
        types::Isolation::Firecracker => {
            #[cfg(target_os = "linux")]
            {
                Box::new(firecracker::FirecrackerBackend)
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(KernelError::NotSupported(
                    "firecracker isolation requires Linux".into(),
                ));
            }
        }
    };

    Ok(Capsule {
        inner: backend.create(spec)?,
    })
}

impl Capsule {
    pub fn spawn(
        &mut self,
        binary: &str,
        args: &[&str],
        env: HashMap<String, String>,
    ) -> KernelResult<CapsuleChild> {
        self.inner.spawn(binary, args, env)
    }

    pub fn kill(&mut self, signal: Signal) -> KernelResult<()> {
        self.inner.kill(signal)
    }

    pub fn destroy(self) -> KernelResult<CapsuleReport> {
        self.inner.destroy()
    }
}

pub use backend::KernelError;
