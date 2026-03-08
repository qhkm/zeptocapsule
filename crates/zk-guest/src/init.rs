//! Guest init — minimal PID 1 bootstrap for the execution capsule.
//!
//! Mounts /proc, /tmp, /workspace as tmpfs, then starts the vsock agent.
//! In dev mode (stdin/stdout transport), skips mount operations.

/// Mount points to set up inside the guest.
pub struct MountConfig {
    pub tmp_size: &'static str,
    pub workspace_size: &'static str,
}

impl Default for MountConfig {
    fn default() -> Self {
        Self {
            tmp_size: "64m",
            workspace_size: "128m",
        }
    }
}

/// Set up the minimal guest filesystem.
///
/// This is a no-op on non-Linux platforms (for dev/testing on macOS).
/// On Linux inside a namespace/microVM, it performs actual mounts.
pub fn setup_guest_fs(config: &MountConfig) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        mount_proc()?;
        mount_tmpfs("/tmp", config.tmp_size)?;
        mount_tmpfs("/workspace", config.workspace_size)?;
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Dev mode: just ensure workspace dir exists
        let _ = std::fs::create_dir_all("/tmp");
        let _ = std::fs::create_dir_all("/workspace");
        let _ = config; // suppress unused warning
    }

    Ok(())
}

/// Mount /proc (Linux only).
#[cfg(target_os = "linux")]
fn mount_proc() -> Result<(), String> {
    use std::ffi::CString;

    let target = CString::new("/proc").unwrap();
    let fstype = CString::new("proc").unwrap();
    let source = CString::new("proc").unwrap();

    std::fs::create_dir_all("/proc").map_err(|e| format!("mkdir /proc: {e}"))?;

    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(format!(
            "mount /proc failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Mount a tmpfs at the given path with the given size (Linux only).
#[cfg(target_os = "linux")]
fn mount_tmpfs(path: &str, size: &str) -> Result<(), String> {
    use std::ffi::CString;

    let target = CString::new(path).unwrap();
    let fstype = CString::new("tmpfs").unwrap();
    let source = CString::new("tmpfs").unwrap();
    let opts = CString::new(format!("size={size},nosuid,nodev")).unwrap();

    std::fs::create_dir_all(path).map_err(|e| format!("mkdir {path}: {e}"))?;

    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            0,
            opts.as_ptr().cast(),
        )
    };
    if ret != 0 {
        return Err(format!(
            "mount tmpfs {path} failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Check if we're running as PID 1 (i.e. as the init process inside a container/VM).
pub fn is_init() -> bool {
    std::process::id() == 1
}
