//! Minimal rootfs setup and pivot_root for Hardened profile.
//!
//! Creates a temporary rootfs directory with bind-mounted host directories
//! (read-only) and minimal /dev devices. Then calls pivot_root to isolate
//! the worker from the host filesystem.

#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct BindMount {
    pub host: String,
    pub guest: String,
    pub readonly: bool,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct DeviceNode {
    pub host: String,
    pub guest: String,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct RootfsLayout {
    pub bind_mounts: Vec<BindMount>,
    pub devices: Vec<DeviceNode>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn rootfs_layout() -> RootfsLayout {
    RootfsLayout {
        bind_mounts: vec![
            BindMount { host: "/bin".into(), guest: "/bin".into(), readonly: true },
            BindMount { host: "/lib".into(), guest: "/lib".into(), readonly: true },
            BindMount { host: "/lib64".into(), guest: "/lib64".into(), readonly: true },
            BindMount { host: "/usr".into(), guest: "/usr".into(), readonly: true },
        ],
        devices: vec![
            DeviceNode { host: "/dev/null".into(), guest: "/dev/null".into() },
            DeviceNode { host: "/dev/zero".into(), guest: "/dev/zero".into() },
            DeviceNode { host: "/dev/urandom".into(), guest: "/dev/urandom".into() },
        ],
    }
}

/// Set up rootfs and call pivot_root. Must be called inside the cloned child
/// process (in the new mount namespace) before execve.
///
/// `new_root` is a temporary directory that becomes the new /.
/// `workspace_guest` is the guest path for the workspace mount.
/// `workspace_host` is the optional host path to bind-mount.
#[cfg(target_os = "linux")]
pub fn setup_and_pivot(
    new_root: &Path,
    workspace_guest: &Path,
    workspace_host: Option<&Path>,
) -> Result<(), String> {
    let layout = rootfs_layout();

    // Create the new root directory
    std::fs::create_dir_all(new_root)
        .map_err(|e| format!("mkdir new_root {}: {e}", new_root.display()))?;

    // Bind-mount host dirs into new root (read-only)
    for mount in &layout.bind_mounts {
        let target = new_root.join(mount.guest.trim_start_matches('/'));
        if !Path::new(&mount.host).exists() {
            continue; // /lib64 may not exist on all systems
        }
        std::fs::create_dir_all(&target)
            .map_err(|e| format!("mkdir {}: {e}", target.display()))?;
        bind_mount_ro(Path::new(&mount.host), &target)?;
    }

    // Create /dev and bind-mount device nodes
    let dev_dir = new_root.join("dev");
    std::fs::create_dir_all(&dev_dir).map_err(|e| format!("mkdir /dev: {e}"))?;
    for dev in &layout.devices {
        let target = new_root.join(dev.guest.trim_start_matches('/'));
        // Create empty file to mount over
        std::fs::write(&target, b"")
            .map_err(|e| format!("create {}: {e}", target.display()))?;
        bind_mount_ro(Path::new(&dev.host), &target)?;
    }

    // Mount /proc in new root
    let proc_dir = new_root.join("proc");
    std::fs::create_dir_all(&proc_dir).map_err(|e| format!("mkdir /proc: {e}"))?;
    mount_proc(&proc_dir)?;

    // Mount /tmp as tmpfs in new root
    let tmp_dir = new_root.join("tmp");
    std::fs::create_dir_all(&tmp_dir).map_err(|e| format!("mkdir /tmp: {e}"))?;
    mount_tmpfs(&tmp_dir, "64m")?;

    // Mount workspace
    let ws_guest = new_root.join(workspace_guest.to_string_lossy().trim_start_matches('/'));
    std::fs::create_dir_all(&ws_guest).map_err(|e| format!("mkdir workspace: {e}"))?;
    if let Some(host_ws) = workspace_host {
        bind_mount_rw(host_ws, &ws_guest)?;
    } else {
        mount_tmpfs(&ws_guest, "128m")?;
    }

    // pivot_root
    let old_root = new_root.join("old_root");
    std::fs::create_dir_all(&old_root).map_err(|e| format!("mkdir old_root: {e}"))?;

    let new_root_c =
        CString::new(new_root.to_string_lossy().as_bytes()).map_err(|e| format!("CString: {e}"))?;
    let old_root_c =
        CString::new(old_root.to_string_lossy().as_bytes()).map_err(|e| format!("CString: {e}"))?;

    let ret = unsafe {
        libc::syscall(
            libc::SYS_pivot_root,
            new_root_c.as_ptr(),
            old_root_c.as_ptr(),
        )
    };
    if ret != 0 {
        return Err(format!(
            "pivot_root failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // chdir to new root
    let slash = CString::new("/").map_err(|e| format!("CString: {e}"))?;
    let ret = unsafe { libc::chdir(slash.as_ptr()) };
    if ret != 0 {
        return Err(format!(
            "chdir / failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Unmount old root
    let old_root_path = CString::new("/old_root").map_err(|e| format!("CString: {e}"))?;
    let ret = unsafe { libc::umount2(old_root_path.as_ptr(), libc::MNT_DETACH) };
    if ret != 0 {
        return Err(format!(
            "umount old_root failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Remove the old_root mountpoint
    let _ = std::fs::remove_dir("/old_root");

    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_mount_ro(source: &Path, target: &Path) -> Result<(), String> {
    let source_c = CString::new(source.to_string_lossy().as_bytes())
        .map_err(|e| format!("CString {}: {e}", source.display()))?;
    let target_c = CString::new(target.to_string_lossy().as_bytes())
        .map_err(|e| format!("CString {}: {e}", target.display()))?;

    // First bind mount
    let ret = unsafe {
        libc::mount(
            source_c.as_ptr(),
            target_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(format!(
            "bind mount {} -> {} failed: {}",
            source.display(),
            target.display(),
            std::io::Error::last_os_error()
        ));
    }

    // Remount read-only
    let ret = unsafe {
        libc::mount(
            std::ptr::null(),
            target_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_REC,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(format!(
            "remount ro {} failed: {}",
            target.display(),
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_mount_rw(source: &Path, target: &Path) -> Result<(), String> {
    let source_c = CString::new(source.to_string_lossy().as_bytes())
        .map_err(|e| format!("CString {}: {e}", source.display()))?;
    let target_c = CString::new(target.to_string_lossy().as_bytes())
        .map_err(|e| format!("CString {}: {e}", target.display()))?;

    let ret = unsafe {
        libc::mount(
            source_c.as_ptr(),
            target_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(format!(
            "bind mount {} -> {} failed: {}",
            source.display(),
            target.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn mount_proc(target: &Path) -> Result<(), String> {
    let target_c = CString::new(target.to_string_lossy().as_bytes())
        .map_err(|e| format!("CString {}: {e}", target.display()))?;
    let fstype = CString::new("proc").map_err(|e| format!("CString: {e}"))?;
    let source = CString::new("proc").map_err(|e| format!("CString: {e}"))?;

    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target_c.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(format!(
            "mount proc failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn mount_tmpfs(target: &Path, size: &str) -> Result<(), String> {
    let target_c = CString::new(target.to_string_lossy().as_bytes())
        .map_err(|e| format!("CString {}: {e}", target.display()))?;
    let fstype = CString::new("tmpfs").map_err(|e| format!("CString: {e}"))?;
    let source = CString::new("tmpfs").map_err(|e| format!("CString: {e}"))?;
    let opts = CString::new(format!("size={size},nosuid,nodev"))
        .map_err(|e| format!("CString: {e}"))?;

    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target_c.as_ptr(),
            fstype.as_ptr(),
            0,
            opts.as_ptr().cast(),
        )
    };
    if ret != 0 {
        return Err(format!(
            "mount tmpfs {} failed: {}",
            target.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rootfs_layout_has_required_directories() {
        let layout = rootfs_layout();
        let dirs: Vec<&str> = layout.bind_mounts.iter().map(|m| m.guest.as_str()).collect();
        assert!(dirs.contains(&"/bin"), "missing /bin");
        assert!(dirs.contains(&"/lib"), "missing /lib");
        assert!(dirs.contains(&"/usr"), "missing /usr");
    }

    #[test]
    fn rootfs_layout_has_required_devices() {
        let layout = rootfs_layout();
        let devs: Vec<&str> = layout.devices.iter().map(|d| d.guest.as_str()).collect();
        assert!(devs.contains(&"/dev/null"), "missing /dev/null");
        assert!(devs.contains(&"/dev/zero"), "missing /dev/zero");
        assert!(devs.contains(&"/dev/urandom"), "missing /dev/urandom");
    }
}
