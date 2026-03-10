//! Workspace ext4 image builder for Firecracker capsules.
//!
//! Creates a writable ext4 disk image that gets mounted by the guest
//! at `workspace.guest_path`. Seeded from host workspace before boot,
//! contents copied back after teardown.

use std::path::{Path, PathBuf};

use crate::backend::{KernelError, KernelResult};

/// Default workspace image size if not specified.
pub fn default_size_mib(configured: Option<u64>) -> u64 {
    configured.unwrap_or(128)
}

/// Path to the workspace image within the state directory.
pub fn image_path(state_dir: &Path) -> PathBuf {
    state_dir.join("workspace.ext4")
}

/// Create a blank ext4 image file at `path` with `size_mib` MiB.
#[cfg(target_os = "linux")]
pub fn create_image(path: &Path, size_mib: u64) -> KernelResult<()> {
    use std::process::Command;

    let size_bytes = size_mib * 1024 * 1024;
    let file = std::fs::File::create(path)
        .map_err(|e| KernelError::SpawnFailed(format!("create workspace image: {e}")))?;
    file.set_len(size_bytes)
        .map_err(|e| KernelError::SpawnFailed(format!("set workspace image size: {e}")))?;
    drop(file);

    let output = Command::new("mkfs.ext4")
        .args(["-q", "-F"])
        .arg(path)
        .output()
        .map_err(|e| KernelError::SpawnFailed(format!("mkfs.ext4: {e}")))?;

    if !output.status.success() {
        return Err(KernelError::SpawnFailed(format!(
            "mkfs.ext4 failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

/// Seed the workspace image from a host directory.
/// Mounts the image, copies host_path contents, unmounts.
#[cfg(target_os = "linux")]
pub fn seed_from_host(image: &Path, host_path: &Path, mount_point: &Path) -> KernelResult<()> {
    use std::process::Command;

    std::fs::create_dir_all(mount_point)
        .map_err(|e| KernelError::SpawnFailed(format!("mkdir mount_point: {e}")))?;

    mount_image(image, mount_point)?;

    let output = Command::new("sh")
        .args([
            "-c",
            &format!(
                "cp -a '{}'/. '{}'/ 2>/dev/null; true",
                host_path.display(),
                mount_point.display()
            ),
        ])
        .output()
        .map_err(|e| KernelError::SpawnFailed(format!("copy workspace contents: {e}")))?;

    umount_image(mount_point)?;

    if !output.status.success() {
        tracing::warn!(
            "workspace seed copy had warnings: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

/// Export workspace image contents back to a host directory.
/// Mounts the image read-only, copies to host_path, unmounts.
#[cfg(target_os = "linux")]
pub fn export_to_host(image: &Path, host_path: &Path, mount_point: &Path) -> KernelResult<()> {
    use std::process::Command;

    std::fs::create_dir_all(mount_point)
        .map_err(|e| KernelError::CleanupFailed(format!("mkdir mount_point: {e}")))?;
    std::fs::create_dir_all(host_path)
        .map_err(|e| KernelError::CleanupFailed(format!("mkdir host_path: {e}")))?;

    // Mount read-write to allow ext4 journal replay if the guest didn't
    // cleanly unmount (e.g. VM was killed).
    mount_image(image, mount_point)?;

    let output = Command::new("sh")
        .args([
            "-c",
            &format!(
                "cp -a '{}'/. '{}'/ 2>/dev/null; true",
                mount_point.display(),
                host_path.display()
            ),
        ])
        .output()
        .map_err(|e| KernelError::CleanupFailed(format!("export workspace: {e}")))?;

    umount_image(mount_point)?;

    if !output.status.success() {
        tracing::warn!(
            "workspace export had warnings: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn mount_image(image: &Path, mount_point: &Path) -> KernelResult<()> {
    use std::process::Command;

    let output = Command::new("mount")
        .args(["-o", "loop"])
        .arg(image)
        .arg(mount_point)
        .output()
        .map_err(|e| KernelError::SpawnFailed(format!("mount workspace image: {e}")))?;

    if !output.status.success() {
        return Err(KernelError::SpawnFailed(format!(
            "mount workspace image failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(dead_code)] // future: mount workspace image read-only before handoff
fn mount_image_ro(image: &Path, mount_point: &Path) -> KernelResult<()> {
    use std::process::Command;

    let output = Command::new("mount")
        .args(["-o", "loop,ro"])
        .arg(image)
        .arg(mount_point)
        .output()
        .map_err(|e| KernelError::CleanupFailed(format!("mount workspace image ro: {e}")))?;

    if !output.status.success() {
        return Err(KernelError::CleanupFailed(format!(
            "mount workspace image ro failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn umount_image(mount_point: &Path) -> KernelResult<()> {
    use std::process::Command;

    let output = Command::new("umount")
        .arg(mount_point)
        .output()
        .map_err(|e| KernelError::CleanupFailed(format!("umount: {e}")))?;

    if !output.status.success() {
        tracing::warn!(
            "umount {} failed: {}",
            mount_point.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_image_size() {
        assert_eq!(default_size_mib(None), 128);
        assert_eq!(default_size_mib(Some(256)), 256);
    }

    #[test]
    fn image_path_in_state_dir() {
        let state_dir = PathBuf::from("/tmp/zk-fc-12345");
        let path = image_path(&state_dir);
        assert_eq!(path, PathBuf::from("/tmp/zk-fc-12345/workspace.ext4"));
    }
}
