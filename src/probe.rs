use std::path::PathBuf;

use crate::types::{Isolation, SecurityProfile};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
    Other(String),
}

#[derive(Debug, Clone)]
pub struct HostCapabilities {
    pub kernel_version: (u32, u32, u32),
    pub arch: Arch,
    pub user_namespaces: bool,
    pub cgroup_v2: bool,
    pub seccomp_filter: bool,
    pub kvm: bool,
    pub firecracker_bin: Option<PathBuf>,
}

impl HostCapabilities {
    /// Returns the maximum supported (Isolation, SecurityProfile) pair
    /// based on the detected host capabilities.
    pub fn max_supported(&self) -> (Isolation, SecurityProfile) {
        if self.kvm && self.firecracker_bin.is_some() {
            return (Isolation::Firecracker, SecurityProfile::Standard);
        }
        if self.user_namespaces && self.cgroup_v2 && self.seccomp_filter {
            return (Isolation::Namespace, SecurityProfile::Hardened);
        }
        if self.user_namespaces && self.cgroup_v2 {
            return (Isolation::Namespace, SecurityProfile::Standard);
        }
        (Isolation::Process, SecurityProfile::Dev)
    }
}

/// Parses a kernel version string like "Linux version 6.1.90-1234 ..." into (major, minor, patch).
pub fn parse_kernel_version(text: &str) -> Option<(u32, u32, u32)> {
    // Look for "Linux version X.Y.Z" pattern
    let version_prefix = "Linux version ";
    let start = text.find(version_prefix)?;
    let after = &text[start + version_prefix.len()..];

    // Take the version number portion (up to the first space or dash after digits/dots)
    let version_str: String = after
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();

    let parts: Vec<&str> = version_str.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    let major = parts[0].parse::<u32>().ok()?;
    let minor = parts[1].parse::<u32>().ok()?;
    let patch = parts.get(2).and_then(|p| p.parse::<u32>().ok()).unwrap_or(0);

    Some((major, minor, patch))
}

/// Detects the CPU architecture of the current host.
pub fn detect_arch() -> Arch {
    match std::env::consts::ARCH {
        "x86_64" => Arch::X86_64,
        "aarch64" => Arch::Aarch64,
        other => Arch::Other(other.to_string()),
    }
}

/// Probes the host for available isolation capabilities.
pub fn probe() -> HostCapabilities {
    let kernel_version = read_kernel_version().unwrap_or((0, 0, 0));
    let arch = detect_arch();
    let user_namespaces = probe_user_namespaces();
    let cgroup_v2 = probe_cgroup_v2();
    let seccomp_filter = probe_seccomp();
    let kvm = probe_kvm();
    let firecracker_bin = find_firecracker_bin();

    HostCapabilities {
        kernel_version,
        arch,
        user_namespaces,
        cgroup_v2,
        seccomp_filter,
        kvm,
        firecracker_bin,
    }
}

/// Reads and parses the kernel version from /proc/version.
fn read_kernel_version() -> Option<(u32, u32, u32)> {
    let text = std::fs::read_to_string("/proc/version").ok()?;
    parse_kernel_version(&text)
}

/// Checks whether unprivileged user namespaces are available.
pub fn probe_user_namespaces() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Try the sysctl first
        if let Ok(contents) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        {
            return contents.trim() == "1";
        }
        // Fall back: on many modern kernels the sysctl doesn't exist but
        // user namespaces are enabled by default.
        true
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Checks whether cgroup v2 is mounted (unified hierarchy).
fn probe_cgroup_v2() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Checks whether seccomp filtering is supported via prctl(PR_GET_SECCOMP).
pub fn probe_seccomp() -> bool {
    #[cfg(target_os = "linux")]
    {
        // PR_GET_SECCOMP = 21
        let ret = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
        // Returns 0 (disabled) or 2 (filter mode) on success; -1 with EINVAL if unsupported.
        ret >= 0
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Checks whether /dev/kvm is accessible.
fn probe_kvm() -> bool {
    std::path::Path::new("/dev/kvm").exists()
}

/// Searches for the firecracker binary in well-known locations and PATH.
pub fn find_firecracker_bin() -> Option<PathBuf> {
    let candidates = [
        PathBuf::from("/usr/bin/firecracker"),
        PathBuf::from("/usr/local/bin/firecracker"),
    ];

    for path in &candidates {
        if path.exists() {
            return Some(path.clone());
        }
    }

    // Search PATH
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let candidate = PathBuf::from(dir).join("firecracker");
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_supported_full_linux() {
        let caps = HostCapabilities {
            kernel_version: (6, 1, 90),
            arch: Arch::X86_64,
            user_namespaces: true,
            cgroup_v2: true,
            seccomp_filter: true,
            kvm: false,
            firecracker_bin: None,
        };
        assert_eq!(
            caps.max_supported(),
            (Isolation::Namespace, SecurityProfile::Hardened)
        );
    }

    #[test]
    fn max_supported_no_seccomp() {
        let caps = HostCapabilities {
            kernel_version: (6, 1, 90),
            arch: Arch::X86_64,
            user_namespaces: true,
            cgroup_v2: true,
            seccomp_filter: false,
            kvm: false,
            firecracker_bin: None,
        };
        assert_eq!(
            caps.max_supported(),
            (Isolation::Namespace, SecurityProfile::Standard)
        );
    }

    #[test]
    fn max_supported_no_namespaces() {
        let caps = HostCapabilities {
            kernel_version: (6, 1, 90),
            arch: Arch::X86_64,
            user_namespaces: false,
            cgroup_v2: true,
            seccomp_filter: true,
            kvm: false,
            firecracker_bin: None,
        };
        assert_eq!(
            caps.max_supported(),
            (Isolation::Process, SecurityProfile::Dev)
        );
    }

    #[test]
    fn max_supported_firecracker() {
        let caps = HostCapabilities {
            kernel_version: (6, 1, 90),
            arch: Arch::X86_64,
            user_namespaces: true,
            cgroup_v2: true,
            seccomp_filter: true,
            kvm: true,
            firecracker_bin: Some(PathBuf::from("/usr/bin/firecracker")),
        };
        assert_eq!(
            caps.max_supported(),
            (Isolation::Firecracker, SecurityProfile::Standard)
        );
    }

    #[test]
    fn max_supported_kvm_but_no_firecracker_binary() {
        let caps = HostCapabilities {
            kernel_version: (6, 1, 90),
            arch: Arch::X86_64,
            user_namespaces: true,
            cgroup_v2: true,
            seccomp_filter: true,
            kvm: true,
            firecracker_bin: None,
        };
        // Without the firecracker binary, falls through to namespace+hardened
        assert_eq!(
            caps.max_supported(),
            (Isolation::Namespace, SecurityProfile::Hardened)
        );
    }

    #[test]
    fn parse_kernel_version_standard() {
        let text = "Linux version 6.1.90-1234";
        assert_eq!(parse_kernel_version(text), Some((6, 1, 90)));
    }

    #[test]
    fn parse_kernel_version_two_part() {
        let text = "Linux version 5.10.0-28-amd64";
        assert_eq!(parse_kernel_version(text), Some((5, 10, 0)));
    }

    #[test]
    fn parse_kernel_version_garbage() {
        let text = "not a kernel";
        assert_eq!(parse_kernel_version(text), None);
    }
}
