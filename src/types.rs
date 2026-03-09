use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isolation {
    Process,
    Namespace,
    Firecracker,
}

#[derive(Debug, Clone)]
pub struct FirecrackerConfig {
    pub firecracker_bin: PathBuf,
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub vcpus: Option<u32>,
    pub memory_mib: Option<u64>,
    pub enable_network: bool,
    pub tap_name: Option<String>,
}

impl FirecrackerConfig {
    /// Effective vCPU count: explicit > ceil(cpu_quota) > 1.
    pub fn effective_vcpus(&self, limits: &ResourceLimits) -> u32 {
        self.vcpus.unwrap_or_else(|| {
            limits
                .cpu_quota
                .map(|q| (q.ceil() as u32).max(1))
                .unwrap_or(1)
        })
    }

    /// Effective guest memory: explicit > limits.memory_mib > 256.
    pub fn effective_memory_mib(&self, limits: &ResourceLimits) -> u64 {
        self.memory_mib.or(limits.memory_mib).unwrap_or(256)
    }
}

#[derive(Debug, Clone)]
pub struct CapsuleSpec {
    pub isolation: Isolation,
    pub workspace: WorkspaceConfig,
    pub limits: ResourceLimits,
    pub init_binary: Option<PathBuf>,
    pub security: SecurityProfile,
    pub security_overrides: SecurityOverrides,
    pub firecracker: Option<FirecrackerConfig>,
}

impl CapsuleSpec {
    pub fn validate(&self) -> Result<(), String> {
        match (self.isolation, self.security) {
            (Isolation::Process, SecurityProfile::Hardened) => {
                return Err("Hardened security profile requires Namespace isolation".into());
            }
            (Isolation::Namespace, SecurityProfile::Dev) => {
                return Err("Dev security profile only works with Process isolation".into());
            }
            _ => {}
        }

        if self.isolation == Isolation::Firecracker {
            if self.firecracker.is_none() {
                return Err("Firecracker isolation requires firecracker config".into());
            }
            if self.limits.max_pids.is_some() {
                return Err("max_pids is not supported with Firecracker isolation".into());
            }
        }

        Ok(())
    }
}

impl Default for CapsuleSpec {
    fn default() -> Self {
        Self {
            isolation: Isolation::Process,
            workspace: WorkspaceConfig::default(),
            limits: ResourceLimits::default(),
            init_binary: None,
            security: SecurityProfile::default(),
            security_overrides: SecurityOverrides::default(),
            firecracker: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub timeout_sec: u64,
    pub memory_mib: Option<u64>,
    pub cpu_quota: Option<f64>,
    pub max_pids: Option<u32>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            timeout_sec: 300,
            memory_mib: None,
            cpu_quota: None,
            max_pids: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkspaceConfig {
    pub host_path: Option<PathBuf>,
    pub guest_path: PathBuf,
    pub size_mib: Option<u64>,
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self {
            host_path: None,
            guest_path: PathBuf::from("/workspace"),
            size_mib: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceViolation {
    WallClock,
    Memory,
    MaxPids,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Terminate,
    Kill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityProfile {
    Dev,
    #[default]
    Standard,
    Hardened,
}

#[derive(Debug, Clone, Default)]
pub struct SecurityOverrides {
    pub cgroup_required: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct RLimits {
    pub max_memory_bytes: Option<u64>,
    pub max_cpu_seconds: Option<u64>,
    pub max_file_size_bytes: Option<u64>,
}

impl From<&ResourceLimits> for RLimits {
    fn from(limits: &ResourceLimits) -> Self {
        Self {
            max_memory_bytes: limits.memory_mib.map(|m| m * 1024 * 1024),
            max_cpu_seconds: Some(limits.timeout_sec),
            max_file_size_bytes: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CapsuleReport {
    pub exit_code: Option<i32>,
    pub exit_signal: Option<i32>,
    pub killed_by: Option<ResourceViolation>,
    pub wall_time: Duration,
    pub peak_memory_mib: Option<u64>,
    pub init_error: Option<String>,
    pub actual_isolation: Option<Isolation>,
    pub actual_security: Option<SecurityProfile>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_profile_default_is_standard() {
        assert_eq!(SecurityProfile::default(), SecurityProfile::Standard);
    }

    #[test]
    fn security_overrides_default_has_no_overrides() {
        let overrides = SecurityOverrides::default();
        assert_eq!(overrides.cgroup_required, None);
    }

    #[test]
    fn capsule_spec_default_has_standard_security() {
        let spec = CapsuleSpec::default();
        assert_eq!(spec.security, SecurityProfile::Standard);
    }

    #[test]
    fn rlimits_from_resource_limits_converts_memory() {
        let limits = ResourceLimits {
            memory_mib: Some(512),
            timeout_sec: 60,
            ..Default::default()
        };
        let rlimits = RLimits::from(&limits);
        assert_eq!(rlimits.max_memory_bytes, Some(512 * 1024 * 1024));
        assert_eq!(rlimits.max_cpu_seconds, Some(60));
    }

    #[test]
    fn validate_rejects_hardened_with_process() {
        let spec = CapsuleSpec {
            isolation: Isolation::Process,
            security: SecurityProfile::Hardened,
            ..Default::default()
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn validate_rejects_dev_with_namespace() {
        let spec = CapsuleSpec {
            isolation: Isolation::Namespace,
            security: SecurityProfile::Dev,
            ..Default::default()
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn validate_accepts_standard_with_namespace() {
        let spec = CapsuleSpec {
            isolation: Isolation::Namespace,
            security: SecurityProfile::Standard,
            ..Default::default()
        };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn validate_accepts_dev_with_process() {
        let spec = CapsuleSpec {
            isolation: Isolation::Process,
            security: SecurityProfile::Dev,
            ..Default::default()
        };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn capsule_report_default_has_none_fields() {
        let report = CapsuleReport::default();
        assert!(report.init_error.is_none());
        assert!(report.actual_isolation.is_none());
        assert!(report.actual_security.is_none());
    }

    #[test]
    fn firecracker_config_default_fields() {
        let config = FirecrackerConfig {
            firecracker_bin: PathBuf::from("/usr/bin/firecracker"),
            kernel_path: PathBuf::from("/var/lib/zk/vmlinux"),
            rootfs_path: PathBuf::from("/var/lib/zk/rootfs.ext4"),
            vcpus: None,
            memory_mib: None,
            enable_network: false,
            tap_name: None,
        };
        assert_eq!(
            config.firecracker_bin,
            PathBuf::from("/usr/bin/firecracker")
        );
        assert!(!config.enable_network);
        assert!(config.vcpus.is_none());
    }

    #[test]
    fn validate_firecracker_requires_firecracker_config() {
        let spec = CapsuleSpec {
            isolation: Isolation::Firecracker,
            security: SecurityProfile::Standard,
            ..Default::default()
        };
        let err = spec.validate().unwrap_err();
        assert!(
            err.contains("firecracker"),
            "error should mention firecracker config: {err}"
        );
    }

    #[test]
    fn validate_firecracker_with_config_ok() {
        let spec = CapsuleSpec {
            isolation: Isolation::Firecracker,
            security: SecurityProfile::Standard,
            firecracker: Some(FirecrackerConfig {
                firecracker_bin: PathBuf::from("/usr/bin/firecracker"),
                kernel_path: PathBuf::from("/var/lib/zk/vmlinux"),
                rootfs_path: PathBuf::from("/var/lib/zk/rootfs.ext4"),
                vcpus: None,
                memory_mib: None,
                enable_network: false,
                tap_name: None,
            }),
            ..Default::default()
        };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn validate_firecracker_rejects_max_pids() {
        let spec = CapsuleSpec {
            isolation: Isolation::Firecracker,
            security: SecurityProfile::Standard,
            limits: ResourceLimits {
                max_pids: Some(100),
                ..Default::default()
            },
            firecracker: Some(FirecrackerConfig {
                firecracker_bin: PathBuf::from("/usr/bin/firecracker"),
                kernel_path: PathBuf::from("/var/lib/zk/vmlinux"),
                rootfs_path: PathBuf::from("/var/lib/zk/rootfs.ext4"),
                vcpus: None,
                memory_mib: None,
                enable_network: false,
                tap_name: None,
            }),
            ..Default::default()
        };
        let err = spec.validate().unwrap_err();
        assert!(
            err.contains("max_pids"),
            "error should mention max_pids: {err}"
        );
    }

    #[test]
    fn firecracker_derived_vcpus() {
        let config = FirecrackerConfig {
            firecracker_bin: PathBuf::from("/usr/bin/firecracker"),
            kernel_path: PathBuf::from("/var/lib/zk/vmlinux"),
            rootfs_path: PathBuf::from("/var/lib/zk/rootfs.ext4"),
            vcpus: None,
            memory_mib: None,
            enable_network: false,
            tap_name: None,
        };
        let limits = ResourceLimits {
            cpu_quota: Some(2.5),
            memory_mib: Some(512),
            ..Default::default()
        };
        assert_eq!(config.effective_vcpus(&limits), 3);
        assert_eq!(config.effective_memory_mib(&limits), 512);
    }

    #[test]
    fn firecracker_derived_defaults() {
        let config = FirecrackerConfig {
            firecracker_bin: PathBuf::from("/usr/bin/firecracker"),
            kernel_path: PathBuf::from("/var/lib/zk/vmlinux"),
            rootfs_path: PathBuf::from("/var/lib/zk/rootfs.ext4"),
            vcpus: None,
            memory_mib: None,
            enable_network: false,
            tap_name: None,
        };
        let limits = ResourceLimits::default();
        assert_eq!(config.effective_vcpus(&limits), 1);
        assert_eq!(config.effective_memory_mib(&limits), 256);
    }
}
