use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isolation {
    Process,
    Namespace,
    Firecracker,
}

#[derive(Debug, Clone)]
pub struct CapsuleSpec {
    pub isolation: Isolation,
    pub workspace: WorkspaceConfig,
    pub limits: ResourceLimits,
    pub init_binary: Option<PathBuf>,
    pub security: SecurityProfile,
    pub security_overrides: SecurityOverrides,
}

impl CapsuleSpec {
    pub fn validate(&self) -> Result<(), String> {
        match (self.isolation, self.security) {
            (Isolation::Process, SecurityProfile::Hardened) => {
                Err("Hardened security profile requires Namespace isolation".into())
            }
            (Isolation::Namespace, SecurityProfile::Dev) => {
                Err("Dev security profile only works with Process isolation".into())
            }
            _ => Ok(()),
        }
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
}
