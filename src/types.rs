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
}

impl Default for CapsuleSpec {
    fn default() -> Self {
        Self {
            isolation: Isolation::Process,
            workspace: WorkspaceConfig::default(),
            limits: ResourceLimits::default(),
            init_binary: None,
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

#[derive(Debug, Clone, Default)]
pub struct CapsuleReport {
    pub exit_code: Option<i32>,
    pub exit_signal: Option<i32>,
    pub killed_by: Option<ResourceViolation>,
    pub wall_time: Duration,
    pub peak_memory_mib: Option<u64>,
}
