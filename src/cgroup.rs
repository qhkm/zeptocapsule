use std::io;
use std::path::PathBuf;

use crate::types::{ResourceLimits, ResourceViolation};

const CGROUP_ROOT: &str = "/sys/fs/cgroup/zeptokernel";

pub struct Cgroup {
    path: PathBuf,
}

impl Cgroup {
    pub fn create(job_id: &str) -> io::Result<Self> {
        let path = PathBuf::from(CGROUP_ROOT).join(job_id);
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    pub fn dummy() -> Self {
        Self {
            path: PathBuf::from("/sys/fs/cgroup/zeptokernel/_dummy_nonexistent"),
        }
    }

    pub fn add_pid(&self, pid: u32) -> io::Result<()> {
        std::fs::write(self.path.join("cgroup.procs"), format!("{pid}\n"))
    }

    pub fn apply_limits(&self, limits: &ResourceLimits) -> io::Result<()> {
        if let Some(mib) = limits.memory_mib {
            std::fs::write(
                self.path.join("memory.max"),
                format!("{}\n", mib * 1024 * 1024),
            )?;
        }
        if let Some(cpu) = limits.cpu_quota {
            let quota = (cpu * 100_000.0) as u64;
            std::fs::write(self.path.join("cpu.max"), format!("{quota} 100000\n"))?;
        }
        if let Some(pids) = limits.max_pids {
            std::fs::write(self.path.join("pids.max"), format!("{pids}\n"))?;
        }
        Ok(())
    }

    pub fn destroy(&self) {
        for _ in 0..3 {
            if std::fs::remove_dir(&self.path).is_ok() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        tracing::warn!("failed to remove cgroup {:?}", self.path);
    }

    pub fn detect_violation(&self) -> Option<ResourceViolation> {
        if self.counter("memory.events", "oom_kill").unwrap_or(0) > 0 {
            return Some(ResourceViolation::Memory);
        }
        if self.counter("pids.events", "max").unwrap_or(0) > 0 {
            return Some(ResourceViolation::MaxPids);
        }
        None
    }

    pub fn peak_memory_mib(&self) -> Option<u64> {
        let peak_bytes = std::fs::read_to_string(self.path.join("memory.peak"))
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()?;
        Some(peak_bytes / (1024 * 1024))
    }

    fn counter(&self, file: &str, key: &str) -> Option<u64> {
        let contents = std::fs::read_to_string(self.path.join(file)).ok()?;
        contents.lines().find_map(|line| {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some(name), Some(value)) if name == key => value.parse::<u64>().ok(),
                _ => None,
            }
        })
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        self.destroy();
    }
}
