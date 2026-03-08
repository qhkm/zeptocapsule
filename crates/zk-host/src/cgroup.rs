//! cgroup v2 lifecycle management for namespace capsules.
//!
//! Each capsule gets its own cgroup at:
//!   /sys/fs/cgroup/zeptokernel/<job_id>/

use std::io;
use std::path::PathBuf;
use zk_proto::ResourceLimits;

const CGROUP_ROOT: &str = "/sys/fs/cgroup/zeptokernel";

pub struct Cgroup {
    path: PathBuf,
}

impl Cgroup {
    /// Create a new cgroup for the given job.
    pub fn create(job_id: &str) -> io::Result<Self> {
        let path = PathBuf::from(CGROUP_ROOT).join(job_id);
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    /// Create a dummy Cgroup that will silently fail all operations.
    ///
    /// Used as a fallback when cgroup setup is unavailable (e.g. running
    /// without cgroup v2 delegation). The path does not exist on disk;
    /// all writes will fail silently and `destroy()` is a no-op.
    pub fn dummy() -> Self {
        Self {
            path: PathBuf::from("/sys/fs/cgroup/zeptokernel/_dummy_nonexistent"),
        }
    }

    /// Add a process to this cgroup.
    pub fn add_pid(&self, pid: u32) -> io::Result<()> {
        std::fs::write(self.path.join("cgroup.procs"), format!("{}\n", pid))
    }

    /// Apply resource limits from a JobSpec's ResourceLimits.
    pub fn apply_limits(&self, limits: &ResourceLimits) -> io::Result<()> {
        if let Some(mib) = limits.memory_mib {
            std::fs::write(
                self.path.join("memory.max"),
                format!("{}\n", mib * 1024 * 1024),
            )?;
        }
        if let Some(cpu) = limits.cpu_quota {
            // cpu.max format: "<quota> <period>" where period=100000 µs = 100ms
            let quota = (cpu * 100_000.0) as u64;
            std::fs::write(
                self.path.join("cpu.max"),
                format!("{} 100000\n", quota),
            )?;
        }
        if let Some(pids) = limits.max_pids {
            std::fs::write(self.path.join("pids.max"), format!("{}\n", pids))?;
        }
        Ok(())
    }

    /// Remove the cgroup. The cgroup must have no live processes.
    pub fn destroy(&self) {
        for _ in 0..3 {
            if std::fs::remove_dir(&self.path).is_ok() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        tracing::warn!("failed to remove cgroup {:?}", self.path);
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        self.destroy();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_root_path() {
        let cg = Cgroup {
            path: PathBuf::from("/sys/fs/cgroup/zeptokernel/test-job"),
        };
        assert_eq!(
            cg.path.join("memory.max"),
            PathBuf::from("/sys/fs/cgroup/zeptokernel/test-job/memory.max")
        );
    }
}
