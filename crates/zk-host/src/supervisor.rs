//! Supervisor — manages multiple capsules, enforces timeouts, forwards events.

use std::collections::HashMap;

use crate::capsule::Capsule;
use zk_proto::CapsuleState;

/// The host-side supervisor that owns all active capsules.
pub struct Supervisor {
    capsules: HashMap<String, Capsule>,
}

impl Supervisor {
    pub fn new() -> Self {
        Self {
            capsules: HashMap::new(),
        }
    }

    pub fn register(&mut self, capsule: Capsule) {
        self.capsules.insert(capsule.job_id.clone(), capsule);
    }

    pub fn get(&self, job_id: &str) -> Option<&Capsule> {
        self.capsules.get(job_id)
    }

    pub fn get_mut(&mut self, job_id: &str) -> Option<&mut Capsule> {
        self.capsules.get_mut(job_id)
    }

    pub fn remove(&mut self, job_id: &str) -> Option<Capsule> {
        self.capsules.remove(job_id)
    }

    /// Return job IDs of capsules that have exceeded their heartbeat timeout.
    pub fn stale_capsules(&self, heartbeat_timeout_sec: u64) -> Vec<String> {
        let timeout = std::time::Duration::from_secs(heartbeat_timeout_sec);
        self.capsules
            .iter()
            .filter(|(_, c)| {
                c.state == CapsuleState::Running
                    && c.elapsed_since_heartbeat()
                        .map(|d| d > timeout)
                        .unwrap_or(false)
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn active_count(&self) -> usize {
        self.capsules
            .values()
            .filter(|c| {
                matches!(
                    c.state,
                    CapsuleState::Initializing | CapsuleState::Ready | CapsuleState::Running | CapsuleState::Waiting
                )
            })
            .count()
    }
}
