//! Capsule — tracks the lifecycle of a single execution capsule.

use std::time::Instant;
use zk_proto::CapsuleState;

/// Runtime state for one execution capsule.
pub struct Capsule {
    pub job_id: String,
    pub run_id: String,
    pub role: String,
    pub state: CapsuleState,
    pub created_at: Instant,
    pub last_heartbeat: Option<Instant>,
    pub exit_reason: Option<String>,
}

impl Capsule {
    pub fn new(job_id: String, run_id: String, role: String) -> Self {
        Self {
            job_id,
            run_id,
            role,
            state: CapsuleState::Initializing,
            created_at: Instant::now(),
            last_heartbeat: None,
            exit_reason: None,
        }
    }

    pub fn record_heartbeat(&mut self) {
        self.last_heartbeat = Some(Instant::now());
    }

    pub fn elapsed_since_heartbeat(&self) -> Option<std::time::Duration> {
        self.last_heartbeat.map(|t| t.elapsed())
    }
}
