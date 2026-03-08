//! ZeptoKernel guest agent.
//!
//! Runs inside the execution capsule as PID 1 (or near-PID 1).
//!
//! Responsibilities:
//! - Listen for host commands on the control channel
//! - Launch the ZeptoClaw worker binary
//! - Forward worker JSON-line events to the host
//! - Handle cancellation and shutdown
//! - Reap child processes

pub mod agent;
pub mod worker;
