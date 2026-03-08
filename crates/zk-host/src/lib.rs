//! ZeptoKernel host supervisor.
//!
//! Responsibilities:
//! - Create execution capsules (namespace sandbox or microVM)
//! - Deliver job specs to guest agents
//! - Monitor heartbeats and enforce timeouts
//! - Collect events and artifacts
//! - Terminate and clean up capsules

pub mod backend;
pub mod capsule;
pub mod process_backend;
pub mod supervisor;
pub mod vm_config;
