//! VM configuration for Firecracker microVM backend.
//!
//! Defines the config structure passed to the Firecracker launcher.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for launching a Firecracker microVM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    /// Path to the guest kernel image.
    pub kernel_path: PathBuf,
    /// Path to the root filesystem image.
    pub rootfs_path: PathBuf,
    /// Guest memory in MiB.
    #[serde(default = "default_memory")]
    pub memory_mib: u64,
    /// Number of vCPUs.
    #[serde(default = "default_vcpus")]
    pub vcpu_count: u32,
    /// Enable vsock device for host↔guest communication.
    #[serde(default = "default_true")]
    pub vsock_enabled: bool,
    /// Vsock CID (guest context ID). Each VM needs a unique CID.
    #[serde(default)]
    pub vsock_cid: Option<u32>,
    /// Enable network device.
    #[serde(default)]
    pub network_enabled: bool,
    /// Path to the Firecracker binary.
    #[serde(default = "default_firecracker_bin")]
    pub firecracker_bin: PathBuf,
    /// Optional: path to a snapshot file for fast restore.
    #[serde(default)]
    pub snapshot_path: Option<PathBuf>,
}

fn default_memory() -> u64 {
    128
}

fn default_vcpus() -> u32 {
    1
}

fn default_true() -> bool {
    true
}

fn default_firecracker_bin() -> PathBuf {
    PathBuf::from("firecracker")
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            kernel_path: PathBuf::from("vmlinux"),
            rootfs_path: PathBuf::from("rootfs.ext4"),
            memory_mib: default_memory(),
            vcpu_count: default_vcpus(),
            vsock_enabled: true,
            vsock_cid: None,
            network_enabled: false,
            firecracker_bin: default_firecracker_bin(),
            snapshot_path: None,
        }
    }
}
