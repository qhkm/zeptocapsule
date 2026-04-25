//! Per-capsule TAP plumbing for the Firecracker backend.
//!
//! Linux-only. Mirrors `netns.rs` but creates a TAP device for the
//! Firecracker microVM instead of a veth pair.
//!
//! Layout:
//!
//! ```text
//!   host                                Firecracker guest
//! ┌─────────────────────────┐    ┌──────────────────────────┐
//! │ zk_tap_<n> 169.254.33.1 │    │ eth0    169.254.33.2     │
//! │   └─ proxy listens here │TAP │   └─ default route via .1│
//! │                         │    │                          │
//! └─────────────────────────┘    └──────────────────────────┘
//! ```
//!
//! Subnet pool: `/30` blocks in `169.254.33.0/24` — distinct from the
//! Namespace backend's `.32` range so a host running both backends does
//! not collide.
//!
//! Permissions: `CAP_NET_ADMIN` for TAP creation. CI runs `--privileged`
//! Docker; production runs as root or with explicit caps.

#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, thiserror::Error)]
pub enum FcNetError {
    #[error("ip {cmd}: exit {code}: {stderr}")]
    IpFailed {
        cmd: String,
        code: i32,
        stderr: String,
    },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("TAP pool exhausted (max 64 concurrent FC capsules)")]
    PoolExhausted,
}

/// One TAP allocation: interface name + IPs.
#[derive(Debug, Clone)]
pub struct TapSetup {
    pub slot: u8,
    pub iface: String,
    pub host_ip: Ipv4Addr,
    pub guest_ip: Ipv4Addr,
    pub prefix_len: u8,
}

const POOL_SIZE: u8 = 64;
static SLOT_BITS: AtomicU64 = AtomicU64::new(0);

fn allocate_slot() -> Result<u8, FcNetError> {
    loop {
        let bits = SLOT_BITS.load(Ordering::Acquire);
        let slot = (0..POOL_SIZE).find(|&s| (bits & (1u64 << s)) == 0);
        let Some(slot) = slot else {
            return Err(FcNetError::PoolExhausted);
        };
        let new = bits | (1u64 << slot);
        if SLOT_BITS
            .compare_exchange(bits, new, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Ok(slot);
        }
    }
}

fn release_slot(slot: u8) {
    if slot >= POOL_SIZE {
        return;
    }
    let mask = !(1u64 << slot);
    SLOT_BITS.fetch_and(mask, Ordering::AcqRel);
}

impl TapSetup {
    fn from_slot(slot: u8) -> Self {
        // Each /30 holds .0 (network), .1 (host), .2 (guest), .3 (broadcast).
        // Slot 0 -> 169.254.33.0/30, slot 1 -> 169.254.33.4/30, ...
        let base = slot.saturating_mul(4);
        let host_ip = Ipv4Addr::new(169, 254, 33, base + 1);
        let guest_ip = Ipv4Addr::new(169, 254, 33, base + 2);
        let iface = format!("zk_tap_{slot}");
        Self {
            slot,
            iface,
            host_ip,
            guest_ip,
            prefix_len: 30,
        }
    }
}

/// Create the TAP device, assign the host IP, bring it up. Firecracker
/// then attaches its emulated NIC to this TAP via the
/// `/network-interfaces/eth0` API call (handled by the FC backend code).
pub fn setup_tap() -> Result<TapSetup, FcNetError> {
    let slot = allocate_slot()?;
    let setup = TapSetup::from_slot(slot);

    // Best-effort cleanup of stale TAP from a prior crashed run.
    let _ = run_ip(&["link", "del", &setup.iface]);

    run_ip(&["tuntap", "add", "mode", "tap", "name", &setup.iface])?;
    if let Err(e) = run_ip(&[
        "addr",
        "add",
        &format!("{}/{}", setup.host_ip, setup.prefix_len),
        "dev",
        &setup.iface,
    ]) {
        let _ = run_ip(&["link", "del", &setup.iface]);
        release_slot(slot);
        return Err(e);
    }
    if let Err(e) = run_ip(&["link", "set", &setup.iface, "up"]) {
        let _ = run_ip(&["link", "del", &setup.iface]);
        release_slot(slot);
        return Err(e);
    }
    Ok(setup)
}

/// Tear down the TAP + release the slot.
pub fn teardown(setup: TapSetup) {
    let _ = run_ip(&["link", "del", &setup.iface]);
    release_slot(setup.slot);
}

fn run_ip(args: &[&str]) -> Result<(), FcNetError> {
    let out = Command::new("ip").args(args).output()?;
    if !out.status.success() {
        return Err(FcNetError::IpFailed {
            cmd: args.join(" "),
            code: out.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_allocator_unique_and_recyclable() {
        let a = allocate_slot().unwrap();
        let b = allocate_slot().unwrap();
        assert_ne!(a, b);
        release_slot(a);
        release_slot(b);
        let c = allocate_slot().unwrap();
        assert!(c < POOL_SIZE);
        release_slot(c);
    }

    #[test]
    fn slot_assigns_distinct_subnets_in_169_254_33() {
        let s0 = TapSetup::from_slot(0);
        let s1 = TapSetup::from_slot(1);
        assert_eq!(s0.host_ip, Ipv4Addr::new(169, 254, 33, 1));
        assert_eq!(s0.guest_ip, Ipv4Addr::new(169, 254, 33, 2));
        assert_eq!(s1.host_ip, Ipv4Addr::new(169, 254, 33, 5));
        assert_eq!(s1.guest_ip, Ipv4Addr::new(169, 254, 33, 6));
        assert_ne!(s0.iface, s1.iface);
        assert_eq!(s0.prefix_len, 30);
    }

    #[test]
    fn tap_range_does_not_overlap_with_netns_range() {
        // Namespace backend uses 169.254.32.0/24, FC backend uses .33.
        // A regression that lets them share would be a debugging nightmare.
        let s = TapSetup::from_slot(POOL_SIZE - 1);
        assert_eq!(s.host_ip.octets()[2], 33);
    }
}
