//! Per-capsule network-namespace plumbing for the Namespace backend.
//!
//! Linux-only. Uses `ip` (iproute2) and `nsenter` shell-outs rather than
//! direct netlink — netlink would be cleaner but the interface count
//! is small and shell-out keeps the module under ~200 LoC.
//!
//! Layout:
//!
//! ```text
//!   host netns                       capsule netns
//! ┌────────────────────────┐    ┌──────────────────────────┐
//! │ zk_h_<n> 169.254.X.1/30├────┤zk_g_<n> 169.254.X.2/30   │
//! │  └─ proxy listens here │veth│  └─ default route via .1 │
//! │                        │pair│                          │
//! └────────────────────────┘    └──────────────────────────┘
//! ```
//!
//! The capsule has no NAT route to the public internet. The only
//! reachable host address is `169.254.X.1`, where the proxy listens.
//! HTTP_PROXY-aware libraries route through it; non-HTTP traffic just
//! fails because there's no other egress path.
//!
//! Allocation: `/30` subnets in `169.254.32.0/24`. 64 concurrent
//! capsules per host. Atomic counter with collision-free increment;
//! release on capsule destroy. The pool wraps at 64 — collisions
//! return an error (callers can retry).
//!
//! Permissions: requires `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` in the
//! initial network namespace. CI runs `--privileged` Docker; production
//! runs as root or with the capabilities set explicitly. Outside those
//! contexts, `setup` returns an error and the namespace backend rejects
//! capsule creation — same fail-closed posture as before.

#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, thiserror::Error)]
pub enum NetnsError {
    #[error("ip {cmd}: exit {code}: {stderr}")]
    IpFailed {
        cmd: String,
        code: i32,
        stderr: String,
    },
    #[error("nsenter {cmd}: exit {code}: {stderr}")]
    NsenterFailed {
        cmd: String,
        code: i32,
        stderr: String,
    },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("subnet pool exhausted (max 64 concurrent capsules)")]
    PoolExhausted,
}

/// One veth allocation: host + guest interface names + IPs.
#[derive(Debug, Clone)]
pub struct VethSetup {
    pub slot: u8,
    pub host_iface: String,
    pub guest_iface: String,
    pub host_ip: Ipv4Addr,
    pub guest_ip: Ipv4Addr,
    pub prefix_len: u8,
}

/// Atomic slot allocator. Slots cycle 0..POOL_SIZE; release returns the
/// slot to the free pool. A bitset would be tighter, but this is
/// allocation-rare and 64 bits suffices.
const POOL_SIZE: u8 = 64;
static SLOT_BITS: AtomicU64 = AtomicU64::new(0);

fn allocate_slot() -> Result<u8, NetnsError> {
    loop {
        let bits = SLOT_BITS.load(Ordering::Acquire);
        let slot = (0..POOL_SIZE).find(|&s| (bits & (1u64 << s)) == 0);
        let Some(slot) = slot else {
            return Err(NetnsError::PoolExhausted);
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

impl VethSetup {
    fn from_slot(slot: u8) -> Self {
        // Each /30 holds .0 (network), .1 (host), .2 (guest), .3 (broadcast).
        // Slot 0 -> 169.254.32.0/30, slot 1 -> 169.254.32.4/30, ...
        let base = slot.saturating_mul(4);
        let host_ip = Ipv4Addr::new(169, 254, 32, base + 1);
        let guest_ip = Ipv4Addr::new(169, 254, 32, base + 2);
        let host_iface = format!("zk_h_{slot}");
        let guest_iface = format!("zk_g_{slot}");
        Self {
            slot,
            host_iface,
            guest_iface,
            host_ip,
            guest_ip,
            prefix_len: 30,
        }
    }
}

/// Set up the host side of the veth pair: create the pair, assign the host
/// IP, bring it up. Returns the [`VethSetup`] handle holding the slot
/// that must be released via [`teardown`] (or [`release_slot`] if the
/// kernel already cleaned up the interface).
pub fn setup_host_side() -> Result<VethSetup, NetnsError> {
    let slot = allocate_slot()?;
    let setup = VethSetup::from_slot(slot);

    // Best-effort cleanup of stale interfaces from a previous crashed run.
    let _ = run_ip(&["link", "del", &setup.host_iface]);

    run_ip(&[
        "link",
        "add",
        &setup.host_iface,
        "type",
        "veth",
        "peer",
        "name",
        &setup.guest_iface,
    ])?;

    if let Err(e) = run_ip(&[
        "addr",
        "add",
        &format!("{}/{}", setup.host_ip, setup.prefix_len),
        "dev",
        &setup.host_iface,
    ]) {
        let _ = run_ip(&["link", "del", &setup.host_iface]);
        release_slot(slot);
        return Err(e);
    }
    if let Err(e) = run_ip(&["link", "set", &setup.host_iface, "up"]) {
        let _ = run_ip(&["link", "del", &setup.host_iface]);
        release_slot(slot);
        return Err(e);
    }

    Ok(setup)
}

/// Move the guest end into the child's netns and configure it: assign IP,
/// bring up, default route via host side, loopback up. Run after `clone(2)`
/// returns the child PID.
pub fn move_guest_into_netns(setup: &VethSetup, child_pid: i32) -> Result<(), NetnsError> {
    // Move guest end. ip link set <iface> netns <pid> works because the
    // parent owns the user namespace that owns the netns.
    run_ip(&[
        "link",
        "set",
        &setup.guest_iface,
        "netns",
        &child_pid.to_string(),
    ])?;

    // Configure inside the child's netns + user namespace via nsenter.
    let ip_with_prefix = format!("{}/{}", setup.guest_ip, setup.prefix_len);
    run_nsenter(
        child_pid,
        &[
            "ip",
            "addr",
            "add",
            &ip_with_prefix,
            "dev",
            &setup.guest_iface,
        ],
    )?;
    run_nsenter(child_pid, &["ip", "link", "set", &setup.guest_iface, "up"])?;
    run_nsenter(child_pid, &["ip", "link", "set", "lo", "up"])?;
    run_nsenter(
        child_pid,
        &[
            "ip",
            "route",
            "add",
            "default",
            "via",
            &setup.host_ip.to_string(),
        ],
    )?;
    Ok(())
}

/// Tear down the veth + release the slot. Best-effort: the kernel cleans
/// the pair up automatically when the capsule netns is destroyed, so this
/// mostly serves to free the slot bit.
pub fn teardown(setup: VethSetup) {
    let _ = run_ip(&["link", "del", &setup.host_iface]);
    release_slot(setup.slot);
}

fn run_ip(args: &[&str]) -> Result<(), NetnsError> {
    let out = Command::new("ip").args(args).output()?;
    if !out.status.success() {
        return Err(NetnsError::IpFailed {
            cmd: args.join(" "),
            code: out.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    Ok(())
}

fn run_nsenter(pid: i32, cmd: &[&str]) -> Result<(), NetnsError> {
    let pid_str = pid.to_string();
    let mut argv = vec!["-t", &pid_str, "-U", "--preserve-credentials", "-n"];
    argv.extend_from_slice(cmd);
    let out = Command::new("nsenter").args(&argv).output()?;
    if !out.status.success() {
        return Err(NetnsError::NsenterFailed {
            cmd: cmd.join(" "),
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
    fn slot_allocator_gives_unique_slots() {
        let a = allocate_slot().unwrap();
        let b = allocate_slot().unwrap();
        let c = allocate_slot().unwrap();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
        release_slot(a);
        release_slot(b);
        release_slot(c);
    }

    #[test]
    fn slot_allocator_recycles_after_release() {
        let a = allocate_slot().unwrap();
        release_slot(a);
        let b = allocate_slot().unwrap();
        // Not guaranteed equal, but within the pool.
        assert!(b < POOL_SIZE);
        release_slot(b);
    }

    #[test]
    fn from_slot_assigns_distinct_subnets() {
        let s0 = VethSetup::from_slot(0);
        let s1 = VethSetup::from_slot(1);
        assert_eq!(s0.host_ip, Ipv4Addr::new(169, 254, 32, 1));
        assert_eq!(s0.guest_ip, Ipv4Addr::new(169, 254, 32, 2));
        assert_eq!(s1.host_ip, Ipv4Addr::new(169, 254, 32, 5));
        assert_eq!(s1.guest_ip, Ipv4Addr::new(169, 254, 32, 6));
        assert_eq!(s0.prefix_len, 30);
        assert_ne!(s0.host_iface, s1.host_iface);
    }

    #[test]
    fn from_slot_max_does_not_overflow() {
        let s = VethSetup::from_slot(POOL_SIZE - 1);
        // 63 * 4 + 1 = 253, fits in u8.
        assert_eq!(s.host_ip, Ipv4Addr::new(169, 254, 32, 253));
        assert_eq!(s.guest_ip, Ipv4Addr::new(169, 254, 32, 254));
    }
}
