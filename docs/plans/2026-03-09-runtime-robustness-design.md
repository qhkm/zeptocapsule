# Runtime Robustness & Multi-Arch Portability Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make ZeptoCapsule's namespace/Hardened backend robust across kernel versions, Linux distros (Debian/Ubuntu/Alpine), and architectures (x86_64 + aarch64).

**Architecture:** Five changes — capability probing, child diagnostic pipe, architecture-clean seccomp, explicit fallback chain, and enhanced reporting. No new crates. Minimal API surface additions.

---

## 1. Capability Probe (`src/probe.rs`)

New module. Non-destructive probes that detect what the current host supports.

### Struct

```rust
pub struct HostCapabilities {
    pub kernel_version: (u32, u32, u32),
    pub arch: Arch,
    pub user_namespaces: bool,
    pub cgroup_v2: bool,
    pub seccomp_filter: bool,
    pub kvm: bool,
    pub firecracker_bin: Option<PathBuf>,
}

pub enum Arch {
    X86_64,
    Aarch64,
    Other(String),
}
```

### Probe Methods

| Feature | Method |
|---------|--------|
| `kernel_version` | Parse `/proc/version` |
| `arch` | `std::env::consts::ARCH` |
| `user_namespaces` | Read `/proc/sys/kernel/unprivileged_userns_clone` if it exists; otherwise fork+`unshare(CLONE_NEWUSER)` |
| `cgroup_v2` | Stat `/sys/fs/cgroup/cgroup.controllers` |
| `seccomp_filter` | `prctl(PR_GET_SECCOMP)` returns 0 (not EINVAL) |
| `kvm` | Stat `/dev/kvm` readable |
| `firecracker_bin` | Check common paths (`/usr/bin/firecracker`, `/usr/local/bin/firecracker`) + PATH lookup |

### Convenience Method

```rust
impl HostCapabilities {
    pub fn max_supported(&self) -> (Isolation, SecurityProfile) {
        if self.kvm && self.firecracker_bin.is_some() {
            return (Isolation::Firecracker, SecurityProfile::Standard);
        }
        if self.user_namespaces && self.cgroup_v2 && self.seccomp_filter {
            return (Isolation::Namespace, SecurityProfile::Hardened);
        }
        if self.user_namespaces && self.cgroup_v2 {
            return (Isolation::Namespace, SecurityProfile::Standard);
        }
        (Isolation::Process, SecurityProfile::Dev)
    }
}
```

### Public API

```rust
pub fn probe() -> HostCapabilities;
```

---

## 2. Child Diagnostic Pipe

### Problem

`child_main` returns -1 on failure. The host sees exit code 255 and empty stdout/stderr. No way to know if it was a mount failure, seccomp rejection, or execve error.

### Solution

Add a dedicated diagnostic pipe to `do_clone()`.

**Host side:**
- Create `(diag_read, diag_write)` pipe before clone
- Keep `diag_read`, pass `diag_write` to child
- After waitpid, read `diag_read` — empty means success or external kill, non-empty means init failure with error message

**Child side:**
- `diag_write` has `O_CLOEXEC` — auto-closes on successful execve
- Helper function writes structured error before returning -1:

```rust
fn child_bail(diag_fd: RawFd, msg: &str) -> isize {
    let bytes = msg.as_bytes();
    unsafe { libc::write(diag_fd, bytes.as_ptr().cast(), bytes.len()) };
    -1
}
```

**Error format:** Plain text, one line. Examples:
- `"rootfs: mkdir /tmp/zk-rootfs-1: EACCES"`
- `"rootfs: mount tmpfs /tmp: EINVAL"`
- `"seccomp: install failed: EINVAL"`
- `"execve /zk-init: ENOENT"`

**Surfaced in `CapsuleReport`:**
```rust
pub init_error: Option<String>,
```

---

## 3. Architecture-Aware Seccomp

### Problem

aarch64 Linux lacks many x86_64 syscalls (`open`, `stat`, `lstat`, `access`, `pipe`, `dup2`, `poll`, `select`, `rename`, `unlink`, `mkdir`, `rmdir`, `symlink`, `link`, `chmod`, `readlink`, `getpgrp`). These were replaced by `*at` equivalents when the aarch64 ABI was designed. The current allowlist references them unconditionally — it won't compile on aarch64.

### Solution

Compile-time gating only. No runtime component.

**Wrap x86_64-only entries:**
```rust
#[cfg(target_arch = "x86_64")]
libc::SYS_open,
#[cfg(target_arch = "x86_64")]
libc::SYS_stat,
// ... etc
```

**x86_64-only syscalls to gate:**
`open`, `stat`, `lstat`, `access`, `pipe`, `dup2`, `poll`, `select`, `rename`, `unlink`, `mkdir`, `rmdir`, `symlink`, `link`, `chmod`, `readlink`, `getpgrp`

**Universal equivalents to ensure present (already in list or add):**
`openat`, `newfstatat`, `statx`, `faccessat`, `pipe2`, `dup3`, `ppoll` (add), `pselect6`, `renameat`/`renameat2`, `unlinkat`, `mkdirat`, `symlinkat`, `linkat`, `fchmodat`, `readlinkat`, `getpgid` (add)

**Additional missing syscalls to add:**
`ppoll`, `getpgid`

---

## 4. Explicit Fallback Chain

### New Field on `CapsuleSpec`

```rust
pub fallback: Option<Vec<(Isolation, SecurityProfile)>>,
```

### Behavior in `zeptocapsule::create()`

1. Try requested `(spec.isolation, spec.security)` first
2. If `NotSupported`, check if `spec.fallback` is set
3. Walk fallback list in order, try each
4. If one succeeds, return capsule with actual level recorded
5. If none succeed (or no fallback), return original `NotSupported` error

### Validation Rules

- Fallback must not escalate (can't fall back from Standard to Hardened)
- Each fallback entry validated against existing rules (e.g., `(Process, Hardened)` is invalid)
- Optional — omit for strict behavior

### New Fields on `CapsuleReport`

```rust
pub actual_isolation: Isolation,
pub actual_security: SecurityProfile,
```

These always reflect what actually ran, even without a fallback chain.

---

## 5. What We Don't Build (YAGNI)

- **Runtime syscall validation** — compile-time gating is sufficient
- **Automatic seccomp learning mode** — adds complexity, hard to secure
- **Kernel version minimum enforcement** — probing covers this
- **cgroup v1 fallback** — v2 is universal on kernel 5.x+ which is our floor
- **Dynamic seccomp profiles per workload** — one Hardened profile is enough

---

## Testing Strategy

### Unit Tests
- `probe.rs`: Mock `/proc/version` parsing, test `max_supported()` derivation
- `seccomp.rs`: Verify aarch64 list compiles and has expected count, verify no x86_64-only entries leak
- Fallback validation: test escalation rejection, valid chains

### Integration Tests (Linux)
- Probe returns sensible values on test host
- Diagnostic pipe captures mount errors, seccomp errors, execve errors
- Fallback chain actually falls back and reports correct actual level
- Hardened profile works on both x86_64 and aarch64 (CI matrix)

### Cross-Compilation Check
- `cargo check --target aarch64-unknown-linux-gnu` must pass (no missing SYS_* constants)
