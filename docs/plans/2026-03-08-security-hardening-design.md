# ZeptoCapsule Security Hardening Design

> **Status: Implemented** (2026-03-08). All features below are live in `src/`.

> **For Codex / agents:** This is the authoritative design for configurable security
> hardening in ZeptoCapsule. Read it fully before starting implementation.

**Goal:** Add tiered security profiles (Dev / Standard / Hardened) so users can
progressively harden capsule isolation without understanding every knob. Document
the long-term path toward Firecracker microVM isolation.

**Architecture:** SecurityProfile enum in CapsuleSpec controls which layers are
active. Each profile is a fixed bundle of features. Individual overrides available
via SecurityOverrides.

**Principle:** Same as the kernel redesign — ZeptoCapsule owns mechanisms.
Profiles are mechanisms (which security layers to activate), not policy.

---

## Design Decisions

| Question | Answer | Rationale |
|----------|--------|-----------|
| Default security posture | Tiered presets (Dev/Standard/Hardened) | Clear upgrade path, no need to understand each knob |
| macOS/dev isolation | rlimits only (no sandbox-exec) | Simple, portable, prevents runaway resources |
| Seccomp profiles | Single built-in whitelist (~70 syscalls) | AI workers don't need exotic syscalls; expand list if needed |
| Stderr handling | Capture per-capsule (CapsuleStderr) | Consistent with stdin/stdout, ZeptoPM decides what to do |
| Cgroup failure mode | Configurable: strict vs permissive | Hardened = fail, Standard = warn, tied to profile |
| API shape | SecurityProfile enum + overrides in CapsuleSpec | Preset-driven, kernel stays policy-free |

---

## New Types

```rust
/// Security hardening tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityProfile {
    /// ProcessBackend + rlimits. No filesystem/network isolation. For dev/macOS.
    Dev,
    /// Namespaces + cgroups. Cgroup failure = warn.
    #[default]
    Standard,
    /// Standard + seccomp + pivot_root + drop capabilities. Cgroup failure = error.
    Hardened,
}

/// Per-profile override knobs.
#[derive(Debug, Clone, Default)]
pub struct SecurityOverrides {
    /// Override whether cgroup setup failure is fatal.
    /// Default: false for Standard, true for Hardened.
    pub cgroup_required: Option<bool>,
}

/// rlimit values for ProcessBackend (Dev profile).
#[derive(Debug, Clone)]
pub struct RLimits {
    pub max_memory_bytes: Option<u64>,    // RLIMIT_AS
    pub max_cpu_seconds: Option<u64>,     // RLIMIT_CPU
    pub max_file_size_bytes: Option<u64>, // RLIMIT_FSIZE
}
```

### CapsuleSpec changes

```rust
pub struct CapsuleSpec {
    pub isolation: Isolation,
    pub workspace: WorkspaceConfig,
    pub limits: ResourceLimits,
    pub init_binary: Option<PathBuf>,
    pub security: SecurityProfile,             // NEW
    pub security_overrides: SecurityOverrides,  // NEW
}
```

### CapsuleChild changes

```rust
pub type CapsuleStderr = Pin<Box<dyn AsyncRead + Send>>;

pub struct CapsuleChild {
    pub stdin: CapsuleStdin,
    pub stdout: CapsuleStdout,
    pub stderr: CapsuleStderr,  // NEW
    pub pid: u32,
}
```

---

## What Each Profile Does

| Feature | Dev | Standard | Hardened |
|---------|-----|----------|----------|
| Isolation backend | Process | Namespace | Namespace |
| rlimits (memory, CPU, fsize) | Yes | No (cgroups) | No (cgroups) |
| Namespaces (pid, mount, net, ipc, uts, user) | No | Yes | Yes |
| cgroups v2 (memory, CPU, PIDs) | No | Yes (warn on fail) | Yes (fail on error) |
| seccomp-bpf | No | No | Yes (~70 syscall whitelist) |
| pivot_root to minimal rootfs | No | No | Yes |
| Drop capabilities | No | No | Yes |
| Capture stderr | Yes | Yes | Yes |
| /dev setup (null, zero, urandom) | No | No | Yes (pivot_root needs it) |
| Network | Host network | Empty netns | Empty netns |

---

## Implementation Details

### Dev Profile (ProcessBackend)

Before `spawn()`, apply rlimits via `pre_exec` hook:

```rust
unsafe {
    cmd.pre_exec(move || {
        if let Some(mem) = rlimits.max_memory_bytes {
            let rlim = libc::rlimit { rlim_cur: mem, rlim_max: mem };
            libc::setrlimit(libc::RLIMIT_AS, &rlim);
        }
        if let Some(cpu) = rlimits.max_cpu_seconds {
            let rlim = libc::rlimit { rlim_cur: cpu, rlim_max: cpu };
            libc::setrlimit(libc::RLIMIT_CPU, &rlim);
        }
        if let Some(fsize) = rlimits.max_file_size_bytes {
            let rlim = libc::rlimit { rlim_cur: fsize, rlim_max: fsize };
            libc::setrlimit(libc::RLIMIT_FSIZE, &rlim);
        }
        Ok(())
    });
}
```

Stderr: change `Stdio::inherit()` to `Stdio::piped()`, expose as `CapsuleStderr`.

RLimits derived from ResourceLimits:
- `memory_mib * 1024 * 1024` → `RLIMIT_AS`
- `timeout_sec` → `RLIMIT_CPU` (approximate, wall-clock watchdog still primary)

### Standard Profile (NamespaceBackend)

Same as current behavior. Changes:
- Stderr piped instead of inherited
- Cgroup failure: warn + `Cgroup::dummy()`

### Hardened Profile (NamespaceBackend)

Three additional layers, applied inside `child_main()` before `execve`:

#### 1. pivot_root

Set up minimal rootfs before exec:

```
/tmp/zk-rootfs-{id}/
  /bin/        — bind-mount from host /bin (read-only)
  /lib/        — bind-mount from host /lib + /lib64 (read-only)
  /usr/        — bind-mount from host /usr (read-only)
  /workspace/  — tmpfs (existing)
  /tmp/        — tmpfs (existing)
  /dev/null    — bind from host /dev/null
  /dev/zero    — bind from host /dev/zero
  /dev/urandom — bind from host /dev/urandom
  /proc/       — mount proc
```

Then `pivot_root(new_root, put_old)` + `umount2(put_old, MNT_DETACH)`.

#### 2. seccomp-bpf

Load BPF filter before `execve`. Whitelist (~70 syscalls):

```
read, write, open, openat, close, stat, fstat, lstat, poll, lseek,
mmap, mprotect, munmap, brk, ioctl, access, pipe, pipe2, select,
sched_yield, mremap, msync, madvise, shmget, shmat, shmctl,
dup, dup2, dup3, nanosleep, clock_nanosleep, getpid, getppid,
socket (AF_UNIX only), sendto, recvfrom, sendmsg, recvmsg,
bind, listen, accept, connect, socketpair, shutdown,
clone (CLONE_VM|CLONE_FS|CLONE_FILES only — threads, not processes),
fork (BLOCKED), vfork (BLOCKED),
execve, exit, exit_group, wait4, waitid,
kill, tgkill, rt_sigaction, rt_sigprocmask, rt_sigreturn,
uname, getcwd, chdir, fchdir,
readlink, readlinkat, getdents, getdents64,
futex, set_robust_list, get_robust_list,
clock_gettime, clock_getres, gettimeofday,
getuid, getgid, geteuid, getegid, getgroups,
fcntl, flock, ftruncate, fallocate,
getrandom, memfd_create, eventfd, eventfd2, epoll_create1,
epoll_ctl, epoll_wait, timerfd_create, timerfd_settime
```

Everything else: `SECCOMP_RET_KILL_PROCESS`.

#### 3. Drop capabilities

After pivot_root, before execve:

```rust
// Prevent gaining new privileges
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

// Drop all capabilities from bounding set
for cap in 0..=CAP_LAST_CAP {
    prctl(PR_CAPBSET_DROP, cap, 0, 0, 0);
}
```

### Cgroup strictness

```rust
fn should_fail_on_cgroup_error(spec: &CapsuleSpec) -> bool {
    spec.security_overrides.cgroup_required.unwrap_or(
        matches!(spec.security, SecurityProfile::Hardened)
    )
}
```

---

## ZeptoPM Config Surface

Users configure via `zeptopm.toml`:

```toml
[daemon]
isolation = "namespace"
security = "hardened"       # "dev" | "standard" | "hardened"
cgroup_required = true      # override (optional)
```

ZeptoPM mapping in `capsule_spec_from_config()`:

```rust
let security = match config.daemon.security.as_deref() {
    Some("dev") => SecurityProfile::Dev,
    Some("hardened") => SecurityProfile::Hardened,
    _ => SecurityProfile::Standard,
};
```

Validation:
- `isolation = "process"` + `security = "hardened"` → error
- `isolation = "namespace"` + `security = "dev"` → error
- `isolation = "process"` + no security → defaults to Dev

---

## Long-Term Roadmap

### Why Firecracker is the endgame

Namespaces share a kernel with the host. A kernel exploit in the worker escapes
all namespace/seccomp/caps protections. A microVM has its own kernel — the
attack surface is the VMM's virtio device model, orders of magnitude smaller.

### Progression

```
v0.1 (current)              v0.2 (this design)           v1.0 (future)
──────────────              ──────────────────           ─────────────
Process (dev)         →     Process + rlimits      →     Process + rlimits
                                                         (unchanged, dev only)

Namespace             →     Namespace (Standard)   →     Namespace
                            Namespace + seccomp          + seccomp
                            + pivot_root                 + pivot_root
                            + caps drop                  + caps drop
                            (Hardened)                   (kept for cheap containers)

                                                   →     Firecracker microVM
                                                         - Full VM boundary
                                                         - OCI rootfs images
                                                         - Configurable network (veth/proxy)
                                                         - GPU passthrough (VFIO)
                                                         - Checkpoint/restore (CRIU)
                                                         - Per-agent syscall audit log
```

### Firecracker backend sketch

```rust
Isolation::Firecracker => {
    // 1. Pull/cache rootfs image (OCI or custom)
    // 2. Launch Firecracker VMM with: rootfs, kernel, vcpu, memory
    // 3. Attach vsock for stdin/stdout/stderr pipes
    // 4. Boot guest → zk-init → exec worker
    // 5. Same CapsuleChild API — pipes are vsock, not Unix pipes
    // 6. destroy() = shutdown VMM, collect CapsuleReport from metrics socket
}
```

**Key insight:** The API doesn't change. `create() → spawn() → pipes → destroy()`
works the same whether the capsule is a process, a namespace, or a microVM.
ZeptoPM doesn't care.

### When to build Firecracker

Build when:
- Multi-tenant workloads (untrusted users submitting agents)
- Network isolation with selective egress needed
- GPU passthrough for local model inference
- Compliance requires VM-level isolation

The Hardened namespace profile covers single-tenant production (your own agents
on your own infrastructure).

---

## Testing Strategy

| Test | Profile | What it verifies |
|------|---------|-----------------|
| rlimits prevent memory bomb | Dev | RLIMIT_AS kills process that allocates too much |
| rlimits prevent CPU spin | Dev | RLIMIT_CPU sends SIGXCPU/SIGKILL |
| stderr captured per capsule | All | stderr available as CapsuleChild.stderr |
| cgroup failure warns in Standard | Standard | Capsule created, warning logged, no limits |
| cgroup failure fails in Hardened | Hardened | KernelError returned, capsule not created |
| seccomp blocks dangerous syscall | Hardened | Worker calling blocked syscall gets killed |
| seccomp allows normal operation | Hardened | Worker running echo/cat works fine |
| pivot_root hides host filesystem | Hardened | Worker can't read /etc/passwd from host |
| pivot_root has /dev/null etc | Hardened | Worker can write to /dev/null, read /dev/urandom |
| capabilities dropped | Hardened | Worker can't chown or setuid |
| SecurityProfile default is Standard | Unit | Default trait returns Standard |

All Hardened/Standard tests are Linux-only (`#[cfg(target_os = "linux")]`).

---

## Decision Log

| Decision | Chosen | Rationale |
|----------|--------|-----------|
| Tiered presets vs individual flags | Presets (SecurityProfile enum) | Clear upgrade path, fewer misconfiguration risks |
| macOS isolation | rlimits only | Simple, portable, no deprecated Apple APIs |
| Seccomp granularity | Single built-in whitelist | YAGNI on per-agent customization |
| Stderr | Capture per-capsule | Consistent with stdin/stdout API |
| Cgroup failure mode | Configurable via profile + override | Hardened = strict, Standard = permissive |
| Firecracker | Deferred to v1.0 | Not needed for single-tenant; namespace Hardened covers production |
