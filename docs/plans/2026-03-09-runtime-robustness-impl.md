# Runtime Robustness & Multi-Arch Portability Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make ZeptoKernel robust across kernel versions, distros, and architectures (x86_64 + aarch64).

**Architecture:** Five independent tasks: capability probe module, child diagnostic pipe, architecture-clean seccomp, fallback chain in create(), and enhanced CapsuleReport. Tasks 1-3 have no dependencies on each other. Task 4 depends on Task 5 (report fields). Task 5 depends on Task 2 (init_error field).

**Tech Stack:** Rust, libc, nix, tokio. No new crate dependencies.

---

### Task 1: Capability Probe Module (`src/probe.rs`)

**Files:**
- Create: `src/probe.rs`
- Modify: `src/lib.rs:1-34` — add `mod probe` and `pub use` exports

**Step 1: Write the failing tests**

Add to `src/probe.rs`:

```rust
//! Host capability detection for ZeptoKernel.
//!
//! Probes the current system to determine which isolation backends
//! and security profiles are supported. All probes are non-destructive
//! and do not require root.

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
    Other(String),
}

#[derive(Debug, Clone)]
pub struct HostCapabilities {
    pub kernel_version: (u32, u32, u32),
    pub arch: Arch,
    pub user_namespaces: bool,
    pub cgroup_v2: bool,
    pub seccomp_filter: bool,
    pub kvm: bool,
    pub firecracker_bin: Option<PathBuf>,
}

impl HostCapabilities {
    /// Derive the highest supported isolation and security levels from features.
    pub fn max_supported(&self) -> (crate::types::Isolation, crate::types::SecurityProfile) {
        use crate::types::{Isolation, SecurityProfile};
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Isolation, SecurityProfile};

    #[test]
    fn max_supported_full_linux() {
        let caps = HostCapabilities {
            kernel_version: (6, 1, 0),
            arch: Arch::X86_64,
            user_namespaces: true,
            cgroup_v2: true,
            seccomp_filter: true,
            kvm: false,
            firecracker_bin: None,
        };
        assert_eq!(caps.max_supported(), (Isolation::Namespace, SecurityProfile::Hardened));
    }

    #[test]
    fn max_supported_no_seccomp() {
        let caps = HostCapabilities {
            kernel_version: (5, 10, 0),
            arch: Arch::Aarch64,
            user_namespaces: true,
            cgroup_v2: true,
            seccomp_filter: false,
            kvm: false,
            firecracker_bin: None,
        };
        assert_eq!(caps.max_supported(), (Isolation::Namespace, SecurityProfile::Standard));
    }

    #[test]
    fn max_supported_no_namespaces() {
        let caps = HostCapabilities {
            kernel_version: (5, 10, 0),
            arch: Arch::X86_64,
            user_namespaces: false,
            cgroup_v2: true,
            seccomp_filter: true,
            kvm: false,
            firecracker_bin: None,
        };
        assert_eq!(caps.max_supported(), (Isolation::Process, SecurityProfile::Dev));
    }

    #[test]
    fn max_supported_firecracker() {
        let caps = HostCapabilities {
            kernel_version: (6, 1, 0),
            arch: Arch::X86_64,
            user_namespaces: true,
            cgroup_v2: true,
            seccomp_filter: true,
            kvm: true,
            firecracker_bin: Some(PathBuf::from("/usr/bin/firecracker")),
        };
        assert_eq!(caps.max_supported(), (Isolation::Firecracker, SecurityProfile::Standard));
    }

    #[test]
    fn max_supported_kvm_but_no_firecracker_binary() {
        let caps = HostCapabilities {
            kernel_version: (6, 1, 0),
            arch: Arch::X86_64,
            user_namespaces: true,
            cgroup_v2: true,
            seccomp_filter: true,
            kvm: true,
            firecracker_bin: None,
        };
        // KVM present but no firecracker binary → fall back to Namespace+Hardened
        assert_eq!(caps.max_supported(), (Isolation::Namespace, SecurityProfile::Hardened));
    }

    #[test]
    fn parse_kernel_version_standard() {
        assert_eq!(parse_kernel_version("Linux version 6.1.90-1234"), Some((6, 1, 90)));
    }

    #[test]
    fn parse_kernel_version_two_part() {
        assert_eq!(parse_kernel_version("Linux version 5.10.0-28-amd64"), Some((5, 10, 0)));
    }

    #[test]
    fn parse_kernel_version_garbage() {
        assert_eq!(parse_kernel_version("not a kernel"), None);
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --lib probe`
Expected: FAIL — `parse_kernel_version` not defined, module not registered.

**Step 3: Register module in lib.rs and implement**

In `src/lib.rs`, add after line 4 (`mod types;`):

```rust
mod probe;
```

And add to the `pub use` block (after line 33):

```rust
pub use probe::{Arch, HostCapabilities};
```

In `src/probe.rs`, add the probe function and kernel version parser (before the `#[cfg(test)]` block):

```rust
/// Parse kernel version from `/proc/version` text.
fn parse_kernel_version(text: &str) -> Option<(u32, u32, u32)> {
    // "Linux version 6.1.90-..." → (6, 1, 90)
    let version_str = text.split_whitespace()
        .nth(2)?;
    let mut parts = version_str.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

/// Detect the host architecture.
fn detect_arch() -> Arch {
    match std::env::consts::ARCH {
        "x86_64" => Arch::X86_64,
        "aarch64" => Arch::Aarch64,
        other => Arch::Other(other.to_string()),
    }
}

/// Probe host capabilities. Non-destructive, does not require root.
pub fn probe() -> HostCapabilities {
    let kernel_version = std::fs::read_to_string("/proc/version")
        .ok()
        .and_then(|s| parse_kernel_version(&s))
        .unwrap_or((0, 0, 0));

    let arch = detect_arch();

    let user_namespaces = probe_user_namespaces();
    let cgroup_v2 = std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    let seccomp_filter = probe_seccomp();
    let kvm = std::path::Path::new("/dev/kvm").exists();
    let firecracker_bin = find_firecracker_bin();

    HostCapabilities {
        kernel_version,
        arch,
        user_namespaces,
        cgroup_v2,
        seccomp_filter,
        kvm,
        firecracker_bin,
    }
}

fn probe_user_namespaces() -> bool {
    // Check sysctl first (Debian/Ubuntu)
    if let Ok(val) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        return val.trim() == "1";
    }
    // If sysctl doesn't exist, assume enabled (RHEL/Fedora, most modern kernels)
    // A more thorough check would fork+unshare, but that's heavyweight for a probe.
    cfg!(target_os = "linux")
}

fn probe_seccomp() -> bool {
    #[cfg(target_os = "linux")]
    {
        // PR_GET_SECCOMP returns 0 if seccomp is available (not in use),
        // or -1/EINVAL if the kernel doesn't support it.
        let ret = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
        ret >= 0
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn find_firecracker_bin() -> Option<PathBuf> {
    let candidates = [
        "/usr/bin/firecracker",
        "/usr/local/bin/firecracker",
    ];
    for path in &candidates {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }
    // Check PATH
    if let Ok(output) = std::process::Command::new("which")
        .arg("firecracker")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }
    None
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test --lib probe`
Expected: All 8 tests PASS.

**Step 5: Commit**

```bash
git add src/probe.rs src/lib.rs
git commit -m "feat: add host capability probe module"
```

---

### Task 2: Child Diagnostic Pipe

**Files:**
- Modify: `src/namespace.rs:194-201` — add `diag_read` to `NamespaceSpawn`
- Modify: `src/namespace.rs:224-382` — add diag pipe to `do_clone()`
- Modify: `src/namespace.rs:404-512` — add `diag_fd` param to `child_main()`, replace bare `return -1` with `child_bail()`
- Modify: `src/namespace.rs:141-191` — read diag pipe in `destroy()`
- Modify: `src/namespace.rs:28-34` — add `diag_read` to `NamespaceState`
- Modify: `src/types.rs:168-175` — add `init_error` to `CapsuleReport`

**Step 1: Add `init_error` field to `CapsuleReport`**

In `src/types.rs`, change the `CapsuleReport` struct (line 168):

```rust
#[derive(Debug, Clone, Default)]
pub struct CapsuleReport {
    pub exit_code: Option<i32>,
    pub exit_signal: Option<i32>,
    pub killed_by: Option<ResourceViolation>,
    pub wall_time: Duration,
    pub peak_memory_mib: Option<u64>,
    pub init_error: Option<String>,
}
```

**Step 2: Add `child_bail()` helper and `diag_fd` to `child_main()`**

In `src/namespace.rs`, add the helper function before `child_main` (before line 404):

```rust
/// Write a diagnostic message to the diag pipe and return -1 (child exit).
/// Used in child_main to report errors back to the host before exiting.
fn child_bail(diag_fd: RawFd, msg: &str) -> isize {
    let bytes = msg.as_bytes();
    unsafe { libc::write(diag_fd, bytes.as_ptr().cast(), bytes.len()) };
    -1
}
```

Change `child_main` signature to accept `diag_fd: RawFd` parameter (add after `stderr_fd`).

Replace every bare `return -1` in `child_main` with descriptive `child_bail()` calls:

- Line 437-438 (`create_dir_all` fails): `return child_bail(diag_fd, &format!("rootfs: mkdir {}: {}", new_root.display(), e));` — need to capture the error, so change from `.is_err()` to `if let Err(e) =`
- Line 441-442 (`copy` fails): `return child_bail(diag_fd, &format!("rootfs: copy zk-init: {}", e));`
- Line 450-451 (`setup_and_pivot` fails): `return child_bail(diag_fd, &format!("rootfs: setup_and_pivot: {}", e));`
- Line 462-463 (`seccomp` fails): `return child_bail(diag_fd, &format!("seccomp: {}", e));`
- Line 474 (CString fails): `return child_bail(diag_fd, "init binary path contains NUL");`
- Line 479 (CString fails): `return child_bail(diag_fd, "worker binary path contains NUL");`
- Line 487 (CString fails): `return child_bail(diag_fd, "worker arg contains NUL");`
- Line 511 (execve fails): `return child_bail(diag_fd, &format!("execve {}: {}", init_binary_path.display(), std::io::Error::last_os_error()));`

Close `diag_fd` with CLOEXEC before execve so it auto-closes on success. Add before the execve call:

```rust
// diag_fd has CLOEXEC — will auto-close on successful execve.
// If execve fails, we report below.
```

Actually, set CLOEXEC on diag_fd at the start of child_main:

```rust
unsafe { libc::fcntl(diag_fd, libc::F_SETFD, libc::FD_CLOEXEC) };
```

**Step 3: Add diag pipe to `do_clone()`**

In `do_clone()`, after the sync pipe creation (line 252-254), add:

```rust
let (diag_r_owned, diag_w_owned) =
    nix::unistd::pipe().map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
let diag_r = diag_r_owned.into_raw_fd();
let diag_w = diag_w_owned.into_raw_fd();
```

Pass `diag_w` to `child_main()` in the clone closure (add after `workspace_host.as_deref()`).

After clone, close `diag_w` on the host side (with the other child-side fd closes around line 322):

```rust
let _ = nix::unistd::close(diag_w);
```

Add `diag_read: RawFd` to `NamespaceSpawn` struct and return `diag_r` in the Ok result.

**Step 4: Add `diag_read` to `NamespaceState` and read it in `destroy()`**

In `NamespaceState` (line 28), add:

```rust
diag_read: Option<RawFd>,
```

In `spawn()` (around line 115), store it:

```rust
state.diag_read = Some(spawn.diag_read);
```

In `destroy()`, after waitpid completes (around line 171), read the diag pipe:

```rust
let init_error = if let Some(diag_fd) = state.diag_read.take() {
    let mut buf = [0u8; 4096];
    let n = nix::unistd::read(diag_fd, &mut buf).unwrap_or(0);
    let _ = nix::unistd::close(diag_fd);
    if n > 0 {
        Some(String::from_utf8_lossy(&buf[..n]).into_owned())
    } else {
        None
    }
} else {
    None
};
```

Include `init_error` in the returned `CapsuleReport`.

**Step 5: Run tests**

Run: `cargo test --lib`
Expected: All existing tests pass. The `init_error` field defaults to `None` so existing report assertions still work.

Run: `cargo check` (on macOS — verifies compile)
Expected: Clean compile.

**Step 6: Commit**

```bash
git add src/namespace.rs src/types.rs
git commit -m "feat: child diagnostic pipe for namespace init error reporting"
```

---

### Task 3: Architecture-Aware Seccomp

**Files:**
- Modify: `src/seccomp.rs:7-149` — wrap x86_64-only syscalls in `#[cfg]`, add missing universal equivalents
- Modify: `src/seccomp.rs:227-256` — update tests

**Step 1: Write a cross-compile check test**

Add to `src/seccomp.rs` tests:

```rust
#[test]
fn seccomp_no_duplicate_syscalls() {
    let allowed = allowed_syscalls();
    let mut seen = std::collections::HashSet::new();
    for nr in &allowed {
        assert!(seen.insert(nr), "duplicate syscall number: {nr}");
    }
}

#[test]
fn seccomp_has_universal_equivalents() {
    let allowed = allowed_syscalls();
    // These must be present on ALL architectures
    assert!(allowed.contains(&libc::SYS_openat), "missing openat");
    assert!(allowed.contains(&libc::SYS_newfstatat), "missing newfstatat");
    assert!(allowed.contains(&libc::SYS_faccessat), "missing faccessat");
    assert!(allowed.contains(&libc::SYS_pipe2), "missing pipe2");
    assert!(allowed.contains(&libc::SYS_dup3), "missing dup3");
    assert!(allowed.contains(&libc::SYS_pselect6), "missing pselect6");
    assert!(allowed.contains(&libc::SYS_renameat2), "missing renameat2");
    assert!(allowed.contains(&libc::SYS_unlinkat), "missing unlinkat");
    assert!(allowed.contains(&libc::SYS_mkdirat), "missing mkdirat");
    assert!(allowed.contains(&libc::SYS_symlinkat), "missing symlinkat");
    assert!(allowed.contains(&libc::SYS_linkat), "missing linkat");
    assert!(allowed.contains(&libc::SYS_fchmodat), "missing fchmodat");
    assert!(allowed.contains(&libc::SYS_readlinkat), "missing readlinkat");
    assert!(allowed.contains(&libc::SYS_statx), "missing statx");
    assert!(allowed.contains(&libc::SYS_fork), "missing fork");
    assert!(allowed.contains(&libc::SYS_vfork), "missing vfork");
    assert!(allowed.contains(&libc::SYS_gettid), "missing gettid");
    assert!(allowed.contains(&libc::SYS_ppoll), "missing ppoll");
    assert!(allowed.contains(&libc::SYS_getpgid), "missing getpgid");
}
```

**Step 2: Run tests to verify `ppoll` and `getpgid` are missing**

Run: `cargo test --lib seccomp`
Expected: FAIL — `SYS_ppoll` and `SYS_getpgid` not in list.

**Step 3: Refactor `allowed_syscalls()` with arch gating**

Replace the entire `allowed_syscalls()` function body:

```rust
pub fn allowed_syscalls() -> Vec<i64> {
    let mut syscalls = vec![
        // ── I/O ──
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_openat,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_lseek,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_preadv,
        libc::SYS_pwritev,
        libc::SYS_faccessat,
        libc::SYS_fcntl,
        libc::SYS_flock,
        libc::SYS_ftruncate,
        libc::SYS_fallocate,
        libc::SYS_ioctl,
        libc::SYS_getdents64,
        libc::SYS_readlinkat,

        // ── Memory ──
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_mremap,
        libc::SYS_msync,
        libc::SYS_madvise,
        libc::SYS_mlock,
        libc::SYS_munlock,
        libc::SYS_memfd_create,

        // ── Pipes and polling ──
        libc::SYS_pipe2,
        libc::SYS_dup,
        libc::SYS_dup3,
        libc::SYS_pselect6,
        libc::SYS_ppoll,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        libc::SYS_eventfd2,
        libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime,
        libc::SYS_timerfd_gettime,

        // ── Process ──
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_execve,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_wait4,
        libc::SYS_waitid,
        libc::SYS_kill,
        libc::SYS_tgkill,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_gettid,
        libc::SYS_getpgid,
        libc::SYS_setpgid,
        libc::SYS_setsid,
        libc::SYS_getrusage,
        libc::SYS_prctl,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        libc::SYS_rseq,

        // ── Signals ──
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,

        // ── User/group IDs ──
        libc::SYS_getuid,
        libc::SYS_getgid,
        libc::SYS_geteuid,
        libc::SYS_getegid,
        libc::SYS_getgroups,

        // ── Networking ──
        libc::SYS_socket,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_connect,
        libc::SYS_socketpair,
        libc::SYS_shutdown,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_getsockname,
        libc::SYS_getpeername,

        // ── Filesystem metadata ──
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_unlinkat,
        libc::SYS_mkdirat,
        libc::SYS_symlinkat,
        libc::SYS_linkat,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_umask,

        // ── Time ──
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_sched_yield,
        libc::SYS_getrandom,

        // ── Misc ──
        libc::SYS_uname,
        libc::SYS_getcwd,
        libc::SYS_chdir,
        libc::SYS_fchdir,
        libc::SYS_futex,
        libc::SYS_statfs,
        libc::SYS_fstatfs,
        libc::SYS_sched_getaffinity,
        libc::SYS_sched_setaffinity,
        libc::SYS_prlimit64,
        libc::SYS_close_range,
    ];

    // x86_64-only legacy syscalls (replaced by *at equivalents on aarch64)
    #[cfg(target_arch = "x86_64")]
    {
        syscalls.extend_from_slice(&[
            libc::SYS_open,
            libc::SYS_stat,
            libc::SYS_lstat,
            libc::SYS_access,
            libc::SYS_pipe,
            libc::SYS_dup2,
            libc::SYS_poll,
            libc::SYS_select,
            libc::SYS_rename,
            libc::SYS_unlink,
            libc::SYS_mkdir,
            libc::SYS_rmdir,
            libc::SYS_symlink,
            libc::SYS_link,
            libc::SYS_chmod,
            libc::SYS_readlink,
            libc::SYS_getpgrp,
            libc::SYS_getdents,
            libc::SYS_epoll_wait,
            libc::SYS_eventfd,
            libc::SYS_gettimeofday,
            libc::SYS_getrlimit,
            libc::SYS_setrlimit,
            libc::SYS_arch_prctl,
        ]);
    }

    syscalls
}
```

**Step 4: Run tests**

Run: `cargo test --lib seccomp`
Expected: All 4 seccomp tests PASS (including new ones for no-duplicates and universal equivalents).

**Step 5: Cross-compile check for aarch64**

Run: `cargo check --target aarch64-unknown-linux-gnu` (requires `rustup target add aarch64-unknown-linux-gnu`)
Expected: Clean compile. No missing `SYS_*` constants.

If the aarch64 target isn't available, at minimum verify: `cargo check` passes on current platform.

**Step 6: Commit**

```bash
git add src/seccomp.rs
git commit -m "feat: architecture-aware seccomp allowlist for x86_64 + aarch64"
```

---

### Task 4: Enhanced CapsuleReport (actual isolation/security tracking)

**Files:**
- Modify: `src/types.rs:168-175` — add `actual_isolation` and `actual_security` fields
- Modify: `src/namespace.rs:184-191` — populate new fields in destroy()
- Modify: `src/process.rs` — populate new fields in destroy()
- Modify: `src/firecracker.rs` — populate new fields in destroy()

**Step 1: Add fields to CapsuleReport**

In `src/types.rs`, update the struct (already has `init_error` from Task 2):

```rust
#[derive(Debug, Clone, Default)]
pub struct CapsuleReport {
    pub exit_code: Option<i32>,
    pub exit_signal: Option<i32>,
    pub killed_by: Option<ResourceViolation>,
    pub wall_time: Duration,
    pub peak_memory_mib: Option<u64>,
    pub init_error: Option<String>,
    pub actual_isolation: Option<Isolation>,
    pub actual_security: Option<SecurityProfile>,
}
```

**Step 2: Add tests**

In `src/types.rs` tests:

```rust
#[test]
fn capsule_report_default_has_none_fields() {
    let report = CapsuleReport::default();
    assert!(report.init_error.is_none());
    assert!(report.actual_isolation.is_none());
    assert!(report.actual_security.is_none());
}
```

**Step 3: Populate in each backend's destroy()**

In `src/namespace.rs` `destroy()`, when building the report, add:

```rust
actual_isolation: Some(crate::types::Isolation::Namespace),
actual_security: Some(self.spec.security),
```

In `src/process.rs` `destroy()`, add:

```rust
actual_isolation: Some(crate::types::Isolation::Process),
actual_security: Some(crate::types::SecurityProfile::Dev),
```

In `src/firecracker.rs` `destroy()`, add:

```rust
actual_isolation: Some(crate::types::Isolation::Firecracker),
actual_security: Some(self.spec.security),
```

Note: You need to store `spec.security` in each backend's capsule struct. The namespace backend already has `spec` stored. Check process and firecracker backends and store `security` or `spec` if not already present.

**Step 4: Run tests**

Run: `cargo test --lib`
Expected: All tests pass.

**Step 5: Commit**

```bash
git add src/types.rs src/namespace.rs src/process.rs src/firecracker.rs
git commit -m "feat: track actual isolation and security profile in CapsuleReport"
```

---

### Task 5: Fallback Chain in `create()`

**Files:**
- Modify: `src/types.rs:40-87` — add `fallback` field to `CapsuleSpec`, update validate()
- Modify: `src/lib.rs:60-93` — implement fallback loop in `create()`

**Step 1: Add `fallback` field and validation**

In `src/types.rs`, add to `CapsuleSpec` (after line 47):

```rust
pub fallback: Option<Vec<(Isolation, SecurityProfile)>>,
```

Update the `Default` impl to include `fallback: None`.

Add validation in `validate()` (after existing checks):

```rust
if let Some(ref chain) = self.fallback {
    let primary_level = security_level(self.isolation, self.security);
    for (i, &(iso, sec)) in chain.iter().enumerate() {
        let fb_level = security_level(iso, sec);
        if fb_level > primary_level {
            return Err(format!(
                "fallback[{i}] ({iso:?}, {sec:?}) escalates security above primary"
            ));
        }
        // Validate each entry as if it were a primary
        let check = CapsuleSpec {
            isolation: iso,
            security: sec,
            fallback: None,
            ..self.clone()
        };
        if let Err(e) = check.validate_primary() {
            return Err(format!("fallback[{i}]: {e}"));
        }
    }
}
```

Rename the existing validation logic to `validate_primary()` (private) and have `validate()` call it for the primary spec then validate the fallback chain.

Add a helper:

```rust
fn security_level(isolation: Isolation, security: SecurityProfile) -> u8 {
    match (isolation, security) {
        (Isolation::Firecracker, _) => 3,
        (Isolation::Namespace, SecurityProfile::Hardened) => 2,
        (Isolation::Namespace, SecurityProfile::Standard) => 1,
        (Isolation::Process, _) => 0,
        _ => 0,
    }
}
```

**Step 2: Add tests**

```rust
#[test]
fn validate_fallback_rejects_escalation() {
    let spec = CapsuleSpec {
        isolation: Isolation::Namespace,
        security: SecurityProfile::Standard,
        fallback: Some(vec![(Isolation::Namespace, SecurityProfile::Hardened)]),
        ..Default::default()
    };
    assert!(spec.validate().is_err());
}

#[test]
fn validate_fallback_accepts_downgrade() {
    let spec = CapsuleSpec {
        isolation: Isolation::Namespace,
        security: SecurityProfile::Hardened,
        fallback: Some(vec![
            (Isolation::Namespace, SecurityProfile::Standard),
            (Isolation::Process, SecurityProfile::Dev),
        ]),
        ..Default::default()
    };
    assert!(spec.validate().is_ok());
}

#[test]
fn validate_no_fallback_is_ok() {
    let spec = CapsuleSpec {
        isolation: Isolation::Namespace,
        security: SecurityProfile::Standard,
        fallback: None,
        ..Default::default()
    };
    assert!(spec.validate().is_ok());
}
```

**Step 3: Implement fallback in `create()`**

In `src/lib.rs`, replace the `create()` function:

```rust
pub fn create(spec: CapsuleSpec) -> KernelResult<Capsule> {
    spec.validate().map_err(KernelError::InvalidState)?;

    // Try primary
    match try_create(&spec) {
        Ok(capsule) => return Ok(capsule),
        Err(KernelError::NotSupported(msg)) => {
            if let Some(ref chain) = spec.fallback {
                for &(iso, sec) in chain {
                    let mut fb_spec = spec.clone();
                    fb_spec.isolation = iso;
                    fb_spec.security = sec;
                    fb_spec.fallback = None;
                    match try_create(&fb_spec) {
                        Ok(capsule) => return Ok(capsule),
                        Err(KernelError::NotSupported(_)) => continue,
                        Err(e) => return Err(e),
                    }
                }
            }
            Err(KernelError::NotSupported(msg))
        }
        Err(e) => Err(e),
    }
}

fn try_create(spec: &CapsuleSpec) -> KernelResult<Capsule> {
    let backend: Box<dyn Backend> = match spec.isolation {
        types::Isolation::Process => Box::new(process::ProcessBackend),
        types::Isolation::Namespace => {
            #[cfg(target_os = "linux")]
            {
                Box::new(namespace::NamespaceBackend)
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(KernelError::NotSupported(
                    "namespace isolation requires Linux".into(),
                ));
            }
        }
        types::Isolation::Firecracker => {
            #[cfg(target_os = "linux")]
            {
                Box::new(firecracker::FirecrackerBackend)
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(KernelError::NotSupported(
                    "firecracker isolation requires Linux".into(),
                ));
            }
        }
    };
    Ok(Capsule {
        inner: backend.create(spec.clone())?,
    })
}
```

Note: `CapsuleSpec` needs `Clone` — it already derives `Clone`.

**Step 4: Run tests**

Run: `cargo test --lib`
Expected: All tests pass.

**Step 5: Commit**

```bash
git add src/types.rs src/lib.rs
git commit -m "feat: explicit fallback chain for isolation level downgrade"
```

---

## Verification

After all 5 tasks:

1. `cargo test --lib` — all unit tests pass
2. `cargo check` — clean compile on macOS
3. Sync to VPS: `rsync -avz --exclude target --exclude .git ~/ios/zeptokernel/ stayflow-vps:~/zeptokernel-test/`
4. Build on VPS: `source ~/.cargo/env && cd ~/zeptokernel-test && cargo build --tests`
5. Run namespace integration tests: `sudo env ZK_RUN_NAMESPACE_TESTS=1 target/debug/deps/namespace_backend-* --test-threads=1 --nocapture`
6. Run unit tests: `cargo test --lib`
7. Verify probe on VPS: write a small test or use `cargo test --lib probe` — the probes read real /proc files, so they'll exercise the actual paths.

Optional (if aarch64 toolchain available):
8. `cargo check --target aarch64-unknown-linux-gnu` — verifies seccomp compiles for aarch64.
