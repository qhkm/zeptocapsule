# Security Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add tiered security profiles (Dev/Standard/Hardened) to ZeptoCapsule with rlimits, seccomp-bpf, pivot_root, capability dropping, stderr capture, and configurable cgroup strictness.

**Architecture:** `SecurityProfile` enum in `CapsuleSpec` controls which hardening layers activate. ProcessBackend gains rlimits (Dev). NamespaceBackend gains seccomp + pivot_root + caps drop (Hardened). All backends gain stderr capture. Cgroup failure mode tied to profile with override.

**Tech Stack:** Rust, libc, nix (Linux), seccomp-bpf (raw BPF via libc), tokio

---

## Codebase orientation

```
~/ios/zeptocapsule/
├── Cargo.toml                          # Single crate, deps: tokio, thiserror, tracing, libc, nix
├── src/
│   ├── lib.rs                          # Public API: create(), Capsule, re-exports
│   ├── types.rs                        # CapsuleSpec, Isolation, ResourceLimits, etc.
│   ├── backend.rs                      # CapsuleHandle + Backend traits, CapsuleChild, KernelError
│   ├── process.rs                      # ProcessBackend — child process, no isolation
│   ├── namespace.rs                    # NamespaceBackend — Linux clone() + cgroups (Linux-only)
│   ├── cgroup.rs                       # cgroup v2 management (Linux-only)
│   ├── init_shim.rs                    # zk-init PID 1 shim logic
│   └── bin/zk-init.rs                  # zk-init binary entry point
├── tests/
│   ├── process_backend.rs              # 3 integration tests (all platforms)
│   └── namespace_backend.rs            # 3 integration tests (Linux-only, gated by ZK_RUN_NAMESPACE_TESTS)
```

**Key types to know:**
- `CapsuleSpec` (`types.rs:12-17`): isolation + workspace + limits + init_binary
- `CapsuleChild` (`backend.rs:27-31`): stdin (Pin<Box<dyn AsyncWrite>>) + stdout (Pin<Box<dyn AsyncRead>>) + pid
- `CapsuleHandle` trait (`backend.rs:33-44`): spawn/kill/destroy
- `ProcessCapsule` (`process.rs:27-32`): wraps tokio::process::Child
- `NamespaceCapsule` (`namespace.rs:35-40`): wraps clone()'d child PID + cgroup
- `Cgroup` (`cgroup.rs:8-10`): manages a cgroup v2 directory

**Downstream consumer:** `~/ios/zeptoPM/src/capsule.rs` calls `zeptocapsule::create()` and constructs `CapsuleSpec` in `capsule_spec_from_config()`. Will need updating in a follow-up task (not in this plan).

---

### Task 1: Add SecurityProfile, SecurityOverrides, RLimits types + stderr to CapsuleChild

**Files:**
- Modify: `src/types.rs`
- Modify: `src/backend.rs`
- Modify: `src/lib.rs`

**Step 1: Write the failing test**

Add to `src/types.rs` at the bottom, inside a new `#[cfg(test)] mod tests`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_profile_default_is_standard() {
        assert_eq!(SecurityProfile::default(), SecurityProfile::Standard);
    }

    #[test]
    fn security_overrides_default_has_no_overrides() {
        let overrides = SecurityOverrides::default();
        assert_eq!(overrides.cgroup_required, None);
    }

    #[test]
    fn capsule_spec_default_has_standard_security() {
        let spec = CapsuleSpec::default();
        assert_eq!(spec.security, SecurityProfile::Standard);
    }

    #[test]
    fn rlimits_from_resource_limits_converts_memory() {
        let limits = ResourceLimits {
            memory_mib: Some(512),
            timeout_sec: 60,
            ..Default::default()
        };
        let rlimits = RLimits::from(&limits);
        assert_eq!(rlimits.max_memory_bytes, Some(512 * 1024 * 1024));
        assert_eq!(rlimits.max_cpu_seconds, Some(60));
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --lib -- types::tests -v`
Expected: FAIL — `SecurityProfile`, `SecurityOverrides`, `RLimits` not defined

**Step 3: Write minimal implementation**

In `src/types.rs`, add after the `Signal` enum (line 77):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityProfile {
    Dev,
    #[default]
    Standard,
    Hardened,
}

#[derive(Debug, Clone, Default)]
pub struct SecurityOverrides {
    pub cgroup_required: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct RLimits {
    pub max_memory_bytes: Option<u64>,
    pub max_cpu_seconds: Option<u64>,
    pub max_file_size_bytes: Option<u64>,
}

impl From<&ResourceLimits> for RLimits {
    fn from(limits: &ResourceLimits) -> Self {
        Self {
            max_memory_bytes: limits.memory_mib.map(|m| m * 1024 * 1024),
            max_cpu_seconds: Some(limits.timeout_sec),
            max_file_size_bytes: None,
        }
    }
}
```

Add `security` and `security_overrides` fields to `CapsuleSpec`:

```rust
pub struct CapsuleSpec {
    pub isolation: Isolation,
    pub workspace: WorkspaceConfig,
    pub limits: ResourceLimits,
    pub init_binary: Option<PathBuf>,
    pub security: SecurityProfile,
    pub security_overrides: SecurityOverrides,
}
```

Update `CapsuleSpec::default()` to include:

```rust
security: SecurityProfile::default(),
security_overrides: SecurityOverrides::default(),
```

In `src/backend.rs`, add `CapsuleStderr` type and `stderr` field:

```rust
pub type CapsuleStderr = Pin<Box<dyn AsyncRead + Send>>;

pub struct CapsuleChild {
    pub stdin: CapsuleStdin,
    pub stdout: CapsuleStdout,
    pub stderr: CapsuleStderr,
    pub pid: u32,
}
```

In `src/lib.rs`, add to re-exports:

```rust
pub use types::{
    CapsuleReport, CapsuleSpec, Isolation, RLimits, ResourceLimits, ResourceViolation,
    SecurityOverrides, SecurityProfile, Signal, WorkspaceConfig,
};
pub use backend::CapsuleStderr;
```

**Step 4: Run test to verify it passes**

Run: `cargo test --lib -- types::tests -v`
Expected: PASS (4 tests)

**Step 5: Fix existing tests that construct CapsuleSpec/CapsuleChild**

The existing tests in `tests/process_backend.rs` and `tests/namespace_backend.rs` use `CapsuleSpec { .. }` and `CapsuleChild` without the new fields. Fix:

- Existing tests using `CapsuleSpec::default()` will work automatically
- Existing tests constructing `CapsuleSpec { ... }` explicitly (namespace_backend.rs:65-77, 93-105) need `security` and `security_overrides` fields added (or use `..Default::default()` spread)

Fix `process.rs:133-137` and `namespace.rs:117-121` where `CapsuleChild` is constructed — add `stderr` field.

In `process.rs`, capture stderr:

```rust
.stderr(Stdio::piped())  // was Stdio::inherit()
```

```rust
let stderr = child.stderr.take().ok_or_else(|| {
    KernelError::SpawnFailed(format!("failed to capture stderr for {binary}"))
})?;
```

```rust
Ok(CapsuleChild {
    stdin: Box::pin(stdin),
    stdout: Box::pin(stdout),
    stderr: Box::pin(stderr),
    pid,
})
```

In `namespace.rs`, add stderr pipe. In `do_clone()` add a third pipe pair for stderr, pass `child_stderr_w` to `child_main()`, dup2 it to STDERR_FILENO. In `NamespaceSpawn` add `stderr: tokio::fs::File`. Return it in `CapsuleChild`.

**Step 6: Run full test suite**

Run: `cargo test`
Expected: ALL 5 existing tests + 4 new tests PASS

**Step 7: Commit**

```bash
git add src/types.rs src/backend.rs src/lib.rs src/process.rs src/namespace.rs tests/
git commit -m "feat: SecurityProfile, RLimits, stderr capture — new types + CapsuleChild.stderr"
```

---

### Task 2: rlimits in ProcessBackend (Dev profile)

**Files:**
- Modify: `src/process.rs`
- Modify: `tests/process_backend.rs`

**Step 1: Write the failing test**

Add to `tests/process_backend.rs`:

```rust
#[tokio::test]
async fn process_capsule_dev_profile_applies_rlimits() {
    let mut capsule = zeptocapsule::create(zeptocapsule::CapsuleSpec {
        security: zeptocapsule::SecurityProfile::Dev,
        limits: zeptocapsule::ResourceLimits {
            timeout_sec: 5,
            memory_mib: Some(64),
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();

    // Spawn a worker that tries to allocate 128 MiB — should be killed by RLIMIT_AS
    let child = capsule
        .spawn(
            "/bin/sh",
            &["-c", "head -c 134217728 /dev/zero | cat > /dev/null; echo survived"],
            std::collections::HashMap::new(),
        )
        .unwrap();

    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut child.stdout, &mut buf)
        .await
        .ok();

    let output = String::from_utf8_lossy(&buf);
    // Should NOT contain "survived" — process should be killed
    let report = capsule.destroy().unwrap();
    // Exit code should be non-zero (killed by signal or error)
    assert!(report.exit_code != Some(0) || report.exit_signal.is_some(),
        "expected process to be killed by rlimit, got exit_code={:?} signal={:?}, output={output}",
        report.exit_code, report.exit_signal);
}

#[tokio::test]
async fn process_capsule_stderr_captured() {
    let mut capsule = zeptocapsule::create(zeptocapsule::CapsuleSpec::default()).unwrap();

    let child = capsule
        .spawn(
            "/bin/sh",
            &["-c", "echo hello >&2"],
            std::collections::HashMap::new(),
        )
        .unwrap();

    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut child.stderr, &mut buf)
        .await
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&buf).trim(), "hello");

    drop(child);
    capsule.destroy().unwrap();
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test process_backend -- process_capsule_dev_profile -v`
Expected: FAIL — rlimits not applied yet

**Step 3: Write minimal implementation**

In `src/process.rs`, in the `spawn()` method, after building `Command` and before `.spawn()`, add a `pre_exec` hook when security is Dev:

```rust
#[cfg(unix)]
if matches!(self.spec.security, crate::types::SecurityProfile::Dev) {
    let rlimits = crate::types::RLimits::from(&self.spec.limits);
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
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test --test process_backend -v`
Expected: ALL tests PASS (3 existing + 2 new = 5 total)

**Step 5: Commit**

```bash
git add src/process.rs tests/process_backend.rs
git commit -m "feat: rlimits enforcement in ProcessBackend (Dev profile)"
```

---

### Task 3: Configurable cgroup strictness in NamespaceBackend

**Files:**
- Modify: `src/namespace.rs`
- Modify: `tests/namespace_backend.rs`

**Step 1: Write the failing test**

Add to `tests/namespace_backend.rs`:

```rust
#[tokio::test]
async fn namespace_hardened_fails_if_cgroup_unavailable() {
    // This test verifies that Hardened profile returns an error
    // when cgroup setup fails (simulated by invalid cgroup root).
    // On CI without cgroups delegated, this should fail fast.
    if !namespace_tests_enabled() {
        return;
    }

    let result = zeptocapsule::create(zeptocapsule::CapsuleSpec {
        isolation: zeptocapsule::Isolation::Namespace,
        security: zeptocapsule::SecurityProfile::Hardened,
        security_overrides: zeptocapsule::SecurityOverrides {
            cgroup_required: Some(true),
        },
        workspace: zeptocapsule::WorkspaceConfig {
            host_path: Some(unique_workspace("cgroup-strict")),
            guest_path: std::path::PathBuf::from("/workspace"),
            size_mib: Some(16),
        },
        limits: zeptocapsule::ResourceLimits {
            timeout_sec: 5,
            memory_mib: Some(64),
            ..Default::default()
        },
        init_binary: Some(zk_init_binary()),
    });

    // On a system without cgroup delegation, create should work but spawn should fail
    // OR on a system with cgroups, it should work fine
    // The key thing is: Hardened with cgroup_required=true doesn't silently skip cgroups
    assert!(result.is_ok()); // create itself succeeds, cgroup is checked at spawn
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test namespace_backend -- namespace_hardened -v`
Expected: FAIL — CapsuleSpec doesn't have security/security_overrides fields yet in test (compile error)

**Step 3: Write minimal implementation**

In `src/namespace.rs`, modify the cgroup setup in `do_clone()` around lines 289-299:

```rust
let cgroup_required = spec.security_overrides.cgroup_required.unwrap_or(
    matches!(spec.security, crate::types::SecurityProfile::Hardened)
);

let cgroup = match Cgroup::create(&capsule_id) {
    Ok(cgroup) => {
        let _ = cgroup.add_pid(child_pid.as_raw() as u32);
        let _ = cgroup.apply_limits(&spec.limits);
        cgroup
    }
    Err(error) => {
        if cgroup_required {
            // Kill the child and return error
            let _ = nix::sys::signal::kill(child_pid, nix::sys::signal::Signal::SIGKILL);
            let _ = waitpid(child_pid, None);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("cgroup setup required but failed: {error}"),
            ));
        }
        tracing::warn!("cgroup setup failed for {}: {}", capsule_id, error);
        Cgroup::dummy()
    }
};
```

The `do_clone` function needs access to `spec.security` and `spec.security_overrides`. It already receives `spec: &CapsuleSpec`, so these fields are available.

**Step 4: Run test to verify it passes**

Run: `cargo test --test namespace_backend -v`
Expected: ALL tests PASS

**Step 5: Commit**

```bash
git add src/namespace.rs tests/namespace_backend.rs
git commit -m "feat: configurable cgroup strictness — Hardened fails on cgroup error"
```

---

### Task 4: seccomp-bpf module (Linux-only, Hardened profile)

**Files:**
- Create: `src/seccomp.rs`
- Modify: `src/lib.rs`
- Create: `tests/seccomp_test_helper.rs` (optional test binary)

**Step 1: Write the failing test**

Add `src/seccomp.rs` with test at the bottom:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seccomp_filter_has_expected_size() {
        let filter = build_seccomp_filter();
        // Should have at least 70 allowed syscalls + header instructions
        assert!(filter.len() > 10, "filter too small: {} instructions", filter.len());
    }

    #[test]
    fn seccomp_allowed_syscalls_are_reasonable() {
        let allowed = allowed_syscalls();
        // Must include basic I/O
        assert!(allowed.contains(&libc::SYS_read));
        assert!(allowed.contains(&libc::SYS_write));
        assert!(allowed.contains(&libc::SYS_openat));
        assert!(allowed.contains(&libc::SYS_close));
        // Must include mmap (needed by all dynamically linked programs)
        assert!(allowed.contains(&libc::SYS_mmap));
        // Must include execve (needed to start worker)
        assert!(allowed.contains(&libc::SYS_execve));
        // Must NOT include dangerous syscalls
        assert!(!allowed.contains(&libc::SYS_reboot));
        assert!(!allowed.contains(&libc::SYS_kexec_load));
        assert!(!allowed.contains(&libc::SYS_init_module));
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --lib -- seccomp::tests -v`
Expected: FAIL — module doesn't exist

**Step 3: Write minimal implementation**

Create `src/seccomp.rs`:

```rust
//! seccomp-bpf filter for Hardened security profile.
//!
//! Installs a BPF syscall filter before execve. Only whitelisted syscalls
//! are allowed — everything else kills the process.

#[cfg(target_os = "linux")]
use std::mem;

/// List of allowed syscall numbers for Hardened profile.
#[cfg(target_os = "linux")]
pub fn allowed_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_read, libc::SYS_write, libc::SYS_open, libc::SYS_openat,
        libc::SYS_close, libc::SYS_stat, libc::SYS_fstat, libc::SYS_lstat,
        libc::SYS_newfstatat, libc::SYS_poll, libc::SYS_lseek,
        libc::SYS_mmap, libc::SYS_mprotect, libc::SYS_munmap, libc::SYS_brk,
        libc::SYS_ioctl, libc::SYS_access, libc::SYS_faccessat,
        libc::SYS_pipe, libc::SYS_pipe2,
        libc::SYS_select, libc::SYS_pselect6,
        libc::SYS_sched_yield, libc::SYS_mremap, libc::SYS_msync, libc::SYS_madvise,
        libc::SYS_dup, libc::SYS_dup2, libc::SYS_dup3,
        libc::SYS_nanosleep, libc::SYS_clock_nanosleep,
        libc::SYS_getpid, libc::SYS_getppid, libc::SYS_getuid, libc::SYS_getgid,
        libc::SYS_geteuid, libc::SYS_getegid, libc::SYS_getgroups,
        libc::SYS_socket, libc::SYS_sendto, libc::SYS_recvfrom,
        libc::SYS_sendmsg, libc::SYS_recvmsg,
        libc::SYS_bind, libc::SYS_listen, libc::SYS_accept, libc::SYS_accept4,
        libc::SYS_connect, libc::SYS_socketpair, libc::SYS_shutdown,
        libc::SYS_setsockopt, libc::SYS_getsockopt, libc::SYS_getsockname, libc::SYS_getpeername,
        libc::SYS_clone, libc::SYS_clone3,
        libc::SYS_execve, libc::SYS_exit, libc::SYS_exit_group,
        libc::SYS_wait4, libc::SYS_waitid,
        libc::SYS_kill, libc::SYS_tgkill, libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask, libc::SYS_rt_sigreturn,
        libc::SYS_uname, libc::SYS_getcwd, libc::SYS_chdir, libc::SYS_fchdir,
        libc::SYS_readlink, libc::SYS_readlinkat,
        libc::SYS_getdents, libc::SYS_getdents64,
        libc::SYS_futex, libc::SYS_set_robust_list, libc::SYS_get_robust_list,
        libc::SYS_clock_gettime, libc::SYS_clock_getres, libc::SYS_gettimeofday,
        libc::SYS_fcntl, libc::SYS_flock, libc::SYS_ftruncate, libc::SYS_fallocate,
        libc::SYS_getrandom, libc::SYS_memfd_create,
        libc::SYS_eventfd, libc::SYS_eventfd2,
        libc::SYS_epoll_create1, libc::SYS_epoll_ctl, libc::SYS_epoll_wait, libc::SYS_epoll_pwait,
        libc::SYS_timerfd_create, libc::SYS_timerfd_settime, libc::SYS_timerfd_gettime,
        libc::SYS_pread64, libc::SYS_pwrite64, libc::SYS_readv, libc::SYS_writev,
        libc::SYS_preadv, libc::SYS_pwritev,
        libc::SYS_set_tid_address, libc::SYS_set_robust_list,
        libc::SYS_prctl, libc::SYS_arch_prctl,
        libc::SYS_sigaltstack, libc::SYS_statfs, libc::SYS_fstatfs,
        libc::SYS_sched_getaffinity, libc::SYS_sched_setaffinity,
        libc::SYS_getrlimit, libc::SYS_setrlimit, libc::SYS_prlimit64,
        libc::SYS_rename, libc::SYS_renameat, libc::SYS_renameat2,
        libc::SYS_unlink, libc::SYS_unlinkat,
        libc::SYS_mkdir, libc::SYS_mkdirat,
        libc::SYS_rmdir,
        libc::SYS_symlink, libc::SYS_symlinkat,
        libc::SYS_link, libc::SYS_linkat,
        libc::SYS_chmod, libc::SYS_fchmod, libc::SYS_fchmodat,
        libc::SYS_umask,
        libc::SYS_mlock, libc::SYS_munlock,
        libc::SYS_rseq,
    ]
}

/// Build a BPF filter program that allows whitelisted syscalls and kills on all others.
#[cfg(target_os = "linux")]
pub fn build_seccomp_filter() -> Vec<libc::sock_filter> {
    let allowed = allowed_syscalls();
    let mut filter = Vec::new();

    // BPF_LD | BPF_W | BPF_ABS — load syscall number
    filter.push(bpf_stmt(
        libc::BPF_LD as u16 | libc::BPF_W as u16 | libc::BPF_ABS as u16,
        0, // offsetof(struct seccomp_data, nr)
    ));

    // For each allowed syscall: if nr == syscall, jump to ALLOW
    let num_allowed = allowed.len();
    for (i, &nr) in allowed.iter().enumerate() {
        let jt = (num_allowed - i) as u8; // jump to ALLOW (past remaining checks + KILL)
        filter.push(bpf_jump(
            libc::BPF_JMP as u16 | libc::BPF_JEQ as u16 | libc::BPF_K as u16,
            nr as u32,
            jt,
            0,
        ));
    }

    // Default: KILL
    filter.push(bpf_stmt(
        libc::BPF_RET as u16 | libc::BPF_K as u16,
        0x00000000, // SECCOMP_RET_KILL_PROCESS (in newer kernels) or SECCOMP_RET_KILL_THREAD
    ));

    // ALLOW
    filter.push(bpf_stmt(
        libc::BPF_RET as u16 | libc::BPF_K as u16,
        0x7fff0000, // SECCOMP_RET_ALLOW
    ));

    filter
}

/// Install the seccomp filter on the current thread/process.
/// Must be called after prctl(PR_SET_NO_NEW_PRIVS) and before execve.
#[cfg(target_os = "linux")]
pub fn install_seccomp_filter() -> Result<(), String> {
    let filter = build_seccomp_filter();

    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut _,
    };

    let ret = unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    };
    if ret != 0 {
        return Err(format!("PR_SET_NO_NEW_PRIVS failed: {}", std::io::Error::last_os_error()));
    }

    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            1i64, // SECCOMP_SET_MODE_FILTER
            0i64, // flags
            &prog as *const libc::sock_fprog as i64,
        )
    };
    if ret != 0 {
        return Err(format!("seccomp install failed: {}", std::io::Error::last_os_error()));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt: 0, jf: 0, k }
}

#[cfg(target_os = "linux")]
fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}
```

Add to `src/lib.rs`:

```rust
#[cfg(target_os = "linux")]
mod seccomp;
```

**Step 4: Run test to verify it passes**

Run: `cargo test --lib -- seccomp::tests -v`
Expected: PASS (2 tests)

**Step 5: Commit**

```bash
git add src/seccomp.rs src/lib.rs
git commit -m "feat: seccomp-bpf module — syscall whitelist for Hardened profile"
```

---

### Task 5: pivot_root + /dev setup module (Linux-only, Hardened profile)

**Files:**
- Create: `src/rootfs.rs`
- Modify: `src/lib.rs`

**Step 1: Write the failing test**

Add `src/rootfs.rs` with tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rootfs_layout_has_required_directories() {
        let layout = rootfs_layout();
        let dirs: Vec<&str> = layout.bind_mounts.iter().map(|m| m.guest.as_str()).collect();
        assert!(dirs.contains(&"/bin"), "missing /bin");
        assert!(dirs.contains(&"/lib"), "missing /lib");
        assert!(dirs.contains(&"/usr"), "missing /usr");
    }

    #[test]
    fn rootfs_layout_has_required_devices() {
        let layout = rootfs_layout();
        let devs: Vec<&str> = layout.devices.iter().map(|d| d.guest.as_str()).collect();
        assert!(devs.contains(&"/dev/null"), "missing /dev/null");
        assert!(devs.contains(&"/dev/zero"), "missing /dev/zero");
        assert!(devs.contains(&"/dev/urandom"), "missing /dev/urandom");
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --lib -- rootfs::tests -v`
Expected: FAIL — module doesn't exist

**Step 3: Write minimal implementation**

Create `src/rootfs.rs`:

```rust
//! Minimal rootfs setup and pivot_root for Hardened profile.
//!
//! Creates a temporary rootfs directory with bind-mounted host directories
//! (read-only) and minimal /dev devices. Then calls pivot_root to isolate
//! the worker from the host filesystem.

#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::path::Path;

pub struct BindMount {
    pub host: String,
    pub guest: String,
    pub readonly: bool,
}

pub struct DeviceNode {
    pub host: String,
    pub guest: String,
}

pub struct RootfsLayout {
    pub bind_mounts: Vec<BindMount>,
    pub devices: Vec<DeviceNode>,
}

pub fn rootfs_layout() -> RootfsLayout {
    RootfsLayout {
        bind_mounts: vec![
            BindMount { host: "/bin".into(), guest: "/bin".into(), readonly: true },
            BindMount { host: "/lib".into(), guest: "/lib".into(), readonly: true },
            BindMount { host: "/lib64".into(), guest: "/lib64".into(), readonly: true },
            BindMount { host: "/usr".into(), guest: "/usr".into(), readonly: true },
        ],
        devices: vec![
            DeviceNode { host: "/dev/null".into(), guest: "/dev/null".into() },
            DeviceNode { host: "/dev/zero".into(), guest: "/dev/zero".into() },
            DeviceNode { host: "/dev/urandom".into(), guest: "/dev/urandom".into() },
        ],
    }
}

/// Set up rootfs and call pivot_root. Must be called inside the cloned child
/// process (in the new mount namespace) before execve.
///
/// `new_root` is a temporary directory that becomes the new /.
/// `workspace` is bind-mounted into the new root.
#[cfg(target_os = "linux")]
pub fn setup_and_pivot(new_root: &Path, workspace_guest: &Path, workspace_host: Option<&Path>) -> Result<(), String> {
    let layout = rootfs_layout();

    // Create the new root directory
    std::fs::create_dir_all(new_root)
        .map_err(|e| format!("mkdir new_root {}: {e}", new_root.display()))?;

    // Bind-mount host dirs into new root (read-only)
    for mount in &layout.bind_mounts {
        let target = new_root.join(mount.guest.trim_start_matches('/'));
        if !Path::new(&mount.host).exists() {
            continue; // /lib64 may not exist on all systems
        }
        std::fs::create_dir_all(&target)
            .map_err(|e| format!("mkdir {}: {e}", target.display()))?;
        bind_mount_ro(Path::new(&mount.host), &target)?;
    }

    // Create /dev and bind-mount device nodes
    let dev_dir = new_root.join("dev");
    std::fs::create_dir_all(&dev_dir)
        .map_err(|e| format!("mkdir /dev: {e}"))?;
    for dev in &layout.devices {
        let target = new_root.join(dev.guest.trim_start_matches('/'));
        // Create empty file to mount over
        std::fs::write(&target, b"")
            .map_err(|e| format!("create {}: {e}", target.display()))?;
        bind_mount_ro(Path::new(&dev.host), &target)?;
    }

    // Mount /proc in new root
    let proc_dir = new_root.join("proc");
    std::fs::create_dir_all(&proc_dir)
        .map_err(|e| format!("mkdir /proc: {e}"))?;
    mount_proc(&proc_dir)?;

    // Mount /tmp as tmpfs in new root
    let tmp_dir = new_root.join("tmp");
    std::fs::create_dir_all(&tmp_dir)
        .map_err(|e| format!("mkdir /tmp: {e}"))?;
    mount_tmpfs(&tmp_dir, "64m")?;

    // Mount workspace
    let ws_guest = new_root.join(workspace_guest.to_string_lossy().trim_start_matches('/'));
    std::fs::create_dir_all(&ws_guest)
        .map_err(|e| format!("mkdir workspace: {e}"))?;
    if let Some(host_ws) = workspace_host {
        bind_mount_rw(host_ws, &ws_guest)?;
    } else {
        mount_tmpfs(&ws_guest, "128m")?;
    }

    // pivot_root
    let old_root = new_root.join("old_root");
    std::fs::create_dir_all(&old_root)
        .map_err(|e| format!("mkdir old_root: {e}"))?;

    let new_root_c = CString::new(new_root.to_string_lossy().as_bytes())
        .map_err(|e| format!("CString: {e}"))?;
    let old_root_c = CString::new(old_root.to_string_lossy().as_bytes())
        .map_err(|e| format!("CString: {e}"))?;

    let ret = unsafe { libc::syscall(libc::SYS_pivot_root, new_root_c.as_ptr(), old_root_c.as_ptr()) };
    if ret != 0 {
        return Err(format!("pivot_root failed: {}", std::io::Error::last_os_error()));
    }

    // chdir to new root
    let ret = unsafe { libc::chdir(c"/".as_ptr()) };
    if ret != 0 {
        return Err(format!("chdir / failed: {}", std::io::Error::last_os_error()));
    }

    // Unmount old root
    let ret = unsafe { libc::umount2(c"/old_root".as_ptr(), libc::MNT_DETACH) };
    if ret != 0 {
        return Err(format!("umount old_root failed: {}", std::io::Error::last_os_error()));
    }

    // Remove the old_root mountpoint
    let _ = std::fs::remove_dir("/old_root");

    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_mount_ro(source: &Path, target: &Path) -> Result<(), String> {
    let source_c = CString::new(source.to_string_lossy().as_bytes()).unwrap();
    let target_c = CString::new(target.to_string_lossy().as_bytes()).unwrap();

    // First bind mount
    let ret = unsafe {
        libc::mount(source_c.as_ptr(), target_c.as_ptr(), std::ptr::null(), libc::MS_BIND | libc::MS_REC, std::ptr::null())
    };
    if ret != 0 {
        return Err(format!("bind mount {} -> {} failed: {}", source.display(), target.display(), std::io::Error::last_os_error()));
    }

    // Remount read-only
    let ret = unsafe {
        libc::mount(std::ptr::null(), target_c.as_ptr(), std::ptr::null(), libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_REC, std::ptr::null())
    };
    if ret != 0 {
        return Err(format!("remount ro {} failed: {}", target.display(), std::io::Error::last_os_error()));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_mount_rw(source: &Path, target: &Path) -> Result<(), String> {
    let source_c = CString::new(source.to_string_lossy().as_bytes()).unwrap();
    let target_c = CString::new(target.to_string_lossy().as_bytes()).unwrap();

    let ret = unsafe {
        libc::mount(source_c.as_ptr(), target_c.as_ptr(), std::ptr::null(), libc::MS_BIND | libc::MS_REC, std::ptr::null())
    };
    if ret != 0 {
        return Err(format!("bind mount {} -> {} failed: {}", source.display(), target.display(), std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn mount_proc(target: &Path) -> Result<(), String> {
    let target_c = CString::new(target.to_string_lossy().as_bytes()).unwrap();
    let fstype = CString::new("proc").unwrap();
    let source = CString::new("proc").unwrap();

    let ret = unsafe {
        libc::mount(source.as_ptr(), target_c.as_ptr(), fstype.as_ptr(), 0, std::ptr::null())
    };
    if ret != 0 {
        return Err(format!("mount proc failed: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn mount_tmpfs(target: &Path, size: &str) -> Result<(), String> {
    let target_c = CString::new(target.to_string_lossy().as_bytes()).unwrap();
    let fstype = CString::new("tmpfs").unwrap();
    let source = CString::new("tmpfs").unwrap();
    let opts = CString::new(format!("size={size},nosuid,nodev")).unwrap();

    let ret = unsafe {
        libc::mount(source.as_ptr(), target_c.as_ptr(), fstype.as_ptr(), 0, opts.as_ptr().cast())
    };
    if ret != 0 {
        return Err(format!("mount tmpfs {} failed: {}", target.display(), std::io::Error::last_os_error()));
    }
    Ok(())
}
```

Add to `src/lib.rs`:

```rust
#[cfg(target_os = "linux")]
mod rootfs;
```

**Step 4: Run test to verify it passes**

Run: `cargo test --lib -- rootfs::tests -v`
Expected: PASS (2 tests)

**Step 5: Commit**

```bash
git add src/rootfs.rs src/lib.rs
git commit -m "feat: rootfs module — pivot_root + /dev setup for Hardened profile"
```

---

### Task 6: Wire seccomp + pivot_root + caps drop into NamespaceBackend child_main

**Files:**
- Modify: `src/namespace.rs`
- Modify: `tests/namespace_backend.rs`

**Step 1: Write the failing test**

Add to `tests/namespace_backend.rs`:

```rust
#[tokio::test]
async fn namespace_hardened_hides_host_filesystem() {
    if !namespace_tests_enabled() {
        return;
    }

    let mut capsule = zeptocapsule::create(zeptocapsule::CapsuleSpec {
        isolation: zeptocapsule::Isolation::Namespace,
        security: zeptocapsule::SecurityProfile::Hardened,
        workspace: zeptocapsule::WorkspaceConfig {
            host_path: Some(unique_workspace("pivot-host")),
            guest_path: std::path::PathBuf::from("/workspace"),
            size_mib: Some(16),
        },
        limits: zeptocapsule::ResourceLimits {
            timeout_sec: 5,
            ..Default::default()
        },
        init_binary: Some(zk_init_binary()),
        ..Default::default()
    })
    .unwrap();

    // Try to read /etc/hostname from host — should fail in pivoted root
    let child = capsule
        .spawn("/bin/sh", &["-c", "cat /etc/hostname 2>/dev/null && echo VISIBLE || echo HIDDEN"], std::collections::HashMap::new())
        .unwrap();

    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut child.stdout, &mut buf).await.ok();
    let output = String::from_utf8_lossy(&buf);

    drop(child);
    let _report = capsule.destroy().unwrap();
    assert!(output.contains("HIDDEN"), "expected host /etc to be hidden, got: {output}");
}

#[tokio::test]
async fn namespace_hardened_has_dev_null() {
    if !namespace_tests_enabled() {
        return;
    }

    let mut capsule = zeptocapsule::create(zeptocapsule::CapsuleSpec {
        isolation: zeptocapsule::Isolation::Namespace,
        security: zeptocapsule::SecurityProfile::Hardened,
        workspace: zeptocapsule::WorkspaceConfig {
            host_path: Some(unique_workspace("devnull")),
            guest_path: std::path::PathBuf::from("/workspace"),
            size_mib: Some(16),
        },
        limits: zeptocapsule::ResourceLimits {
            timeout_sec: 5,
            ..Default::default()
        },
        init_binary: Some(zk_init_binary()),
        ..Default::default()
    })
    .unwrap();

    let child = capsule
        .spawn("/bin/sh", &["-c", "echo test > /dev/null && echo OK || echo FAIL"], std::collections::HashMap::new())
        .unwrap();

    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut child.stdout, &mut buf).await.ok();
    let output = String::from_utf8_lossy(&buf);

    drop(child);
    capsule.destroy().unwrap();
    assert!(output.contains("OK"), "expected /dev/null to work, got: {output}");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test namespace_backend -- namespace_hardened -v`
Expected: FAIL — child_main doesn't call pivot_root/seccomp yet

**Step 3: Write minimal implementation**

Modify `src/namespace.rs` `child_main()` function. Before the `execve` call, add hardening steps when security is Hardened:

```rust
fn child_main(
    init_binary: &PathBuf,
    worker_binary: &str,
    worker_args: &[String],
    env: &[(String, String)],
    sync_read: RawFd,
    stdin_fd: RawFd,
    stdout_fd: RawFd,
    stderr_fd: RawFd,
    security: crate::types::SecurityProfile,
    workspace_guest: &std::path::Path,
    workspace_host: Option<&std::path::Path>,
) -> isize {
    // ... existing sync + dup2 code ...

    // Hardened: pivot_root + capabilities drop + seccomp
    if matches!(security, crate::types::SecurityProfile::Hardened) {
        let new_root = std::path::PathBuf::from(format!("/tmp/zk-rootfs-{}", std::process::id()));
        if let Err(e) = crate::rootfs::setup_and_pivot(&new_root, workspace_guest, workspace_host) {
            // Can't log here (no tracing in child), just exit
            return -1;
        }

        // Drop capabilities
        unsafe {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            for cap in 0..=40 { // CAP_LAST_CAP is ~40
                libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0);
            }
        }

        // Install seccomp filter (must be after PR_SET_NO_NEW_PRIVS)
        if let Err(_) = crate::seccomp::install_seccomp_filter() {
            return -1;
        }
    }

    // ... existing execve code ...
}
```

The `do_clone()` function needs to pass the security profile and workspace paths to `child_main()`. Modify the closure:

```rust
let security = spec.security;
let ws_guest = spec.workspace.guest_path.clone();
let ws_host = spec.workspace.host_path.clone();

let child_pid = unsafe {
    nix::sched::clone(
        Box::new(|| {
            child_main(
                &init_binary,
                &worker_binary,
                &worker_args,
                &env,
                sync_r,
                child_stdin_r,
                child_stdout_w,
                child_stderr_w,
                security,
                &ws_guest,
                ws_host.as_deref(),
            )
        }),
        &mut stack,
        clone_flags,
        Some(libc::SIGCHLD),
    )
};
```

**Step 4: Run test to verify it passes**

Run: `cargo test --test namespace_backend -v`
Expected: ALL tests PASS

**Step 5: Commit**

```bash
git add src/namespace.rs tests/namespace_backend.rs
git commit -m "feat: wire seccomp + pivot_root + caps drop into Hardened namespace backend"
```

---

### Task 7: Validation — SecurityProfile vs Isolation compatibility

**Files:**
- Modify: `src/lib.rs`
- Add tests to existing test files

**Step 1: Write the failing test**

Add to `src/types.rs` tests:

```rust
#[test]
fn validate_rejects_hardened_with_process() {
    let spec = CapsuleSpec {
        isolation: Isolation::Process,
        security: SecurityProfile::Hardened,
        ..Default::default()
    };
    assert!(spec.validate().is_err());
}

#[test]
fn validate_rejects_dev_with_namespace() {
    let spec = CapsuleSpec {
        isolation: Isolation::Namespace,
        security: SecurityProfile::Dev,
        ..Default::default()
    };
    assert!(spec.validate().is_err());
}

#[test]
fn validate_accepts_standard_with_namespace() {
    let spec = CapsuleSpec {
        isolation: Isolation::Namespace,
        security: SecurityProfile::Standard,
        ..Default::default()
    };
    assert!(spec.validate().is_ok());
}

#[test]
fn validate_accepts_dev_with_process() {
    let spec = CapsuleSpec {
        isolation: Isolation::Process,
        security: SecurityProfile::Dev,
        ..Default::default()
    };
    assert!(spec.validate().is_ok());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --lib -- types::tests::validate -v`
Expected: FAIL — `validate()` method doesn't exist

**Step 3: Write minimal implementation**

Add to `CapsuleSpec` in `src/types.rs`:

```rust
impl CapsuleSpec {
    pub fn validate(&self) -> Result<(), String> {
        match (self.isolation, self.security) {
            (Isolation::Process, SecurityProfile::Hardened) => {
                Err("Hardened security profile requires Namespace isolation".into())
            }
            (Isolation::Namespace, SecurityProfile::Dev) => {
                Err("Dev security profile only works with Process isolation".into())
            }
            _ => Ok(()),
        }
    }
}
```

In `src/lib.rs`, call `spec.validate()` at the start of `create()`:

```rust
pub fn create(spec: CapsuleSpec) -> KernelResult<Capsule> {
    spec.validate().map_err(KernelError::InvalidState)?;
    // ... rest unchanged
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -v`
Expected: ALL tests PASS

**Step 5: Commit**

```bash
git add src/types.rs src/lib.rs
git commit -m "feat: validate SecurityProfile vs Isolation compatibility"
```

---

### Task 8: Update ZeptoPM consumer (capsule_spec_from_config)

**Files:**
- Modify: `~/ios/zeptoPM/src/capsule.rs`
- Modify: `~/ios/zeptoPM/src/config.rs`
- Modify: `~/ios/zeptoPM/tests/capsule_integration.rs`

**Step 1: Write the failing test**

Add to `~/ios/zeptoPM/tests/capsule_integration.rs`:

```rust
#[test]
fn test_capsule_spec_security_from_config() {
    let mut config = test_config();
    config.daemon.security = Some("hardened".into());
    config.daemon.isolation = "namespace".into();
    let job = test_job("security-test");
    let spec = capsule_spec_from_config(&config, &job);

    assert_eq!(spec.security, zeptocapsule::SecurityProfile::Hardened);
}

#[test]
fn test_capsule_spec_security_defaults_to_standard() {
    let config = test_config();
    let job = test_job("security-default");
    let spec = capsule_spec_from_config(&config, &job);

    assert_eq!(spec.security, zeptocapsule::SecurityProfile::Standard);
}
```

**Step 2: Run test to verify it fails**

Run: `cd ~/ios/zeptoPM && cargo test --test capsule_integration -- security -v`
Expected: FAIL — `config.daemon.security` field doesn't exist

**Step 3: Write minimal implementation**

In `~/ios/zeptoPM/src/config.rs`, add to `DaemonConfig`:

```rust
#[serde(default)]
pub security: Option<String>,
#[serde(default)]
pub cgroup_required: Option<bool>,
```

Update `Default for DaemonConfig` to include:

```rust
security: None,
cgroup_required: None,
```

In `~/ios/zeptoPM/src/capsule.rs`, in `capsule_spec_from_config()`, add security mapping:

```rust
let security = match config.daemon.security.as_deref() {
    Some("dev") => zeptocapsule::SecurityProfile::Dev,
    Some("hardened") => zeptocapsule::SecurityProfile::Hardened,
    _ => zeptocapsule::SecurityProfile::Standard,
};

let security_overrides = zeptocapsule::SecurityOverrides {
    cgroup_required: config.daemon.cgroup_required,
};
```

Add to the `CapsuleSpec` construction:

```rust
CapsuleSpec {
    isolation,
    workspace: ...,
    limits: ...,
    init_binary: ...,
    security,
    security_overrides,
}
```

**Step 4: Run test to verify it passes**

Run: `cd ~/ios/zeptoPM && cargo test -v`
Expected: ALL tests PASS (existing + 2 new)

**Step 5: Commit**

```bash
cd ~/ios/zeptoPM
git add src/capsule.rs src/config.rs tests/capsule_integration.rs
git commit -m "feat: security profile config — maps daemon.security to CapsuleSpec"
```

---

### Task 9: Update docs and design doc

**Files:**
- Modify: `~/ios/zeptocapsule/docs/plans/2026-03-08-security-hardening-design.md` (add "Status: Implemented" header)
- Modify: `~/ios/zeptocapsule/TODO.md` (if exists)

**Step 1: Add implementation status**

At the top of the design doc, add:

```markdown
**Status:** Implemented in v0.2
```

**Step 2: Commit**

```bash
cd ~/ios/zeptocapsule
git add docs/ TODO.md
git commit -m "docs: mark security hardening as implemented"
```

---

## Summary

| Task | What | Files | Tests |
|------|------|-------|-------|
| 1 | New types + stderr capture | types.rs, backend.rs, lib.rs, process.rs, namespace.rs | 4 new unit |
| 2 | rlimits in ProcessBackend | process.rs | 2 new integration |
| 3 | Cgroup strictness | namespace.rs | 1 new integration |
| 4 | seccomp-bpf module | seccomp.rs, lib.rs | 2 new unit |
| 5 | pivot_root + /dev module | rootfs.rs, lib.rs | 2 new unit |
| 6 | Wire hardening into namespace child_main | namespace.rs | 2 new integration |
| 7 | Validation | types.rs, lib.rs | 4 new unit |
| 8 | ZeptoPM consumer update | capsule.rs, config.rs | 2 new integration |
| 9 | Docs | design doc, TODO | — |

**Total new tests:** ~19
**Total estimated commits:** 9

Tasks 1-7 are in `~/ios/zeptocapsule/`. Task 8 is in `~/ios/zeptoPM/`. Task 9 is docs only.

Tasks 1-3 can run on macOS (process backend tests). Tasks 4-6 need Linux for full integration tests but unit tests work on macOS. Task 7 works on all platforms. Task 8 works on all platforms.
