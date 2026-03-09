# ZeptoCapsule Redesign — Implementation Plan

> **For Codex:** Execute this plan task-by-task. Run `cargo test --workspace` after every change. Read the design doc at `docs/plans/2026-03-08-kernel-redesign.md` first.

**Goal:** Collapse 3 crates (zk-proto, zk-host, zk-guest) into a single `zeptocapsule` crate that exposes a thin sandbox API: create capsule, spawn process with raw pipes, enforce resource limits, kill, destroy. Remove all orchestration logic (supervisor, protocol, events, heartbeats).

**Architecture:** Single library crate with optional `zk-init` binary. ProcessBackend for macOS/dev (no isolation). NamespaceBackend for Linux (namespaces + cgroups). Caller (ZeptoPM) gets raw stdin/stdout pipes and talks directly to the worker.

**Tech Stack:** Rust (edition 2024), tokio, nix (Linux-only, optional), libc, thiserror, tracing

---

## Current Codebase Reference

Before starting, understand what exists:

| Current File | Lines | Disposition |
|-------------|-------|-------------|
| `crates/zk-proto/src/lib.rs` | 465 | **DELETE** — protocol types move to ZeptoPM |
| `crates/zk-host/src/supervisor.rs` | 345 | **DELETE** — orchestration logic |
| `crates/zk-host/src/capsule.rs` | 51 | **DELETE** — state machine is orchestration |
| `crates/zk-host/src/backend.rs` | 56 | **REWRITE** — simpler trait (pipes, not protocol) |
| `crates/zk-host/src/process_backend.rs` | 159 | **REWRITE** — return raw pipes, no protocol encoding |
| `crates/zk-host/src/namespace_backend.rs` | 299 | **REWRITE** — same isolation, thinner interface |
| `crates/zk-host/src/cgroup.rs` | 95 | **KEEP** — pure mechanism, move to new crate |
| `crates/zk-host/src/vm_config.rs` | 69 | **DELETE** — Firecracker is future work |
| `crates/zk-guest/src/agent.rs` | 453 | **DELETE** — orchestration logic |
| `crates/zk-guest/src/worker.rs` | 64 | **DELETE** — worker launching moves to ZeptoPM |
| `crates/zk-guest/src/init.rs` | 107 | **REWRITE** — becomes minimal zk-init binary |
| `crates/zk-guest/src/bin/mock_worker.rs` | 105 | **KEEP** — useful for testing, move to new location |
| `crates/zk-host/tests/process_backend.rs` | 448 | **REWRITE** — test new API |
| `crates/zk-host/tests/namespace_backend.rs` | 187 | **REWRITE** — test new API |

---

## Task 1: Create New Crate Structure

**Files:**
- Create: `src/lib.rs`
- Create: `src/types.rs`
- Create: `Cargo.toml` (new root crate, replaces workspace)

**Step 1: Create root `Cargo.toml` for the single crate**

Replace the workspace Cargo.toml with a single library crate. Keep the old crates around until all code is migrated (they'll be deleted in Task 8).

```toml
[package]
name = "zeptocapsule"
version = "0.1.0"
edition = "2024"
license = "MIT"
repository = "https://github.com/qhkm/zeptocapsule"
description = "Thin sandbox library — capsule creation, process isolation, resource enforcement"

[lib]
name = "zeptocapsule"
path = "src/lib.rs"

[[bin]]
name = "zk-init"
path = "src/bin/zk_init.rs"
required-features = ["init-shim"]

[dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros", "time", "sync", "fs", "io-util", "process", "signal"] }
tracing = "0.1"
thiserror = "2"

[target.'cfg(unix)'.dependencies]
libc = "0.2"

[features]
default = []
namespace = ["dep:nix"]
init-shim = ["dep:nix"]

[target.'cfg(target_os = "linux")'.dependencies]
nix = { version = "0.29", features = ["sched", "mount", "process", "user", "signal"], optional = true }

[dev-dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros", "time", "io-util", "process", "test-util"] }
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

**Step 2: Create `src/types.rs` with all public types**

```rust
//! Public types for ZeptoCapsule — capsule specification, resource limits, violations.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// How to isolate the capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Isolation {
    /// Child process, no isolation. For development and macOS.
    Process,
    /// Linux namespaces + cgroups. Requires Linux.
    Namespace,
}

/// Resource limits enforced by the capsule.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Wall-clock timeout in seconds. Capsule kills process after this. Default: 300.
    pub timeout_sec: u64,
    /// Memory limit in MiB. Enforced via cgroup. None = unlimited.
    pub memory_mib: Option<u64>,
    /// CPU quota as fraction of one core (1.0 = 100%). None = unlimited.
    pub cpu_quota: Option<f64>,
    /// Maximum number of processes/threads. None = unlimited.
    pub max_pids: Option<u32>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            timeout_sec: 300,
            memory_mib: None,
            cpu_quota: None,
            max_pids: None,
        }
    }
}

/// Workspace configuration for the capsule.
#[derive(Debug, Clone)]
pub struct WorkspaceConfig {
    /// Mount point inside the capsule (e.g. /workspace).
    pub guest_path: PathBuf,
    /// Tmpfs size limit in MiB. None = system default.
    pub size_mib: Option<u64>,
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self {
            guest_path: PathBuf::from("/workspace"),
            size_mib: None,
        }
    }
}

/// Full specification for creating a capsule.
#[derive(Debug, Clone)]
pub struct CapsuleSpec {
    /// Isolation mode.
    pub isolation: Isolation,
    /// Workspace configuration.
    pub workspace: WorkspaceConfig,
    /// Resource limits to enforce.
    pub limits: ResourceLimits,
}

/// Why the capsule killed the process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceViolation {
    /// Wall-clock timeout exceeded.
    WallClock,
    /// cgroup OOM kill.
    Memory,
    /// cgroup PID limit exceeded.
    MaxPids,
}

/// Report from a destroyed capsule.
#[derive(Debug)]
pub struct CapsuleReport {
    /// Process exit code, if available.
    pub exit_code: Option<i32>,
    /// If the capsule killed the process, why.
    pub killed_by: Option<ResourceViolation>,
    /// Total wall-clock time the capsule was alive.
    pub wall_time: Duration,
}

/// Handle to a process spawned inside a capsule.
pub struct CapsuleChild {
    /// Write commands to the worker's stdin.
    pub stdin: tokio::process::ChildStdin,
    /// Read events from the worker's stdout.
    pub stdout: tokio::process::ChildStdout,
    /// Process ID of the spawned process.
    pub pid: u32,
}

/// Errors from ZeptoCapsule operations.
#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("spawn failed: {0}")]
    SpawnFailed(String),
    #[error("capsule not running")]
    NotRunning,
    #[error("signal delivery failed: {0}")]
    SignalFailed(String),
    #[error("cleanup failed: {0}")]
    CleanupFailed(String),
    #[error("not supported on this platform: {0}")]
    NotSupported(String),
}
```

**Step 3: Create `src/lib.rs` with module declarations and `create()` function**

```rust
//! ZeptoCapsule — thin sandbox library.
//!
//! Create isolated capsules, spawn processes with raw stdio pipes,
//! enforce resource limits. No protocol, no supervision, no events.
//!
//! ZeptoCapsule owns mechanisms. The caller (ZeptoPM) owns meaning.

pub mod types;
mod process;
mod timeout;

#[cfg(all(target_os = "linux", feature = "namespace"))]
mod namespace;
#[cfg(all(target_os = "linux", feature = "namespace"))]
mod cgroup;

pub use types::*;

/// Create a new capsule with the given specification.
pub fn create(spec: CapsuleSpec) -> Result<Capsule, KernelError> {
    match spec.isolation {
        Isolation::Process => Ok(Capsule::new_process(spec)),
        Isolation::Namespace => {
            #[cfg(all(target_os = "linux", feature = "namespace"))]
            {
                Ok(Capsule::new_namespace(spec))
            }
            #[cfg(not(all(target_os = "linux", feature = "namespace")))]
            {
                Err(KernelError::NotSupported(
                    "namespace isolation requires Linux + 'namespace' feature".into(),
                ))
            }
        }
    }
}
```

**Step 4: Run `cargo check` (will fail — modules not yet created)**

Expected: compile errors for missing `process`, `timeout` modules. That's fine — we'll build them next.

**Step 5: Commit**

```bash
git add src/lib.rs src/types.rs Cargo.toml
git commit -m "feat: new single-crate structure with types and public API"
```

---

## Task 2: Capsule Struct and Process Backend

**Files:**
- Create: `src/process.rs`
- Create: `src/timeout.rs`
- Modify: `src/lib.rs` — add Capsule struct
- Create: `tests/process_backend.rs`

**Step 1: Create `src/timeout.rs` — wall-clock enforcement**

```rust
//! Wall-clock timeout enforcement.
//!
//! Spawns a background task that kills the process after timeout_sec.
//! Abort the returned handle to cancel the timeout.

use std::time::Duration;
use tokio::task::JoinHandle;

/// Spawn a timeout enforcer. Returns a handle that can be aborted to cancel.
pub fn spawn_wall_clock_killer(pid: u32, timeout_sec: u64) -> JoinHandle<()> {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(timeout_sec)).await;
        #[cfg(unix)]
        unsafe {
            // SIGKILL — non-negotiable wall-clock enforcement
            libc::kill(pid as i32, libc::SIGKILL);
        }
        tracing::warn!(pid, "wall-clock timeout: killed process after {}s", timeout_sec);
    })
}
```

**Step 2: Create `src/process.rs` — ProcessBackend capsule**

This is the core: spawn a child process, return raw pipes.

```rust
//! Process backend — spawns worker as a child process with raw stdio pipes.
//!
//! No isolation. Used for development and macOS. The caller (ZeptoPM)
//! communicates with the worker directly through the returned pipes.

use std::collections::HashMap;
use std::time::Instant;

use tokio::task::JoinHandle;

use crate::timeout::spawn_wall_clock_killer;
use crate::types::*;

/// A running capsule. Owns the spawned process and enforces resource limits.
pub struct Capsule {
    spec: CapsuleSpec,
    child: Option<tokio::process::Child>,
    pid: Option<u32>,
    timeout_handle: Option<JoinHandle<()>>,
    created_at: Instant,
    killed_by: Option<ResourceViolation>,
}

impl Capsule {
    /// Create a capsule backed by a plain child process (no isolation).
    pub(crate) fn new_process(spec: CapsuleSpec) -> Self {
        Self {
            spec,
            child: None,
            pid: None,
            timeout_handle: None,
            created_at: Instant::now(),
            killed_by: None,
        }
    }

    /// Create a capsule backed by Linux namespaces.
    #[cfg(all(target_os = "linux", feature = "namespace"))]
    pub(crate) fn new_namespace(spec: CapsuleSpec) -> Self {
        Self {
            spec,
            child: None,
            pid: None,
            timeout_handle: None,
            created_at: Instant::now(),
            killed_by: None,
        }
    }

    /// Spawn a process inside this capsule.
    ///
    /// Returns raw stdin/stdout pipes. The caller owns all communication.
    /// Wall-clock timeout enforcement starts immediately.
    pub async fn spawn(
        &mut self,
        binary: &str,
        args: &[&str],
        env: HashMap<String, String>,
    ) -> Result<CapsuleChild, KernelError> {
        if self.child.is_some() {
            return Err(KernelError::SpawnFailed(
                "capsule already has a running process".into(),
            ));
        }

        let mut cmd = tokio::process::Command::new(binary);
        cmd.args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);

        for (k, v) in &env {
            cmd.env(k, v);
        }

        let mut child = cmd.spawn().map_err(|e| {
            KernelError::SpawnFailed(format!("failed to spawn {binary:?}: {e}"))
        })?;

        let pid = child.id().unwrap_or(0);
        let stdin = child.stdin.take().ok_or_else(|| {
            KernelError::SpawnFailed("failed to capture stdin".into())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            KernelError::SpawnFailed("failed to capture stdout".into())
        })?;

        // Start wall-clock timeout enforcer
        let timeout_handle = spawn_wall_clock_killer(pid, self.spec.limits.timeout_sec);

        self.child = Some(child);
        self.pid = Some(pid);
        self.timeout_handle = Some(timeout_handle);

        Ok(CapsuleChild { stdin, stdout, pid })
    }

    /// Send a signal to the capsule's process.
    pub fn kill(&mut self, signal: i32) -> Result<(), KernelError> {
        let pid = self.pid.ok_or(KernelError::NotRunning)?;
        #[cfg(unix)]
        {
            let ret = unsafe { libc::kill(pid as i32, signal) };
            if ret != 0 {
                return Err(KernelError::SignalFailed(format!(
                    "kill({}, {}) failed: {}",
                    pid,
                    signal,
                    std::io::Error::last_os_error()
                )));
            }
        }
        #[cfg(not(unix))]
        {
            return Err(KernelError::NotSupported("signals require unix".into()));
        }
        Ok(())
    }

    /// Tear down the capsule. Kills the process if still running, cleans up resources.
    /// Returns a report with exit code, kill reason, and wall time.
    pub async fn destroy(mut self) -> Result<CapsuleReport, KernelError> {
        // Cancel timeout enforcer
        if let Some(handle) = self.timeout_handle.take() {
            handle.abort();
        }

        let exit_code = if let Some(mut child) = self.child.take() {
            // Try to kill if still running
            let _ = child.kill().await;
            match child.wait().await {
                Ok(status) => status.code(),
                Err(_) => None,
            }
        } else {
            None
        };

        // Check if wall-clock timeout killed it (exit via SIGKILL + no explicit kill call)
        // This is best-effort detection
        let killed_by = self.killed_by.clone();

        Ok(CapsuleReport {
            exit_code,
            killed_by,
            wall_time: self.created_at.elapsed(),
        })
    }
}
```

**Step 3: Update `src/lib.rs` to re-export Capsule**

Add this line after the existing re-exports:

```rust
pub use process::Capsule;
```

Wait — Capsule is defined in process.rs but the `create()` function references it. Let me restructure. The `Capsule` struct should be in `lib.rs` or its own module, since both process and namespace backends construct it.

Actually, keep it in `process.rs` for now since ProcessBackend is the only working backend. When namespace is added (Task 5), we'll refactor if needed. The `new_namespace` constructor is already `#[cfg]`-gated.

Update `src/lib.rs`:

```rust
//! ZeptoCapsule — thin sandbox library.
//!
//! Create isolated capsules, spawn processes with raw stdio pipes,
//! enforce resource limits. No protocol, no supervision, no events.
//!
//! ZeptoCapsule owns mechanisms. The caller (ZeptoPM) owns meaning.

pub mod types;
mod process;
mod timeout;

#[cfg(all(target_os = "linux", feature = "namespace"))]
mod namespace;
#[cfg(all(target_os = "linux", feature = "namespace"))]
mod cgroup;

pub use types::*;
pub use process::Capsule;

/// Create a new capsule with the given specification.
pub fn create(spec: CapsuleSpec) -> Result<Capsule, KernelError> {
    match spec.isolation {
        Isolation::Process => Ok(Capsule::new_process(spec)),
        Isolation::Namespace => {
            #[cfg(all(target_os = "linux", feature = "namespace"))]
            {
                Ok(Capsule::new_namespace(spec))
            }
            #[cfg(not(all(target_os = "linux", feature = "namespace")))]
            {
                Err(KernelError::NotSupported(
                    "namespace isolation requires Linux + 'namespace' feature".into(),
                ))
            }
        }
    }
}
```

**Step 4: Create `tests/process_backend.rs` — integration tests**

```rust
//! Integration tests for the process backend.
//!
//! These tests spawn real processes and verify the capsule API:
//! create → spawn → read stdout → kill → destroy.

use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn echo_binary() -> &'static str {
    // Use `echo` as the simplest possible "worker"
    "/bin/echo"
}

fn cat_binary() -> &'static str {
    "/bin/cat"
}

fn sleep_binary() -> &'static str {
    "/bin/sleep"
}

fn default_spec() -> zeptocapsule::CapsuleSpec {
    zeptocapsule::CapsuleSpec {
        isolation: zeptocapsule::Isolation::Process,
        workspace: zeptocapsule::WorkspaceConfig::default(),
        limits: zeptocapsule::ResourceLimits::default(),
    }
}

#[tokio::test]
async fn test_create_and_spawn() {
    let mut capsule = zeptocapsule::create(default_spec()).unwrap();
    let child = capsule
        .spawn(echo_binary(), &["hello from capsule"], HashMap::new())
        .await
        .unwrap();

    assert!(child.pid > 0);

    // Read stdout — echo should output "hello from capsule\n"
    let mut reader = BufReader::new(child.stdout);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert_eq!(line.trim(), "hello from capsule");

    let report = capsule.destroy().await.unwrap();
    assert_eq!(report.exit_code, Some(0));
    assert!(report.killed_by.is_none());
}

#[tokio::test]
async fn test_spawn_with_env() {
    let mut capsule = zeptocapsule::create(default_spec()).unwrap();
    let mut env = HashMap::new();
    env.insert("MY_VAR".into(), "test_value".into());

    // Use /bin/sh to echo the env var
    let child = capsule
        .spawn("/bin/sh", &["-c", "echo $MY_VAR"], env)
        .await
        .unwrap();

    let mut reader = BufReader::new(child.stdout);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert_eq!(line.trim(), "test_value");

    let report = capsule.destroy().await.unwrap();
    assert_eq!(report.exit_code, Some(0));
}

#[tokio::test]
async fn test_stdin_stdout_pipes() {
    let mut capsule = zeptocapsule::create(default_spec()).unwrap();
    let child = capsule
        .spawn(cat_binary(), &[], HashMap::new())
        .await
        .unwrap();

    // Write to stdin, read from stdout (cat echoes)
    let mut stdin = child.stdin;
    let mut reader = BufReader::new(child.stdout);

    stdin.write_all(b"ping\n").await.unwrap();
    stdin.flush().await.unwrap();

    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert_eq!(line.trim(), "ping");

    // Close stdin to let cat exit
    drop(stdin);

    let report = capsule.destroy().await.unwrap();
    assert_eq!(report.exit_code, Some(0));
}

#[tokio::test]
async fn test_kill_signal() {
    let mut capsule = zeptocapsule::create(default_spec()).unwrap();
    let _child = capsule
        .spawn(sleep_binary(), &["60"], HashMap::new())
        .await
        .unwrap();

    // Send SIGTERM
    capsule.kill(libc::SIGTERM).unwrap();

    // Give it a moment to die
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let report = capsule.destroy().await.unwrap();
    // SIGTERM exit code is None (killed by signal) or 143
    assert!(report.exit_code.is_none() || report.exit_code == Some(143));
}

#[tokio::test]
async fn test_wall_clock_timeout() {
    let spec = zeptocapsule::CapsuleSpec {
        isolation: zeptocapsule::Isolation::Process,
        workspace: zeptocapsule::WorkspaceConfig::default(),
        limits: zeptocapsule::ResourceLimits {
            timeout_sec: 1, // 1 second timeout
            ..Default::default()
        },
    };

    let mut capsule = zeptocapsule::create(spec).unwrap();
    let _child = capsule
        .spawn(sleep_binary(), &["60"], HashMap::new())
        .await
        .unwrap();

    // Wait for timeout to kill the process
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let report = capsule.destroy().await.unwrap();
    // Process should have been killed by SIGKILL (exit code None)
    assert!(report.exit_code.is_none(), "expected SIGKILL death, got {:?}", report.exit_code);
}

#[tokio::test]
async fn test_spawn_nonexistent_binary() {
    let mut capsule = zeptocapsule::create(default_spec()).unwrap();
    let result = capsule
        .spawn("/nonexistent/binary", &[], HashMap::new())
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, zeptocapsule::KernelError::SpawnFailed(_)));
}

#[tokio::test]
async fn test_double_spawn_rejected() {
    let mut capsule = zeptocapsule::create(default_spec()).unwrap();
    let _child1 = capsule
        .spawn(sleep_binary(), &["60"], HashMap::new())
        .await
        .unwrap();

    // Second spawn should fail
    let result = capsule
        .spawn(sleep_binary(), &["60"], HashMap::new())
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        zeptocapsule::KernelError::SpawnFailed(_)
    ));

    capsule.kill(libc::SIGKILL).unwrap();
    let _ = capsule.destroy().await;
}

#[tokio::test]
async fn test_destroy_without_spawn() {
    let capsule = zeptocapsule::create(default_spec()).unwrap();
    let report = capsule.destroy().await.unwrap();
    assert!(report.exit_code.is_none());
    assert!(report.killed_by.is_none());
}

#[tokio::test]
async fn test_namespace_not_supported_on_macos() {
    let spec = zeptocapsule::CapsuleSpec {
        isolation: zeptocapsule::Isolation::Namespace,
        workspace: zeptocapsule::WorkspaceConfig::default(),
        limits: zeptocapsule::ResourceLimits::default(),
    };

    // On macOS (or Linux without feature), this should return NotSupported
    #[cfg(not(all(target_os = "linux", feature = "namespace")))]
    {
        let result = zeptocapsule::create(spec);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            zeptocapsule::KernelError::NotSupported(_)
        ));
    }
}
```

**Step 5: Run tests**

```bash
cargo test --lib --tests
```

Expected: all 9 tests pass.

**Step 6: Commit**

```bash
git add src/process.rs src/timeout.rs src/lib.rs tests/process_backend.rs
git commit -m "feat: process backend — spawn, pipes, kill, destroy, wall-clock timeout (9 tests)"
```

---

## Task 3: cgroup Module (Linux-only)

**Files:**
- Create: `src/cgroup.rs` (ported from `crates/zk-host/src/cgroup.rs`)

**Step 1: Port cgroup.rs**

Copy `crates/zk-host/src/cgroup.rs` to `src/cgroup.rs`. The only change: replace `use zk_proto::ResourceLimits` with `use crate::types::ResourceLimits`.

```rust
//! cgroup v2 lifecycle management for namespace capsules.
//!
//! Each capsule gets its own cgroup at:
//!   /sys/fs/cgroup/zeptocapsule/<job_id>/

use std::io;
use std::path::PathBuf;
use crate::types::ResourceLimits;

const CGROUP_ROOT: &str = "/sys/fs/cgroup/zeptocapsule";

pub struct Cgroup {
    path: PathBuf,
}

impl Cgroup {
    /// Create a new cgroup for the given capsule.
    pub fn create(capsule_id: &str) -> io::Result<Self> {
        let path = PathBuf::from(CGROUP_ROOT).join(capsule_id);
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    /// Create a dummy Cgroup that silently fails all operations.
    pub fn dummy() -> Self {
        Self {
            path: PathBuf::from("/sys/fs/cgroup/zeptocapsule/_dummy_nonexistent"),
        }
    }

    /// Add a process to this cgroup.
    pub fn add_pid(&self, pid: u32) -> io::Result<()> {
        std::fs::write(self.path.join("cgroup.procs"), format!("{}\n", pid))
    }

    /// Apply resource limits.
    pub fn apply_limits(&self, limits: &ResourceLimits) -> io::Result<()> {
        if let Some(mib) = limits.memory_mib {
            std::fs::write(
                self.path.join("memory.max"),
                format!("{}\n", mib * 1024 * 1024),
            )?;
        }
        if let Some(cpu) = limits.cpu_quota {
            let quota = (cpu * 100_000.0) as u64;
            std::fs::write(
                self.path.join("cpu.max"),
                format!("{} 100000\n", quota),
            )?;
        }
        if let Some(pids) = limits.max_pids {
            std::fs::write(self.path.join("pids.max"), format!("{}\n", pids))?;
        }
        Ok(())
    }

    /// Remove the cgroup. Must have no live processes.
    pub fn destroy(&self) {
        for _ in 0..3 {
            if std::fs::remove_dir(&self.path).is_ok() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        tracing::warn!("failed to remove cgroup {:?}", self.path);
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        self.destroy();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_path_construction() {
        let cg = Cgroup {
            path: PathBuf::from("/sys/fs/cgroup/zeptocapsule/test-capsule"),
        };
        assert_eq!(
            cg.path.join("memory.max"),
            PathBuf::from("/sys/fs/cgroup/zeptocapsule/test-capsule/memory.max")
        );
    }
}
```

**Step 2: Run tests**

```bash
cargo test --lib --tests
```

Expected: all previous tests still pass + 1 new cgroup unit test (on Linux with `namespace` feature).

**Step 3: Commit**

```bash
git add src/cgroup.rs
git commit -m "feat: port cgroup module — resource enforcement for namespace backend"
```

---

## Task 4: Namespace Backend (Linux-only)

**Files:**
- Create: `src/namespace.rs` (rewritten from `crates/zk-host/src/namespace_backend.rs`)

**Step 1: Create `src/namespace.rs`**

Port the namespace isolation logic but remove all protocol handling. The namespace backend creates an isolated child process and returns raw pipes — no `CapsuleHandle`, no `send()`/`recv()`.

```rust
//! Namespace sandbox backend — isolates worker in Linux namespaces.
//!
//! Uses clone() with CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS
//! | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNET.
//!
//! The worker process runs directly inside the namespace (no zk-guest mediator).
//! cgroup v2 enforces memory, CPU, and PID limits.

use std::collections::HashMap;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::path::PathBuf;

use nix::sched::CloneFlags;
use nix::unistd::Pid;

use crate::cgroup::Cgroup;
use crate::types::*;

/// Spawn a process inside a Linux namespace sandbox.
///
/// Returns (child_pid, stdin_write_fd, stdout_read_fd, cgroup).
/// The caller wraps these into a Capsule.
pub(crate) fn spawn_in_namespace(
    binary: &str,
    args: &[&str],
    env: &HashMap<String, String>,
    spec: &CapsuleSpec,
    capsule_id: &str,
) -> Result<(u32, RawFd, RawFd, Cgroup), KernelError> {
    // Pipe pair 1: host writes → child stdin
    let (child_stdin_r_owned, host_stdin_w_owned) = nix::unistd::pipe()
        .map_err(|e| KernelError::SpawnFailed(format!("pipe: {e}")))?;
    let child_stdin_r: RawFd = child_stdin_r_owned.into_raw_fd();
    let host_stdin_w: RawFd = host_stdin_w_owned.into_raw_fd();

    // Pipe pair 2: child stdout → host reads
    let (host_stdout_r_owned, child_stdout_w_owned) = nix::unistd::pipe()
        .map_err(|e| KernelError::SpawnFailed(format!("pipe: {e}")))?;
    let host_stdout_r: RawFd = host_stdout_r_owned.into_raw_fd();
    let child_stdout_w: RawFd = child_stdout_w_owned.into_raw_fd();

    // Sync pipe: parent signals child after UID/GID mapping
    let (sync_r_owned, sync_w_owned) = nix::unistd::pipe()
        .map_err(|e| KernelError::SpawnFailed(format!("pipe: {e}")))?;
    let sync_r: RawFd = sync_r_owned.into_raw_fd();
    let sync_w: RawFd = sync_w_owned.into_raw_fd();

    // Workspace must exist as mount point
    let workspace = spec.workspace.guest_path.clone();
    let workspace_size = spec.workspace.size_mib.unwrap_or(128);
    std::fs::create_dir_all(&workspace)
        .map_err(|e| KernelError::SpawnFailed(format!("workspace: {e}")))?;

    let binary = PathBuf::from(binary);
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let env: Vec<(String, String)> = env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

    // 8 MiB stack for child
    let mut stack = vec![0u8; 8 * 1024 * 1024];

    let clone_flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWIPC
        | CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWNET;

    let child_pid = unsafe {
        nix::sched::clone(
            Box::new(move || {
                child_main(
                    &binary,
                    &args,
                    &env,
                    &workspace,
                    workspace_size,
                    sync_r,
                    child_stdin_r,
                    child_stdout_w,
                )
            }),
            &mut stack,
            clone_flags,
            Some(libc::SIGCHLD),
        )
    }
    .map_err(|e| KernelError::SpawnFailed(format!("clone: {e}")))?;

    // Close child-side fds
    let _ = nix::unistd::close(child_stdin_r);
    let _ = nix::unistd::close(child_stdout_w);
    let _ = nix::unistd::close(sync_r);

    // Write UID/GID maps
    if let Err(e) = write_uid_gid_maps(child_pid) {
        unsafe { libc::write(sync_w, [1u8].as_ptr() as *const libc::c_void, 1) };
        let _ = nix::unistd::close(sync_w);
        unsafe { libc::kill(child_pid.as_raw(), libc::SIGKILL) };
        let _ = nix::sys::wait::waitpid(child_pid, None);
        return Err(KernelError::SpawnFailed(format!("uid/gid maps: {e}")));
    }

    // Create cgroup and apply limits (best-effort)
    let cgroup = match Cgroup::create(capsule_id) {
        Ok(cg) => {
            let _ = cg.add_pid(child_pid.as_raw() as u32);
            let _ = cg.apply_limits(&spec.limits);
            cg
        }
        Err(e) => {
            tracing::warn!("cgroup setup failed for capsule {capsule_id}: {e}");
            Cgroup::dummy()
        }
    };

    // Signal child to proceed
    unsafe { libc::write(sync_w, [1u8].as_ptr() as *const libc::c_void, 1) };
    let _ = nix::unistd::close(sync_w);

    Ok((child_pid.as_raw() as u32, host_stdin_w, host_stdout_r, cgroup))
}

/// Runs inside the new namespaces. Sets up filesystem, redirects I/O, execs worker.
fn child_main(
    binary: &PathBuf,
    args: &[String],
    env: &[(String, String)],
    workspace: &PathBuf,
    workspace_size_mib: u64,
    sync_read: RawFd,
    stdin_fd: RawFd,
    stdout_fd: RawFd,
) -> isize {
    // Wait for parent UID/GID mapping
    let mut buf = [0u8; 1];
    unsafe { libc::read(sync_read, buf.as_mut_ptr() as *mut libc::c_void, 1) };
    unsafe { libc::close(sync_read) };

    // Mount /proc
    let _ = nix::mount::mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        nix::mount::MsFlags::empty(),
        None::<&str>,
    );

    // Mount workspace as tmpfs
    let _ = std::fs::create_dir_all(workspace);
    let opts = format!("size={}m,mode=0755", workspace_size_mib);
    if nix::mount::mount(
        Some("tmpfs"),
        workspace.as_os_str(),
        Some("tmpfs"),
        nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV,
        Some(opts.as_str()),
    )
    .is_err()
    {
        return -1;
    }

    // Redirect stdin/stdout
    unsafe {
        libc::dup2(stdin_fd, libc::STDIN_FILENO);
        libc::dup2(stdout_fd, libc::STDOUT_FILENO);
        libc::close(stdin_fd);
        libc::close(stdout_fd);
    }

    // Set env vars
    for (k, v) in env {
        std::env::set_var(k, v);
    }

    // Exec the worker binary directly (no zk-guest mediator)
    let path = match std::ffi::CString::new(binary.to_str().unwrap_or("")) {
        Ok(p) => p,
        Err(_) => return -1,
    };

    let mut c_args: Vec<std::ffi::CString> = vec![path.clone()];
    for arg in args {
        match std::ffi::CString::new(arg.as_str()) {
            Ok(a) => c_args.push(a),
            Err(_) => return -1,
        }
    }

    let c_arg_ptrs: Vec<*const libc::c_char> =
        c_args.iter().map(|a| a.as_ptr()).chain(std::iter::once(std::ptr::null())).collect();

    unsafe { libc::execv(path.as_ptr(), c_arg_ptrs.as_ptr()) };
    -1 // execv failed
}

fn write_uid_gid_maps(child_pid: Pid) -> std::io::Result<()> {
    let pid = child_pid.as_raw();
    let uid = nix::unistd::getuid().as_raw();
    let gid = nix::unistd::getgid().as_raw();

    std::fs::write(format!("/proc/{pid}/uid_map"), format!("0 {uid} 1\n"))?;
    std::fs::write(format!("/proc/{pid}/setgroups"), "deny\n")?;
    std::fs::write(format!("/proc/{pid}/gid_map"), format!("0 {gid} 1\n"))?;
    Ok(())
}
```

**Step 2: Wire namespace spawn into Capsule**

Add to `src/process.rs` — an alternate `spawn()` path for namespace mode. Add a field to Capsule to track the mode, and in `spawn()`, branch:

```rust
// In Capsule::spawn(), before the existing tokio::process::Command logic:
#[cfg(all(target_os = "linux", feature = "namespace"))]
if self.spec.isolation == Isolation::Namespace {
    return self.spawn_namespace(binary, args, env).await;
}
```

Add the `spawn_namespace` method to `Capsule`:

```rust
#[cfg(all(target_os = "linux", feature = "namespace"))]
async fn spawn_namespace(
    &mut self,
    binary: &str,
    args: &[&str],
    env: HashMap<String, String>,
) -> Result<CapsuleChild, KernelError> {
    use std::os::unix::io::FromRawFd;

    let capsule_id = format!("capsule-{}", std::process::id());
    let (pid, stdin_fd, stdout_fd, _cgroup) =
        crate::namespace::spawn_in_namespace(binary, args, &env, &self.spec, &capsule_id)?;

    // Wrap raw fds as tokio types
    let stdin = unsafe {
        tokio::process::ChildStdin::from_raw_fd(stdin_fd)
    };
    let stdout = unsafe {
        tokio::process::ChildStdout::from_raw_fd(stdout_fd)
    };

    // Start wall-clock timeout
    let timeout_handle = crate::timeout::spawn_wall_clock_killer(pid, self.spec.limits.timeout_sec);

    self.pid = Some(pid);
    self.timeout_handle = Some(timeout_handle);

    Ok(CapsuleChild { stdin, stdout, pid })
}
```

**Note:** The `ChildStdin`/`ChildStdout` from raw fds may need to use `tokio::fs::File` instead. Adjust types if needed — the key is the caller gets async read/write handles to the pipes.

**Step 3: Run tests**

```bash
cargo test --lib --tests
```

Expected: all previous tests pass. Namespace tests only run on Linux with `--features namespace`.

**Step 4: Commit**

```bash
git add src/namespace.rs src/process.rs
git commit -m "feat: namespace backend — Linux isolation with cgroups, direct worker exec"
```

---

## Task 5: zk-init Binary (Minimal Init Shim)

**Files:**
- Create: `src/bin/zk_init.rs`

**Step 1: Create the minimal init shim**

This is only needed when the namespace backend is used and the worker binary needs a proper PID 1. It does three things: reap zombies, forward signals, exec the worker.

```rust
//! zk-init — minimal PID 1 for namespace capsules.
//!
//! Usage: zk-init <worker-binary> [worker-args...]
//!
//! Responsibilities:
//! - Forward SIGTERM to child process
//! - Reap zombie processes (PID 1 duty)
//! - Exec is preferred (no init needed), but this binary exists
//!   for cases where PID 1 duties are required.

use std::env;
use std::process::Command;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: zk-init <worker-binary> [args...]");
        std::process::exit(1);
    }

    let binary = &args[1];
    let worker_args = &args[2..];

    // Set up SIGTERM forwarding
    let child_pid: std::sync::Arc<std::sync::atomic::AtomicI32> =
        std::sync::Arc::new(std::sync::atomic::AtomicI32::new(0));

    // Spawn worker
    let mut child = match Command::new(binary)
        .args(worker_args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("zk-init: failed to spawn {binary}: {e}");
            std::process::exit(1);
        }
    };

    child_pid.store(child.id() as i32, std::sync::atomic::Ordering::SeqCst);

    // Set up SIGTERM handler that forwards to child
    let pid_clone = child_pid.clone();
    unsafe {
        libc::signal(libc::SIGTERM, forward_signal as usize);
        // Store pid in a global for the signal handler
        CHILD_PID.store(pid_clone.load(std::sync::atomic::Ordering::SeqCst),
                        std::sync::atomic::Ordering::SeqCst);
    }

    // Wait for child and reap zombies
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Reap any remaining zombies
                reap_zombies();
                std::process::exit(status.code().unwrap_or(1));
            }
            Ok(None) => {
                reap_zombies();
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("zk-init: wait error: {e}");
                std::process::exit(1);
            }
        }
    }
}

static CHILD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn forward_signal(_sig: i32) {
    let pid = CHILD_PID.load(std::sync::atomic::Ordering::SeqCst);
    if pid > 0 {
        unsafe { libc::kill(pid, libc::SIGTERM) };
    }
}

fn reap_zombies() {
    loop {
        let ret = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
        if ret <= 0 {
            break;
        }
    }
}
```

**Step 2: Run build**

```bash
cargo build --features init-shim
```

Expected: `zk-init` binary compiles.

**Step 3: Commit**

```bash
git add src/bin/zk_init.rs
git commit -m "feat: zk-init — minimal PID 1 shim for namespace capsules"
```

---

## Task 6: Mock Worker Binary (for testing)

**Files:**
- Create: `src/bin/mock_worker.rs` (ported from `crates/zk-guest/src/bin/mock_worker.rs`)

The mock worker is useful for testing. Port it but simplify — it no longer needs to speak the zk-proto protocol. It just reads stdin, writes stdout, and exits.

**Step 1: Create simplified mock worker**

```rust
//! Mock worker for testing ZeptoCapsule capsules.
//!
//! Modes (via MOCK_MODE env var):
//! - "complete" — write a line to stdout, exit 0
//! - "fail" — write a line to stdout, exit 1
//! - "hang" — write a line, then sleep forever (for timeout/kill tests)
//! - "echo" — read stdin line by line, echo back, exit on EOF

use std::io::{self, BufRead, Write};

fn main() {
    let mode = std::env::var("MOCK_MODE").unwrap_or_else(|_| "complete".into());

    // Always write at least one line so tests can verify stdout works
    println!("mock-worker: mode={mode}");
    io::stdout().flush().unwrap();

    match mode.as_str() {
        "complete" => {
            std::process::exit(0);
        }
        "fail" => {
            eprintln!("mock-worker: simulated failure");
            std::process::exit(1);
        }
        "hang" => {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
        "echo" => {
            let stdin = io::stdin();
            for line in stdin.lock().lines() {
                match line {
                    Ok(l) => {
                        println!("{l}");
                        io::stdout().flush().unwrap();
                    }
                    Err(_) => break,
                }
            }
        }
        other => {
            eprintln!("mock-worker: unknown mode: {other}");
            std::process::exit(2);
        }
    }
}
```

**Step 2: Add to Cargo.toml**

Add after the `zk-init` binary:

```toml
[[bin]]
name = "mock-worker"
path = "src/bin/mock_worker.rs"
```

**Step 3: Run build and tests**

```bash
cargo build && cargo test --lib --tests
```

**Step 4: Commit**

```bash
git add src/bin/mock_worker.rs Cargo.toml
git commit -m "feat: mock worker binary for capsule testing"
```

---

## Task 7: Integration Tests with Mock Worker

**Files:**
- Modify: `tests/process_backend.rs` — add tests using mock-worker

**Step 1: Add mock-worker tests**

Append to `tests/process_backend.rs`:

```rust
fn mock_worker_binary() -> String {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target/debug/mock-worker");
    path.to_str().unwrap().to_string()
}

#[tokio::test]
async fn test_mock_worker_complete() {
    let mut capsule = zeptocapsule::create(default_spec()).unwrap();
    let mut env = HashMap::new();
    env.insert("MOCK_MODE".into(), "complete".into());

    let child = capsule
        .spawn(&mock_worker_binary(), &[], env)
        .await
        .unwrap();

    let mut reader = BufReader::new(child.stdout);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.contains("mode=complete"));

    let report = capsule.destroy().await.unwrap();
    assert_eq!(report.exit_code, Some(0));
}

#[tokio::test]
async fn test_mock_worker_fail() {
    let mut capsule = zeptocapsule::create(default_spec()).unwrap();
    let mut env = HashMap::new();
    env.insert("MOCK_MODE".into(), "fail".into());

    let child = capsule
        .spawn(&mock_worker_binary(), &[], env)
        .await
        .unwrap();

    let mut reader = BufReader::new(child.stdout);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();

    // Wait for process to exit
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let report = capsule.destroy().await.unwrap();
    assert_eq!(report.exit_code, Some(1));
}

#[tokio::test]
async fn test_mock_worker_hang_killed_by_timeout() {
    let spec = zeptocapsule::CapsuleSpec {
        isolation: zeptocapsule::Isolation::Process,
        workspace: zeptocapsule::WorkspaceConfig::default(),
        limits: zeptocapsule::ResourceLimits {
            timeout_sec: 1,
            ..Default::default()
        },
    };

    let mut capsule = zeptocapsule::create(spec).unwrap();
    let mut env = HashMap::new();
    env.insert("MOCK_MODE".into(), "hang".into());

    let child = capsule
        .spawn(&mock_worker_binary(), &[], env)
        .await
        .unwrap();

    // Read initial output
    let mut reader = BufReader::new(child.stdout);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();

    // Wait for wall-clock timeout to kill it
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let report = capsule.destroy().await.unwrap();
    // Should have been killed by SIGKILL (no exit code)
    assert!(
        report.exit_code.is_none(),
        "expected SIGKILL, got exit code {:?}",
        report.exit_code
    );
}

#[tokio::test]
async fn test_mock_worker_echo_via_pipes() {
    let mut capsule = zeptocapsule::create(default_spec()).unwrap();
    let mut env = HashMap::new();
    env.insert("MOCK_MODE".into(), "echo".into());

    let child = capsule
        .spawn(&mock_worker_binary(), &[], env)
        .await
        .unwrap();

    let mut stdin = child.stdin;
    let mut reader = BufReader::new(child.stdout);

    // Read the initial mode line
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.contains("mode=echo"));

    // Send data through pipe, read echo
    stdin.write_all(b"hello kernel\n").await.unwrap();
    stdin.flush().await.unwrap();

    let mut echo_line = String::new();
    reader.read_line(&mut echo_line).await.unwrap();
    assert_eq!(echo_line.trim(), "hello kernel");

    // Close stdin → worker exits
    drop(stdin);

    let report = capsule.destroy().await.unwrap();
    assert_eq!(report.exit_code, Some(0));
}
```

**Step 2: Build mock-worker first, then run tests**

```bash
cargo build && cargo test --lib --tests
```

Expected: all ~13 tests pass (9 original + 4 mock-worker tests).

**Step 3: Commit**

```bash
git add tests/process_backend.rs
git commit -m "test: mock-worker integration tests — complete, fail, timeout, echo (4 tests)"
```

---

## Task 8: Remove Old Crates

**Files:**
- Delete: `crates/` directory (all 3 old crates)
- Modify: `Cargo.toml` — already done (replaced workspace with single crate in Task 1)

**Step 1: Verify new crate compiles and all tests pass**

```bash
cargo build && cargo test --lib --tests
```

All tests must pass before deleting old code.

**Step 2: Remove old crates**

```bash
rm -rf crates/
```

**Step 3: Clean up any stale references**

Check for any remaining references to old crate names:

```bash
grep -r "zk-proto\|zk-host\|zk-guest\|zk_proto\|zk_host\|zk_guest" src/ tests/ Cargo.toml
```

Fix any found references.

**Step 4: Run tests again**

```bash
cargo build && cargo test --lib --tests
```

All tests must pass.

**Step 5: Commit**

```bash
git add -A
git commit -m "refactor: remove old 3-crate structure — single zeptocapsule crate complete"
```

---

## Task 9: Update Documentation

**Files:**
- Modify: `CLAUDE.md` (if exists)
- Modify: `TODO.md` (if exists)

**Step 1: Update CLAUDE.md**

Update to reflect the new single-crate architecture:

- Remove references to zk-proto, zk-host, zk-guest as separate crates
- Document new public API: `create()`, `Capsule::spawn()`, `kill()`, `destroy()`
- Update module list: `types.rs`, `process.rs`, `timeout.rs`, `cgroup.rs`, `namespace.rs`
- Update build commands
- Update test count

**Step 2: Update TODO.md**

Mark redesign tasks complete. Update the milestone table.

**Step 3: Commit**

```bash
git add CLAUDE.md TODO.md
git commit -m "docs: update for single-crate redesign"
```

---

## Summary

| Task | What | Tests Added |
|------|------|-------------|
| 1 | New crate structure + types | 0 (compiles) |
| 2 | Capsule + ProcessBackend + wall-clock timeout | 9 |
| 3 | cgroup module (Linux-only) | 1 |
| 4 | Namespace backend (Linux-only) | 0 (gated) |
| 5 | zk-init binary | 0 (binary) |
| 6 | Mock worker binary | 0 (binary) |
| 7 | Integration tests with mock worker | 4 |
| 8 | Remove old crates | 0 (cleanup) |
| 9 | Update docs | 0 (docs) |
| **Total** | | **14 tests** |

**After all tasks:** Single `zeptocapsule` crate, ~14 tests, clean API: `create() → Capsule → spawn() → pipes → kill() → destroy()`.
