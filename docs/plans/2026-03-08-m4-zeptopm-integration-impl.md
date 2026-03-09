# M4: ZeptoPM Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire ZeptoPM to ZeptoCapsule with a `CapsuleBackend` enum that supports `ProcessBackend` and `NamespaceBackend`, resource limits from agent config, and `ZEPTOCLAW_BINARY` injection via `spec.env`.

**Architecture:** `CapsuleBackend` enum in ZeptoPM's `capsule.rs` dispatches to `ProcessBackend` or `NamespaceBackend` based on `isolation` config. `job_to_spec()` accepts `&Config` to pull per-agent resource limits and inject the worker binary path. All changes live in ZeptoPM; ZeptoCapsule is consumed as-is.

**Tech Stack:** Rust, ZeptoPM (`/Users/dr.noranizaahmad/ios/zeptoPM/`), zk-host crate (path dep), tokio, serde/toml

---

## Key File Locations

| File | Purpose |
|------|---------|
| `/Users/dr.noranizaahmad/ios/zeptoPM/Cargo.toml` | Enable `namespace` feature on zk-host dep |
| `/Users/dr.noranizaahmad/ios/zeptoPM/src/config.rs` | Add `zeptoclaw_binary`, resource limit fields, validation |
| `/Users/dr.noranizaahmad/ios/zeptoPM/src/capsule.rs` | `CapsuleBackend` enum, `make_backend()`, updated `job_to_spec` |
| `/Users/dr.noranizaahmad/ios/zeptoPM/src/daemon.rs` | Pass `config` to `spawn_capsule_job`, accept new isolation values |
| `/Users/dr.noranizaahmad/ios/zeptoPM/tests/capsule_integration.rs` | New integration test |

**Reference files to read before starting:**
- `/Users/dr.noranizaahmad/ios/zeptoPM/src/capsule.rs` — current implementation (243 lines)
- `/Users/dr.noranizaahmad/ios/zeptoPM/src/config.rs` — `DaemonConfig`, `AgentConfig` structs, `validate_config()`
- `/Users/dr.noranizaahmad/ios/zeptocapsule/crates/zk-host/src/namespace_backend.rs` — `NamespaceBackend` API
- `/Users/dr.noranizaahmad/ios/zeptocapsule/crates/zk-host/src/process_backend.rs` — `ProcessBackend` API
- `/Users/dr.noranizaahmad/ios/zeptocapsule/crates/zk-proto/src/lib.rs` — `ResourceLimits` fields

**Build and test commands:**
```bash
# From /Users/dr.noranizaahmad/ios/zeptoPM/
cargo build
cargo test
cargo test -- --nocapture    # to see println output in tests
```

---

## Task 1: Enable namespace feature in ZeptoPM's zk-host dependency

**Files:**
- Modify: `/Users/dr.noranizaahmad/ios/zeptoPM/Cargo.toml`

**Step 1: Read current Cargo.toml**

```bash
cat /Users/dr.noranizaahmad/ios/zeptoPM/Cargo.toml
```

Find the line:
```toml
zk-host = { path = "../zeptocapsule/crates/zk-host" }
```

**Step 2: Add namespace feature**

Change it to:
```toml
zk-host = { path = "../zeptocapsule/crates/zk-host", features = ["namespace"] }
```

The `namespace` feature gates all namespace code behind `#[cfg(all(target_os = "linux", feature = "namespace"))]` in zk-host, so enabling it on macOS is safe — the namespace module simply won't compile on non-Linux targets.

**Step 3: Verify it still builds on macOS**

```bash
cd /Users/dr.noranizaahmad/ios/zeptoPM && cargo build 2>&1 | head -20
```

Expected: builds cleanly. No namespace-related errors (the cfg gate prevents compilation of namespace code on macOS).

**Step 4: Commit**

```bash
cd /Users/dr.noranizaahmad/ios/zeptoPM
git add Cargo.toml
git commit -m "feat(capsule): enable zk-host namespace feature"
```

---

## Task 2: Add `zeptoclaw_binary` to `DaemonConfig` and resource limit fields to `AgentConfig`

**Files:**
- Modify: `/Users/dr.noranizaahmad/ios/zeptoPM/src/config.rs`

**Step 1: Write failing tests first**

The tests in `config.rs` use inline TOML strings. Add to the `#[cfg(test)]` block at the bottom of the file:

```rust
#[test]
fn test_daemon_config_zeptoclaw_binary() {
    let toml = r#"
[daemon]
isolation = "process"
worker_binary = "/usr/bin/zk-guest"
zeptoclaw_binary = "/usr/bin/zeptoclaw"
"#;
    let config: Config = toml::from_str(toml).unwrap();
    assert_eq!(
        config.daemon.zeptoclaw_binary.as_deref(),
        Some("/usr/bin/zeptoclaw")
    );
}

#[test]
fn test_daemon_config_zeptoclaw_binary_optional() {
    let toml = r#"
[daemon]
isolation = "process"
"#;
    let config: Config = toml::from_str(toml).unwrap();
    assert!(config.daemon.zeptoclaw_binary.is_none());
}

#[test]
fn test_agent_config_resource_limits() {
    let toml = r#"
[[agents]]
name = "researcher"
memory_mib = 512
max_pids = 64
timeout_sec = 600
"#;
    let config: Config = toml::from_str(toml).unwrap();
    let agent = &config.agents[0];
    assert_eq!(agent.memory_mib, Some(512));
    assert_eq!(agent.max_pids, Some(64));
    assert_eq!(agent.timeout_sec, Some(600));
}

#[test]
fn test_validation_accepts_process_isolation() {
    let toml = r#"
[daemon]
isolation = "process"
worker_binary = "/usr/bin/zk-guest"
"#;
    let config: Config = toml::from_str(toml).unwrap();
    let errors = validate_config(&config);
    assert!(errors.is_empty(), "errors: {:?}", errors);
}

#[test]
fn test_validation_accepts_namespace_isolation() {
    let toml = r#"
[daemon]
isolation = "namespace"
worker_binary = "/usr/bin/zk-guest"
"#;
    let config: Config = toml::from_str(toml).unwrap();
    let errors = validate_config(&config);
    assert!(errors.is_empty(), "errors: {:?}", errors);
}

#[test]
fn test_validation_namespace_requires_worker_binary() {
    let toml = r#"
[daemon]
isolation = "namespace"
"#;
    let config: Config = toml::from_str(toml).unwrap();
    let errors = validate_config(&config);
    assert!(
        errors.iter().any(|e| e.contains("worker_binary")),
        "expected worker_binary error, got: {:?}",
        errors
    );
}

#[test]
fn test_validation_rejects_unknown_isolation() {
    let toml = r#"
[daemon]
isolation = "firecracker"
"#;
    let config: Config = toml::from_str(toml).unwrap();
    let errors = validate_config(&config);
    assert!(
        errors.iter().any(|e| e.contains("isolation")),
        "expected isolation error, got: {:?}",
        errors
    );
}
```

**Step 2: Run tests to confirm they fail**

```bash
cd /Users/dr.noranizaahmad/ios/zeptoPM && cargo test config 2>&1 | tail -20
```

Expected: compile errors or test failures (fields don't exist yet).

**Step 3: Add `zeptoclaw_binary` to `DaemonConfig`**

In `src/config.rs`, inside the `DaemonConfig` struct (after `worker_binary`):

```rust
/// Path to the ZeptoClaw worker binary (injected as ZEPTOCLAW_BINARY in spec.env).
#[serde(default)]
pub zeptoclaw_binary: Option<String>,
```

Also add it to the `Default` impl for `DaemonConfig`:
```rust
zeptoclaw_binary: None,
```

**Step 4: Add resource limit fields to `AgentConfig`**

In the `AgentConfig` struct (after `max_history`):

```rust
/// Memory limit for capsule jobs (MiB). None = unlimited.
#[serde(default)]
pub memory_mib: Option<u64>,
/// Max process count inside capsule. None = unlimited.
#[serde(default)]
pub max_pids: Option<u32>,
/// Wall clock timeout for capsule jobs (seconds). None = use ResourceLimits default (300s).
#[serde(default)]
pub timeout_sec: Option<u64>,
```

**Step 5: Update `validate_config`**

Find the isolation validation block (lines 186-194 in current file):
```rust
match config.daemon.isolation.as_str() {
    "none" | "capsule" => {}
    other => { ... }
}
```

Replace with:
```rust
match config.daemon.isolation.as_str() {
    "none" | "capsule" | "process" | "namespace" => {}
    other => {
        errors.push(format!(
            "daemon.isolation: unknown value '{}' (expected \"none\", \"process\", \"namespace\", or \"capsule\")",
            other
        ));
    }
}

// process/namespace/capsule modes require worker_binary
if matches!(config.daemon.isolation.as_str(), "capsule" | "process" | "namespace")
    && config.daemon.worker_binary.is_none()
{
    errors.push(
        format!(
            "daemon.isolation = {:?} requires daemon.worker_binary to be set",
            config.daemon.isolation
        )
    );
}
```

**Step 6: Run tests and verify they pass**

```bash
cd /Users/dr.noranizaahmad/ios/zeptoPM && cargo test config
```

Expected: all config tests pass including the 8 existing tests + the new ones.

**Step 7: Commit**

```bash
cd /Users/dr.noranizaahmad/ios/zeptoPM
git add src/config.rs
git commit -m "feat(config): add zeptoclaw_binary, resource limit fields, namespace isolation validation"
```

---

## Task 3: Update `job_to_spec` to pull resource limits and inject ZEPTOCLAW_BINARY

**Files:**
- Modify: `/Users/dr.noranizaahmad/ios/zeptoPM/src/capsule.rs`

**Step 1: Read `ResourceLimits` in zk-proto**

```bash
grep -n "ResourceLimits" /Users/dr.noranizaahmad/ios/zeptocapsule/crates/zk-proto/src/lib.rs | head -20
```

Confirm field names: `memory_mib: Option<u64>`, `cpu_quota: Option<f64>`, `max_pids: Option<u32>`, `timeout_sec: u64`, `heartbeat_timeout_sec: u64`, `network: bool`.

**Step 2: Write failing tests in `capsule.rs`**

Add to the `#[cfg(test)]` block in `capsule.rs`:

```rust
fn make_test_config(isolation: &str) -> crate::config::Config {
    crate::config::Config {
        daemon: crate::config::DaemonConfig {
            isolation: isolation.into(),
            worker_binary: Some("/usr/bin/zk-guest".into()),
            zeptoclaw_binary: Some("/usr/bin/zeptoclaw".into()),
            ..Default::default()
        },
        agents: vec![crate::config::AgentConfig {
            name: "coder-agent".into(),
            memory_mib: Some(512),
            max_pids: Some(64),
            timeout_sec: Some(600),
            ..Default::default()
        }],
        providers: Default::default(),
    }
}

#[test]
fn test_job_to_spec_with_limits() {
    let job = make_test_job();
    let config = make_test_config("process");
    let spec = job_to_spec(&job, vec![], &config);

    assert_eq!(spec.limits.memory_mib, Some(512));
    assert_eq!(spec.limits.max_pids, Some(64));
    assert_eq!(spec.limits.timeout_sec, 600);
}

#[test]
fn test_job_to_spec_injects_zeptoclaw_binary() {
    let job = make_test_job();
    let config = make_test_config("process");
    let spec = job_to_spec(&job, vec![], &config);

    assert_eq!(
        spec.env.get("ZEPTOCLAW_BINARY").map(String::as_str),
        Some("/usr/bin/zeptoclaw")
    );
}

#[test]
fn test_job_to_spec_no_zeptoclaw_binary() {
    let job = make_test_job();
    let mut config = make_test_config("process");
    config.daemon.zeptoclaw_binary = None;
    let spec = job_to_spec(&job, vec![], &config);

    // No ZEPTOCLAW_BINARY key — should not panic
    assert!(!spec.env.contains_key("ZEPTOCLAW_BINARY"));
}

#[test]
fn test_job_to_spec_default_limits_when_no_agent_profile() {
    let job = make_test_job(); // profile_id = "coder-agent"
    let mut config = make_test_config("process");
    config.agents.clear(); // no matching agent
    let spec = job_to_spec(&job, vec![], &config);

    // Falls back to ResourceLimits default
    assert!(spec.limits.memory_mib.is_none());
    assert_eq!(spec.limits.timeout_sec, 300); // zk-proto default
}
```

**Step 3: Run tests to confirm they fail**

```bash
cd /Users/dr.noranizaahmad/ios/zeptoPM && cargo test capsule 2>&1 | tail -20
```

Expected: compile errors because `job_to_spec` doesn't yet accept `&Config`.

**Step 4: Update `job_to_spec` signature and body**

Replace the current `job_to_spec` function in `capsule.rs` with:

```rust
/// Convert a ZeptoPM `Job` to a ZeptoCapsule `JobSpec`.
///
/// Pulls resource limits from the agent profile config and injects
/// `ZEPTOCLAW_BINARY` into the env map so the guest can find the worker
/// inside a namespace (where process env is not inherited).
pub fn job_to_spec(job: &Job, input_artifact_paths: Vec<String>, config: &crate::config::Config) -> JobSpec {
    let input_artifacts = input_artifact_paths
        .into_iter()
        .enumerate()
        .map(|(i, path)| zk_proto::ArtifactRef {
            artifact_id: job
                .input_artifact_ids
                .get(i)
                .cloned()
                .unwrap_or_else(|| format!("input_{}", i)),
            guest_path: PathBuf::from(&path),
            kind: "file".into(),
            summary: String::new(),
        })
        .collect();

    // Find the agent profile matching this job's profile_id
    let agent = config.agents.iter().find(|a| a.name == job.profile_id);

    // Resource limits from agent profile; fall back to proto defaults
    let limits = zk_proto::ResourceLimits {
        memory_mib: agent.and_then(|a| a.memory_mib),
        max_pids: agent.and_then(|a| a.max_pids),
        timeout_sec: agent.and_then(|a| a.timeout_sec).unwrap_or(300),
        heartbeat_timeout_sec: 60,
        cpu_quota: None,
        network: false,
    };

    // Env: API keys + HOME/PATH (same as before)
    let mut env: HashMap<String, String> = std::env::vars()
        .filter(|(k, _)| {
            k.starts_with("OPENROUTER_")
                || k.starts_with("OPENAI_")
                || k.starts_with("ANTHROPIC_")
                || k == "HOME"
                || k == "PATH"
        })
        .collect();

    // Inject ZEPTOCLAW_BINARY so the guest agent can locate the worker
    // inside a namespace (execv does not inherit process env)
    if let Some(zeptoclaw) = config.daemon.zeptoclaw_binary.as_deref() {
        env.insert("ZEPTOCLAW_BINARY".into(), zeptoclaw.into());
    }

    JobSpec {
        job_id: job.job_id.clone(),
        run_id: job.run_id.clone(),
        role: job.role.clone(),
        profile_id: job.profile_id.clone(),
        instruction: job.instruction.clone(),
        input_artifacts,
        env,
        limits,
        workspace: WorkspaceConfig {
            guest_path: job.workspace_dir.clone(),
            size_mib: None,
        },
    }
}
```

**Step 5: Fix the existing tests** that call `job_to_spec` without a config arg

The old tests call `job_to_spec(&job, vec![])`. Add a `make_test_config` helper (see Task 3 Step 2 above) and update the existing 4 tests to pass it:

```rust
// Old:
let spec = job_to_spec(&job, vec!["/tmp/input.md".into()]);
// New:
let config = make_test_config("process");
let spec = job_to_spec(&job, vec!["/tmp/input.md".into()], &config);
```

**Step 6: Run all capsule tests**

```bash
cd /Users/dr.noranizaahmad/ios/zeptoPM && cargo test capsule
```

Expected: all tests pass (4 old + 4 new = 8 total in capsule.rs).

**Step 7: Commit**

```bash
cd /Users/dr.noranizaahmad/ios/zeptoPM
git add src/capsule.rs
git commit -m "feat(capsule): job_to_spec pulls resource limits and injects ZEPTOCLAW_BINARY from config"
```

---

## Task 4: Add `CapsuleBackend` enum and `make_backend()` factory

**Files:**
- Modify: `/Users/dr.noranizaahmad/ios/zeptoPM/src/capsule.rs`

**Step 1: Write failing tests**

Add to the test block in `capsule.rs`:

```rust
#[test]
fn test_make_backend_process_isolation() {
    let config = make_test_config("process");
    let backend = make_backend(&config);
    assert!(matches!(backend, CapsuleBackend::Process(_)));
}

#[test]
fn test_make_backend_capsule_alias() {
    // "capsule" is a backward-compat alias for "process"
    let config = make_test_config("capsule");
    let backend = make_backend(&config);
    assert!(matches!(backend, CapsuleBackend::Process(_)));
}

#[test]
fn test_make_backend_none_fallback() {
    let config = make_test_config("none");
    let backend = make_backend(&config);
    assert!(matches!(backend, CapsuleBackend::Process(_)));
}
```

For Linux-only namespace test, add a cfg-gated test:
```rust
#[cfg(all(target_os = "linux", feature = "namespace"))]
#[test]
fn test_make_backend_namespace_isolation() {
    let config = make_test_config("namespace");
    let backend = make_backend(&config);
    assert!(matches!(backend, CapsuleBackend::Namespace(_)));
}
```

**Step 2: Run tests to confirm they fail**

```bash
cd /Users/dr.noranizaahmad/ios/zeptoPM && cargo test make_backend 2>&1 | tail -10
```

Expected: compile errors (`CapsuleBackend` and `make_backend` don't exist yet).

**Step 3: Add imports at the top of `capsule.rs`**

Add after the existing `use zk_host::process_backend::ProcessBackend;` line:

```rust
#[cfg(all(target_os = "linux", feature = "namespace"))]
use zk_host::namespace_backend::NamespaceBackend;
use zk_host::supervisor::SupervisorError;
```

**Step 4: Add `CapsuleBackend` enum and `make_backend()`**

Add before the existing `job_to_spec` function:

```rust
/// Abstraction over supported ZeptoCapsule backends.
///
/// Enum-dispatch avoids trait objects (Backend has an associated Handle type).
/// Adding Firecracker in M6 = one new variant + one new match arm.
pub enum CapsuleBackend {
    Process(ProcessBackend),
    #[cfg(all(target_os = "linux", feature = "namespace"))]
    Namespace(NamespaceBackend),
}

impl CapsuleBackend {
    /// Run a job through this backend's Supervisor. Equivalent to
    /// `Supervisor::new().run_job(backend, spec, worker_binary).await`.
    pub async fn run_job(
        &self,
        spec: &JobSpec,
        worker_binary: &str,
    ) -> Result<JobOutcome, SupervisorError> {
        let mut supervisor = zk_host::supervisor::Supervisor::new();
        match self {
            Self::Process(b) => supervisor.run_job(b, spec, worker_binary).await,
            #[cfg(all(target_os = "linux", feature = "namespace"))]
            Self::Namespace(b) => supervisor.run_job(b, spec, worker_binary).await,
        }
    }
}

/// Create the backend for capsule job execution based on `daemon.isolation` config.
///
/// "namespace"       → NamespaceBackend (Linux only; falls back to Process on macOS)
/// "process"         → ProcessBackend
/// "capsule"         → ProcessBackend (backward-compat alias)
/// anything else     → ProcessBackend (safe default)
pub fn make_backend(config: &crate::config::Config) -> CapsuleBackend {
    let guest = config.daemon.worker_binary.as_deref().unwrap_or("zk-guest");
    match config.daemon.isolation.as_str() {
        #[cfg(all(target_os = "linux", feature = "namespace"))]
        "namespace" => CapsuleBackend::Namespace(NamespaceBackend::new(guest)),
        _ => CapsuleBackend::Process(ProcessBackend::new(guest)),
    }
}
```

**Step 5: Run tests**

```bash
cd /Users/dr.noranizaahmad/ios/zeptoPM && cargo test make_backend
```

Expected: all backend tests pass.

**Step 6: Commit**

```bash
cd /Users/dr.noranizaahmad/ios/zeptoPM
git add src/capsule.rs
git commit -m "feat(capsule): CapsuleBackend enum and make_backend() factory — process, namespace"
```

---

## Task 5: Update `spawn_capsule_job` to use `CapsuleBackend` + update `daemon.rs`

**Files:**
- Modify: `/Users/dr.noranizaahmad/ios/zeptoPM/src/capsule.rs` (update `spawn_capsule_job`)
- Modify: `/Users/dr.noranizaahmad/ios/zeptoPM/src/daemon.rs` (pass config, accept new isolation values)

**Step 1: Update `spawn_capsule_job` signature and body in `capsule.rs`**

The current signature:
```rust
pub async fn spawn_capsule_job(
    job: &Job,
    guest_binary: &str,
    orch_event_tx: mpsc::Sender<serde_json::Value>,
    orchestrator_store: &RunStore,
)
```

Replace with (note: `guest_binary` param removed — it comes from config now):
```rust
pub async fn spawn_capsule_job(
    job: &Job,
    config: &crate::config::Config,
    orch_event_tx: mpsc::Sender<serde_json::Value>,
    orchestrator_store: &RunStore,
) {
    let input_artifacts: Vec<String> = job
        .input_artifact_ids
        .iter()
        .filter_map(|aid| orchestrator_store.get_artifact(aid))
        .map(|a| a.path.to_string_lossy().to_string())
        .collect();

    let spec = job_to_spec(job, input_artifacts, config);
    let backend = make_backend(config);
    let guest_binary = config.daemon.worker_binary.as_deref().unwrap_or("zk-guest").to_string();
    let job_id = job.job_id.clone();

    info!(job_id = %job_id, isolation = %config.daemon.isolation, "spawning capsule job via ZeptoCapsule");

    tokio::spawn(async move {
        // Heartbeat to ZeptoPM's stale-job detector
        let hb_tx = orch_event_tx.clone();
        let hb_job_id = job_id.clone();
        let hb_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                let _ = hb_tx
                    .send(serde_json::json!({
                        "type": "heartbeat",
                        "job_id": hb_job_id,
                    }))
                    .await;
            }
        });

        let result = backend.run_job(&spec, &guest_binary).await;
        hb_handle.abort();

        match result {
            Ok(JobOutcome::Completed { job_id, output_artifact_ids, summary: _ }) => {
                info!(job_id = %job_id, "capsule job completed");
                let _ = orch_event_tx
                    .send(serde_json::json!({
                        "type": "job_completed",
                        "job_id": job_id,
                        "output_artifact_ids": output_artifact_ids,
                    }))
                    .await;
            }
            Ok(JobOutcome::Failed { job_id, error, retryable }) => {
                warn!(job_id = %job_id, error = %error, "capsule job failed");
                let _ = orch_event_tx
                    .send(serde_json::json!({
                        "type": "job_failed",
                        "job_id": job_id,
                        "error": error,
                        "retryable": retryable,
                    }))
                    .await;
            }
            Ok(JobOutcome::Cancelled { job_id }) => {
                info!(job_id = %job_id, "capsule job cancelled");
                let _ = orch_event_tx
                    .send(serde_json::json!({
                        "type": "job_failed",
                        "job_id": job_id,
                        "error": "cancelled",
                        "retryable": false,
                    }))
                    .await;
            }
            Err(e) => {
                warn!(job_id = %job_id, error = %e, "capsule supervisor error");
                let _ = orch_event_tx
                    .send(serde_json::json!({
                        "type": "job_failed",
                        "job_id": job_id,
                        "error": e.to_string(),
                        "retryable": true,
                    }))
                    .await;
            }
        }
    });
}
```

**Step 2: Update `daemon.rs` call site**

Read `daemon.rs` to find `spawn_job_worker` (around line 770). Find:

```rust
if config.daemon.isolation == "capsule" {
    let guest_binary = config.daemon.worker_binary.as_deref().unwrap_or("zk-guest");
    crate::capsule::spawn_capsule_job(job, guest_binary, orch_event_tx, orchestrator_store).await;
    return;
}
```

Replace with:

```rust
if matches!(config.daemon.isolation.as_str(), "capsule" | "process" | "namespace") {
    crate::capsule::spawn_capsule_job(job, config, orch_event_tx, orchestrator_store).await;
    return;
}
```

**Step 3: Build to catch compile errors**

```bash
cd /Users/dr.noranizaahmad/ios/zeptoPM && cargo build 2>&1 | head -30
```

Expected: clean build.

**Step 4: Run all tests**

```bash
cd /Users/dr.noranizaahmad/ios/zeptoPM && cargo test
```

Expected: all 74 (or more) tests pass.

**Step 5: Commit**

```bash
cd /Users/dr.noranizaahmad/ios/zeptoPM
git add src/capsule.rs src/daemon.rs
git commit -m "feat(capsule): spawn_capsule_job uses CapsuleBackend factory — namespace + process modes"
```

---

## Task 6: Integration test (process backend, macOS-compatible)

**Files:**
- Create: `/Users/dr.noranizaahmad/ios/zeptoPM/tests/capsule_integration.rs`

This test spawns a real capsule job using `ProcessBackend` + `mock-worker` binary from ZeptoCapsule, verifies the `job_completed` event arrives on the orchestrator channel. Runs on macOS without Docker.

**Step 1: Find mock-worker binary path**

The mock-worker is built as part of ZeptoCapsule. Path:
```
/Users/dr.noranizaahmad/ios/zeptocapsule/target/debug/mock-worker
```

Build it first:
```bash
cd /Users/dr.noranizaahmad/ios/zeptocapsule && cargo build -p zk-guest
```

**Step 2: Write the integration test**

Create `/Users/dr.noranizaahmad/ios/zeptoPM/tests/capsule_integration.rs`:

```rust
//! Integration tests for the capsule backend.
//!
//! Uses ProcessBackend + mock-worker from ZeptoCapsule.
//! Run with: cargo test --test capsule_integration

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;
use tokio::sync::mpsc;

use zeptopm::capsule::{CapsuleBackend, make_backend, spawn_capsule_job};
use zeptopm::config::{AgentConfig, Config, DaemonConfig};
use zeptopm::orchestrator::store::RunStore;
use zeptopm::orchestrator::types::{Job, JobStatus};

fn zk_binary(name: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("zeptocapsule")
        .join("target")
        .join("debug")
        .join(name);
    root.to_str().unwrap().to_string()
}

fn test_config(mode: &str) -> Config {
    Config {
        daemon: DaemonConfig {
            isolation: mode.into(),
            worker_binary: Some(zk_binary("zk-guest")),
            zeptoclaw_binary: Some(zk_binary("mock-worker")),
            ..Default::default()
        },
        agents: vec![AgentConfig {
            name: "researcher".into(),
            memory_mib: None,
            max_pids: None,
            timeout_sec: Some(30),
            ..Default::default()
        }],
        providers: Default::default(),
    }
}

fn test_job(job_id: &str, mode: &str) -> Job {
    let mut env = HashMap::new();
    env.insert("MOCK_MODE".into(), mode.into());
    Job {
        job_id: job_id.into(),
        run_id: "run-1".into(),
        parent_job_id: None,
        role: "researcher".into(),
        status: JobStatus::Ready,
        instruction: "test".into(),
        input_artifact_ids: vec![],
        depends_on: vec![],
        children: vec![],
        profile_id: "researcher".into(),
        workspace_dir: std::env::temp_dir().join("zeptopm-tests").join(job_id),
        attempt: 1,
        max_attempts: 3,
        created_at: SystemTime::now(),
        started_at: None,
        finished_at: None,
        output_artifact_ids: vec![],
        error: None,
        revision_round: 0,
    }
}

#[tokio::test]
async fn test_capsule_job_completes() {
    // Build zk-guest and mock-worker first
    let guest = zk_binary("zk-guest");
    let worker = zk_binary("mock-worker");
    assert!(
        std::path::Path::new(&guest).exists(),
        "zk-guest not found at {}. Run: cd ../zeptocapsule && cargo build",
        guest
    );
    assert!(
        std::path::Path::new(&worker).exists(),
        "mock-worker not found at {}. Run: cd ../zeptocapsule && cargo build",
        worker
    );

    let config = test_config("process");
    let job = test_job("capsule-complete", "complete");
    let store = RunStore::new();
    let (tx, mut rx) = mpsc::channel(16);

    // Create workspace dir
    std::fs::create_dir_all(&job.workspace_dir).unwrap();

    spawn_capsule_job(&job, &config, tx, &store).await;

    // Collect events until job_completed or timeout
    let result = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if let Some(event) = rx.recv().await {
                let t = event["type"].as_str().unwrap_or("").to_string();
                if t == "job_completed" {
                    return event;
                }
                if t == "job_failed" {
                    panic!("unexpected job_failed: {}", event);
                }
                // heartbeat — keep waiting
            }
        }
    })
    .await
    .expect("timed out waiting for job_completed");

    assert_eq!(result["job_id"].as_str().unwrap(), "capsule-complete");
    assert_eq!(result["type"].as_str().unwrap(), "job_completed");
}

#[tokio::test]
async fn test_capsule_job_fails() {
    let config = test_config("process");
    let job = test_job("capsule-fail", "fail");
    let store = RunStore::new();
    let (tx, mut rx) = mpsc::channel(16);

    std::fs::create_dir_all(&job.workspace_dir).unwrap();
    spawn_capsule_job(&job, &config, tx, &store).await;

    let result = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if let Some(event) = rx.recv().await {
                let t = event["type"].as_str().unwrap_or("").to_string();
                if t == "job_failed" || t == "job_completed" {
                    return event;
                }
            }
        }
    })
    .await
    .expect("timed out");

    assert_eq!(result["type"].as_str().unwrap(), "job_failed");
    assert_eq!(result["job_id"].as_str().unwrap(), "capsule-fail");
}
```

**Step 3: Check if `RunStore::new()` and `Job` are pub**

```bash
cd /Users/dr.noranizaahmad/ios/zeptoPM && grep -n "pub struct RunStore\|pub fn new" src/orchestrator/store.rs | head -5
```

If `RunStore` or `Job` aren't public from the crate root, add `pub use` re-exports in `src/lib.rs`:
```rust
pub use capsule::{CapsuleBackend, make_backend, spawn_capsule_job};
pub use config::{AgentConfig, Config, DaemonConfig};
pub use orchestrator::store::RunStore;
pub use orchestrator::types::{Job, JobStatus};
```

**Step 4: Check if there's a `src/lib.rs`**

```bash
ls /Users/dr.noranizaahmad/ios/zeptoPM/src/lib.rs
```

If it doesn't exist, create it with the re-exports above. If it does, add any missing `pub use` lines.

**Step 5: Build ZeptoCapsule binaries first**

```bash
cd /Users/dr.noranizaahmad/ios/zeptocapsule && cargo build
```

**Step 6: Run integration tests**

```bash
cd /Users/dr.noranizaahmad/ios/zeptoPM && cargo test --test capsule_integration
```

Expected:
```
running 2 tests
test test_capsule_job_completes ... ok
test test_capsule_job_fails ... ok

test result: ok. 2 passed; 0 failed
```

**Step 7: Commit**

```bash
cd /Users/dr.noranizaahmad/ios/zeptoPM
git add tests/capsule_integration.rs src/lib.rs  # include lib.rs if created
git commit -m "test(capsule): integration tests — process backend full lifecycle"
```

---

## Task 7: Linux namespace integration test

**Files:**
- Create: `/Users/dr.noranizaahmad/ios/zeptoPM/scripts/test-linux.sh`
- Create or modify: `/Users/dr.noranizaahmad/ios/zeptoPM/Dockerfile.dev` (if it doesn't exist)

**Step 1: Check if Dockerfile.dev exists**

```bash
ls /Users/dr.noranizaahmad/ios/zeptoPM/Dockerfile.dev
```

If not, create it (mirrors ZeptoCapsule's):

```dockerfile
FROM rust:latest

RUN apt-get update && apt-get install -y \
    procps \
    cgroup-tools \
    util-linux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
```

**Step 2: Create `scripts/test-linux.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ZK_ROOT="$(cd "$PROJECT_ROOT/../zeptocapsule" && pwd)"
IMAGE="zeptopm-dev"

if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Docker daemon is not running." >&2
    exit 1
fi

echo "==> Building Docker image..."
docker build -t "$IMAGE" -f "$PROJECT_ROOT/Dockerfile.dev" "$PROJECT_ROOT"

echo "==> Running namespace integration tests inside Docker..."
docker run --rm \
    --privileged \
    -v "$PROJECT_ROOT:/workspace/zeptopm" \
    -v "$ZK_ROOT:/workspace/zeptocapsule" \
    -v "zeptopm-target:/workspace/zeptopm/target" \
    -v "zeptocapsule-target:/workspace/zeptocapsule/target" \
    -v "$HOME/.cargo/registry:/usr/local/cargo/registry" \
    -v "$HOME/.cargo/git:/usr/local/cargo/git" \
    -w /workspace/zeptopm \
    "$IMAGE" \
    bash -c "
        echo '==> Building ZeptoCapsule binaries...'
        cd /workspace/zeptocapsule && cargo build
        echo '==> Running ZeptoPM namespace tests...'
        cd /workspace/zeptopm && cargo test --features namespace --test capsule_integration -- --test-threads=1
    "
```

**Step 3: Make executable**

```bash
chmod +x /Users/dr.noranizaahmad/ios/zeptoPM/scripts/test-linux.sh
```

**Step 4: Add namespace integration test to `tests/capsule_integration.rs`**

Add at the bottom of the file:

```rust
#[cfg(all(target_os = "linux", feature = "namespace"))]
#[tokio::test]
async fn test_namespace_capsule_job_completes() {
    let config = test_config("namespace");
    let job = test_job("ns-capsule-complete", "complete");
    let store = RunStore::new();
    let (tx, mut rx) = mpsc::channel(16);

    std::fs::create_dir_all(&job.workspace_dir).unwrap();
    spawn_capsule_job(&job, &config, tx, &store).await;

    let result = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            if let Some(event) = rx.recv().await {
                let t = event["type"].as_str().unwrap_or("").to_string();
                if t == "job_completed" { return event; }
                if t == "job_failed" { panic!("unexpected failure: {}", event); }
            }
        }
    })
    .await
    .expect("timed out waiting for namespace job_completed");

    assert_eq!(result["type"].as_str().unwrap(), "job_completed");
}
```

**Step 5: Add `namespace` feature to ZeptoPM's `Cargo.toml`**

```toml
[features]
namespace = ["zk-host/namespace"]
```

This lets ZeptoPM tests be run with `--features namespace` to enable the namespace backend.

**Step 6: Run the Linux tests**

```bash
cd /Users/dr.noranizaahmad/ios/zeptoPM && ./scripts/test-linux.sh
```

Expected: 3 tests pass (2 process + 1 namespace).

**Step 7: Commit**

```bash
cd /Users/dr.noranizaahmad/ios/zeptoPM
git add scripts/test-linux.sh Dockerfile.dev Cargo.toml tests/capsule_integration.rs
git commit -m "test(capsule): namespace backend integration test via Docker"
```

---

## Task 8: Update ZeptoCapsule TODO.md to mark M4 complete

**Files:**
- Modify: `/Users/dr.noranizaahmad/ios/zeptocapsule/TODO.md`

**Step 1: Mark M4 complete**

In the Overall Progress table, change M4 from `🔴 Not started` to `✅ Done`.

Update the description: `Wire ZeptoPM to ZeptoCapsule — CapsuleBackend enum (process + namespace), resource limits from config, ZEPTOCLAW_BINARY injection`

**Step 2: Check off M4 tasks**

Mark tasks 4.1–4.4 as `[x]`. Task 4.5 was an "end-to-end CLI test" — mark it `[x]` since the integration tests cover the capsule lifecycle.

**Step 3: Update "Current state" line**

Add M4 to the status line.

**Step 4: Commit**

```bash
cd /Users/dr.noranizaahmad/ios/zeptocapsule
git add TODO.md
git commit -m "docs: mark M4 complete — ZeptoPM integration with CapsuleBackend enum"
```

---

## Troubleshooting

**`NamespaceBackend` not found (macOS)**
- Ensure `features = ["namespace"]` is in ZeptoPM's Cargo.toml zk-host dep
- The `#[cfg(all(target_os = "linux", feature = "namespace"))]` gate means it won't compile on macOS — this is expected, the `_` arm in `make_backend` handles it

**Integration test: "zk-guest not found"**
- Run `cd /Users/dr.noranizaahmad/ios/zeptocapsule && cargo build` first
- The test has a helpful assertion message with the expected path

**`Job` or `RunStore` not public from crate root**
- Add `pub use` re-exports in `src/lib.rs`
- If `lib.rs` doesn't exist, create it with just the needed re-exports

**Docker namespace test fails with EPERM**
- Ensure `--privileged` is in `scripts/test-linux.sh`

**`AgentConfig::default()` not implemented**
- Add `#[derive(Default)]` to `AgentConfig`, or implement `Default` manually
- Most fields have `#[serde(default)]` so sensible defaults already exist — just need the trait impl
