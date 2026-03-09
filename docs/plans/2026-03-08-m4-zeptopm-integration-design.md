# M4: ZeptoPM Integration Design

**Date:** 2026-03-08
**Status:** Approved
**Scope:** Wire ZeptoPM to ZeptoCapsule with an abstracted backend factory supporting process, namespace, and (stub) Firecracker backends.

---

## Goal

ZeptoPM already has a working `capsule.rs` integration using `ProcessBackend`. M4 adds:

1. A `CapsuleBackend` enum (enum-dispatch pattern) that centralises backend selection
2. `NamespaceBackend` as a first-class option (`isolation = "namespace"`)
3. Resource limits from agent config flowing into `JobSpec`
4. `ZEPTOCLAW_BINARY` injected via `spec.env` so the guest can find the worker inside a namespace
5. Tests at unit and integration level

---

## Backend Abstraction

### Why enum-dispatch

The ZeptoCapsule `Backend` trait has an associated `Handle` type and async methods — neither is object-safe. Alternatives:

| Approach | Trade-off |
|----------|-----------|
| `CapsuleBackend` enum | Idiomatic Rust, zero overhead, add variants for new backends — **chosen** |
| `DynBackend` in zk-host | Cleaner for third-party backends, but requires trait object redesign in ZeptoCapsule |
| Generics-only at call site | No shared type, match scattered across call sites |

### Implementation

All changes are in **ZeptoPM** (`/Users/dr.noranizaahmad/ios/zeptoPM/`). ZeptoCapsule's API is consumed as-is.

```rust
// src/capsule.rs

pub enum CapsuleBackend {
    Process(ProcessBackend),
    #[cfg(all(target_os = "linux", feature = "namespace"))]
    Namespace(NamespaceBackend),
    // Firecracker(FirecrackerBackend),  // M6
}

impl CapsuleBackend {
    async fn run_job(
        &self,
        spec: &JobSpec,
        worker_binary: &str,
    ) -> Result<JobOutcome, SupervisorError> {
        let mut supervisor = Supervisor::new();
        match self {
            Self::Process(b) => supervisor.run_job(b, spec, worker_binary).await,
            #[cfg(all(target_os = "linux", feature = "namespace"))]
            Self::Namespace(b) => supervisor.run_job(b, spec, worker_binary).await,
        }
    }
}

pub fn make_backend(config: &Config) -> CapsuleBackend {
    let guest = config.daemon.worker_binary.as_deref().unwrap_or("zk-guest");
    match config.daemon.isolation.as_str() {
        #[cfg(all(target_os = "linux", feature = "namespace"))]
        "namespace" => CapsuleBackend::Namespace(NamespaceBackend::new(guest)),
        _ => CapsuleBackend::Process(ProcessBackend::new(guest)),
    }
}
```

`spawn_capsule_job` calls `make_backend()` then `backend.run_job()`. Adding Firecracker in M6 = one new variant + one new match arm.

---

## Config Changes

### New fields in `[daemon]`

```toml
[daemon]
isolation = "namespace"          # "process" (default) | "namespace"
worker_binary = "/path/to/zk-guest"
zeptoclaw_binary = "/path/to/zeptoclaw-worker"   # NEW: injected as ZEPTOCLAW_BINARY in spec.env
```

### New fields in `[[agents]]`

```toml
[[agents]]
name = "researcher"
# ... existing fields ...
memory_mib = 512        # NEW: maps to ResourceLimits.memory_mib
max_pids = 64           # NEW: maps to ResourceLimits.max_pids
timeout_sec = 300       # NEW: maps to ResourceLimits.timeout_sec (overrides default 300)
```

### Validation

- `isolation = "namespace"` on non-Linux: runtime warning, falls back to `"process"`
- `isolation = "namespace"` without `namespace` Cargo feature: compile-time fallback to `"process"`
- `isolation = "namespace"` without `worker_binary`: error (same as current `"capsule"` validation)

---

## `job_to_spec` Improvements

```rust
pub fn job_to_spec(job: &Job, input_artifact_paths: Vec<String>, config: &Config) -> JobSpec {
    // Find the agent profile matching this job
    let agent = config.agents.iter().find(|a| a.name == job.profile_id);

    // Resource limits from agent profile (fall back to defaults)
    let limits = ResourceLimits {
        memory_mib: agent.and_then(|a| a.memory_mib),
        max_pids: agent.and_then(|a| a.max_pids),
        timeout_sec: agent.and_then(|a| a.timeout_sec).unwrap_or(300),
        heartbeat_timeout_sec: 60,
        cpu_quota: None,
        network: false,
    };

    // Env: API keys + HOME/PATH + ZEPTOCLAW_BINARY
    let mut env: HashMap<String, String> = std::env::vars()
        .filter(|(k, _)| {
            k.starts_with("OPENROUTER_") || k.starts_with("OPENAI_")
                || k.starts_with("ANTHROPIC_") || k == "HOME" || k == "PATH"
        })
        .collect();

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

---

## Testing

### Unit tests (ZeptoPM — `src/capsule.rs`)

| Test | Verifies |
|------|----------|
| `test_make_backend_process` | `isolation = "process"` → `CapsuleBackend::Process` |
| `test_make_backend_namespace` | `isolation = "namespace"` → `CapsuleBackend::Namespace` (Linux only) |
| `test_job_to_spec_with_limits` | memory_mib/timeout_sec/max_pids flow from agent config |
| `test_job_to_spec_injects_zeptoclaw_binary` | `ZEPTOCLAW_BINARY` in `spec.env` |
| `test_job_to_spec_no_zeptoclaw_binary` | Missing config → key absent from env (no panic) |

### Integration test (ZeptoPM — `tests/capsule_integration.rs`)

Uses `ProcessBackend` + `mock-worker` (same pattern as ZeptoCapsule's `process_backend.rs`). Spawns a real capsule job end-to-end, verifies `job_completed` event arrives on the orchestrator channel. Runs on macOS without Docker.

### Namespace integration test (ZeptoPM — Linux only)

`#[cfg(all(target_os = "linux", feature = "namespace"))]` gated test. Runs via `scripts/test-zeptopm-linux.sh` (mirrors ZeptoCapsule's Docker script with `--privileged`).

---

## What Does NOT Change

- `zk-proto` — no protocol changes
- `zk-host` — no changes to Backend/CapsuleHandle traits or implementations
- `zk-guest` — no changes (agent already reads `ZEPTOCLAW_BINARY` from `spec.env` after M3 fix)
- ZeptoPM's orchestrator engine, scheduler, store — unchanged
- ZeptoPM's existing `isolation = "capsule"` config — remapped to `"process"` internally (or kept as alias for backward compatibility)

---

## Deferred

- Firecracker backend variant (M6)
- Per-job network flag (`ResourceLimits.network = true` for outbound HTTP workers, M5)
- Artifact retrieval from namespace workspace (host can read the tmpfs source dir directly — no special handling needed)
- `pivot_root` to minimal readonly rootfs (post-M3 namespace hardening)
