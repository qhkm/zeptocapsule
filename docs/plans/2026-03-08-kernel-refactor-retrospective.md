# ZeptoCapsule Refactor: Retrospective and Motivation

**Date:** 2026-03-08
**Status:** Complete
**Scope:** Collapse 3-crate workspace into single `zeptocapsule` crate; strip orchestration logic from the kernel; wire ZeptoPM to own job lifecycle over raw stdio.

---

## Why We Refactored

### The Original Shape

ZeptoCapsule started life as a **mini-orchestrator** embedded in the sandbox layer:

```
zk-proto   — shared types: JobSpec, ArtifactRef, HostCommand, GuestEvent
zk-host    — Supervisor, Backend trait, ProcessBackend, NamespaceBackend
             runs jobs, tracks heartbeats, synthesizes JobOutcome
zk-guest   — worker entry point, reads HostCommand, emits GuestEvent
```

`Supervisor::run_job()` accepted a `JobSpec` (with `job_id`, `instruction`, `input_artifacts`, `env`, `limits`, `workspace`) and returned `JobOutcome::Completed | Failed | Cancelled`. ZeptoPM called `Supervisor::run_job()` and received structured results.

This felt ergonomic until we started wiring ZeptoPM M4.

### The Problems We Hit

**1. Duplicated protocol ownership**

`zk-proto` defined `JobSpec`, `ArtifactRef`, `HostCommand`, and `GuestEvent`. ZeptoPM also had its own `Job` struct and orchestrator event types. Translating between them (`job_to_spec()`) was pure friction — two representations of the same information with no single owner.

**2. Backend trait was not object-safe**

`Backend` had an associated `Handle` type. It could not be boxed as `Box<dyn Backend>`. We worked around this with a `CapsuleBackend` enum (enum-dispatch) in ZeptoPM, which was functional but meant ZeptoPM carried boilerplate that existed only because of a trait design limitation in ZeptoCapsule.

**3. Heartbeat logic in the wrong layer**

`Supervisor` tracked heartbeat timeouts and synthesized `JobOutcome::Failed { retryable: true }` on timeout. But "retryable" is a policy decision — it belongs in ZeptoPM's orchestrator, which knows retry budgets, backoff, and run state. The kernel was making policy calls it had no business making.

**4. Namespace feature flag leaked into ZeptoPM**

`NamespaceBackend` being in `zk-host` forced a `[features] namespace = ["zk-host/namespace"]` section in ZeptoPM's `Cargo.toml`. ZeptoPM had to know about kernel compilation flags to choose a backend at runtime. Backend selection is a ZeptoPM concern; the kernel should expose a uniform API.

**5. Three-crate workspace overhead**

For a library with one user (ZeptoPM), the `zk-proto / zk-host / zk-guest` split added cross-crate dependency management, feature flag propagation, and `cargo check` complexity with no benefit. The crates were never going to have separate versioning or independent consumers.

---

## What Changed

### The New Shape

```
zeptocapsule (single crate)
  src/lib.rs        — public API: create(), Capsule, CapsuleSpec, ResourceLimits, ...
  src/types.rs      — CapsuleSpec, ResourceLimits, WorkspaceConfig, Isolation, CapsuleReport
  src/backend.rs    — Backend + CapsuleHandle traits (internal, object-safe)
  src/process.rs    — ProcessBackend (dev / macOS)
  src/namespace.rs  — NamespaceBackend (Linux, cfg-gated)
  src/cgroup.rs     — cgroup v2 enforcement (Linux, cfg-gated)
  src/init_shim.rs  — minimal init shim helpers
  src/bin/zk-init.rs — init binary for namespace boot
```

**Public API surface:**

```rust
// Create a capsule
let mut capsule = zeptocapsule::create(CapsuleSpec {
    isolation: Isolation::Process,        // or Isolation::Namespace
    limits: ResourceLimits { timeout_sec: 300, memory_mib: Some(512), .. },
    workspace: WorkspaceConfig { guest_path: "/workspace".into(), .. },
    ..Default::default()
})?;

// Spawn the worker binary — get raw stdin/stdout
let child = capsule.spawn("/path/to/zeptoclaw", &[], env)?;
// child.stdin, child.stdout — ZeptoPM owns the protocol from here

// Tear down
let report = capsule.destroy()?;
// report.killed_by, report.exit_code, report.wall_time
```

ZeptoCapsule has **no concept of jobs, instructions, artifacts, heartbeats, or outcomes**. It creates a sandbox, runs a binary, enforces limits, and returns a report.

### ZeptoPM After the Refactor

ZeptoPM gained back the responsibilities that were incorrectly delegated:

| Responsibility | Before | After |
|----------------|--------|-------|
| Job → kernel spec translation | `job_to_spec() -> JobSpec` (zk-proto types) | `capsule_spec_from_config() -> CapsuleSpec` |
| Backend selection | `CapsuleBackend` enum + `make_backend()` in ZeptoPM | `Isolation` enum value inside `CapsuleSpec` — kernel dispatches internally |
| Worker env building | Mixed into `job_to_spec()` | `build_worker_env()` — clear single-purpose function |
| Protocol handling | `Supervisor` read `GuestEvent` JSON lines | ZeptoPM reads JSON lines from `child.stdout` directly |
| Heartbeat policy | `Supervisor` synthesized timeout failures | ZeptoPM engine: `detect_stale_jobs()` with configurable threshold |
| Retry policy | `JobOutcome::Failed { retryable }` from kernel | ZeptoPM engine: retry logic with `max_attempts`, backoff |

---

## The Design Principle (Restated)

> **ZeptoCapsule owns mechanisms. ZeptoPM owns meaning.**

| Question | Owner |
|----------|-------|
| Is the process isolated? | ZeptoCapsule |
| Did the process exceed memory? | ZeptoCapsule |
| Did the job time out? | ZeptoCapsule (wall-clock kill) |
| Should we retry the job? | ZeptoPM |
| Did the worker complete the task? | ZeptoPM |
| What artifacts did the worker produce? | ZeptoPM |
| Is the agent healthy? | ZeptoPM |

---

## What We Gained

- **Single dependency**: ZeptoPM imports `zeptocapsule`, nothing else from the kernel.
- **Object-safe backend dispatch**: `Box<dyn CapsuleHandle>` inside the kernel; ZeptoPM never sees Backend trait complexity.
- **Isolation is an enum value**: `CapsuleSpec { isolation: Isolation::Namespace, .. }` — ZeptoPM sets the value, kernel dispatches. No cfg-gated enums in ZeptoPM.
- **Protocol ownership is clear**: ZeptoPM writes to `child.stdin` and reads from `child.stdout`. The kernel is transparent.
- **Stub crate for macOS dev**: `zeptocapsule-stub` mirrors the real API with `ProcessBackend` only; `Isolation::Namespace` returns `KernelError::NotSupported`. ZeptoPM's development loop doesn't require Linux.

---

## What We Did Not Change

- ZeptoPM orchestrator engine, scheduler, store, planner — unchanged.
- ZeptoClaw worker protocol — unchanged (JSON lines over stdin/stdout).
- Resource limits config fields in `[[agents]]` — unchanged (`memory_mib`, `max_pids`, `timeout_sec`).
- Integration test strategy — macOS tests use `ProcessBackend`; Linux namespace tests gated behind Docker + `#[cfg(target_os = "linux")]`.

---

## Commits

The refactor landed across two repos:

- `zeptocapsule`: single-crate collapse (kernel-redesign branch, merged to main)
- `zeptoPM`: `src/capsule.rs` rewritten to use new API; `Cargo.toml` drops `zk-host`/`zk-proto`; all 95 tests passing
