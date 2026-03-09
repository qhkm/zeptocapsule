# ZeptoCapsule Redesign: Thin Sandbox Layer

> **For Codex / agents:** This is the authoritative design for the ZeptoCapsule redesign.
> The implementation plan follows this document. Read it fully before starting work.

**Goal:** Redesign ZeptoCapsule from a mini-orchestrator into a thin sandbox library.
ZeptoCapsule owns mechanisms (isolation, resource enforcement). ZeptoPM owns meaning
(job lifecycle, supervision, event interpretation).

**Status of current codebase:** 3-crate workspace (zk-proto, zk-host, zk-guest) with
supervisor lifecycle logic, HostCommand/GuestEvent protocol, heartbeat tracking, and
terminal event synthesis. All of that orchestration logic moves to ZeptoPM.

---

## Design Principle

> **ZeptoCapsule owns mechanisms. ZeptoPM owns meaning.**

If something exists because the worker is inside an isolated capsule, ZeptoCapsule handles it.
If something exists because you are managing a job, workflow, or agent lifecycle, ZeptoPM handles it.

---

## The Three Layers

| Layer | Role | Analogy |
|-------|------|---------|
| **ZeptoPM** | Orchestrator: job graph, spawning, retries, supervision, artifact aggregation, scheduling, policy, backend selection | Team manager |
| **ZeptoCapsule** | Isolated execution capsule: sandbox, boot, workspace, launch worker, enforce limits, shutdown | Secure room |
| **ZeptoClaw** | Worker runtime: reasoning, tool usage, model calls, outputs, artifacts, structured events | Employee |

---

## What ZeptoCapsule Owns

- Capsule creation and destruction
- Namespace / microVM boot
- Mounts and workspace wiring
- cgroup limits: memory, CPU, PIDs
- Hard wall-clock kill enforced at the capsule boundary
- Signal delivery and force-kill
- PID 1 duties when needed: zombie reaping, signal forwarding, clean shutdown
- Raw stdio / socket transport to the worker

## What ZeptoCapsule Does NOT Own

- Heartbeat semantics
- "Job started/completed/failed" interpretation
- Retries and supervision policy
- Stale detection based on app-level liveness
- Artifact / business event aggregation
- Cancellation policy beyond "kill this process/capsule now"
- Wire protocol between orchestrator and worker (that's ZeptoPM <-> ZeptoClaw)

---

## New API Surface

### Public Types

```rust
/// Specification for creating a capsule.
pub struct CapsuleSpec {
    pub isolation: Isolation,
    pub workspace: WorkspaceConfig,
    pub limits: ResourceLimits,
}

pub enum Isolation {
    Process,    // Child process, no isolation (dev/macOS)
    Namespace,  // Linux namespaces + cgroups
    Firecracker, // microVM (future)
}

pub struct ResourceLimits {
    pub timeout_sec: u64,         // Wall-clock hard kill (default 300)
    pub memory_mib: Option<u64>,  // cgroup memory limit
    pub cpu_quota: Option<f64>,   // CPU fraction (1.0 = 1 core)
    pub max_pids: Option<u32>,    // cgroup PID limit
}

pub struct WorkspaceConfig {
    pub guest_path: PathBuf,      // Mount point (/workspace)
    pub size_mib: Option<u64>,    // tmpfs size limit
}

/// Why the capsule killed the process.
pub enum ResourceViolation {
    WallClock,   // timeout_sec exceeded
    Memory,      // cgroup OOM
    MaxPids,     // cgroup PID limit
}
```

### Public Methods

```rust
/// Create an isolated capsule environment.
pub fn create(spec: CapsuleSpec) -> Result<Capsule, KernelError>;

impl Capsule {
    /// Spawn a process inside the capsule.
    /// Returns raw pipes — caller (ZeptoPM) owns all communication.
    pub fn spawn(
        &mut self,
        binary: &str,
        args: &[&str],
        env: HashMap<String, String>,
    ) -> Result<CapsuleChild, KernelError>;

    /// Send a signal to the capsule process.
    pub fn kill(&mut self, signal: Signal) -> Result<(), KernelError>;

    /// Tear down the capsule and clean up resources.
    pub fn destroy(self) -> Result<(), KernelError>;
}

/// Handle to the spawned process inside the capsule.
pub struct CapsuleChild {
    pub stdin: ChildStdin,    // AsyncWrite — ZeptoPM writes job commands
    pub stdout: ChildStdout,  // AsyncRead — ZeptoPM reads worker events
    pub pid: u32,             // Process ID (for signal delivery)
}
```

### Usage Pattern (from ZeptoPM's perspective)

```rust
// 1. Create sandbox
let capsule = zeptocapsule::create(CapsuleSpec {
    isolation: Isolation::Process,
    workspace: WorkspaceConfig { guest_path: "/workspace".into(), size_mib: Some(512) },
    limits: ResourceLimits { timeout_sec: 300, memory_mib: Some(1024), ..default() },
})?;

// 2. Spawn worker inside sandbox
let child = capsule.spawn("/usr/local/bin/zeptoclaw", &["--job-spec", "/tmp/spec.json"], env)?;

// 3. ZeptoPM talks directly to ZeptoClaw through pipes
//    (same JSON-line IPC protocol it already uses for isolation="none" mode)
send_job_command(&child.stdin, &job).await;
loop {
    let event = read_worker_event(&child.stdout).await;
    match event {
        WorkerEvent::Completed { .. } => { orch_tx.send(job_completed); break; }
        WorkerEvent::Failed { .. } => { orch_tx.send(job_failed); break; }
        WorkerEvent::Heartbeat { .. } => { engine.record_heartbeat(job_id); }
        WorkerEvent::Artifact { .. } => { store_artifact(..); }
    }
}

// 4. Cleanup
capsule.destroy()?;

// Resource violations (OOM, timeout) surface as process death.
// ZeptoPM detects via pipe EOF + exit code, same as any crashed worker.
```

---

## Crate Structure

**Before (3 crates):**
```
crates/
  zk-proto/    — Wire protocol types (HostCommand, GuestEvent, JobSpec)
  zk-host/     — Supervisor, Backend trait, capsule state machine
  zk-guest/    — Full guest agent (worker launch, event forwarding, heartbeats)
```

**After (1 crate + 1 binary):**
```
src/
  lib.rs           — Public API: create(), CapsuleSpec, ResourceLimits
  types.rs         — CapsuleSpec, ResourceLimits, WorkspaceConfig, ResourceViolation
  backend.rs       — Backend trait, CapsuleHandle trait
  process.rs       — ProcessBackend (child process, no isolation, macOS/Linux)
  namespace.rs     — NamespaceBackend (Linux namespaces + cgroups)
  cgroup.rs        — cgroup v2 enforcement (memory, CPU, PIDs)
  init_shim.rs     — Minimal PID 1 logic (shared code for zk-init binary)

bin/
  zk-init.rs       — Init shim binary for namespace/microVM backends
```

### What Gets Removed

| Current Code | Disposition |
|-------------|-------------|
| `zk-proto` crate | **Delete.** Protocol types belong to ZeptoPM <-> ZeptoClaw. |
| `zk-host/supervisor.rs` | **Delete.** Lifecycle management moves to ZeptoPM. |
| `zk-host/capsule.rs` (state machine) | **Delete.** CapsuleState enum is orchestration logic. |
| `zk-guest/agent.rs` (run_agent) | **Delete.** Event multiplexing, worker management, heartbeats — all orchestration. |
| `zk-guest/worker.rs` (WorkerHandle) | **Delete.** ZeptoPM spawns ZeptoClaw directly through capsule pipes. |
| `HostCommand` / `GuestEvent` enums | **Delete.** No kernel-level protocol. |
| `JobSpec` / `JobOutcome` | **Delete.** ZeptoPM defines its own. |

### What Gets Kept (refactored)

| Current Code | After |
|-------------|-------|
| `zk-host/process_backend.rs` | `process.rs` — simplified, returns pipes instead of protocol handle |
| `zk-host/namespace_backend.rs` | `namespace.rs` — same isolation logic, thinner interface |
| `zk-host/cgroup.rs` | `cgroup.rs` — unchanged, pure mechanism |
| `zk-proto/ResourceLimits` | `types.rs` — kept, slightly simplified |
| `zk-proto/WorkspaceConfig` | `types.rs` — kept as-is |
| `zk-guest` (PID 1 logic only) | `init_shim.rs` + `bin/zk-init.rs` — zombie reaping, signal forwarding, exec worker |

---

## zk-init: Minimal Init Shim

Only used for namespace and microVM backends. Not needed for ProcessBackend.

**Responsibilities (and nothing else):**
- Mount `/proc` (namespace mode)
- Set up workspace mount (tmpfs)
- Forward signals to child process (SIGTERM, SIGKILL)
- Reap zombie processes (PID 1 duty)
- Exec the worker binary

**Not responsible for:**
- Protocol handling
- Event forwarding or synthesis
- Heartbeat generation
- Worker lifecycle decisions

**Invocation:**
```
zk-init <worker-binary> [worker-args...]
```

zk-init execs the worker binary after setup. Worker stdin/stdout connect directly
to the pipes ZeptoPM holds. zk-init gets out of the way.

---

## ZeptoPM Integration Changes

### capsule.rs Rewrite

Current `capsule.rs` in ZeptoPM is a translation layer: Job -> JobSpec, JobOutcome -> events,
plus a heartbeat hack. After the redesign, it becomes a thin capsule consumer:

```rust
// capsule.rs — ZeptoPM side
pub async fn run_job_in_capsule(
    job: &Job,
    config: &Config,
    orch_tx: Sender<OrchEvent>,
) -> Result<(), Error> {
    // 1. Create capsule from config
    let capsule = zeptocapsule::create(capsule_spec_from_config(config))?;

    // 2. Spawn ZeptoClaw inside capsule
    let child = capsule.spawn(
        &config.daemon.zeptoclaw_binary,
        &["--job-spec", &spec_path],
        build_env(job, config),
    )?;

    // 3. Drive IPC — same event loop as isolation="none" mode
    //    (reuse existing logic from agent.rs)
    drive_worker_events(child.stdin, child.stdout, job, orch_tx).await;

    // 4. Cleanup
    capsule.destroy()?;
    Ok(())
}
```

**Key insight:** ZeptoPM already has the worker IPC logic for `isolation = "none"` mode.
Capsule mode just wraps it in a sandbox. No new event handling needed.

### Cargo.toml Change

```toml
# Before
zk-host = { path = "../zeptocapsule/crates/zk-host" }
zk-proto = { path = "../zeptocapsule/crates/zk-proto" }

# After
zeptocapsule = { path = "../zeptocapsule" }
```

### What Stays the Same in ZeptoPM

- `daemon.rs` orchestration loop — unchanged
- `agent.rs` worker IPC protocol — unchanged (ZeptoClaw speaks same protocol)
- `worker.rs` — unchanged
- `orchestrator/` — unchanged (engine, scheduler, store, review, planner)
- All 81 existing tests — unchanged (they don't test capsule mode)

---

## Resource Violation Handling

ZeptoCapsule kills the process. ZeptoPM detects it the same way it detects any worker crash:

1. **OOM kill** — cgroup kills process, stdout pipe gets EOF, ZeptoPM sees unexpected exit
2. **Wall-clock timeout** — ZeptoCapsule sends SIGKILL after timeout, same result
3. **Max PIDs** — cgroup rejects fork, worker likely crashes, same result

ZeptoPM doesn't need a special `ResourceViolation` callback. It reads the exit code
and pipe state, same as `isolation = "none"` mode. The capsule just adds the enforcement
that prevents a runaway worker from affecting the host.

For optional observability, `capsule.destroy()` can return a `CapsuleReport`:

```rust
pub struct CapsuleReport {
    pub exit_code: Option<i32>,
    pub killed_by: Option<ResourceViolation>,  // Why ZeptoCapsule killed it
    pub wall_time: Duration,
    pub peak_memory_mib: Option<u64>,          // From cgroup stats
}
```

This lets ZeptoPM log "worker killed by OOM (peak 1024 MiB)" vs "worker crashed (exit 1)"
for better diagnostics, but it's optional — the worker is dead either way.

---

## Testing Strategy

### ZeptoCapsule Tests

| Test | Backend | What It Verifies |
|------|---------|-----------------|
| Create + spawn + read stdout | Process | Basic lifecycle works |
| Kill signal delivery | Process | SIGTERM reaches child |
| Wall-clock timeout kill | Process | Process killed after N seconds |
| Destroy cleans up | Process | No zombie processes, temp files cleaned |
| Namespace isolation | Namespace | PID/mount/network isolated (Linux-only) |
| cgroup memory limit | Namespace | OOM kill on memory violation (Linux-only) |
| cgroup PID limit | Namespace | Fork rejected (Linux-only) |
| zk-init signal forwarding | Namespace | SIGTERM forwarded to worker (Linux-only) |
| zk-init zombie reaping | Namespace | No zombies accumulate (Linux-only) |

**No job/event/heartbeat/protocol tests.** Those aren't ZeptoCapsule's concern.

### ZeptoPM Tests

- `capsule_spec_from_config()` unit tests (replaces current broken `job_to_spec` tests)
- Existing 81 tests pass unchanged
- E2E: deferred until ZeptoClaw has full capabilities

---

## Migration Plan

### Phase 1: Redesign ZeptoCapsule

In `~/ios/zeptocapsule/`:

1. Create new single-crate structure alongside existing crates
2. Implement `types.rs`: CapsuleSpec, ResourceLimits, WorkspaceConfig, ResourceViolation
3. Implement `backend.rs`: Backend + CapsuleHandle traits (simplified)
4. Implement `process.rs`: ProcessBackend returning raw pipes
5. Port `namespace.rs` and `cgroup.rs` from existing code
6. Build `zk-init` binary (minimal init shim)
7. Write tests for new API
8. Remove old 3-crate structure
9. Update Cargo.toml workspace

### Phase 2: Rewire ZeptoPM

In `~/ios/zeptoPM/`:

1. Update Cargo.toml: `zeptocapsule = { path = "..." }`
2. Rewrite `capsule.rs` to use new thin API
3. Remove heartbeat hack and event translation
4. Fix capsule.rs tests for new API
5. Verify all 81 tests still pass

### Phase 3: E2E Validation

1. Build ZeptoClaw worker binary
2. ZeptoPM submits job with `isolation = "process"`
3. ZeptoClaw executes inside capsule, events flow through pipes
4. Verify resource violations surface correctly
5. Verify clean shutdown and cleanup

---

## Decision Log

| Decision | Chosen | Rationale |
|----------|--------|-----------|
| Single crate vs 3 crates | Single | Simpler dependency, less indirection |
| zk-guest as init shim vs remove entirely | Init shim for namespace/microVM | PID 1 has real OS duties (zombie reaping, signal forwarding) |
| Protocol in kernel vs PM | ZeptoPM <-> ZeptoClaw only | Kernel shouldn't interpret bytes on the pipe |
| ResourceViolation callback vs exit code | Exit code + optional CapsuleReport | Keeps ZeptoPM's error handling uniform across isolation modes |
| Supervisor in kernel vs PM | ZeptoPM only | Avoids duplication; PM already has supervision logic |
