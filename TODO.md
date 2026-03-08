# ZeptoKernel — TODO & Roadmap

> **For agents:** Read this file first when picking up work. Check off items as you complete them. Run `cargo test --workspace` after every change — all tests must pass before committing.

## Quick Context

**What is this?** Secure per-worker execution capsule for the Zepto AI agent stack.

**Stack:** ZeptoPM (orchestrator) → ZeptoKernel (isolation) → ZeptoClaw (worker binary)

**Repo:** `/Users/dr.noranizaahmad/ios/zeptokernel/`

**Design spec:** `docs/plans/2026-03-08-zeptokernel-design.md`

**Current state:** M1 complete, M2 complete, M2.5 complete, M3 complete (namespace isolation, Docker test env). 25 tests passing (9 proto + 11 process_backend + 5 namespace + 1 cgroup unit).

**Crates:**
| Crate | Path | Purpose |
|-------|------|---------|
| `zk-proto` | `crates/zk-proto/` | Shared protocol: HostCommand, GuestEvent, JobSpec, wire format |
| `zk-host` | `crates/zk-host/` | Host supervisor: spawn capsules, monitor heartbeats, enforce limits |
| `zk-guest` | `crates/zk-guest/` | Guest agent: runs inside capsule, launches worker, forwards events |

**Commits so far:**
```
26ae83a test(host): namespace backend integration tests (Linux-only)
d3aad38 feat(host): implement do_clone — child setup, UID maps, cgroup, pipe IPC
85b8b6c feat(host): namespace_backend skeleton — CapsuleHandle, Backend stubs
fcdd84c feat(host): cgroup v2 lifecycle management module
9dc61e2 feat(host): add namespace feature flag and nix dependency
eadfae7 fix(infra): dockerignore, Docker preflight check, explain --privileged
fea0b28 feat(infra): Docker dev environment for Linux namespace tests
a25b6b8 docs: M3 namespace isolation implementation plan
... (earlier commits below)
6a210a2 feat(host): M2 — process backend, supervisor lifecycle, integration tests
6fe04f0 feat: align protocol with vsock microVM spec
8109916 feat: scaffold ZeptoKernel — secure per-worker execution capsule
```

---

## Overall Progress

| Milestone | Status | Description |
|-----------|--------|-------------|
| M1: Protocol + Guest Shell | ✅ Done | Types, wire format, guest control loop, init |
| M2: Host Supervisor + Process Backend | ✅ Done | Backend trait, ProcessBackend, Supervisor lifecycle, 7 integration tests |
| M2.5: Real Worker Launching | ✅ Done | Guest actually launches worker binary, forwards events, emits heartbeats |
| M3: Namespace Isolation (Linux) | ✅ Done | NamespaceBackend: user/PID/mount/IPC/UTS/net namespaces, cgroup v2, Docker test env, 5 integration tests |
| M4: ZeptoPM Integration | 🔴 Not started | Wire ZeptoPM to call zk-host instead of spawning workers directly |
| M5: Hardening + Policy | 🔴 Not started | Per-role profiles, secret redaction, audit logging |
| M6: Firecracker Backend | 🔴 Not started | MicroVM with vsock, snapshot/restore |

---

## M2.5: Real Worker Launching (Next Priority)

The guest agent currently fakes job completion. These tasks make it actually launch and monitor a worker binary.

### Tasks

- [x] **2.5.1 — Worker process launcher** (`crates/zk-guest/src/worker.rs`)
  - Spawn worker as child process with `--job-spec` + `--job-id` args
  - Set env vars from `JobSpec.env` on the child
  - Pipe worker stdout for JSON-line event parsing; stderr inherited
  - `WorkerHandle` wraps child + stdout lines

- [x] **2.5.2 — Event forwarding from worker** (`crates/zk-guest/src/agent.rs`)
  - `forward_worker_line` forwards non-terminal events (heartbeat, progress, artifact_produced)
  - Guest owns terminal events (Started, Completed, Failed, Cancelled)
  - Malformed lines are logged and ignored

- [x] **2.5.3 — Periodic heartbeat emission** (`crates/zk-guest/src/agent.rs`)
  - Heartbeat every 5s via `tokio::time::interval` in the `select!` loop
  - Phase changes to "cancelling" when cancellation is in progress

- [x] **2.5.4 — Worker exit handling** (`crates/zk-guest/src/agent.rs`)
  - Exit 0 → `Completed { job_id, output_artifact_ids: vec![], summary: "" }`
  - Exit non-zero → `Failed { job_id, error: "worker exited with code N", retryable: false }`
  - Signal death (Unix) → `Failed { retryable: true }`
  - Cancellation wins regardless of exit code → `Cancelled`

- [x] **2.5.5 — Job cancellation with signals** (`crates/zk-guest/src/agent.rs`)
  - `CancelJob` → SIGTERM via `libc::kill`
  - 10-second grace period tracked via `cancel_deadline`
  - Heartbeat tick checks deadline and escalates to SIGKILL

- [x] **2.5.6 — Mock worker binary** (`crates/zk-guest/src/bin/mock_worker.rs`)
  - Modes via `MOCK_MODE` env var or `--mode` arg: `complete`, `fail`, `hang`, `events`
  - Only emits non-terminal events (heartbeat, progress); guest emits terminal events
  - Registered as `[[bin]] mock-worker` in zk-guest crate

- [x] **2.5.7 — Update existing integration tests**
  - All 7 original tests updated to use `mock-worker` via `ZEPTOCLAW_BINARY` env
  - 3 new tests: `test_start_job_fails`, `test_start_job_receives_heartbeats`, `test_cancel_job_while_running`
  - `drain_to_terminal()` helper for consuming intermediate events
  - Total: 10 integration tests passing

**Exit criteria:** `cargo test --workspace` passes. Host spawns guest, guest launches mock worker, heartbeats flow, job completes/fails/cancels correctly.

---

## M3: Namespace Isolation (Linux Only)

Requires Linux. User has a VPS for this work. Process backend remains the macOS dev-mode fallback.

### Tasks

- [x] **3.1 — Namespace sandbox backend** (`crates/zk-host/src/namespace_backend.rs`)
  - `NamespaceBackend` + `NamespaceHandle` implementing `Backend` + `CapsuleHandle` traits
  - `clone(2)` with `CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNET`
  - UID/GID maps written by parent after clone (root-in-namespace → host user)
  - Sync pipe to block child until UID/GID maps are written
  - Control channel: stdin/stdout pipe pair (same as ProcessBackend, no protocol changes)

- [x] **3.2 — Mount namespace setup** (`crates/zk-host/src/namespace_backend.rs` — `child_main`)
  - `/proc` mounted as procfs (process tree visibility)
  - `/workspace` mounted as tmpfs (job workspace, size from `WorkspaceConfig.size_mib`)
  - stdin/stdout redirected to pipe pair before `execv(zk-guest)`
  - **Deferred:** pivot_root to minimal readonly rootfs (post-M3)

- [x] **3.3 — cgroup v2 resource limits** (`crates/zk-host/src/cgroup.rs`)
  - `Cgroup` struct with `create()`, `add_pid()`, `apply_limits()`, `destroy()` (retry 3×)
  - `Cgroup::dummy()` fallback for systems without cgroup v2 delegation
  - Best-effort: spawn continues on cgroup failure with a warning

- [x] **3.4 — Network namespace** (via `CLONE_NEWNET` in `do_clone`)
  - Loopback-only network namespace created for every capsule
  - **Deferred:** veth pair for outbound HTTP workers (M5)

- [ ] **3.5 — Seccomp filter** — deferred to M5 hardening

- [x] **3.6 — Namespace backend integration tests** (`crates/zk-host/tests/namespace_backend.rs`)
  - 5 tests gated on `#[cfg(all(target_os = "linux", feature = "namespace"))]`
  - Run via `./scripts/test-linux.sh` inside privileged Docker container
  - Tests: full lifecycle, supervisor run_job, job failure, cancel (with heartbeat wait + timeout), no-network

- [x] **3.7 — Feature flag + Docker dev environment**
  - `namespace` Cargo feature (disabled by default on macOS)
  - `Dockerfile.dev` + `scripts/test-linux.sh` with `--privileged` + named volume for artifact isolation
  - `ZEPTOCLAW_BINARY` in `spec.env` supported by agent (checked before process env)

**Exit criteria:** On Linux, `cargo test --workspace --features namespace` passes. Worker cannot escape sandbox.

---

## M4: ZeptoPM Integration

Wire ZeptoPM to use ZeptoKernel instead of spawning workers directly.

### Tasks

- [ ] **4.1 — ZeptoPM → zk-host library API**
  - ZeptoPM currently at `/Users/dr.noranizaahmad/ios/zeptoPM/`
  - Option A: ZeptoPM calls `zk-host` as a library (add as dependency)
  - Option B: ZeptoPM spawns `zk-host` binary and communicates via its own JSON-line protocol
  - **Decision needed:** Library vs binary. Library is simpler but couples the crates.

- [ ] **4.2 — JobSpec mapping**
  - Map ZeptoPM's `Job` struct → ZeptoKernel's `JobSpec`
  - Map fields: job_id, run_id, role, instruction, env, limits
  - Handle input artifacts: resolve ZeptoPM artifact paths to capsule paths
  - **File:** Adapter code in ZeptoPM or a shared crate

- [ ] **4.3 — Event translation**
  - Map `GuestEvent` → ZeptoPM orchestrator events
  - `Started` → update job status to Running
  - `Heartbeat` → update last_seen timestamp
  - `Progress` → update progress percentage
  - `Completed` → mark job done, store summary
  - `Failed` → mark job failed, check retryable flag
  - `Cancelled` → mark job cancelled
  - `ArtifactProduced` → register artifact in ZeptoPM store

- [ ] **4.4 — Artifact path resolution**
  - In process backend: workspace is a host directory → direct access
  - In namespace backend: workspace is bind-mounted → host can read the source dir
  - In Firecracker: need vsock transfer or virtio-fs → handle differently
  - Abstract behind an artifact retrieval trait

- [ ] **4.5 — CLI integration test**
  - `zeptopm run submit --task "test task"` works with ZeptoKernel isolation
  - Verify job lifecycle visible in `zeptopm run status`
  - Verify `--tail` flag shows real-time events from capsule

**Exit criteria:** `zeptopm run submit` spawns a ZeptoKernel capsule, job completes, artifacts visible in ZeptoPM.

---

## M5: Hardening + Policy

### Tasks

- [ ] **5.1 — Per-role capability profiles**
  - Define role configs: researcher (network), writer (no network), coder (git), reviewer (no network)
  - Load from ZeptoPM config or YAML file
  - Map roles to ResourceLimits + allowed syscalls + network access
  - **File:** `crates/zk-host/src/policy.rs`

- [ ] **5.2 — Secret injection and redaction**
  - Secrets delivered via `JobSpec.env` (already in protocol)
  - Ensure secrets never appear in:
    - Event messages (heartbeat, progress, failed error strings)
    - Log output (tracing spans/events)
    - Artifact content (optional scanning)
  - Redact known secret patterns (API keys, tokens) from forwarded events

- [ ] **5.3 — Audit logging**
  - Log all capsule lifecycle events to structured audit log
  - Fields: timestamp, job_id, run_id, event_type, source, details
  - Write to file or forward to logging service
  - Include: capsule create/destroy, job start/complete/fail, resource usage
  - **File:** `crates/zk-host/src/audit.rs`

- [ ] **5.4 — Cleanup failure recovery**
  - If cgroup removal fails, retry 3 times with backoff
  - If mount cleanup fails, log and continue (don't block other capsules)
  - Orphan detection: on supervisor start, scan for leftover cgroups/mounts from previous runs
  - **File:** Update `crates/zk-host/src/supervisor.rs`

- [ ] **5.5 — Resource usage reporting**
  - After job completion, report peak memory, CPU time, wall time, artifact size
  - Read from cgroup accounting files (memory.peak, cpu.stat)
  - Include in `JobOutcome::Completed` or as separate report
  - Forward to ZeptoPM for dashboarding

**Exit criteria:** Secrets never leak. Audit log captures full lifecycle. Orphan cleanup works.

---

## M6: Firecracker Backend (Future — requires Linux + Firecracker)

### Tasks

- [ ] **6.1 — Minimal guest kernel build**
  - Strip Linux kernel to essentials (no modules, no device drivers except virtio)
  - Target size: ~4-5 MiB vmlinux
  - Build script or Dockerfile
  - Store kernel at known path (configurable via VmConfig)

- [ ] **6.2 — Minimal rootfs image**
  - ext4 image with: /init (zk-guest binary, statically linked), CA certs, worker binary
  - Build script using `mkfs.ext4` + `mount` + copy files + `umount`
  - Per-role variants (researcher gets network stack, others don't)
  - Target size: ~10-20 MiB

- [ ] **6.3 — Firecracker launcher** (`crates/zk-host/src/firecracker_backend.rs`)
  - Implement `Backend` trait
  - Configure VM via Firecracker REST API (PUT /machine-config, /boot-source, /drives, /vsock)
  - Start Firecracker process
  - Wait for vsock connection from guest
  - Implement `CapsuleHandle` over vsock (port 7000 control, 7001 events)

- [ ] **6.4 — Vsock transport** (`crates/zk-host/src/vsock.rs`)
  - Host-side vsock listener/connector
  - Use `tokio-vsock` crate or raw `libc::AF_VSOCK` sockets
  - Implement `CapsuleHandle` trait methods over vsock streams
  - Two-port model: control (7000) and events (7001)

- [ ] **6.5 — Guest vsock agent** (`crates/zk-guest/src/vsock.rs`)
  - Guest-side vsock connector (connect to host CID 2, ports 7000/7001)
  - Replace stdin/stdout transport with vsock streams
  - Same `run_agent()` function, different Reader/Writer
  - Auto-detect transport: if stdin is a tty, use vsock; else use stdin/stdout

- [ ] **6.6 — Snapshot/restore**
  - Boot VM, run through init + ready, create snapshot
  - Store snapshot per role: `researcher-snap/`, `writer-snap/`, etc.
  - On `spawn()`: restore from snapshot instead of cold boot
  - Target: sub-100ms "cold" start (from prewarmed snapshot)
  - Firecracker API: PUT /snapshot/create, PUT /snapshot/load

- [ ] **6.7 — Firecracker integration tests**
  - Requires Firecracker binary + KVM support
  - Gate behind `firecracker` feature flag
  - Test: Full job lifecycle through Firecracker VM
  - Test: VM cleanup after job completion
  - Test: Snapshot create and restore
  - Test: Timeout enforcement kills VM

**Exit criteria:** Job runs inside Firecracker VM. Vsock protocol works. Snapshot restore gives <100ms starts.

---

## Infrastructure & Tooling Tasks

These can be done anytime, independently of milestones.

- [ ] **CLI for zk-host** — Replace hardcoded test job in `main.rs` with proper CLI (clap)
  - `zk-host run --guest <path> --job-spec <json>` — run single job
  - `zk-host run --guest <path> --worker <worker-binary>` — run with worker
  - `zk-host info` — show version and backend info

- [ ] **Logging improvements** — Add structured tracing spans
  - Per-capsule span with job_id, run_id
  - Per-phase spans (handshake, job, cleanup)
  - Configurable log level via `RUST_LOG`

- [ ] **CI setup** — GitHub Actions
  - Build + test on macOS (process backend only)
  - Build + test on Linux (process + namespace backends)
  - Clippy + rustfmt checks

- [ ] **Error context** — Improve error messages
  - Add `thiserror` context to all error variants
  - Include job_id in all supervisor errors
  - Include capsule id in all backend errors

- [ ] **Documentation** — Rustdoc on public APIs
  - `zk-proto`: document all types and wire format
  - `zk-host`: document Backend/CapsuleHandle traits
  - Generate with `cargo doc --workspace --no-deps`

---

## Known Issues

1. **M2 design checklist not updated** — The design doc at `docs/plans/2026-03-08-zeptokernel-design.md:370-376` still shows M2 items as `[ ]` unchecked. Should be updated to `[x]`.

2. **macOS limitations** — Namespace isolation (M3) and Firecracker (M6) require Linux. Process backend is the only option on macOS. User has a VPS for Linux work.

3. **SIGKILL escalation not tested** — The `test_cancel_job_while_running` test uses `hang` mode which responds to SIGTERM (tokio's `kill_on_drop` handles cleanup). A dedicated test for SIGTERM-ignoring workers would require a custom shell script or more complex mock.

---

## File Reference

| File | Lines | What's there |
|------|-------|-------------|
| `crates/zk-proto/src/lib.rs` | 465 | All protocol types, wire helpers, 9 tests |
| `crates/zk-host/src/backend.rs` | ~60 | `Backend` + `CapsuleHandle` traits, `BackendError` |
| `crates/zk-host/src/process_backend.rs` | ~165 | `ProcessBackend` + `ProcessHandle` impl |
| `crates/zk-host/src/supervisor.rs` | ~295 | `Supervisor`, `run_job()`, `JobOutcome`, heartbeat/timeout |
| `crates/zk-host/src/capsule.rs` | ~50 | `Capsule` state struct |
| `crates/zk-host/src/vm_config.rs` | ~55 | `VmConfig` for Firecracker |
| `crates/zk-host/src/main.rs` | ~45 | CLI entry point (hardcoded test job) |
| `crates/zk-host/tests/process_backend.rs` | ~450 | 10 integration tests |
| `crates/zk-host/src/namespace_backend.rs` | ~300 | NamespaceBackend, NamespaceHandle, do_clone, child_main |
| `crates/zk-host/src/cgroup.rs` | ~95 | Cgroup v2 lifecycle, dummy() fallback |
| `crates/zk-host/tests/namespace_backend.rs` | ~190 | 5 Linux-only namespace integration tests |
| `crates/zk-guest/src/agent.rs` | ~450 | Guest control loop — tokio::select! loop, worker launch, heartbeat, cancel |
| `crates/zk-guest/src/init.rs` | ~80 | Mount helpers (Linux-only) |
| `crates/zk-guest/src/worker.rs` | ~65 | WorkerHandle, launch_worker(), write_job_spec() |
| `crates/zk-guest/src/main.rs` | ~10 | Entry point, calls `run_agent()` |
| `Dockerfile.dev` | ~10 | Linux Rust dev image for namespace tests |
| `scripts/test-linux.sh` | ~25 | Docker run with --privileged for namespace tests |
| `docs/plans/2026-03-08-zeptokernel-design.md` | 412 | Full design spec |
| `CLAUDE.md` | 61 | Project instructions for agents |

---

## How to Pick Up Work

1. **Read this file** — you're doing it now
2. **Read `CLAUDE.md`** — project conventions and build commands
3. **Read the design spec** — `docs/plans/2026-03-08-zeptokernel-design.md`
4. **Run tests** — `cd /Users/dr.noranizaahmad/ios/zeptokernel && cargo test --workspace`
5. **Pick the next unchecked task** — M4 (ZeptoPM integration) is the next milestone
6. **Implement, test, commit** — one task at a time, all tests must pass
7. **Update this file** — check off completed tasks, add any new discoveries
