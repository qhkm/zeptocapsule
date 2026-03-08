# ZeptoKernel Design Spec

## Goal

Build a secure, per-worker execution capsule that isolates ZeptoClaw workers from the host, from each other, and from secrets they don't need. ZeptoPM spawns capsules; ZeptoKernel runs them; ZeptoClaw does the work.

## Architecture

```
ZeptoPM (orchestrator)
  │
  ├── zk-host (supervisor)
  │     ├── Backend::spawn() → capsule
  │     ├── capsule.send(StartJob)
  │     ├── capsule.recv() → GuestEvent stream
  │     ├── heartbeat/timeout monitor
  │     └── capsule.terminate() + cleanup
  │
  └── [capsule boundary] ─────────────────
        │
        ├── zk-guest (agent, PID 1)
        │     ├── control channel listener
        │     ├── worker launcher
        │     └── event forwarder
        │
        └── zeptoclaw-worker (the actual AI task)
              ├── reads job spec
              ├── calls LLM APIs
              ├── writes artifacts to /workspace
              └── emits JSON-line events to stdout
```

## Protocol

### Transport

- **Dev/namespace mode:** Unix socket or stdin/stdout JSON lines
- **MicroVM mode:** virtio-vsock
- **Wire format:** One JSON object per line, newline-terminated

### Host → Guest Commands

| Command | Fields | Purpose |
|---------|--------|---------|
| `start_job` | JobSpec (see below) | Start a job in the capsule |
| `cancel_job` | `job_id` | Cancel a running job |
| `ping` | `seq` | Health check |
| `shutdown` | — | Graceful shutdown |

### Guest → Host Events

| Event | Key Fields | Purpose |
|-------|-----------|---------|
| `ready` | — | Guest agent is initialized |
| `pong` | `seq` | Response to ping |
| `started` | `job_id` | Worker has begun executing |
| `heartbeat` | `job_id`, `memory_used_mib?` | Worker is alive |
| `progress` | `job_id`, `phase`, `message` | Status update |
| `waiting` | `job_id`, `reason` | Worker blocked (e.g. LLM API) |
| `artifact_produced` | `job_id`, `artifact_id`, `kind`, `guest_path`, `summary` | Output file ready |
| `completed` | `job_id`, `output_artifact_ids` | Job finished successfully |
| `failed` | `job_id`, `error`, `retryable` | Job failed |
| `cancelled` | `job_id` | Job was cancelled |

### JobSpec

```rust
struct JobSpec {
    job_id: String,
    run_id: String,
    role: String,              // "researcher", "writer", etc.
    profile_id: String,        // maps to agent config in ZeptoPM
    instruction: String,
    input_artifacts: Vec<ArtifactRef>,
    env: HashMap<String, String>,  // scoped secrets + config
    limits: ResourceLimits,
    workspace: WorkspaceConfig,
}
```

### Resource Limits

```rust
struct ResourceLimits {
    timeout_sec: u64,          // wall clock limit (default 300)
    memory_mib: Option<u64>,   // cgroup memory limit
    cpu_quota: Option<f64>,    // cpu fraction (1.0 = one core)
    max_pids: Option<u32>,     // process count limit
    network: bool,             // outbound network allowed (default false)
    heartbeat_timeout_sec: u64, // kill if no heartbeat (default 60)
}
```

## Isolation Backends

### Backend Trait

```rust
trait Backend {
    type Handle: CapsuleHandle;
    async fn spawn(&self, spec: &JobSpec, worker_binary: &str) -> Result<Self::Handle>;
}

trait CapsuleHandle {
    async fn send(&self, cmd: HostCommand) -> Result<()>;
    async fn recv(&self) -> Result<GuestEvent>;
    async fn terminate(&self) -> Result<()>;
    fn id(&self) -> String;
}
```

### V1: Namespace Sandbox (Linux)

Uses Linux kernel features directly:

| Mechanism | Purpose |
|-----------|---------|
| User namespace | Unprivileged isolation |
| PID namespace | Process tree isolation |
| Mount namespace | Filesystem isolation |
| IPC namespace | IPC isolation |
| UTS namespace | Hostname isolation |
| Network namespace | Network isolation (when disabled) |
| cgroup v2 | Memory, CPU, PID limits |
| seccomp | Syscall filtering |

Filesystem layout inside capsule:
```
/                          # readonly rootfs (minimal)
/workspace                 # writable tmpfs (job workspace)
/tmp                       # writable tmpfs
/zeptoclaw/worker          # readonly bind mount of worker binary
/etc/ssl/certs/            # readonly CA certs (if network=true)
```

Control channel: Unix socket passed to guest agent.

### V2: Firecracker MicroVM (Future)

- Host launches Firecracker with minimal kernel + rootfs
- Control via virtio-vsock
- Artifact transfer via virtio-fs or vsock streaming
- Snapshot/restore for prewarmed role images

## Supervisor Lifecycle

### Capsule States

```
Initializing → Ready → Running → Completed
                  │         │
                  │         ├── Waiting → Running
                  │         │
                  │         ├── Failed
                  │         │
                  │         └── Cancelled
                  │
                  └── Failed (spawn failure)
```

### Heartbeat Monitoring

1. After `started`, supervisor expects periodic `heartbeat` events
2. If no heartbeat within `heartbeat_timeout_sec`, capsule is terminated
3. Supervisor reports failure with `"heartbeat timeout"` reason

### Timeout Enforcement

1. Wall clock timer starts when `started` event received
2. At `timeout_sec`, supervisor sends `cancel_job`
3. After 10s grace period, `terminate()` is called
4. After 5s more, SIGKILL escalation

### Cleanup

On completion, failure, or cancellation:
1. Terminate worker process tree
2. Release cgroup resources
3. Unmount temporary filesystems
4. Remove workspace (unless retention configured)
5. Report final state to ZeptoPM

## Guest Agent Design

The guest agent (`zk-guest`) runs as the first process inside the capsule.

### Startup Sequence

1. Mount tmpfs at /workspace and /tmp
2. Set hostname
3. Open control channel
4. Send `ready` event
5. Wait for `start_job` command

### Job Execution

1. Receive `start_job` with JobSpec
2. Write job spec to /workspace/job-spec.json
3. Set environment variables from `spec.env`
4. Launch: `zeptoclaw worker --job-spec /workspace/job-spec.json`
5. Read worker stdout, parse JSON-line events
6. Forward valid events to host
7. Start heartbeat timer (emit heartbeat every 15s)
8. On worker exit, send `completed` or `failed`

### Shutdown

1. Receive `shutdown` or `cancel_job`
2. Send SIGTERM to worker
3. Wait up to 10s for exit
4. SIGKILL if still alive
5. Report final status
6. Exit

## Security Model

### Default Deny

Every capsule starts with:
- No network access
- No host filesystem access beyond readonly rootfs
- No environment variables beyond explicitly injected ones
- No access to sibling capsule state
- Limited syscalls (seccomp allowlist)

### Secret Injection

- API keys and secrets delivered via `JobSpec.env`
- Injected at capsule start, not inherited from host environment
- Never written to disk (env-only)
- Never included in event messages or logs

### Per-Role Capabilities

| Role | Network | Filesystem | Tools |
|------|---------|-----------|-------|
| researcher | outbound HTTP | readonly inputs + writable workspace | HTTP client |
| reviewer | none | readonly inputs + writable workspace | diff engine |
| writer | none | readonly inputs + writable workspace | — |
| coder | none | writable workspace | git (optional) |

Capabilities are configured per-profile in ZeptoPM config and delivered via JobSpec.

## Artifact Handling

### Write Path (guest → host)

1. Worker writes artifact to `/workspace/output.md` (or similar)
2. Worker emits `artifact_produced` event with path and metadata
3. Guest agent forwards event to host
4. Host reads artifact from shared mount or requests transfer

### V1: Shared Filesystem

In namespace mode, workspace is a bind-mounted host directory.
Host reads artifacts directly after job completion.

### V2: Streaming Transfer

In microVM mode, artifacts are streamed over vsock or pulled via virtio-fs.

## Integration with ZeptoPM

### Current State

ZeptoPM spawns workers as child processes with JSON-line IPC:
```
ZeptoPM → spawn child → stdin/stdout JSON lines → worker
```

### Migration Path

1. **Phase 0 (current):** ZeptoPM spawns bare workers. No isolation.
2. **Phase 1:** ZeptoPM spawns `zk-host` which wraps worker in namespace capsule. Same JSON-line protocol, stronger boundaries.
3. **Phase 2:** `zk-host` uses Firecracker backend. Same protocol, VM-level isolation.

The key insight: the protocol between ZeptoPM and workers doesn't change. ZeptoKernel sits between them as a transparent isolation layer.

## Implementation Milestones

### M1: Protocol + Guest Agent Shell
- [x] Define HostCommand, GuestEvent, JobSpec types
- [x] JSON-line encode/decode helpers
- [x] Guest agent control loop (stdin/stdout)
- [ ] Unit tests for protocol roundtrips
- **Exit criteria:** `echo '{"type":"ping","seq":1}' | zk-guest` returns pong

### M2: Host Supervisor + Process Backend
- [ ] Backend trait definition
- [ ] Process backend (spawn worker as child process, no namespace isolation)
- [ ] Supervisor with heartbeat monitoring
- [ ] Timeout enforcement
- [ ] Integration test: host spawns guest, sends job, receives events

### M3: Namespace Isolation (Linux)
- [ ] User + PID + mount namespace setup
- [ ] cgroup v2 memory + CPU + PID limits
- [ ] Readonly rootfs + writable workspace mount
- [ ] Network namespace (disabled by default)
- [ ] Seccomp filter
- **Exit criteria:** Worker cannot access host filesystem or network

### M4: ZeptoPM Integration
- [ ] ZeptoPM calls `zk-host` instead of spawning workers directly
- [ ] JobSpec populated from ZeptoPM's Job type
- [ ] Event translation (GuestEvent → ZeptoPM orchestrator events)
- [ ] Artifact path resolution through capsule boundary
- **Exit criteria:** `zeptopm run submit` works with ZeptoKernel isolation

### M5: Hardening + Policy
- [ ] Per-role capability profiles
- [ ] Secret injection and redaction
- [ ] Audit logging
- [ ] Cleanup failure recovery
- [ ] Resource usage reporting

### M6: Firecracker Backend (Future)
- [ ] Minimal Linux guest kernel build
- [ ] Custom init binary
- [ ] vsock control channel
- [ ] Artifact transfer over vsock/virtio-fs
- [ ] Snapshot/restore for prewarmed images

## Open Decisions

1. **Artifact transfer in microVM mode:** virtio-fs shared mount vs. vsock streaming vs. host pull after completion. Leaning toward virtio-fs for simplicity.
2. **Warm capsule reuse:** One-shot (create per job, destroy after) vs. warm pool (pre-create, assign job, reset). Starting with one-shot; warm pool is an optimization.
3. **Dev-mode on macOS:** Namespace sandbox requires Linux. Options: (a) process backend with no isolation for dev, (b) Docker-in-Docker, (c) remote Linux dev box. Recommend (a) for fast iteration.
4. **Seccomp profile:** Start with a permissive allowlist and tighten iteratively based on observed syscall usage.
