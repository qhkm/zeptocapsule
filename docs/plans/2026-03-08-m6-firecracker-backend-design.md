# M6: Firecracker Backend Design

**Date:** 2026-03-08  
**Status:** Implemented  
**Scope:** Add a Linux-only Firecracker backend behind the existing thin `zeptocapsule` API.

## Goal

Implement `Isolation::Firecracker` without changing the public `create() -> spawn() -> destroy()` contract already used by ZeptoPM.

The backend must stay within the current kernel boundary:

- ZeptoCapsule owns VM boot, resource enforcement, raw transport, and teardown.
- ZeptoPM owns job semantics, retries, heartbeats, and event interpretation.
- `zk-init` remains a minimal PID 1 and signal/control shim, not a guest-side orchestrator.

## Contract Fit

The current crate already exposes the right boundary in `src/backend.rs`:

```rust
pub trait CapsuleHandle: Send {
    fn spawn(
        &mut self,
        binary: &str,
        args: &[&str],
        env: HashMap<String, String>,
    ) -> KernelResult<CapsuleChild>;

    fn kill(&mut self, signal: Signal) -> KernelResult<()>;

    fn destroy(self: Box<Self>) -> KernelResult<CapsuleReport>;
}
```

Firecracker must implement that trait directly. The API exposed to ZeptoPM does not change.

## Key Design Decisions

### 1. `kill()` targets the worker first, not the VM

`Signal::Terminate` must map to "ask `zk-init` to terminate the worker process".  
`Signal::Kill` may escalate to terminating the whole VM if the guest does not respond.

This keeps Firecracker aligned with the existing process and namespace backends.

### 2. Serial output is diagnostics only

The serial console may be captured for boot diagnostics and backend failure context, but it must not be parsed as job outcome or worker protocol.

### 3. Workspace semantics stay job-boundary compatible

The current API models workspace as:

- `workspace.host_path`
- `workspace.guest_path`

Namespace preserves that through bind mounts. Firecracker cannot bind mount host directories directly, so v1 will use:

- host workspace copied into a per-capsule writable workspace image before boot
- guest mounts that image at `workspace.guest_path`
- workspace copied back to `host_path` during `destroy()`

This preserves the ZeptoPM contract that:

- input files written before `spawn()` are visible in the guest
- artifacts written by the worker are visible on the host after teardown

Live host visibility during execution is not required for ZeptoPM today.

### 4. Worker staging is explicit

`spawn(binary, ...)` currently receives a host binary path. A microVM guest cannot execute that path directly.

For v1:

- copy the worker binary into the writable capsule rootfs before boot
- execute it at a fixed guest path such as `/run/zeptocapsule/worker`

Constraint:

- either the worker must be statically linked, or the guest rootfs must contain compatible runtime libraries

Do not make ZeptoPM provide a different API for guest-only paths.

### 5. Firecracker-specific control lives inside the backend

The public `CapsuleChild` remains raw stdio.

Internally, the backend will use:

- vsock `1001` for stdin
- vsock `1002` for stdout
- vsock `1003` for stderr
- vsock `1004` for control

The control port is backend-private and used only for `kill()` and graceful shutdown signaling.

## Proposed Types

Keep `CapsuleSpec` backend-neutral, but add an optional Firecracker config block:

```rust
pub struct CapsuleSpec {
    pub isolation: Isolation,
    pub workspace: WorkspaceConfig,
    pub limits: ResourceLimits,
    pub init_binary: Option<PathBuf>,
    pub security: SecurityProfile,
    pub security_overrides: SecurityOverrides,
    pub firecracker: Option<FirecrackerConfig>,
}

pub struct FirecrackerConfig {
    pub firecracker_bin: PathBuf,
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub vcpus: Option<u32>,
    pub memory_mib: Option<u64>,
    pub enable_network: bool,
    pub tap_name: Option<String>,
}
```

Validation rules:

- `isolation == Isolation::Firecracker` requires `target_os = "linux"`
- `CapsuleSpec.firecracker` must be `Some(...)`
- `init_binary` is ignored for Firecracker because `zk-init` must already exist inside the guest image

Use `ResourceLimits` to derive defaults:

- `memory_mib`: `limits.memory_mib.unwrap_or(256)`
- `vcpus`: derived from `cpu_quota` using `ceil(quota)` with min `1`
- `timeout_sec`: enforced by a host watchdog, same as namespace

## Host-Side Components

Add new files:

- `src/firecracker.rs` — `Backend` + `CapsuleHandle` implementation
- `src/firecracker_api.rs` — Firecracker REST API client over Unix socket
- `src/vsock.rs` — host-side Firecracker vsock connector

Add a Linux-only test file:

- `tests/firecracker_backend.rs`

### `FirecrackerCapsule`

```rust
pub struct FirecrackerCapsule {
    spec: CapsuleSpec,
    config: FirecrackerConfig,
    state_dir: PathBuf,
    api_socket: PathBuf,
    vsock_socket: PathBuf,
    serial_log: PathBuf,
    rootfs_overlay: PathBuf,
    workspace_image: PathBuf,
    fc_process: Option<std::process::Child>,
    started_at: Instant,
    timeout_cancel: Option<oneshot::Sender<()>>,
    killed_by: Arc<Mutex<Option<ResourceViolation>>>,
}
```

`state_dir` contains all per-capsule temporary assets:

- Firecracker API socket
- Firecracker vsock socket
- serial log
- copied rootfs / overlay file
- workspace disk image
- staged worker binary
- generated machine config JSON if needed for debugging

## Guest-Side Components

Reuse `src/init_shim.rs`, but extend it for microVM control:

- if no control env vars are present, keep current namespace behavior
- if Firecracker control env vars are present:
  - connect/listen on the control vsock port
  - spawn the worker
  - forward terminate/kill requests to the worker PID
  - continue reaping until the worker exits

This is still a thin init shim. It should not speak job protocol and should not emit structured worker events.

## Lifecycle

### `create(spec)`

Responsibilities:

1. Validate KVM availability:
   - `/dev/kvm` exists and is writable
   - Firecracker binary exists and is executable
   - kernel and rootfs files exist
2. Create per-capsule `state_dir`
3. Prepare writable rootfs copy from the configured base image
4. Prepare writable workspace image
5. If `workspace.host_path` exists, copy its contents into the workspace image
6. Do not boot the VM yet

Failure at this stage returns `KernelError::NotSupported` or `KernelError::SpawnFailed`.

### `spawn(binary, args, env)`

Responsibilities:

1. Stage worker binary into the writable rootfs
2. Start Firecracker with:
   - API socket
   - serial log path
   - vsock device
   - rootfs drive
   - workspace drive
3. Configure the VM over REST:
   - machine config
   - boot source
   - drives
   - vsock
   - optional network
4. Start the instance
5. Connect host-side vsock streams
6. Wait for `zk-init` readiness on the control channel
7. Return `CapsuleChild` backed by vsock I/O
8. Start a host watchdog for wall-clock timeout

Boot readiness must be determined by a small backend-private control handshake, not by parsing serial logs.

### `kill(signal)`

Responsibilities:

1. Send a control message to `zk-init` over the control vsock port
2. Wait a short grace period for guest acknowledgement or EOF
3. If `Signal::Kill` or guest non-response:
   - try Firecracker graceful shutdown if still useful
   - otherwise kill the `firecracker` process directly

### `destroy()`

Responsibilities:

1. Cancel the watchdog
2. Ensure the VM is stopped
3. Collect exit facts:
   - worker exit status if available from control channel
   - timeout kill reason if set by watchdog
   - boot/transport failure hints from serial log
4. Copy workspace image contents back into `workspace.host_path` if configured
5. Remove `state_dir`
6. Return `CapsuleReport`

`destroy()` must report backend/resource facts only:

- `exit_code`
- `exit_signal`
- `killed_by`
- `wall_time`
- `peak_memory_mib` if host metrics are available later

## Workspace Strategy

For v1, do not introduce virtio-fs.

Use a second writable ext4 image as the workspace disk:

- mounted by the guest at `workspace.guest_path`
- seeded from `workspace.host_path` before boot
- copied back after teardown

Why:

- simpler than adding a virtio-fs daemon
- works with the existing ZeptoPM contract
- avoids making workspace visibility depend on host kernel or vhost-user support

This also matches how job specs are already written into the host workspace before spawn.

## Worker Binary Strategy

Stage the worker into the writable rootfs before boot:

- host path: `binary`
- guest path: `/run/zeptocapsule/worker`

The backend then boots the VM and asks `zk-init` to execute `/run/zeptocapsule/worker`.

For v1, reject unsupported worker layouts early:

- if the binary is dynamically linked and the configured guest image is not known to contain compatible runtime libs, return `KernelError::NotSupported`

That is better than starting a VM that fails with an opaque exec error.

## Firecracker API/Transport Details

### REST API

Add a minimal client in `src/firecracker_api.rs` for:

- `PUT /machine-config`
- `PUT /boot-source`
- `PUT /drives/{id}`
- `PUT /vsocks/{id}`
- `PUT /network-interfaces/{id}` when enabled
- `PUT /actions` for `InstanceStart`

Use a tiny manual HTTP client over Unix sockets instead of adding a heavy dependency.

### Vsock transport

Add a small `src/vsock.rs` helper that:

- connects to the host-side Firecracker vsock Unix socket
- performs the Firecracker connect handshake for a target guest port
- exposes `AsyncRead` / `AsyncWrite`

This module should hide the Firecracker-specific framing from the backend.

## Resource Mapping

Map existing limits conservatively:

- `timeout_sec` -> host watchdog + `killed_by = WallClock`
- `memory_mib` -> Firecracker guest memory size
- `cpu_quota` -> VM vCPU count using `ceil(quota)` and minimum `1`
- `max_pids` -> not enforceable at the host boundary in v1; document as unsupported and reject if set

Do not silently claim `MaxPids` support if it cannot be enforced.

## Error Model

Keep failures in existing kernel terms:

- `KernelError::NotSupported` for missing KVM, missing Firecracker binary, unsupported worker/runtime shape, or unsupported `max_pids`
- `KernelError::SpawnFailed` for VM boot/configuration failures
- `KernelError::Transport` for vsock/control failures
- `KernelError::CleanupFailed` for teardown or workspace export failures

Include a short serial-log excerpt in boot-related error strings when useful, but do not expose the full log inline.

## Testing Plan

Add Linux-only tests behind `ZK_RUN_FIRECRACKER_TESTS=1`:

1. `firecracker_stdio_round_trip`
   - boot VM
   - run `/bin/cat`
   - verify stdin/stdout pipes work through vsock

2. `firecracker_workspace_round_trip`
   - seed host workspace with input file
   - worker reads it and writes an output file
   - verify copied-back artifacts appear on host after destroy

3. `firecracker_timeout_kills_worker`
   - run `sleep`
   - verify `CapsuleReport.killed_by == Some(WallClock)`

4. `firecracker_kill_terminate_reaches_worker`
   - run a worker that traps SIGTERM
   - verify graceful terminate path works through control channel

5. `firecracker_missing_kvm_is_not_supported`
   - unit/integration guard for host prerequisite validation

These tests should be skipped by default, just like namespace runtime tests.

## Implementation Sequence

### Phase 1: Types and wiring

1. Add `FirecrackerConfig` to `src/types.rs`
2. Extend `CapsuleSpec::validate()`
3. Wire `Isolation::Firecracker` in `src/lib.rs`

Expected result:

- crate compiles
- Firecracker still returns `NotSupported` until backend lands

### Phase 2: Host plumbing

1. Add `src/firecracker_api.rs`
2. Add `src/vsock.rs`
3. Add `src/firecracker.rs` with stub `create/spawn/kill/destroy`

Expected result:

- Firecracker backend can validate prerequisites and launch the VMM
- no workspace sync or full stdio yet

### Phase 3: Boot and stdio

1. Stage worker into writable rootfs
2. Add control port handshake
3. Return working `CapsuleChild` over vsock

Expected result:

- `firecracker_stdio_round_trip` passes

### Phase 4: Workspace import/export

1. Build workspace image
2. Seed from `workspace.host_path`
3. Export back on destroy

Expected result:

- workspace round-trip test passes

### Phase 5: Kill and timeout semantics

1. Extend `zk-init` with control loop
2. Implement graceful terminate
3. Implement timeout watchdog and escalation

Expected result:

- timeout and terminate-path tests pass

### Phase 6: Hardening and docs

1. Add optional network setup
2. Improve boot diagnostics
3. Document image-build workflow for the guest rootfs
4. Update `TODO.md` when tests are green

## Non-Goals for v1

- snapshots / restore
- GPU passthrough
- virtio-fs
- guest metrics daemon
- guest-side event protocol
- network namespace parity with the namespace backend

## Open Questions

### How should the guest rootfs be built?

Recommended answer:

- keep a curated base ext4 image under deploy/build tooling
- include `zk-init`, shell tools needed for debugging, and the runtime libs ZeptoClaw needs

Do not generate a bespoke rootfs from scratch in `create()`.

### Should `init_binary` be reused?

No.

`init_binary` is a host-side path used by the namespace backend. Firecracker should assume `zk-init` is already present inside the guest image.

### Should `max_pids` be emulated inside the guest?

Not in v1.

Reject it for Firecracker until there is a defensible enforcement mechanism.
