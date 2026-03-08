# M3: Namespace Isolation Design

**Date:** 2026-03-08
**Status:** Approved
**Scope:** Linux namespace sandbox backend with Docker-based development workflow

---

## Goal

Implement the `NamespaceBackend` — a `Backend` trait implementation that isolates each ZeptoClaw worker in Linux namespaces (user, PID, mount, IPC, UTS, network) with cgroup v2 resource limits. Development and testing happen on macOS via a privileged Docker container.

---

## Docker Development Workflow

Write code on macOS. Build and test in Docker via a shell script.

**Files:**
- `Dockerfile.dev` — `rust:latest` on Debian, installs system deps (libseccomp-dev, etc.)
- `scripts/test-linux.sh` — builds image, mounts source, runs `cargo test --workspace --features namespace`

The script mounts the project source into the container so edits on macOS are reflected immediately without rebuilding the image. Tests run with `--privileged` to allow namespace creation, cgroup writes, and mount operations.

```bash
# Usage
./scripts/test-linux.sh
```

---

## Namespace Backend Architecture

### New Files

| File | Purpose |
|------|---------|
| `crates/zk-host/src/namespace_backend.rs` | `NamespaceBackend` + `NamespaceHandle` impl |
| `crates/zk-host/src/cgroup.rs` | cgroup v2 lifecycle management |
| `crates/zk-host/tests/namespace_backend.rs` | Linux-only integration tests |

### Feature Flag

```toml
# crates/zk-host/Cargo.toml
[features]
namespace = ["dep:nix"]

[target.'cfg(target_os = "linux")'.dependencies]
nix = { version = "0.29", features = ["sched", "mount", "process", "user"], optional = true }
```

All namespace code is gated `#[cfg(feature = "namespace")]`. The feature is disabled by default — process backend remains the macOS fallback.

### Spawn Flow

```
NamespaceBackend::spawn(spec, worker_binary):

  1. Create pipe pair (host_read/write ↔ guest_stdin/stdout)
  2. Allocate child stack (8 MiB Vec<u8>)
  3. nix::sched::clone(child_fn, stack,
       CloneFlags::CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS
                    | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNET
                    | Signal::SIGCHLD)
  4. Parent:
       a. Write UID/GID maps → /proc/<pid>/uid_map, gid_map, setgroups
          (maps child uid 0 → host nobody; gid 0 → host nogroup)
       b. Create cgroup: /sys/fs/cgroup/zeptokernel/<job_id>/
          Write memory.max, cpu.max, pids.max
          Write child PID → cgroup.procs
       c. Signal child to proceed (via sync pipe)
       d. Return NamespaceHandle wrapping the pipe pair
  5. Child:
       a. Wait for parent signal
       b. Mount /proc (proc filesystem)
       c. Mount /tmp as tmpfs (64 MiB, nosuid, nodev)
       d. Mount /workspace as tmpfs (spec.workspace.size_mib, nosuid, nodev)
       e. dup2(guest_read_fd → STDIN_FILENO)
          dup2(guest_write_fd → STDOUT_FILENO)
       f. exec("zk-guest")
```

### NamespaceHandle

Implements `CapsuleHandle` using the same pipe-based stdin/stdout as `ProcessHandle`. No protocol changes — `Supervisor` and all existing code works unchanged.

### Control Channel

Stays **stdin/stdout** (pipe pair). The namespace boundary is transparent to the protocol. Unix socket transport is a future enhancement.

---

## cgroup v2

```
/sys/fs/cgroup/zeptokernel/<job_id>/
  cgroup.procs   ← child PID
  memory.max     ← limits.memory_mib * 1024²  (or "max" if None)
  cpu.max        ← "N 100000" where N = quota * 100000  (or "max")
  pids.max       ← limits.max_pids  (or "max")
```

**Lifecycle:**
1. Create directory on spawn
2. Write child PID after clone
3. Remove directory on `terminate()` (retry 3× with backoff on failure)

**Error handling:** If cgroup creation fails (e.g. cgroup v1 system), log a warning and continue — isolation still works via namespaces.

---

## Mount Setup

Performed in the child process before exec, inside the new mount namespace:

```
mount -t proc proc /proc          # process filesystem
mount -t tmpfs tmpfs /tmp         # 64 MiB scratch space
mount -t tmpfs tmpfs /workspace   # job workspace (size from spec)
```

**Pivot root:** Skipped for Docker-based development. The child inherits the container's rootfs and mounts on top of it within its own mount namespace. Full pivot_root to a minimal readonly rootfs is a follow-up task (after M3).

**Seccomp:** Skipped in initial implementation. Marked as TODO. Tighten in M5 hardening.

---

## Integration Tests

File: `crates/zk-host/tests/namespace_backend.rs`
Gate: `#[cfg(target_os = "linux")]` — compiled and run only inside Docker.

| Test | Verifies |
|------|----------|
| `test_namespace_full_lifecycle` | Spawn → handshake → job → Completed |
| `test_namespace_workspace_isolated` | Worker writes to `/workspace` (tmpfs) |
| `test_namespace_no_host_fs` | Worker cannot read host `/etc/passwd` |
| `test_namespace_no_network` | Worker cannot reach external network |
| `test_namespace_memory_limit` | Worker killed at `memory_mib` limit |
| `test_namespace_pid_limit` | Worker can't exceed `max_pids` |
| `test_namespace_cancel` | CancelJob works through namespace boundary |

Run with:
```bash
./scripts/test-linux.sh
# Which runs: cargo test --workspace --features namespace
```

---

## What Does NOT Change

- `zk-proto` — no protocol changes
- `zk-guest` — no guest changes (stdin/stdout transport unchanged)
- `ProcessBackend` — still the macOS/dev fallback
- `Supervisor` — works with any `Backend` impl

---

## Deferred

- `pivot_root` to minimal readonly rootfs (after M3)
- Seccomp syscall filter (M5)
- Unix socket control channel (M6 vsock work)
- Network namespace with veth pair for outbound HTTP workers (M5)
