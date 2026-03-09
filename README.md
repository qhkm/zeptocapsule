<div align="center">

# 🛡️ ZeptoCapsule

**Isolation sandbox for AI agents — process, namespace, and Firecracker capsules.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-nightly-orange.svg)](https://www.rust-lang.org/)
[![Linux](https://img.shields.io/badge/Linux-full_support-brightgreen.svg)]()
[![macOS](https://img.shields.io/badge/macOS-process_only-yellow.svg)]()

**`3 isolation levels`** · **`automatic fallback`** · **`host capability probing`** · **`zero-config on macOS`**

[Quick Start](#-quick-start) · [Backends](#-isolation-backends) · [Security Profiles](#-security-profiles) · [API](#-api-reference)

</div>

---

## 📖 Why Not Just Docker?

Docker is built for long-running services. AI agents are short-lived jobs — spin up, call an LLM API, write an artifact, die. Each one takes ~7 MB of memory and finishes in seconds.

| Approach | Startup | Overhead | Isolation |
|:---------|:--------|:---------|:----------|
| Docker container | ~1-2s | Image layers, networking stack, storage driver | Good |
| Firecracker microVM | ~125ms | Full guest kernel, ext4 rootfs | Excellent |
| Linux namespace | ~5ms | Kernel namespaces + cgroups, no runtime | Good |
| Plain fork() | ~1ms | Near-zero | Minimal |

The right answer depends on the workload. An agent calling GPT-4 doesn't need a microVM. An agent running untrusted code does.

**ZeptoCapsule gives you all three behind one API** — and automatically falls back when the host doesn't support a level.

---

## ✨ Features

<table>
<tr>
<td width="50%">

🔒 **Three isolation backends** — process, namespace, Firecracker

🔍 **Host capability probing** — auto-detects what your system supports

⬇️ **Automatic fallback** — degrades gracefully (Firecracker → namespace → process)

🛡️ **Security profiles** — Dev, Standard, Hardened

</td>
<td width="50%">

⏱️ **Resource limits** — memory, CPU, PIDs, wall-clock timeout

📁 **Workspace mounting** — host dir ↔ guest dir, artifact collection

🔧 **Init shim** — `zk-init` binary bootstraps guest environments

📊 **Capsule reports** — exit code, peak memory, wall time, kill reason

</td>
</tr>
</table>

---

## 📦 Install

> ZeptoCapsule is a library crate. Add it as a dependency:

```toml
[dependencies]
zeptocapsule = { path = "../zeptocapsule" }
```

Or build and run tests directly:

```bash
git clone https://github.com/qhkm/zeptocapsule.git
cd zeptocapsule
cargo test
```

---

## 🚀 Quick Start

```rust
use zeptocapsule::{create, CapsuleSpec, Isolation, ResourceLimits, WorkspaceConfig, SecurityProfile};
use std::collections::HashMap;

#[tokio::main]
async fn main() {
    // Create a capsule
    let spec = CapsuleSpec {
        isolation: Isolation::Process,
        security: SecurityProfile::Dev,
        limits: ResourceLimits {
            timeout_sec: 30,
            memory_mib: Some(512),
            cpu_quota: None,
            max_pids: None,
        },
        workspace: WorkspaceConfig {
            host_path: Some("/tmp/my-workspace".into()),
            guest_path: "/workspace".into(),
            size_mib: None,
        },
        ..Default::default()
    };

    let mut capsule = create(spec).unwrap();

    // Spawn a worker process inside the capsule
    let child = capsule.spawn(
        "/usr/bin/echo",
        &["hello from capsule"],
        HashMap::new(),
    ).unwrap();

    // Read output, send input via child.stdout, child.stdin
    // ...

    // Tear down and get report
    let report = capsule.destroy().unwrap();
    println!("Exit: {:?}, Wall time: {:?}", report.exit_code, report.wall_time);
}
```

---

## 🔒 Isolation Backends

### Process (`Isolation::Process`)

Plain `fork()` + `setrlimit()`. Works everywhere — macOS, Linux, any Unix.

- Wall-clock timeout via SIGKILL
- Memory/CPU/file-size limits via `setrlimit`
- No filesystem or network isolation
- **Best for:** development, trusted agents, macOS

### Namespace (`Isolation::Namespace`)

Linux user namespaces + cgroup v2. Container-level isolation without a container runtime.

- `CLONE_NEWUSER` + `CLONE_NEWPID` + `CLONE_NEWNS` + `CLONE_NEWIPC` + `CLONE_NEWUTS` + `CLONE_NEWNET`
- cgroup v2 enforcement: memory, CPU, PIDs
- Init shim (`zk-init`) bootstraps the guest environment
- Hardened mode adds `pivot_root` + seccomp-bpf
- **Best for:** production Linux, untrusted prompts, resource enforcement

### Firecracker (`Isolation::Firecracker`)

Full microVM via [Firecracker](https://firecracker-microvm.github.io/). Strongest isolation — separate kernel, separate address space.

- KVM hardware acceleration
- vsock (virtio sockets) for host ↔ guest stdio on ports 1001–1004
- ext4 workspace images — seeded from host, exported back after teardown
- Control channel for TERMINATE/KILL signals
- **Best for:** untrusted code execution, hard security boundaries, multi-tenant

---

## 🛡️ Security Profiles

| Profile | Available With | What It Adds |
|:--------|:---------------|:-------------|
| 🟢 **Dev** | Process | `setrlimit` + wall-clock timeout only |
| 🟡 **Standard** | Namespace, Firecracker | User namespaces + cgroup limits + init shim |
| 🔴 **Hardened** | Namespace, Firecracker | Standard + `pivot_root` + seccomp-bpf whitelist |

### Seccomp Whitelist (Hardened)

Architecture-aware (x86_64 + aarch64). Only these syscall groups are allowed:

- **I/O:** read, write, close, dup, pipe, poll, select
- **Memory:** mmap, mprotect, brk, munmap
- **Process:** clone, execve, exit, wait, getpid
- **Signals:** rt_sigaction, rt_sigprocmask, kill
- **Filesystem:** open, stat, access, getcwd, chdir
- **Socket:** socket, connect, bind, listen, accept, sendto, recvfrom

Everything else → SIGSYS kill.

---

## ⬇️ Automatic Fallback

ZeptoCapsule probes host capabilities at runtime and degrades gracefully:

```
Firecracker requested → KVM available? → ✅ Use Firecracker
                                        → ❌ Try namespace
Namespace requested  → User NS + cgroup v2? → ✅ Use namespace
                                              → ❌ Fall back to process
Process requested    → Always works
```

Configure explicit fallback chains:

```rust
let spec = CapsuleSpec {
    isolation: Isolation::Firecracker,
    security: SecurityProfile::Hardened,
    fallback: Some(vec![
        (Isolation::Namespace, SecurityProfile::Hardened),
        (Isolation::Namespace, SecurityProfile::Standard),
        (Isolation::Process, SecurityProfile::Dev),
    ]),
    ..Default::default()
};
```

The `CapsuleReport` tells you what actually ran:

```rust
let report = capsule.destroy().unwrap();
println!("Requested: Firecracker/Hardened");
println!("Actual: {:?}/{:?}", report.actual_isolation, report.actual_security);
```

---

## 🔍 Host Probing

```rust
use zeptocapsule::probe;

let caps = probe();
println!("Arch: {:?}", caps.arch);
println!("User namespaces: {}", caps.user_namespaces);
println!("cgroup v2: {}", caps.cgroup_v2);
println!("Seccomp: {}", caps.seccomp_filter);
println!("KVM: {}", caps.kvm);
println!("Firecracker: {:?}", caps.firecracker_bin);

let (max_iso, max_sec) = caps.max_supported();
println!("Max supported: {:?}/{:?}", max_iso, max_sec);
```

---

## 📖 API Reference

### Core

| Function | Description |
|:---------|:------------|
| `create(spec)` | Create a capsule from spec |
| `capsule.spawn(bin, args, env)` | Spawn a process inside the capsule |
| `capsule.kill(signal)` | Send Terminate or Kill signal |
| `capsule.destroy()` | Tear down capsule, return `CapsuleReport` |

### Types

| Type | Description |
|:-----|:------------|
| `CapsuleSpec` | Isolation level, limits, workspace, security profile |
| `CapsuleChild` | Spawned process handle with stdin/stdout/stderr |
| `CapsuleReport` | Exit code, wall time, peak memory, kill reason |
| `ResourceLimits` | Timeout, memory, CPU quota, max PIDs |
| `HostCapabilities` | Detected host features (KVM, namespaces, cgroups) |

### Errors

| Variant | When |
|:--------|:-----|
| `SpawnFailed` | Process/namespace/VM creation failed |
| `Transport` | stdio or vsock communication error |
| `CleanupFailed` | Teardown error (cgroup, workspace) |
| `InvalidState` | Wrong lifecycle state (e.g., destroy before spawn) |
| `NotSupported` | Requested isolation not available on this host |

---

## 🏗️ Architecture

```
ZeptoPM (orchestrator)
    │
    ▼
ZeptoCapsule
    │
    ├── probe()          → detect host capabilities
    ├── create(spec)     → pick backend + apply fallback
    │
    ├── ProcessBackend   → fork() + setrlimit
    ├── NamespaceBackend → clone(NEWUSER|NEWPID|...) + cgroup v2
    └── FirecrackerBackend → microVM + vsock + ext4 workspace
         │
         ├── zk-init (guest) → bootstrap FS, exec worker
         ├── vsock 1001-1004 → stdin/stdout/stderr/control
         └── workspace.ext4  → seed from host, export back
```

---

## 🤝 Contributing

```bash
# Run tests (process backend — works everywhere)
cargo test

# Run namespace tests (Linux only, needs privileges)
ZK_RUN_NAMESPACE_TESTS=1 cargo test

# Check Linux compilation from macOS
cargo check --target x86_64-unknown-linux-gnu
```

---

<div align="center">

## 📄 License

[Apache 2.0](LICENSE)

Made with 🦀 by [Kitakod Ventures](https://github.com/qhkm)

</div>
