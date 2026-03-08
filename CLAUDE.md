# CLAUDE.md — ZeptoKernel

## Project Overview

ZeptoKernel is the secure per-worker execution capsule for the Zepto stack. It wraps a single ZeptoClaw worker in an isolated runtime with filesystem, process, network, and resource boundaries.

**Stack position:**
- **ZeptoPM** — orchestrates jobs, workers, retries, dependency graphs
- **ZeptoKernel** — provides the isolated runtime envelope (this project)
- **ZeptoClaw** — the worker binary that performs the actual AI task

## Workspace Structure

Cargo workspace with 3 crates:

| Crate | Purpose |
|-------|---------|
| `zk-proto` | Shared protocol types — HostCommand, GuestEvent, JobSpec, wire helpers |
| `zk-host` | Host supervisor — launches capsules, monitors heartbeats, enforces limits |
| `zk-guest` | Guest agent — runs inside capsule, bridges host commands to worker binary |

## Build Commands

```bash
cargo build                    # Build all crates
cargo test                     # Run all tests
cargo build -p zk-proto        # Build only protocol crate
cargo test -p zk-proto         # Test only protocol crate
```

## Architecture

### Protocol (`zk-proto`)
- `HostCommand` — commands from host to guest (StartJob, CancelJob, Ping, Shutdown)
- `GuestEvent` — events from guest to host (Ready, Started, Heartbeat, Progress, ArtifactProduced, Completed, Failed, Cancelled)
- `JobSpec` — full job specification including resource limits, env, workspace config
- Wire format: JSON lines (one JSON object per line, newline-terminated)

### Host Supervisor (`zk-host`)
- `Backend` trait — abstracts isolation mechanism (namespace sandbox vs microVM)
- `CapsuleHandle` trait — control interface for a running capsule
- `Supervisor` — manages multiple capsules, tracks heartbeats, detects stale workers
- `Capsule` — runtime state for one execution capsule

### Guest Agent (`zk-guest`)
- Runs as the control process inside the capsule
- Reads HostCommands from control channel (stdin for dev, vsock for production)
- Launches ZeptoClaw worker binary
- Forwards worker events back to host

## Design Principles

1. **Default deny** — no network, no broad mounts, no secrets unless explicitly granted
2. **Single responsibility** — one worker per capsule, ZeptoPM orchestrates
3. **Disposable runtime** — capsules are easy to destroy and recreate
4. **Backend-agnostic** — same protocol works across namespace sandbox and microVM

## Key Design Docs

- `docs/plans/2026-03-08-zeptokernel-design.md` — full design spec
