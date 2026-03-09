# CLAUDE.md — ZeptoCapsule

## Project Overview

ZeptoCapsule is the thin sandbox layer in the Zepto stack.

Stack position:
- ZeptoPM — orchestration, supervision, retries, event interpretation
- ZeptoCapsule — capsule creation, process isolation, resource enforcement
- ZeptoClaw — worker runtime speaking its own protocol directly to ZeptoPM

## Current Structure

Single crate:
- `src/lib.rs` — public API
- `src/types.rs` — `CapsuleSpec`, `ResourceLimits`, `WorkspaceConfig`, reports
- `src/process.rs` — process backend for dev/macOS
- `src/namespace.rs` — Linux namespace backend
- `src/cgroup.rs` — cgroup v2 enforcement/observability
- `src/init_shim.rs` and `src/bin/zk-init.rs` — minimal init shim support

Historical redesign and migration notes remain under `docs/plans/`.

## Build Commands

```bash
cargo build
cargo test
cargo test -p zeptocapsule
cargo check --target x86_64-unknown-linux-gnu -p zeptocapsule
```

## Design Boundary

ZeptoCapsule owns mechanisms:
- capsule creation and teardown
- process spawning inside the capsule
- namespace / cgroup isolation
- wall-clock kill, signal delivery, cleanup
- raw stdin/stdout transport

ZeptoCapsule does not own:
- worker protocol
- heartbeat semantics
- retries or supervision policy
- job lifecycle meaning

## Key Design Docs

- `docs/plans/2026-03-08-kernel-redesign.md`
- `docs/plans/2026-03-08-kernel-redesign-impl.md`
