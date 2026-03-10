# ZeptoCapsule — TODO & Roadmap

> Run `cargo test --workspace` after changes. Historical migration context lives in `docs/plans/`; the live implementation is the single crate under `src/`.

## Current Shape

ZeptoCapsule is a thin sandbox library with three isolation backends (Process, Namespace, Firecracker), runtime capability probing, fallback chains, and seccomp hardening.

Implemented:
- `src/lib.rs` — public API, `create()` with fallback chain, `default_init_binary()`
- `src/types.rs` — `CapsuleSpec`, `ResourceLimits`, `CapsuleReport` (with `actual_isolation`, `actual_security`, `init_error`)
- `src/backend.rs` — backend-neutral capsule traits and raw pipe handles
- `src/process.rs` — process backend (dev/macOS)
- `src/namespace.rs` — Linux namespace backend with child diagnostic pipe
- `src/cgroup.rs` — cgroup v2 limits and basic observability
- `src/probe.rs` — host capability detection (namespaces, cgroup v2, seccomp, KVM, arch)
- `src/seccomp.rs` — seccomp-bpf syscall whitelist for Hardened profile (x86_64 + aarch64)
- `src/rootfs.rs` — minimal rootfs layout with bind mounts and pivot_root
- `src/firecracker.rs` — Firecracker microVM backend
- `src/firecracker_api.rs` — minimal HTTP/1.1 client over Unix socket
- `src/vsock.rs` — host-side vsock connector for Firecracker stdio
- `src/workspace_image.rs` — ext4 workspace image builder
- `src/init_shim.rs` and `src/bin/zk-init.rs` — init shim (supports both namespace and Firecracker modes)
- `tests/process_backend.rs` — process backend coverage
- `tests/namespace_backend.rs` — Linux-only namespace coverage behind `ZK_RUN_NAMESPACE_TESTS=1`
- `tests/firecracker_backend.rs` — Firecracker integration tests behind `ZK_RUN_FIRECRACKER_TESTS=1`
- `.github/workflows/ci.yml` — multi-distro CI (Ubuntu 22.04/24.04, aarch64 cross-check, clippy/fmt)

## Completed

- [x] Run namespace tests on Linux — verified on jawiat VPS (Ubuntu 24.04, kernel 6.8.0), all 5 integration tests pass
- [x] `zk-init` binary path resolution — `default_init_binary()` checks `ZEPTOCAPSULE_INIT_BINARY` env var, then `{exe_dir}/zk-init`
- [x] M6 Firecracker backend — full implementation with vsock stdio, ext4 workspace, control channel
- [x] Runtime robustness — capability probing, child diagnostic pipe, arch-aware seccomp, fallback chain, enhanced reporting
- [x] aarch64 cross-compile — verified clean `cargo check --target aarch64-unknown-linux-gnu`
- [x] CI pipeline — GitHub Actions with multi-distro testing, aarch64 check, clippy -D warnings
- [x] ZeptoPM integration — confirmed end-to-end on jawiat VPS: Process and Namespace capsules spawn workers, IPC works, CapsuleReport correct

## Remaining TODO

- [ ] Document guest rootfs/kernel artifact flow for Firecracker deployment (`scripts/build-fc-rootfs.sh` exists but no deployment guide)

## Key Files

Core API:
- `src/lib.rs`
- `src/types.rs`
- `src/backend.rs`

Backends:
- `src/process.rs`
- `src/namespace.rs`
- `src/firecracker.rs`

Support:
- `src/probe.rs`
- `src/cgroup.rs`
- `src/seccomp.rs`
- `src/rootfs.rs`
- `src/init_shim.rs`
- `src/firecracker_api.rs`
- `src/vsock.rs`
- `src/workspace_image.rs`

Tests:
- `tests/process_backend.rs`
- `tests/namespace_backend.rs`
- `tests/firecracker_backend.rs`

Scripts:
- `scripts/test-linux.sh` — Docker-based namespace test runner
- `scripts/test-firecracker.sh` — Docker+KVM Firecracker test runner
- `scripts/build-fc-rootfs.sh` — Alpine minirootfs builder

## Historical Docs

- `docs/plans/2026-03-08-kernel-redesign.md`
- `docs/plans/2026-03-08-kernel-redesign-impl.md`
- `docs/plans/2026-03-08-m6-firecracker-backend-design.md`
- `docs/plans/2026-03-08-m6-firecracker-backend-impl.md`
- `docs/plans/2026-03-09-runtime-robustness-design.md`
- `docs/plans/2026-03-09-runtime-robustness-impl.md`
