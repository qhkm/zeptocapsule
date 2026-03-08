# ZeptoKernel — TODO & Roadmap

> Run `cargo test --workspace` after changes. Historical migration context lives in `docs/plans/`; the live implementation is the single crate under `src/`.

## Current Shape

ZeptoKernel is a thin sandbox library.

Implemented:
- `src/lib.rs` — public API
- `src/types.rs` — capsule spec, limits, report types
- `src/backend.rs` — backend-neutral capsule traits and raw pipe handles
- `src/process.rs` — process backend
- `src/namespace.rs` — Linux namespace backend
- `src/cgroup.rs` — cgroup v2 limits and basic observability
- `src/init_shim.rs` and `src/bin/zk-init.rs` — minimal init shim support
- `tests/process_backend.rs` — process backend coverage
- `tests/namespace_backend.rs` — Linux-only namespace coverage behind `ZK_RUN_NAMESPACE_TESTS=1`
- `default_init_binary()` — exported helper for ZeptoPM / deploy tooling

## Remaining TODO

- [ ] Run `scripts/test-linux.sh` on a privileged Linux/Docker host to execute the namespace runtime tests end-to-end
- [ ] Rewire ZeptoPM to depend only on `zeptokernel`
- [ ] Decide how ZeptoPM resolves and ships the `zk-init` binary path in dev, CI, and deployment
- [ ] Add Firecracker only after the thin API is proven in ZeptoPM

## Key Files

- `src/lib.rs`
- `src/types.rs`
- `src/backend.rs`
- `src/process.rs`
- `src/namespace.rs`
- `src/cgroup.rs`
- `src/init_shim.rs`
- `tests/process_backend.rs`
- `tests/namespace_backend.rs`

## Historical Docs

- `docs/plans/2026-03-08-kernel-redesign.md`
- `docs/plans/2026-03-08-kernel-redesign-impl.md`
