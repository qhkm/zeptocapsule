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
- [x] Firecracker deployment guide — `docs/firecracker-deployment.md` covers kernel, rootfs, zk-init build/deploy/verify

## Remaining TODO

### Network Egress Policy Layer (M7)

> **Motivation:** ZeptoCapsule today isolates filesystem, namespace, and process resources, but agent outbound HTTP/HTTPS is not policy-gated. CrabTrap (https://github.com/brexhq/CrabTrap) is a focused egress proxy that demonstrates the right shape: deterministic rules first, LLM-judge fallback, full audit trail. Pull those ideas into ZeptoCapsule as a first-class network policy layer so capsules can constrain *what* an agent talks to, not just *how* it runs.
>
> Design doc: `docs/plans/2026-04-25-network-egress-policy-design.md`
>
> Reference implementation to study: https://github.com/brexhq/CrabTrap (Go, MIT-style scope).

- [x] **Egress policy spec** — `EgressPolicy`, `EgressRule`, `EgressAction`, `HostMatch`, `PathMatch`, `Method`, `JudgeConfig`, `EgressDecision` defined in `src/egress/types.rs` with serde derives. `CapsuleSpec.egress` and `CapsuleReport.egress_log` wired. `SecurityProfile::default_egress()` returns per-tier starting policy
- [x] **In-capsule HTTP/HTTPS interceptor** — `src/egress/proxy.rs` + `src/egress/ca.rs`. Loopback proxy with TLS MITM, per-capsule CA via `rcgen` (aws_lc_rs), leaf cert cache, IP-pinned upstream connect. HTTP/1.1 only in v1. 9 integration-style tests
- [x] **Static rule engine** — `src/egress/rules.rs`: `CompiledPolicy::compile()` + `evaluate()`. Exact/Suffix/Glob host matching (case-insensitive), method filter, Exact/Prefix/Glob path matching. First-match-wins. 13 unit tests
- [x] **SSRF + DNS-rebind defense** — `src/egress/ssrf.rs`: `classify_ip()` covers RFC1918, loopback, link-local, CGN (100.64/10), AWS IMDS v4+v6, IPv6 ULA, IPv4-mapped bypass guard. DNS pinning happens at the proxy on resolve. 16 unit tests
- [x] **LLM-judge fallback** — `src/egress/judge.rs`: OpenAI-compatible chat-completion client over the existing tokio + tokio-rustls stack, prompt-injection-hardened (policy text JSON-escaped, request fields as typed JSON), strict-JSON response schema validation, 5-fail/10s circuit breaker. 14 unit tests. Wired into proxy via `ProxyConfig::judge`
- [x] **Audit trail** — `EgressDecision` (serde-serializable, ts as Unix-epoch microseconds) emitted per request via mpsc channel, drained into `CapsuleReport.egress_log` on `destroy()`
- [x] **Auto policy-builder** — `cargo run --bin zk-policy-build -- --log audit.json --output policy.json`. Drafts a deny-by-default policy with one Allow rule per observed host, methods unioned. 8 unit tests
- [x] **Process backend integration** — `ProcessCapsule` spawns the proxy + writes 0o600 CA temp file at create, injects `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`NODE_EXTRA_CA_CERTS`/`CURL_CA_BUNDLE`, drains audit log + cleans temp file on destroy. 2 integration tests
- [x] **Namespace backend integration** — `src/egress/netns.rs` + `src/namespace.rs`. Per-capsule veth in `169.254.32.0/24` /30 subnets, proxy bound on host-side veth IP, no NAT path means proxy is the only egress. `nsenter` configures guest side from parent (works in Hardened pivot_root mode). 4 unit tests + 2 ZK_RUN_NAMESPACE_TESTS-gated integration tests. Verified end-to-end in privileged Docker (175 tests pass on Linux)
- [ ] **Firecracker backend integration** — deferred. v1 fails capsule creation with a clear error if `egress` is set. Needs vsock-routed proxy listener + guest `zk-init` iptables shim + CA cert dropped into rootfs at build time
- [x] **Docs** — `docs/network-egress.md` covering quick start, backend matrix, policy authoring, SSRF, LLM judge, audit log, policy-builder, troubleshooting, v1 limits

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
