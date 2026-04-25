# Network Egress Policy Design (M7)

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Status:** Design draft, 2026-04-25
**Goal:** Add a first-class outbound HTTP/HTTPS policy layer to ZeptoCapsule so capsules can constrain *what hosts and APIs* an agent reaches, with deterministic rules first and an optional LLM-judge fallback for ambiguous cases.

**Why now:** ZeptoCapsule isolates FS, namespaces, processes, and resources — but a capsule today can still call any URL on the public internet. For Standard/Hardened tiers, that's an open hole. CrabTrap (https://github.com/brexhq/CrabTrap, Go, by Brex) demonstrates the proxy-with-LLM-judge model in production. Rather than ship CrabTrap as a sidecar, fold the model directly into ZeptoCapsule so it's available to every capsule by default and aligned with the local-first ZeptoStack thesis.

**Reference:** https://github.com/brexhq/CrabTrap — read the README, QUICKSTART, and the proxy/judge source files before implementing. Mirror their TLS-termination, prompt-injection-hardening, and circuit-breaker patterns.

---

## 1. Scope

In:
- Outbound HTTP and HTTPS from inside the capsule, intercepted at a local proxy
- Static rule engine (prefix / exact / glob, method filter)
- SSRF and DNS-rebinding defense
- Optional LLM-judge fallback with circuit breaker
- Per-capsule audit log surfaced in `CapsuleReport`
- Tier-aware defaults (Dev / Standard / Hardened)

Out (for v1):
- Inbound traffic — capsules don't expose ports to the host today
- WebSocket inspection beyond connect-time policy check
- Response body filtering
- Human-in-the-loop approval queues (defer to ZeptoPM)
- Cross-capsule traffic (handled by namespace networking, not policy)

---

## 2. Public API additions

```rust
// src/types.rs

pub struct EgressPolicy {
    pub default_action: EgressAction,        // Allow | Deny | Judge
    pub rules: Vec<EgressRule>,              // evaluated top-to-bottom
    pub judge: Option<JudgeConfig>,          // None disables LLM fallback
    pub block_private_networks: bool,        // RFC1918 + loopback + link-local + metadata
}

pub struct EgressRule {
    pub id: String,
    pub host_match: HostMatch,               // Exact | Suffix | Glob
    pub method_match: Option<Vec<Method>>,
    pub path_match: Option<PathMatch>,       // Prefix | Exact | Glob
    pub action: EgressAction,
}

pub enum EgressAction { Allow, Deny, Judge }

pub struct JudgeConfig {
    pub endpoint: String,                    // OpenAI-compatible chat-completions URL
    pub model: String,
    pub api_key_env: String,                 // env var name; never inline the key
    pub policy_text: String,                 // natural-language rules, JSON-escaped
    pub timeout: Duration,                   // default 30s
    pub fallback_on_unavailable: EgressAction, // Deny | Allow (default Deny)
}
```

`CapsuleSpec` gains `egress: Option<EgressPolicy>`. `None` preserves today's behavior (passthrough), so the change is non-breaking.

`CapsuleReport` gains `egress_log: Vec<EgressDecision>` (request, decision, rule_id or judge_reason, timestamp).

---

## 3. Tier-aware defaults

Wired in `SecurityProfile::default_egress()`:

| Tier | `default_action` | `block_private_networks` | Judge |
|---|---|---|---|
| Dev | Allow | false | None |
| Standard | Deny | true | optional |
| Hardened | Deny | true | required, fallback=Deny |

Standard tier with no rules = full deny (forces explicit allowlist). Standard with explicit rules + judge = CrabTrap-equivalent posture.

---

## 4. Interceptor architecture

Per-backend approach — same policy engine, different transport plumbing:

**Process backend:**
- Spawn a per-capsule proxy task on a loopback port (random ephemeral)
- Inject `HTTP_PROXY` and `HTTPS_PROXY` into capsule env
- Inject generated CA cert path via `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS`
- TLS MITM: per-host leaf cert signed by capsule-scoped CA (CA destroyed at capsule teardown)

**Namespace backend:**
- Same as Process, but proxy lives in host net namespace; capsule has its own net namespace with a veth pair to host
- iptables/nftables in capsule netns: REDIRECT 80/443 to host proxy via veth
- DNS resolution forced through proxy (no direct resolver in capsule)

**Firecracker backend:**
- Proxy on host listens on vsock CID/port pair
- Guest `zk-init` configures iptables to route 80/443 through a vsock-aware shim
- Same CA injection model — CA cert dropped into guest rootfs at build time

Engine is one shared module (`src/egress/`); backends only differ in how bytes get to it.

---

## 5. Static rule engine

Evaluation order:
1. SSRF check (if `block_private_networks` true) — resolve DNS, reject if resolved IP is RFC1918 / 127.0.0.0/8 / 169.254.0.0/16 / metadata IPs (`169.254.169.254`, fd00:ec2::254). DNS pinned: same IP used for the actual request.
2. Walk `rules` top-to-bottom. First match wins.
3. If no rule matches → `default_action`.
4. If action is `Judge` and `judge` is `None` → treat as `default_action`.

Match semantics mirror CrabTrap:
- `HostMatch::Exact("api.openai.com")`
- `HostMatch::Suffix(".openai.com")`
- `HostMatch::Glob("api.*.openai.com")`
- `PathMatch::Prefix("/v1/chat/")`
- `PathMatch::Glob("/v1/**/completions")`

---

## 6. LLM judge

Lifted from CrabTrap with adjustments for local-first:

- JSON-encode the full request (method, host, path, headers, body excerpt), JSON-escape the `policy_text` — defends against prompt injection from request bodies
- Prompt template returns strict JSON: `{"decision": "allow|deny", "reason": "..."}`
- Reject any non-JSON or schema-violating response → fall through to `fallback_on_unavailable`
- Circuit breaker: 5 consecutive failures → trip for 10s, all calls during trip use `fallback_on_unavailable`
- Default endpoint can be local (e.g. ZeptoLM when it ships) or remote OpenAI-compatible

---

## 7. Audit log

Append-only per-capsule, in-memory during run, flushed to `CapsuleReport.egress_log` on teardown. Optional streaming to ZeptoPM via existing report channel for long-running capsules.

`EgressDecision`:
```rust
pub struct EgressDecision {
    pub ts: SystemTime,
    pub method: Method,
    pub url: String,             // host + path; no body
    pub decision: EgressAction,
    pub matched_rule: Option<String>,
    pub judge_reason: Option<String>,
    pub latency_us: u64,
}
```

No bodies logged by default (PII risk). Opt-in via `JudgeConfig` debug flag.

---

## 8. Policy-builder (auto-draft)

Offline tool: `cargo run --bin zk-policy-build -- --log <path>`

Reads exported audit logs from a Dev-tier capsule run, clusters destinations, drafts a minimal `EgressPolicy` covering observed traffic. Output is human-edited before being applied to Standard/Hardened tiers. Mirrors CrabTrap's policy-builder.

---

## 9. Implementation order

1. `src/egress/types.rs` — types + serde
2. `src/egress/rules.rs` — pure rule engine + tests (no I/O)
3. `src/egress/ssrf.rs` — private network blocker + DNS pinner
4. `src/egress/proxy.rs` — minimal HTTP/HTTPS proxy with TLS MITM
5. Process backend integration + tests
6. Namespace backend integration + tests
7. `src/egress/judge.rs` — LLM judge client + circuit breaker
8. Firecracker backend integration + tests
9. `bin/zk-policy-build.rs` — auto policy-builder
10. `docs/network-egress.md` — user-facing docs

Each step ships with tests and a green `cargo test --workspace`.

---

## 10. Open questions

- **CA trust scope:** Per-capsule CA (destroyed at teardown) is safest. Confirm guest tooling honors `SSL_CERT_FILE` for all common HTTP libs (curl, requests, reqwest, node fetch). If not, fall back to bind-mounting the CA into `/etc/ssl/certs/` for the namespace backend.
- **HTTP/2 + HTTP/3:** v1 supports HTTP/1.1 only. HTTP/2 requires ALPN handling at the proxy. HTTP/3 (QUIC) is harder — likely deny in v1.
- **Performance:** Proxy adds latency. For Hardened tier this is acceptable; for Dev it should be opt-in.
- **Judge cost:** LLM calls per ambiguous request can blow up cost. Cache (URL+method → decision) with short TTL inside the judge module.

---

## 11. Non-goals (explicitly)

- Not building a full WAF
- Not inspecting response bodies
- Not modifying request bodies
- Not enforcing per-user quotas (that's ZeptoPM's budget layer)
- Not a CrabTrap drop-in replacement — we keep scope tight to capsule-local enforcement
