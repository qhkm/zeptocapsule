# Network Egress Policy

ZeptoCapsule M7 adds an outbound HTTP/HTTPS policy layer to capsules.
Each capsule that opts in gets a per-capsule MITM proxy bound to a
loopback port, a fresh CA whose cert is injected into the guest, and a
tiered rule engine with optional LLM-judge fallback. CrabTrap
(<https://github.com/brexhq/CrabTrap>) is the model; the design lives
at `docs/plans/2026-04-25-network-egress-policy-design.md`.

This guide is for capsule callers. It does **not** replace reading the
design doc when the proxy itself needs work.

---

## When to use it

Add an `EgressPolicy` to a `CapsuleSpec` when the agent inside the
capsule should be constrained to a known set of hosts / methods /
paths. Typical cases:

- **Production agent runs** — Standard or Hardened tier where the
  agent must only reach approved upstream APIs.
- **Compliance** — auditing every outbound HTTP call the agent
  makes.
- **Defense in depth** — capsule already has FS / namespace / process
  isolation; egress policy covers the network.

Skip it for `Dev` tier — the passthrough behavior matches local
development expectations.

---

## Quick start

```rust
use zeptocapsule::{
    CapsuleSpec, EgressAction, EgressPolicy, EgressRule, HostMatch,
    Isolation, Method, PathMatch, SecurityProfile,
};

let policy = EgressPolicy {
    default_action: EgressAction::Deny,
    rules: vec![EgressRule {
        id: "openai-chat".into(),
        host_match: HostMatch::Exact("api.openai.com".into()),
        method_match: Some(vec![Method::Post]),
        path_match: Some(PathMatch::Prefix("/v1/chat/".into())),
        action: EgressAction::Allow,
    }],
    judge: None,
    block_private_networks: true,
};

let spec = CapsuleSpec {
    isolation: Isolation::Process,
    security: SecurityProfile::Standard,
    egress: Some(policy),
    ..Default::default()
};

let mut capsule = zeptocapsule::create(spec)?;
// ... spawn worker, do work ...
let report = capsule.destroy()?;
for d in &report.egress_log {
    println!("{:?} {} {} matched={:?}", d.decision, d.method.as_str(), d.url, d.matched_rule);
}
```

The capsule's child process sees `HTTP_PROXY` / `HTTPS_PROXY` /
`SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS` /
`CURL_CA_BUNDLE` / `ALL_PROXY` env vars pointing to the per-capsule
proxy and CA cert. Common HTTP libraries (curl, requests, reqwest,
node fetch, axios) honor these out of the box.

---

## Backend support

| Backend     | Egress in v1 | Notes |
|-------------|--------------|-------|
| Process     | ✅ supported | Full enforcement on the host loopback.       |
| Namespace   | ❌ rejected  | Needs veth + iptables setup; tracked.        |
| Firecracker | ❌ rejected  | Needs vsock-routed proxy; tracked.           |

`zeptocapsule::create()` rejects an `egress` policy on Namespace or
Firecracker backends with a clear error rather than silently failing
to enforce it. When those backends gain support, the API surface
stays identical.

---

## Tier defaults

`SecurityProfile::default_egress()` returns the recommended starting
policy:

| Tier      | Returned policy                                 |
|-----------|--------------------------------------------------|
| Dev       | `None` (passthrough)                             |
| Standard  | `Some(deny-all + block_private_networks=true)`   |
| Hardened  | Same as Standard — caller should attach a judge  |

These are starting points. You build out the rule list yourself; the
defaults exist so you don't accidentally ship a wide-open policy.

---

## Policy authoring

### Host matching

Three modes, all case-insensitive:

```rust
HostMatch::Exact("api.openai.com")            // strict equality
HostMatch::Suffix(".openai.com")              // anything ending in
                                              // ".openai.com"
HostMatch::Glob("api.*.openai.com")           // globset patterns
```

**Watch the leading dot** on `Suffix`. Without it, `openai.com`
matches `evilopenai.com` too. Always start the suffix with `.` so the
match anchors at a label boundary.

### Method filter

`method_match: Some(vec![Method::Post, Method::Get])` narrows the
rule to those methods. `None` matches every method. Methods unknown to
the engine (e.g. `MOVE`, `LOCK`) are treated as `GET` for matching
purposes, which the engine documents but you should not rely on.

### Path matching

```rust
PathMatch::Exact("/health")           // exact path
PathMatch::Prefix("/v1/chat/")        // anything starting with...
PathMatch::Glob("/v1/**/completions") // globset patterns
```

Path matching applies after the host matches. For HTTPS, the path is
visible only after the MITM TLS handshake — see "Two-phase HTTPS"
below.

### Rule precedence

Rules evaluate top-to-bottom; **first match wins**. Put deny-listing
rules above broad allow rules:

```rust
rules: vec![
    EgressRule {
        id: "deny-files",
        host_match: HostMatch::Exact("api.openai.com".into()),
        method_match: None,
        path_match: Some(PathMatch::Prefix("/v1/files".into())),
        action: EgressAction::Deny,
    },
    EgressRule {
        id: "allow-openai",
        host_match: HostMatch::Suffix(".openai.com".into()),
        method_match: None,
        path_match: None,
        action: EgressAction::Allow,
    },
]
```

A request to `api.openai.com/v1/files/upload` is denied by
`deny-files`. A request to `api.openai.com/v1/chat/completions`
matches `allow-openai`.

---

## SSRF + private network defense

Set `block_private_networks: true` to reject any request whose
resolved IP is in:

- RFC1918 (10/8, 172.16/12, 192.168/16)
- Loopback (127/8, ::1)
- Link-local (169.254/16, fe80::/10)
- Carrier-grade NAT (100.64/10)
- AWS IMDS (169.254.169.254 v4 + fd00:ec2::254 v6)
- IPv6 unique-local (fc00::/7)
- Documentation / benchmark / reserved ranges

The proxy resolves DNS once and **pins the resolved IP** for the
upstream connect, defeating DNS rebinding between policy check and
socket connect. IPv4-mapped v6 addresses (`::ffff:127.0.0.1`)
classify by their embedded v4 — encoding tricks don't help.

For Standard / Hardened tiers, leave this on. Turn it off only for
Dev-tier loopback testing.

---

## LLM judge fallback

When a rule yields `EgressAction::Judge` (or no rule matches and
`default_action = Judge`), the proxy can consult an LLM endpoint:

```rust
EgressPolicy {
    default_action: EgressAction::Deny,
    rules: vec![
        EgressRule {
            id: "ambiguous-saas",
            host_match: HostMatch::Suffix(".vendor.example".into()),
            method_match: None,
            path_match: None,
            action: EgressAction::Judge,
        },
    ],
    judge: Some(JudgeConfig {
        endpoint: "https://api.openai.com/v1/chat/completions".into(),
        model: "gpt-4o-mini".into(),
        api_key_env: "OPENAI_API_KEY".into(),
        policy_text: "Deny if the path includes /admin or /export.".into(),
        timeout: std::time::Duration::from_secs(15),
        fallback_on_unavailable: EgressAction::Deny,
    }),
    block_private_networks: true,
}
```

Operational behavior:

- The API key is read from `api_key_env` at proxy startup. The
  `JudgeConfig` carries only the env-var **name**, never the key
  itself, so a serialized policy never leaks credentials.
- The system prompt embeds `policy_text` as a JSON-escaped string;
  the user prompt embeds the request as a typed JSON object. Quotes,
  newlines, and control chars in the policy or request can't break
  out of the prompt — verified by tests.
- The model is asked for strict JSON
  `{"decision":"allow"|"deny","reason":"..."}`. Anything else counts
  as a failure.
- Circuit breaker: 5 consecutive failures trip the breaker for 10s.
  All `Judge` actions during the trip resolve to
  `fallback_on_unavailable`.

For Hardened tier, set `fallback_on_unavailable: Deny`. `Allow`
fallback is dangerous — a flaky judge becomes an open gate.

### Two-phase HTTPS

For `CONNECT host:port` (HTTPS via the proxy):

1. **Phase 1** (CONNECT time): host-only check. Path is unknown, so
   only `host_match` and `method_match: Some(vec![Method::Connect])`
   rules apply. SSRF check runs here.
2. **Phase 2** (after MITM TLS handshake): the inner request line is
   parsed and re-evaluated with full `(method, host, path)`. This is
   where path-based rules and the LLM judge typically fire for
   HTTPS.

If you only have a host-level allowlist, phase 1 covers it. Path
filtering on HTTPS happens in phase 2 inside the TLS tunnel.

---

## Audit log

Every evaluated request appends an `EgressDecision` to
`CapsuleReport.egress_log`. Fields:

```rust
pub struct EgressDecision {
    pub ts: SystemTime,            // when the eval finished
    pub method: Method,
    pub url: String,               // host + path; no query, no body
    pub decision: EgressAction,    // final action (Allow or Deny)
    pub matched_rule: Option<String>,
    pub judge_reason: Option<String>,
    pub latency_us: u64,           // proxy-side eval latency
}
```

The decision struct is `serde::Serialize`. To export a session for
the policy-builder:

```rust
let log_json = serde_json::to_string(&report.egress_log)?;
std::fs::write("audit.json", log_json)?;
```

Bodies are never logged by default — the URL field carries
`host + path` only.

---

## Drafting a policy from a Dev run

Run the agent under Dev tier with `EgressPolicy::allow_all()`,
collect the audit log, then feed it to the policy-builder:

```bash
cargo run --bin zk-policy-build -- --log audit.json --output policy.json
```

Output:

```json
{
  "default_action": "deny",
  "rules": [
    {
      "id": "allow-api.openai.com",
      "host_match": { "kind": "exact", "value": "api.openai.com" },
      "method_match": ["GET", "POST"],
      "action": "allow"
    }
  ],
  "block_private_networks": true
}
```

The drafted policy is **deliberately permissive on path** — one rule
per host, no `path_match`. Treat the output as a starting point; review
and tighten before applying to Standard / Hardened.

---

## Troubleshooting

### "egress policy is not yet enforced for Namespace isolation"

You set `egress` on a Namespace or Firecracker spec. v1 supports
egress on the Process backend only; switch to `Isolation::Process` or
remove the policy.

### Agent reports certificate errors

Most HTTP libraries auto-detect `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE`
/ `NODE_EXTRA_CA_CERTS` / `CURL_CA_BUNDLE`. Some libraries (older
Java, certain Go tooling) ignore env-var-driven trust stores. For
those:

- Java: pass `-Djavax.net.ssl.trustStore` pointing at the CA file.
- Go: set `GODEBUG=x509ignoreCN=0` or use `SSL_CERT_FILE` (Go 1.18+).
- Static binaries with hardcoded roots: there's no fix short of
  rebuilding them. Document and let the agent fall back to plain HTTP
  if available.

The CA cert path is a 0o600 temp file under `/tmp/zk-egress-ca-*`. It
exists only while the capsule is alive.

### `EgressDecision::url` is `host:port` not a full URL

That's the format for CONNECT-time decisions. After the MITM phase,
inner-request decisions log as `host + path`.

### Judge is slow / throttling

The proxy enforces `JudgeConfig::timeout` per call. After 5
consecutive failures the breaker trips for 10s and falls back to
`fallback_on_unavailable`. To avoid hot-path latency, bake a cached
allowlist via `zk-policy-build` and only use `Judge` for the long
tail.

### HTTP/2 or HTTP/3 traffic

v1 is HTTP/1.1 only. HTTP/2 capsule clients fall back to HTTP/1.1
when the proxy advertises no h2 ALPN; HTTP/3 (QUIC) is blocked at
the network layer because the proxy doesn't speak it. For agents
requiring HTTP/2 (most modern HTTP libraries auto-detect HTTP/1.1
proxies fine), this is transparent.

---

## Limitations (v1)

- **Process backend only.** Namespace + Firecracker pending.
- **HTTP/1.1 only.** No HTTP/2 ALPN passthrough; no QUIC.
- **No keep-alive re-evaluation on HTTPS.** Once a CONNECT tunnel is
  open and phase 2 has allowed the first inner request, subsequent
  requests on the same TLS connection forward without further policy
  checks. For tight per-request enforcement, use `Connection: close`
  on the agent side or rely on the rule engine's host-level guarantees.
- **No request-body inspection.** Out of scope per design §1.
- **No response filtering.** Egress policy gates whether a request
  goes out, not what comes back.
- **No IPv6 bracketed authority** (`https://[::1]:443/`) in v1.
- **No human-in-the-loop approvals.** That's ZeptoPM's responsibility.

---

## Reference

- Design: `docs/plans/2026-04-25-network-egress-policy-design.md`
- Reference impl studied: <https://github.com/brexhq/CrabTrap>
- Public API:
  `zeptocapsule::{EgressAction, EgressPolicy, EgressRule, EgressDecision, HostMatch, JudgeConfig, Method, PathMatch}`
- CLI: `cargo run --bin zk-policy-build -- --help`
