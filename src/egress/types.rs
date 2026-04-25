use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// What to do with an outbound request.
///
/// `Judge` defers to the optional LLM judge configured in [`EgressPolicy::judge`].
/// If no judge is configured, the engine treats `Judge` as the policy's
/// `default_action`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressAction {
    Allow,
    Deny,
    Judge,
}

/// HTTP methods we recognize in policy rules.
///
/// Stored as a typed enum (not a string) so policy authors get compile-time
/// safety in Rust callers. Wire format is `UPPERCASE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Connect,
    Trace,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Patch => "PATCH",
            Method::Head => "HEAD",
            Method::Options => "OPTIONS",
            Method::Connect => "CONNECT",
            Method::Trace => "TRACE",
        }
    }

    /// Parse a wire-format method ("GET", "post", etc.). Returns `None` for
    /// unknown methods so the caller can decide whether to deny or pass.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Some(Method::Get),
            "POST" => Some(Method::Post),
            "PUT" => Some(Method::Put),
            "DELETE" => Some(Method::Delete),
            "PATCH" => Some(Method::Patch),
            "HEAD" => Some(Method::Head),
            "OPTIONS" => Some(Method::Options),
            "CONNECT" => Some(Method::Connect),
            "TRACE" => Some(Method::Trace),
            _ => None,
        }
    }
}

/// Host-name matcher. Glob patterns use the `globset` crate's syntax
/// (e.g. `api.*.example.com`). Matching is case-insensitive on the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum HostMatch {
    /// Match the host exactly (case-insensitive).
    Exact(String),
    /// Match if the host ends with this suffix. A leading dot is recommended
    /// (`.example.com`) so `evil-example.com` does not match.
    Suffix(String),
    /// Match against a glob pattern.
    Glob(String),
}

/// Path matcher (path component only, no query string).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PathMatch {
    Prefix(String),
    Exact(String),
    Glob(String),
}

/// One policy rule. Rules are evaluated top-to-bottom; first match wins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRule {
    /// Stable identifier surfaced in the audit log.
    pub id: String,
    pub host_match: HostMatch,
    /// `None` matches any method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_match: Option<Vec<Method>>,
    /// `None` matches any path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_match: Option<PathMatch>,
    pub action: EgressAction,
}

/// Configuration for the optional LLM judge.
///
/// The API key is referenced by environment-variable name only — the key
/// itself never lives in a [`CapsuleSpec`] and never gets serialized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JudgeConfig {
    /// OpenAI-compatible chat-completions endpoint.
    pub endpoint: String,
    pub model: String,
    /// Name of the env var holding the API key.
    pub api_key_env: String,
    /// Natural-language policy. JSON-escaped before being inlined into the
    /// judge prompt — defends against prompt injection from request bodies.
    pub policy_text: String,
    #[serde(with = "humantime_serde", default = "default_judge_timeout")]
    pub timeout: Duration,
    /// Action when the judge times out, errors, or trips the circuit breaker.
    pub fallback_on_unavailable: EgressAction,
}

fn default_judge_timeout() -> Duration {
    Duration::from_secs(30)
}

// `humantime_serde` is a tiny shim. Pull it in only when serde support for
// `Duration` is used. Avoid adding the crate by inlining the minimal serializer
// we need — seconds as a `u64`.
mod humantime_serde {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}

/// Top-level egress policy attached to a [`crate::CapsuleSpec`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressPolicy {
    pub default_action: EgressAction,
    #[serde(default)]
    pub rules: Vec<EgressRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judge: Option<JudgeConfig>,
    /// Block RFC1918 / loopback / link-local / cloud-metadata destinations
    /// regardless of `rules`. Run before rule evaluation.
    #[serde(default)]
    pub block_private_networks: bool,
}

impl EgressPolicy {
    /// Convenience: deny-by-default, no rules, block private networks.
    pub fn deny_all() -> Self {
        Self {
            default_action: EgressAction::Deny,
            rules: Vec::new(),
            judge: None,
            block_private_networks: true,
        }
    }

    /// Convenience: allow-by-default, no rules, no SSRF guard. The Dev-tier
    /// passthrough.
    pub fn allow_all() -> Self {
        Self {
            default_action: EgressAction::Allow,
            rules: Vec::new(),
            judge: None,
            block_private_networks: false,
        }
    }
}

/// One audit-log entry: a single evaluated request and its outcome.
#[derive(Debug, Clone)]
pub struct EgressDecision {
    pub ts: SystemTime,
    pub method: Method,
    /// `host + path`. Query string and body intentionally omitted (PII risk).
    pub url: String,
    pub decision: EgressAction,
    pub matched_rule: Option<String>,
    pub judge_reason: Option<String>,
    pub latency_us: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_round_trip() {
        for m in [
            Method::Get,
            Method::Post,
            Method::Put,
            Method::Delete,
            Method::Patch,
            Method::Head,
            Method::Options,
            Method::Connect,
            Method::Trace,
        ] {
            assert_eq!(Method::parse(m.as_str()), Some(m));
        }
        assert_eq!(Method::parse("get"), Some(Method::Get));
        assert_eq!(Method::parse("Foo"), None);
    }

    #[test]
    fn deny_all_policy_is_locked_down() {
        let p = EgressPolicy::deny_all();
        assert_eq!(p.default_action, EgressAction::Deny);
        assert!(p.rules.is_empty());
        assert!(p.judge.is_none());
        assert!(p.block_private_networks);
    }

    #[test]
    fn allow_all_policy_is_passthrough() {
        let p = EgressPolicy::allow_all();
        assert_eq!(p.default_action, EgressAction::Allow);
        assert!(!p.block_private_networks);
    }

    #[test]
    fn policy_serde_round_trip() {
        let p = EgressPolicy {
            default_action: EgressAction::Deny,
            rules: vec![EgressRule {
                id: "openai".into(),
                host_match: HostMatch::Suffix(".openai.com".into()),
                method_match: Some(vec![Method::Post]),
                path_match: Some(PathMatch::Prefix("/v1/".into())),
                action: EgressAction::Allow,
            }],
            judge: Some(JudgeConfig {
                endpoint: "http://localhost:9000/v1/chat/completions".into(),
                model: "local".into(),
                api_key_env: "ZK_JUDGE_KEY".into(),
                policy_text: "deny PII exfil".into(),
                timeout: Duration::from_secs(15),
                fallback_on_unavailable: EgressAction::Deny,
            }),
            block_private_networks: true,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: EgressPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn judge_config_never_holds_api_key_inline() {
        // Documented invariant: the field name is api_key_env, never api_key.
        // This test exists to make a future rename impossible without touching
        // it (and re-considering the security posture).
        let j = JudgeConfig {
            endpoint: "x".into(),
            model: "m".into(),
            api_key_env: "Z".into(),
            policy_text: "p".into(),
            timeout: Duration::from_secs(1),
            fallback_on_unavailable: EgressAction::Deny,
        };
        let json = serde_json::to_string(&j).unwrap();
        assert!(json.contains("api_key_env"));
        assert!(!json.contains("\"api_key\""));
    }

    #[test]
    fn host_match_serde_uses_kind_value_form() {
        let h = HostMatch::Suffix(".example.com".into());
        let json = serde_json::to_string(&h).unwrap();
        assert!(json.contains("\"kind\":\"suffix\""));
        assert!(json.contains("\"value\":\".example.com\""));
    }
}
