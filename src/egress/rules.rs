//! Pure deterministic rule engine.
//!
//! No I/O, no async, no DNS — given a parsed request and an
//! [`EgressPolicy`], return what to do. The proxy layer (later milestone)
//! drives this; tests can drive it directly.

use globset::{Glob, GlobMatcher};

use super::types::{EgressAction, EgressPolicy, EgressRule, HostMatch, Method, PathMatch};

/// A request as the proxy sees it after parsing the request line.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub method: Method,
    /// Host without port. Case-insensitive matching is applied here.
    pub host: &'a str,
    /// Path with leading slash, no query string.
    pub path: &'a str,
}

/// Outcome of evaluating one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub action: EgressAction,
    /// `Some(id)` if a rule matched, `None` if `default_action` was taken.
    pub matched_rule: Option<String>,
}

/// Errors compiling a policy's glob patterns.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("rule '{rule_id}': invalid host glob '{pattern}': {source}")]
    HostGlob {
        rule_id: String,
        pattern: String,
        #[source]
        source: globset::Error,
    },
    #[error("rule '{rule_id}': invalid path glob '{pattern}': {source}")]
    PathGlob {
        rule_id: String,
        pattern: String,
        #[source]
        source: globset::Error,
    },
}

/// Pre-compiled form of an [`EgressPolicy`]. Globs are compiled once;
/// evaluating a request is allocation-free past this point.
#[derive(Debug)]
pub struct CompiledPolicy {
    default_action: EgressAction,
    rules: Vec<CompiledRule>,
}

#[derive(Debug)]
struct CompiledRule {
    id: String,
    host: CompiledHost,
    methods: Option<Vec<Method>>,
    path: Option<CompiledPath>,
    action: EgressAction,
}

#[derive(Debug)]
enum CompiledHost {
    Exact(String),
    Suffix(String),
    Glob(GlobMatcher),
}

#[derive(Debug)]
enum CompiledPath {
    Exact(String),
    Prefix(String),
    Glob(GlobMatcher),
}

impl CompiledPolicy {
    pub fn compile(policy: &EgressPolicy) -> Result<Self, CompileError> {
        let mut rules = Vec::with_capacity(policy.rules.len());
        for r in &policy.rules {
            rules.push(compile_rule(r)?);
        }
        Ok(Self {
            default_action: policy.default_action,
            rules,
        })
    }

    pub fn evaluate(&self, req: &Request<'_>) -> Evaluation {
        for r in &self.rules {
            if rule_matches(r, req) {
                return Evaluation {
                    action: r.action,
                    matched_rule: Some(r.id.clone()),
                };
            }
        }
        Evaluation {
            action: self.default_action,
            matched_rule: None,
        }
    }
}

fn compile_rule(r: &EgressRule) -> Result<CompiledRule, CompileError> {
    let host = match &r.host_match {
        HostMatch::Exact(s) => CompiledHost::Exact(s.to_ascii_lowercase()),
        HostMatch::Suffix(s) => CompiledHost::Suffix(s.to_ascii_lowercase()),
        HostMatch::Glob(pat) => {
            let glob =
                Glob::new(&pat.to_ascii_lowercase()).map_err(|e| CompileError::HostGlob {
                    rule_id: r.id.clone(),
                    pattern: pat.clone(),
                    source: e,
                })?;
            CompiledHost::Glob(glob.compile_matcher())
        }
    };
    let path = match &r.path_match {
        None => None,
        Some(PathMatch::Exact(s)) => Some(CompiledPath::Exact(s.clone())),
        Some(PathMatch::Prefix(s)) => Some(CompiledPath::Prefix(s.clone())),
        Some(PathMatch::Glob(pat)) => {
            let glob = Glob::new(pat).map_err(|e| CompileError::PathGlob {
                rule_id: r.id.clone(),
                pattern: pat.clone(),
                source: e,
            })?;
            Some(CompiledPath::Glob(glob.compile_matcher()))
        }
    };
    Ok(CompiledRule {
        id: r.id.clone(),
        host,
        methods: r.method_match.clone(),
        path,
        action: r.action,
    })
}

fn rule_matches(rule: &CompiledRule, req: &Request<'_>) -> bool {
    if !host_matches(&rule.host, req.host) {
        return false;
    }
    if let Some(ms) = &rule.methods
        && !ms.contains(&req.method)
    {
        return false;
    }
    if let Some(p) = &rule.path
        && !path_matches(p, req.path)
    {
        return false;
    }
    true
}

fn host_matches(m: &CompiledHost, host: &str) -> bool {
    let host_lc = host.to_ascii_lowercase();
    match m {
        CompiledHost::Exact(s) => host_lc == *s,
        CompiledHost::Suffix(s) => host_lc.ends_with(s.as_str()),
        CompiledHost::Glob(g) => g.is_match(&host_lc),
    }
}

fn path_matches(m: &CompiledPath, path: &str) -> bool {
    match m {
        CompiledPath::Exact(s) => path == s,
        CompiledPath::Prefix(s) => path.starts_with(s.as_str()),
        CompiledPath::Glob(g) => g.is_match(path),
    }
}

/// Convenience wrapper: compile + evaluate in one shot. Recompiles every call,
/// so callers on a hot path should hold a [`CompiledPolicy`] instead.
pub fn evaluate(policy: &EgressPolicy, req: &Request<'_>) -> Result<Evaluation, CompileError> {
    Ok(CompiledPolicy::compile(policy)?.evaluate(req))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(
        id: &str,
        host: HostMatch,
        methods: Option<Vec<Method>>,
        path: Option<PathMatch>,
        action: EgressAction,
    ) -> EgressRule {
        EgressRule {
            id: id.into(),
            host_match: host,
            method_match: methods,
            path_match: path,
            action,
        }
    }

    fn req<'a>(method: Method, host: &'a str, path: &'a str) -> Request<'a> {
        Request { method, host, path }
    }

    #[test]
    fn no_rules_uses_default_action() {
        let p = EgressPolicy {
            default_action: EgressAction::Deny,
            rules: vec![],
            judge: None,
            block_private_networks: false,
        };
        let e = evaluate(&p, &req(Method::Get, "x.com", "/")).unwrap();
        assert_eq!(e.action, EgressAction::Deny);
        assert_eq!(e.matched_rule, None);
    }

    #[test]
    fn exact_host_match() {
        let p = EgressPolicy {
            default_action: EgressAction::Deny,
            rules: vec![rule(
                "r1",
                HostMatch::Exact("api.openai.com".into()),
                None,
                None,
                EgressAction::Allow,
            )],
            judge: None,
            block_private_networks: false,
        };
        let e = evaluate(&p, &req(Method::Get, "api.openai.com", "/v1/x")).unwrap();
        assert_eq!(e.action, EgressAction::Allow);
        assert_eq!(e.matched_rule.as_deref(), Some("r1"));

        let e = evaluate(&p, &req(Method::Get, "evil.com", "/")).unwrap();
        assert_eq!(e.action, EgressAction::Deny);
        assert!(e.matched_rule.is_none());
    }

    #[test]
    fn host_match_is_case_insensitive() {
        let p = EgressPolicy {
            default_action: EgressAction::Deny,
            rules: vec![rule(
                "r1",
                HostMatch::Exact("API.OpenAI.com".into()),
                None,
                None,
                EgressAction::Allow,
            )],
            judge: None,
            block_private_networks: false,
        };
        let e = evaluate(&p, &req(Method::Get, "api.openai.com", "/")).unwrap();
        assert_eq!(e.action, EgressAction::Allow);
    }

    #[test]
    fn suffix_match_does_not_swallow_lookalikes() {
        // Bug class: ".openai.com" matching "evilopenai.com". The leading dot
        // in the suffix prevents this; without it, a misconfiguration could
        // leak.
        let p = EgressPolicy {
            default_action: EgressAction::Deny,
            rules: vec![rule(
                "r1",
                HostMatch::Suffix(".openai.com".into()),
                None,
                None,
                EgressAction::Allow,
            )],
            judge: None,
            block_private_networks: false,
        };
        assert_eq!(
            evaluate(&p, &req(Method::Get, "api.openai.com", "/"))
                .unwrap()
                .action,
            EgressAction::Allow
        );
        assert_eq!(
            evaluate(&p, &req(Method::Get, "evilopenai.com", "/"))
                .unwrap()
                .action,
            EgressAction::Deny
        );
    }

    #[test]
    fn glob_host_match() {
        let p = EgressPolicy {
            default_action: EgressAction::Deny,
            rules: vec![rule(
                "r1",
                HostMatch::Glob("api.*.openai.com".into()),
                None,
                None,
                EgressAction::Allow,
            )],
            judge: None,
            block_private_networks: false,
        };
        assert_eq!(
            evaluate(&p, &req(Method::Get, "api.eu.openai.com", "/"))
                .unwrap()
                .action,
            EgressAction::Allow
        );
        assert_eq!(
            evaluate(&p, &req(Method::Get, "api.openai.com", "/"))
                .unwrap()
                .action,
            EgressAction::Deny
        );
    }

    #[test]
    fn method_filter_narrows_match() {
        let p = EgressPolicy {
            default_action: EgressAction::Deny,
            rules: vec![rule(
                "r1",
                HostMatch::Exact("api.x.com".into()),
                Some(vec![Method::Post]),
                None,
                EgressAction::Allow,
            )],
            judge: None,
            block_private_networks: false,
        };
        assert_eq!(
            evaluate(&p, &req(Method::Post, "api.x.com", "/"))
                .unwrap()
                .action,
            EgressAction::Allow
        );
        assert_eq!(
            evaluate(&p, &req(Method::Get, "api.x.com", "/"))
                .unwrap()
                .action,
            EgressAction::Deny
        );
    }

    #[test]
    fn path_prefix_match() {
        let p = EgressPolicy {
            default_action: EgressAction::Deny,
            rules: vec![rule(
                "chat",
                HostMatch::Exact("api.openai.com".into()),
                None,
                Some(PathMatch::Prefix("/v1/chat/".into())),
                EgressAction::Allow,
            )],
            judge: None,
            block_private_networks: false,
        };
        assert_eq!(
            evaluate(
                &p,
                &req(Method::Post, "api.openai.com", "/v1/chat/completions")
            )
            .unwrap()
            .action,
            EgressAction::Allow
        );
        assert_eq!(
            evaluate(&p, &req(Method::Post, "api.openai.com", "/v1/embeddings"))
                .unwrap()
                .action,
            EgressAction::Deny
        );
    }

    #[test]
    fn path_exact_match() {
        let p = EgressPolicy {
            default_action: EgressAction::Deny,
            rules: vec![rule(
                "h",
                HostMatch::Exact("h.com".into()),
                None,
                Some(PathMatch::Exact("/health".into())),
                EgressAction::Allow,
            )],
            judge: None,
            block_private_networks: false,
        };
        assert_eq!(
            evaluate(&p, &req(Method::Get, "h.com", "/health"))
                .unwrap()
                .action,
            EgressAction::Allow
        );
        assert_eq!(
            evaluate(&p, &req(Method::Get, "h.com", "/health/x"))
                .unwrap()
                .action,
            EgressAction::Deny
        );
    }

    #[test]
    fn path_glob_match() {
        let p = EgressPolicy {
            default_action: EgressAction::Deny,
            rules: vec![rule(
                "g",
                HostMatch::Exact("api.openai.com".into()),
                None,
                Some(PathMatch::Glob("/v1/**/completions".into())),
                EgressAction::Allow,
            )],
            judge: None,
            block_private_networks: false,
        };
        assert_eq!(
            evaluate(
                &p,
                &req(Method::Post, "api.openai.com", "/v1/chat/completions")
            )
            .unwrap()
            .action,
            EgressAction::Allow
        );
        assert_eq!(
            evaluate(&p, &req(Method::Post, "api.openai.com", "/v1/files"))
                .unwrap()
                .action,
            EgressAction::Deny
        );
    }

    #[test]
    fn first_match_wins() {
        let p = EgressPolicy {
            default_action: EgressAction::Deny,
            rules: vec![
                rule(
                    "deny-files",
                    HostMatch::Exact("api.openai.com".into()),
                    None,
                    Some(PathMatch::Prefix("/v1/files".into())),
                    EgressAction::Deny,
                ),
                rule(
                    "allow-rest",
                    HostMatch::Suffix(".openai.com".into()),
                    None,
                    None,
                    EgressAction::Allow,
                ),
            ],
            judge: None,
            block_private_networks: false,
        };
        let e = evaluate(&p, &req(Method::Post, "api.openai.com", "/v1/files/upload")).unwrap();
        assert_eq!(e.action, EgressAction::Deny);
        assert_eq!(e.matched_rule.as_deref(), Some("deny-files"));

        let e = evaluate(
            &p,
            &req(Method::Post, "api.openai.com", "/v1/chat/completions"),
        )
        .unwrap();
        assert_eq!(e.action, EgressAction::Allow);
        assert_eq!(e.matched_rule.as_deref(), Some("allow-rest"));
    }

    #[test]
    fn judge_action_is_returned_verbatim() {
        // The engine itself does not consult the judge — that's the proxy
        // layer's job. A `Judge` rule simply produces a `Judge` evaluation.
        let p = EgressPolicy {
            default_action: EgressAction::Deny,
            rules: vec![rule(
                "ambig",
                HostMatch::Exact("unknown.com".into()),
                None,
                None,
                EgressAction::Judge,
            )],
            judge: None,
            block_private_networks: false,
        };
        let e = evaluate(&p, &req(Method::Get, "unknown.com", "/")).unwrap();
        assert_eq!(e.action, EgressAction::Judge);
        assert_eq!(e.matched_rule.as_deref(), Some("ambig"));
    }

    #[test]
    fn invalid_glob_surfaces_compile_error() {
        let p = EgressPolicy {
            default_action: EgressAction::Deny,
            rules: vec![rule(
                "bad",
                HostMatch::Glob("[invalid".into()),
                None,
                None,
                EgressAction::Allow,
            )],
            judge: None,
            block_private_networks: false,
        };
        let err = CompiledPolicy::compile(&p).unwrap_err();
        assert!(matches!(err, CompileError::HostGlob { .. }));
    }

    #[test]
    fn compiled_policy_is_reusable_across_requests() {
        let p = EgressPolicy {
            default_action: EgressAction::Deny,
            rules: vec![rule(
                "r",
                HostMatch::Suffix(".openai.com".into()),
                None,
                None,
                EgressAction::Allow,
            )],
            judge: None,
            block_private_networks: false,
        };
        let c = CompiledPolicy::compile(&p).unwrap();
        for path in ["/", "/v1/x", "/foo/bar"] {
            assert_eq!(
                c.evaluate(&req(Method::Get, "api.openai.com", path)).action,
                EgressAction::Allow
            );
        }
    }
}
