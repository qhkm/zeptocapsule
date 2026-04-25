//! Network egress policy layer.
//!
//! Provides outbound HTTP/HTTPS policy enforcement: deterministic rule engine,
//! SSRF/private-network classifier, and (in later milestones) a TLS-MITM
//! proxy and optional LLM judge fallback.
//!
//! Design: `docs/plans/2026-04-25-network-egress-policy-design.md`.
//! Reference impl studied: <https://github.com/brexhq/CrabTrap>.

pub mod rules;
pub mod ssrf;
pub mod types;

pub use types::{
    EgressAction, EgressDecision, EgressPolicy, EgressRule, HostMatch, JudgeConfig, Method,
    PathMatch,
};
