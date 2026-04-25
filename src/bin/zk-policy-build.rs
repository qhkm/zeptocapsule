//! `zk-policy-build` — draft an EgressPolicy from observed audit logs.
//!
//! Workflow:
//! 1. Run a Dev-tier capsule with `egress = Some(EgressPolicy::allow_all())`
//!    so every request is allowed and recorded.
//! 2. After the capsule destroys, serialize `CapsuleReport.egress_log` to
//!    a JSON file (one `EgressDecision` per array entry).
//! 3. `cargo run --bin zk-policy-build -- --log <path> --output <path>`
//!    drafts a minimal allowlist policy. Human review before applying to
//!    Standard / Hardened tiers.
//!
//! The drafted policy:
//! - One rule per observed host (case-insensitive, exact match).
//! - `method_match` is the set of methods actually seen.
//! - `path_match` is `None` — the tool intentionally over-allows on
//!   path so the human reviewer can tighten paths in the file. We'd
//!   rather draft something working than something already too tight.
//! - `default_action = Deny`, `block_private_networks = true`.
//!
//! Mirrors CrabTrap's policy-builder. Deliberately conservative on
//! inference to leave headroom for human judgment.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use zeptocapsule::{EgressAction, EgressDecision, EgressPolicy, EgressRule, HostMatch, Method};

fn main() -> ExitCode {
    let args = match Args::parse(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("zk-policy-build: {e}\n\n{}", USAGE);
            return ExitCode::from(2);
        }
    };

    if args.help {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let log = match read_log(&args) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("zk-policy-build: read log: {e}");
            return ExitCode::FAILURE;
        }
    };

    let policy = build_policy(&log);
    let json = match serde_json::to_string_pretty(&policy) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("zk-policy-build: serialize policy: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = write_output(&args, &json) {
        eprintln!("zk-policy-build: write output: {e}");
        return ExitCode::FAILURE;
    }

    eprintln!(
        "zk-policy-build: drafted {} rule(s) from {} decision(s)",
        policy.rules.len(),
        log.len()
    );
    ExitCode::SUCCESS
}

const USAGE: &str = "\
usage: zk-policy-build [--log <path>|-] [--output <path>|-] [--help]

Drafts an EgressPolicy from a JSON array of EgressDecision entries.
Use - for stdin/stdout. Defaults: stdin -> stdout.

example:
  zk-policy-build --log audit.json --output policy.json
";

#[derive(Debug, Default)]
struct Args {
    log: Option<PathBuf>,
    output: Option<PathBuf>,
    help: bool,
}

impl Args {
    fn parse<I: IntoIterator<Item = String>>(iter: I) -> Result<Self, String> {
        let mut args = Self::default();
        let mut it = iter.into_iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--help" | "-h" => args.help = true,
                "--log" => {
                    let v = it
                        .next()
                        .ok_or_else(|| "--log requires a value".to_string())?;
                    args.log = Some(PathBuf::from(v));
                }
                "--output" | "-o" => {
                    let v = it
                        .next()
                        .ok_or_else(|| "--output requires a value".to_string())?;
                    args.output = Some(PathBuf::from(v));
                }
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        Ok(args)
    }
}

fn read_log(args: &Args) -> io::Result<Vec<EgressDecision>> {
    let raw = match &args.log {
        Some(p) if p == &PathBuf::from("-") => read_stdin()?,
        None => read_stdin()?,
        Some(p) => fs::read_to_string(p)?,
    };
    serde_json::from_str::<Vec<EgressDecision>>(&raw)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn read_stdin() -> io::Result<String> {
    let mut s = String::new();
    io::stdin().read_to_string(&mut s)?;
    Ok(s)
}

fn write_output(args: &Args, body: &str) -> io::Result<()> {
    match &args.output {
        Some(p) if p == &PathBuf::from("-") => {
            io::stdout().write_all(body.as_bytes())?;
            io::stdout().write_all(b"\n")?;
        }
        None => {
            io::stdout().write_all(body.as_bytes())?;
            io::stdout().write_all(b"\n")?;
        }
        Some(p) => fs::write(p, body)?,
    }
    Ok(())
}

/// Draft a minimal allowlist policy from a list of decisions. Only entries
/// whose original decision was `Allow` (or `Judge` resolved to allow at
/// the proxy) seed rules — denies aren't policy candidates.
fn build_policy(log: &[EgressDecision]) -> EgressPolicy {
    // host -> (set of methods seen)
    let mut by_host: BTreeMap<String, BTreeSet<Method>> = BTreeMap::new();

    for d in log {
        if d.decision != EgressAction::Allow {
            continue;
        }
        let host = host_from_url(&d.url);
        if host.is_empty() {
            continue;
        }
        by_host
            .entry(host.to_ascii_lowercase())
            .or_default()
            .insert(d.method);
    }

    let mut rules = Vec::with_capacity(by_host.len());
    for (host, methods) in by_host {
        let methods: Vec<Method> = methods.into_iter().collect();
        let id = format!("allow-{}", host);
        rules.push(EgressRule {
            id,
            host_match: HostMatch::Exact(host),
            method_match: Some(methods),
            path_match: None,
            action: EgressAction::Allow,
        });
    }

    EgressPolicy {
        default_action: EgressAction::Deny,
        rules,
        judge: None,
        block_private_networks: true,
    }
}

/// Extract the host from a URL of the form `host[:port]/path` or
/// `host:port` (the form recorded by [`zeptocapsule::EgressDecision::url`]).
fn host_from_url(url: &str) -> &str {
    // Strip a leading scheme if any caller decides to include one.
    let s = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let s = s.split('/').next().unwrap_or(s);
    // Trim the port if present.
    match s.rfind(':') {
        Some(i) => &s[..i],
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn dec(method: Method, url: &str, decision: EgressAction) -> EgressDecision {
        EgressDecision {
            ts: SystemTime::now(),
            method,
            url: url.to_owned(),
            decision,
            matched_rule: None,
            judge_reason: None,
            latency_us: 0,
        }
    }

    #[test]
    fn host_extraction_strips_port_and_path() {
        assert_eq!(host_from_url("api.openai.com/v1/x"), "api.openai.com");
        assert_eq!(host_from_url("api.openai.com:443"), "api.openai.com");
        assert_eq!(host_from_url("https://api.openai.com/v1"), "api.openai.com");
    }

    #[test]
    fn build_policy_groups_by_host_and_unions_methods() {
        let log = vec![
            dec(Method::Get, "api.openai.com/v1/x", EgressAction::Allow),
            dec(Method::Post, "api.openai.com/v1/y", EgressAction::Allow),
            dec(Method::Get, "api.openai.com/v1/x", EgressAction::Allow),
            dec(
                Method::Get,
                "raw.githubusercontent.com/repo",
                EgressAction::Allow,
            ),
        ];
        let p = build_policy(&log);
        assert_eq!(p.rules.len(), 2);
        assert_eq!(p.default_action, EgressAction::Deny);
        assert!(p.block_private_networks);

        let openai = p
            .rules
            .iter()
            .find(|r| matches!(&r.host_match, HostMatch::Exact(h) if h == "api.openai.com"))
            .unwrap();
        let methods = openai.method_match.as_ref().unwrap();
        assert!(methods.contains(&Method::Get));
        assert!(methods.contains(&Method::Post));
        assert_eq!(methods.len(), 2);
    }

    #[test]
    fn build_policy_skips_denied_decisions() {
        let log = vec![
            dec(Method::Get, "good.com/x", EgressAction::Allow),
            dec(Method::Get, "evil.com/x", EgressAction::Deny),
        ];
        let p = build_policy(&log);
        assert_eq!(p.rules.len(), 1);
        let r = &p.rules[0];
        assert!(matches!(&r.host_match, HostMatch::Exact(h) if h == "good.com"));
    }

    #[test]
    fn build_policy_lowercases_host_for_dedup() {
        let log = vec![
            dec(Method::Get, "API.openai.com/x", EgressAction::Allow),
            dec(Method::Post, "api.openai.com/y", EgressAction::Allow),
        ];
        let p = build_policy(&log);
        assert_eq!(
            p.rules.len(),
            1,
            "case difference must not produce duplicate rules"
        );
    }

    #[test]
    fn build_policy_round_trips_json() {
        let log = vec![dec(Method::Post, "api.x.com/v1", EgressAction::Allow)];
        let p = build_policy(&log);
        let s = serde_json::to_string(&p).unwrap();
        let back: EgressPolicy = serde_json::from_str(&s).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn args_parses_long_forms() {
        let a = Args::parse(
            vec!["--log", "a.json", "--output", "b.json"]
                .into_iter()
                .map(String::from),
        )
        .unwrap();
        assert_eq!(a.log, Some(PathBuf::from("a.json")));
        assert_eq!(a.output, Some(PathBuf::from("b.json")));
        assert!(!a.help);
    }

    #[test]
    fn args_parses_help() {
        let a = Args::parse(vec!["--help".to_string()]).unwrap();
        assert!(a.help);
    }

    #[test]
    fn args_rejects_unknown() {
        let err = Args::parse(vec!["--bogus".to_string()]).unwrap_err();
        assert!(err.contains("unknown"));
    }
}
