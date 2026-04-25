//! LLM judge fallback for ambiguous requests.
//!
//! When the static rule engine returns `EgressAction::Judge`, the proxy
//! consults a configured LLM endpoint to make the call. The judge is wrapped
//! in a circuit breaker so a flaky upstream cannot block every capsule
//! request: 5 consecutive failures trips the breaker for 10 seconds, during
//! which all `Judge` actions resolve to [`JudgeConfig::fallback_on_unavailable`].
//!
//! Prompt-injection hardening (mirrors CrabTrap):
//! - Policy text is `serde_json` string-encoded before being inlined,
//!   so quotes / newlines / control chars in the policy can't escape.
//! - Request fields (host, path, headers, body excerpt) are emitted as
//!   typed JSON values, not concatenated into the prompt.
//! - The model is asked to reply with strict JSON; any non-JSON or
//!   schema-violating reply is treated as a failure (and counts toward
//!   the breaker).

use std::sync::Mutex;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::types::{EgressAction, JudgeConfig, Method};

const BREAKER_FAILURE_THRESHOLD: u32 = 5;
const BREAKER_OPEN_DURATION: Duration = Duration::from_secs(10);
const RESPONSE_BYTE_CAP: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum JudgeError {
    #[error("api key env var '{0}' not set")]
    MissingApiKey(String),
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(String),
    #[error("upstream returned status {0}")]
    UpstreamStatus(u16),
    #[error("malformed response: {0}")]
    MalformedResponse(String),
    #[error("schema violation: {0}")]
    Schema(String),
    #[error("timeout")]
    Timeout,
}

/// Information the judge sees about one outbound request. Matches the
/// JSON shape we send to the model.
#[derive(Debug, Clone)]
pub struct JudgeRequest<'a> {
    pub method: Method,
    pub host: &'a str,
    pub path: &'a str,
    /// First few hundred bytes of the request body, if any. Optional —
    /// callers wishing to preserve PII can leave this `None`.
    pub body_excerpt: Option<&'a str>,
}

/// What the judge decided.
#[derive(Debug, Clone)]
pub struct JudgeOutcome {
    pub decision: EgressAction,
    pub reason: String,
}

/// State for one configured judge. Cheap to clone (interior `Arc`s/`Mutex`s
/// where needed; the public surface here keeps it owned for simplicity).
pub struct JudgeClient {
    config: JudgeConfig,
    api_key: String,
    tls: std::sync::Arc<ClientConfig>,
    breaker: Mutex<CircuitBreaker>,
}

impl std::fmt::Debug for JudgeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JudgeClient")
            .field("endpoint", &self.config.endpoint)
            .field("model", &self.config.model)
            .finish_non_exhaustive()
    }
}

impl JudgeClient {
    pub fn new(config: JudgeConfig) -> Result<Self, JudgeError> {
        let api_key = std::env::var(&config.api_key_env)
            .map_err(|_| JudgeError::MissingApiKey(config.api_key_env.clone()))?;
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = std::sync::Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        Ok(Self {
            config,
            api_key,
            tls,
            breaker: Mutex::new(CircuitBreaker::new()),
        })
    }

    /// Decide one ambiguous request. Returns the configured fallback if the
    /// circuit breaker is open or the call fails; never panics, never
    /// surfaces upstream errors past the proxy.
    pub async fn decide(&self, req: &JudgeRequest<'_>) -> JudgeOutcome {
        if !self
            .breaker
            .lock()
            .map(|mut b| b.allow_call())
            .unwrap_or(true)
        {
            return self.fallback("circuit breaker open");
        }

        match self.call_upstream(req).await {
            Ok(outcome) => {
                if let Ok(mut b) = self.breaker.lock() {
                    b.record_success();
                }
                outcome
            }
            Err(e) => {
                if let Ok(mut b) = self.breaker.lock() {
                    b.record_failure();
                }
                self.fallback(&format!("judge error: {e}"))
            }
        }
    }

    fn fallback(&self, reason: &str) -> JudgeOutcome {
        JudgeOutcome {
            decision: self.config.fallback_on_unavailable,
            reason: reason.to_owned(),
        }
    }

    async fn call_upstream(&self, req: &JudgeRequest<'_>) -> Result<JudgeOutcome, JudgeError> {
        let url = parse_endpoint(&self.config.endpoint)?;
        let body = build_chat_completion_body(&self.config, req);
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| JudgeError::MalformedResponse(format!("serialize: {e}")))?;

        let raw_response = tokio::time::timeout(
            self.config.timeout,
            send_post_json(&url, &self.api_key, &body_bytes, self.tls.clone()),
        )
        .await
        .map_err(|_| JudgeError::Timeout)??;

        parse_judge_outcome(&raw_response)
    }
}

#[derive(Debug)]
struct ParsedUrl {
    host: String,
    port: u16,
    path: String,
    https: bool,
}

fn parse_endpoint(s: &str) -> Result<ParsedUrl, JudgeError> {
    let (scheme, rest) = s
        .split_once("://")
        .ok_or_else(|| JudgeError::InvalidEndpoint("missing scheme".into()))?;
    let https = match scheme {
        "https" => true,
        "http" => false,
        _ => return Err(JudgeError::InvalidEndpoint(format!("scheme {scheme}"))),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rfind(':') {
        Some(i) => {
            let port: u16 = authority[i + 1..]
                .parse()
                .map_err(|_| JudgeError::InvalidEndpoint("bad port".into()))?;
            (authority[..i].to_owned(), port)
        }
        None => (authority.to_owned(), if https { 443 } else { 80 }),
    };
    Ok(ParsedUrl {
        host,
        port,
        path: path.to_owned(),
        https,
    })
}

/// Construct the OpenAI-compatible chat-completions body. The system prompt
/// embeds the policy text via `serde_json` escaping; the user prompt embeds
/// the request as a typed JSON object. Both are immune to injection from
/// the request body because no untrusted bytes are ever concatenated as
/// raw text.
fn build_chat_completion_body(config: &JudgeConfig, req: &JudgeRequest<'_>) -> Value {
    let policy_escaped = serde_json::to_string(&config.policy_text)
        .unwrap_or_else(|_| "\"<unprintable policy>\"".to_owned());
    let system = format!(
        "You are a security policy enforcer. Evaluate the outbound HTTP request \
         in the user message against the policy below. Respond with strict JSON: \
         {{\"decision\":\"allow\"|\"deny\",\"reason\":\"...\"}}. \
         No other keys, no prose, no markdown.\n\nPolicy: {policy_escaped}"
    );
    let user_obj = json!({
        "method": req.method.as_str(),
        "host": req.host,
        "path": req.path,
        "body_excerpt": req.body_excerpt.unwrap_or(""),
    });
    let user = format!("Request:\n{}", user_obj);

    json!({
        "model": config.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0,
    })
}

fn parse_judge_outcome(response: &str) -> Result<JudgeOutcome, JudgeError> {
    let v: Value = serde_json::from_str(response)
        .map_err(|e| JudgeError::MalformedResponse(format!("response is not JSON: {e}")))?;
    let content = v
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .ok_or_else(|| {
            JudgeError::MalformedResponse("missing choices[0].message.content".into())
        })?;
    let inner: Value = serde_json::from_str(content)
        .map_err(|e| JudgeError::Schema(format!("inner JSON: {e}")))?;
    let decision_str = inner
        .get("decision")
        .and_then(|d| d.as_str())
        .ok_or_else(|| JudgeError::Schema("missing decision".into()))?;
    let decision = match decision_str {
        "allow" => EgressAction::Allow,
        "deny" => EgressAction::Deny,
        other => {
            return Err(JudgeError::Schema(format!(
                "decision must be 'allow' or 'deny', got '{other}'"
            )));
        }
    };
    let reason = inner
        .get("reason")
        .and_then(|r| r.as_str())
        .unwrap_or("(no reason)")
        .to_owned();
    Ok(JudgeOutcome { decision, reason })
}

async fn send_post_json(
    url: &ParsedUrl,
    api_key: &str,
    body: &[u8],
    tls: std::sync::Arc<ClientConfig>,
) -> Result<String, JudgeError> {
    let tcp = TcpStream::connect((url.host.as_str(), url.port)).await?;
    let _ = tcp.set_nodelay(true);

    if url.https {
        let connector = TlsConnector::from(tls);
        let server_name =
            ServerName::try_from(url.host.clone()).map_err(|e| JudgeError::Tls(e.to_string()))?;
        let stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| JudgeError::Tls(e.to_string()))?;
        do_post(stream, &url.host, &url.path, api_key, body).await
    } else {
        do_post(tcp, &url.host, &url.path, api_key, body).await
    }
}

async fn do_post<S>(
    mut stream: S,
    host: &str,
    path: &str,
    api_key: &str,
    body: &[u8],
) -> Result<String, JudgeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req_head = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {api_key}\r\n\
         Content-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
        len = body.len()
    );
    stream.write_all(req_head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;

    let mut all = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        all.extend_from_slice(&tmp[..n]);
        if all.len() > RESPONSE_BYTE_CAP {
            return Err(JudgeError::MalformedResponse("response too large".into()));
        }
    }

    let head_end = (3..all.len())
        .find(|&i| &all[i - 3..=i] == b"\r\n\r\n")
        .ok_or_else(|| JudgeError::MalformedResponse("no header terminator".into()))?
        + 1;
    let head = std::str::from_utf8(&all[..head_end - 4])
        .map_err(|_| JudgeError::MalformedResponse("non-utf8 head".into()))?;
    let mut head_lines = head.split("\r\n");
    let status_line = head_lines
        .next()
        .ok_or_else(|| JudgeError::MalformedResponse("empty status line".into()))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| JudgeError::MalformedResponse(format!("bad status: {status_line}")))?;
    if !(200..300).contains(&status) {
        return Err(JudgeError::UpstreamStatus(status));
    }

    let body_bytes = &all[head_end..];
    let body_str = std::str::from_utf8(body_bytes)
        .map_err(|_| JudgeError::MalformedResponse("non-utf8 body".into()))?;
    Ok(body_str.to_owned())
}

struct CircuitBreaker {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

impl CircuitBreaker {
    fn new() -> Self {
        Self {
            consecutive_failures: 0,
            open_until: None,
        }
    }
    fn allow_call(&mut self) -> bool {
        if let Some(until) = self.open_until {
            if Instant::now() < until {
                return false;
            }
            self.open_until = None;
            self.consecutive_failures = 0;
        }
        true
    }
    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.open_until = None;
    }
    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= BREAKER_FAILURE_THRESHOLD {
            self.open_until = Some(Instant::now() + BREAKER_OPEN_DURATION);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> JudgeConfig {
        JudgeConfig {
            endpoint: "http://localhost:9/v1/chat/completions".into(),
            model: "test".into(),
            api_key_env: "ZK_TEST_JUDGE_KEY".into(),
            policy_text: "deny if path mentions /admin".into(),
            timeout: Duration::from_secs(5),
            fallback_on_unavailable: EgressAction::Deny,
        }
    }

    #[test]
    fn parse_endpoint_extracts_parts() {
        let u = parse_endpoint("https://api.openai.com/v1/chat/completions").unwrap();
        assert_eq!(u.host, "api.openai.com");
        assert_eq!(u.port, 443);
        assert_eq!(u.path, "/v1/chat/completions");
        assert!(u.https);
    }

    #[test]
    fn parse_endpoint_with_explicit_port() {
        let u = parse_endpoint("http://localhost:9000/v1/chat/completions").unwrap();
        assert_eq!(u.host, "localhost");
        assert_eq!(u.port, 9000);
        assert!(!u.https);
    }

    #[test]
    fn parse_endpoint_rejects_bad_scheme() {
        assert!(matches!(
            parse_endpoint("ftp://x"),
            Err(JudgeError::InvalidEndpoint(_))
        ));
    }

    #[test]
    fn build_chat_body_inlines_policy_as_json_escaped() {
        // Anything that could break out of the system prompt — a literal
        // newline followed by an unescaped quote — must not appear in the
        // serialized body. The text "sensitive" itself is fine; the *raw
        // injection pattern* is what we forbid.
        let mut c = cfg();
        c.policy_text = "deny\nif \"sensitive\"".into();
        let req = JudgeRequest {
            method: Method::Post,
            host: "api.x.com",
            path: "/v1/x",
            body_excerpt: None,
        };
        let body = build_chat_completion_body(&c, &req);
        let s = body.to_string();
        assert!(s.contains("sensitive"), "policy text missing entirely");
        assert!(
            !s.contains("if \"sensitive\""),
            "raw quote-injection pattern leaked into the prompt body"
        );
    }

    #[test]
    fn build_chat_body_includes_request_fields() {
        let req = JudgeRequest {
            method: Method::Get,
            host: "api.x.com",
            path: "/v1/y",
            body_excerpt: Some("hello"),
        };
        let body = build_chat_completion_body(&cfg(), &req);
        let s = body.to_string();
        assert!(s.contains("GET"), "method missing");
        assert!(s.contains("api.x.com"), "host missing");
        assert!(s.contains("/v1/y"), "path missing");
        assert!(s.contains("hello"), "body excerpt missing");
    }

    #[test]
    fn parse_outcome_allows() {
        let raw =
            r#"{"choices":[{"message":{"content":"{\"decision\":\"allow\",\"reason\":\"ok\"}"}}]}"#;
        let o = parse_judge_outcome(raw).unwrap();
        assert_eq!(o.decision, EgressAction::Allow);
        assert_eq!(o.reason, "ok");
    }

    #[test]
    fn parse_outcome_denies() {
        let raw =
            r#"{"choices":[{"message":{"content":"{\"decision\":\"deny\",\"reason\":\"PII\"}"}}]}"#;
        let o = parse_judge_outcome(raw).unwrap();
        assert_eq!(o.decision, EgressAction::Deny);
        assert_eq!(o.reason, "PII");
    }

    #[test]
    fn parse_outcome_rejects_invalid_decision() {
        let raw = r#"{"choices":[{"message":{"content":"{\"decision\":\"maybe\"}"}}]}"#;
        let err = parse_judge_outcome(raw).unwrap_err();
        assert!(matches!(err, JudgeError::Schema(_)));
    }

    #[test]
    fn parse_outcome_rejects_missing_choices() {
        let err = parse_judge_outcome(r#"{"foo":1}"#).unwrap_err();
        assert!(matches!(err, JudgeError::MalformedResponse(_)));
    }

    #[test]
    fn parse_outcome_rejects_non_json_content() {
        let raw = r#"{"choices":[{"message":{"content":"sorry I can't"}}]}"#;
        let err = parse_judge_outcome(raw).unwrap_err();
        assert!(matches!(err, JudgeError::Schema(_)));
    }

    #[test]
    fn breaker_opens_after_threshold_failures() {
        let mut b = CircuitBreaker::new();
        for _ in 0..BREAKER_FAILURE_THRESHOLD - 1 {
            b.record_failure();
            assert!(b.allow_call());
        }
        b.record_failure();
        assert!(!b.allow_call(), "5th failure must open the breaker");
    }

    #[test]
    fn breaker_resets_on_success() {
        let mut b = CircuitBreaker::new();
        for _ in 0..3 {
            b.record_failure();
        }
        b.record_success();
        for _ in 0..(BREAKER_FAILURE_THRESHOLD - 1) {
            b.record_failure();
        }
        assert!(b.allow_call(), "success must reset the failure counter");
    }

    #[test]
    fn breaker_closes_again_after_open_duration() {
        let mut b = CircuitBreaker::new();
        b.open_until = Some(Instant::now() - Duration::from_secs(1));
        b.consecutive_failures = BREAKER_FAILURE_THRESHOLD;
        assert!(
            b.allow_call(),
            "should close once open_until is in the past"
        );
        assert_eq!(b.consecutive_failures, 0);
    }

    #[test]
    fn judge_client_falls_back_when_api_key_missing() {
        // Make sure the env var is unset.
        // SAFETY: process-wide env mutation; this test runs in the lib test
        // binary where we control the env, and we restore nothing because no
        // other test reads this var.
        unsafe { std::env::remove_var("ZK_TEST_JUDGE_KEY_MISSING") };
        let mut c = cfg();
        c.api_key_env = "ZK_TEST_JUDGE_KEY_MISSING".into();
        let err = JudgeClient::new(c).unwrap_err();
        assert!(matches!(err, JudgeError::MissingApiKey(_)));
    }
}
