//! HTTP/HTTPS proxy with TLS-MITM termination.
//!
//! Bound to a loopback port; the agent reaches it via `HTTP_PROXY` /
//! `HTTPS_PROXY` env vars and trusts the per-capsule CA via
//! `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS`. HTTP/1.1
//! only — HTTP/2 and HTTP/3 are not supported in v1 (deny on detection).
//!
//! Flow:
//! - Plain HTTP: parse request line + headers → resolve + SSRF-check → eval
//!   rules → if Allow, IP-pinned TCP connect upstream and forward, else
//!   reply 403.
//! - CONNECT: parse `host:port` → resolve + SSRF-check → eval host-only
//!   rules → if Allow, reply `200 Connection Established`, sign a leaf cert
//!   for the host, terminate TLS with the agent, parse the inner request
//!   line + headers, eval again with full path, then IP-pinned TLS connect
//!   to upstream (using the original SNI hostname so cert validation still
//!   binds to the real host) and forward.
//!
//! Per-connection state is short-lived; per-capsule CA + policy + audit
//! channel are held in `ProxyState` behind an `Arc`.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::ca::CapsuleCa;
use super::judge::{JudgeClient, JudgeRequest};
use super::rules::{CompiledPolicy, Request as RuleRequest};
use super::ssrf::is_private_or_metadata;
use super::types::{EgressAction, EgressDecision, Method};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("invalid request: {0}")]
    BadRequest(String),
    #[error("ca: {0}")]
    Ca(String),
}

/// Proxy configuration handed to [`spawn`].
pub struct ProxyConfig {
    pub policy: CompiledPolicy,
    pub ca: CapsuleCa,
    pub block_private_networks: bool,
    /// Action applied when the policy returns `Judge` and no judge is wired
    /// (or the judge times out / fails open). `Allow` here is dangerous — the
    /// SecurityProfile defaults choose `Deny` for Standard/Hardened.
    pub default_action: EgressAction,
    /// Optional LLM judge consulted on `EgressAction::Judge`. `None` collapses
    /// `Judge` to `default_action`.
    pub judge: Option<JudgeClient>,
}

/// Handle returned by [`spawn`]. Holds the listening address, the CA cert
/// PEM (for env injection), and the audit-log receiver.
pub struct ProxyHandle {
    pub addr: SocketAddr,
    pub ca_cert_pem: String,
    audit_rx: StdMutex<Option<mpsc::UnboundedReceiver<EgressDecision>>>,
    shutdown_tx: StdMutex<Option<oneshot::Sender<()>>>,
}

impl ProxyHandle {
    /// Pull whatever decisions have queued so far. Non-blocking.
    pub fn drain_audit_log(&self) -> Vec<EgressDecision> {
        let mut guard = self.audit_rx.lock().expect("audit rx mutex");
        let mut log = Vec::new();
        if let Some(rx) = guard.as_mut() {
            while let Ok(d) = rx.try_recv() {
                log.push(d);
            }
        }
        log
    }

    /// Stop the accept loop. Existing connections drain naturally.
    pub fn shutdown(&self) {
        if let Some(tx) = self.shutdown_tx.lock().expect("shutdown mutex").take() {
            let _ = tx.send(());
        }
    }
}

struct ProxyState {
    policy: Arc<CompiledPolicy>,
    ca: Arc<CapsuleCa>,
    block_private_networks: bool,
    default_action: EgressAction,
    audit_tx: mpsc::UnboundedSender<EgressDecision>,
    upstream_tls: Arc<ClientConfig>,
    judge: Option<Arc<JudgeClient>>,
}

/// Spawn the proxy task on `127.0.0.1:0`.
///
/// Synchronous bind so this can be called from `Backend::create`. The
/// accept loop runs on the ambient tokio runtime, which must be active —
/// in practice it always is because [`crate::create`] is invoked from
/// async code.
pub fn spawn(config: ProxyConfig) -> io::Result<ProxyHandle> {
    spawn_on("127.0.0.1:0".parse().expect("valid loopback addr"), config)
}

/// Spawn the proxy task bound to a specific socket address.
///
/// Used by the namespace backend to bind the proxy to a per-capsule
/// host-side veth IP. The IP must already exist on the host (set up via
/// `ip addr add`) before this call; otherwise `bind` fails with
/// `EADDRNOTAVAIL`.
pub fn spawn_on(bind: SocketAddr, config: ProxyConfig) -> io::Result<ProxyHandle> {
    let std_listener = std::net::TcpListener::bind(bind)?;
    std_listener.set_nonblocking(true)?;
    let addr = std_listener.local_addr()?;
    let listener = TcpListener::from_std(std_listener)?;

    let (audit_tx, audit_rx) = mpsc::unbounded_channel();
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let upstream_tls = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    let ca_cert_pem = config.ca.ca_cert_pem().to_owned();

    let state = Arc::new(ProxyState {
        policy: Arc::new(config.policy),
        ca: Arc::new(config.ca),
        block_private_networks: config.block_private_networks,
        default_action: config.default_action,
        audit_tx,
        upstream_tls,
        judge: config.judge.map(Arc::new),
    });

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accept = listener.accept() => match accept {
                    Ok((stream, _)) => {
                        let _ = stream.set_nodelay(true);
                        let st = Arc::clone(&state);
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, st).await {
                                tracing::debug!("egress proxy connection: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("egress proxy accept failed: {e}");
                        break;
                    }
                }
            }
        }
    });

    Ok(ProxyHandle {
        addr,
        ca_cert_pem,
        audit_rx: StdMutex::new(Some(audit_rx)),
        shutdown_tx: StdMutex::new(Some(shutdown_tx)),
    })
}

async fn handle_connection(
    mut stream: TcpStream,
    state: Arc<ProxyState>,
) -> Result<(), ProxyError> {
    let header_bytes = read_until_double_crlf(&mut stream).await?;
    let parsed = parse_request_head(&header_bytes)?;
    if parsed.method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(stream, parsed, state).await
    } else {
        handle_plain(stream, parsed, header_bytes, state).await
    }
}

/// Result of parsing the first HTTP request line + headers.
#[derive(Debug)]
struct ParsedHead {
    method: String,
    /// For plain HTTP this may be an absolute URI ("http://host/path") or
    /// origin-form ("/path"). For CONNECT it's "host:port".
    target: String,
    /// Always the path from the URI, never an absolute URL. Empty for CONNECT.
    path: String,
    /// Host header value or absolute-URI host. May include port.
    host_header: Option<String>,
    /// Bytes the parsed head consumed; remainder of the buffer is body bytes
    /// (post-headers, may be partial).
    head_len: usize,
    http_version: u8,
}

fn parse_request_head(buf: &[u8]) -> Result<ParsedHead, ProxyError> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let status = req
        .parse(buf)
        .map_err(|e| ProxyError::BadRequest(format!("parse: {e}")))?;
    let head_len = match status {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => {
            return Err(ProxyError::BadRequest("incomplete headers".into()));
        }
    };
    let method = req
        .method
        .ok_or_else(|| ProxyError::BadRequest("missing method".into()))?
        .to_owned();
    let target = req
        .path
        .ok_or_else(|| ProxyError::BadRequest("missing target".into()))?
        .to_owned();
    let http_version = req
        .version
        .ok_or_else(|| ProxyError::BadRequest("missing version".into()))?;
    let host_header = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .map(|s| s.trim().to_owned());

    let path = if method.eq_ignore_ascii_case("CONNECT") {
        String::new()
    } else if target.starts_with("http://") || target.starts_with("https://") {
        // Absolute-URI form ("http://host:port/path"). Strip scheme + host.
        let after_scheme = target
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(&target);
        match after_scheme.find('/') {
            Some(i) => after_scheme[i..].to_owned(),
            None => "/".to_owned(),
        }
    } else {
        target.clone()
    };

    Ok(ParsedHead {
        method,
        target,
        path,
        host_header,
        head_len,
        http_version,
    })
}

/// Read bytes until we see `\r\n\r\n` (end of HTTP headers), or hit the cap.
async fn read_until_double_crlf(stream: &mut TcpStream) -> Result<Vec<u8>, ProxyError> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(ProxyError::BadRequest("eof before headers".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(ProxyError::BadRequest("headers too large".into()));
        }
    }
}

async fn handle_plain(
    mut client: TcpStream,
    head: ParsedHead,
    raw_head: Vec<u8>,
    state: Arc<ProxyState>,
) -> Result<(), ProxyError> {
    let started = Instant::now();
    let (host, port) = parse_authority(&head, 80)?;

    let method = Method::parse(&head.method).unwrap_or(Method::Get);
    let path_for_eval = if head.path.is_empty() {
        "/"
    } else {
        head.path.as_str()
    };
    let eval = match resolve_and_eval(&state, method, &host, path_for_eval, port).await {
        Ok(eval) => eval,
        Err(e) => {
            write_error(&mut client, 502, "DNS or SSRF check failed").await?;
            log_decision(
                &state,
                method,
                &format!("{host}{}", head.path),
                EgressAction::Deny,
                None,
                Some(format!("resolve: {e}")),
                started,
            );
            return Ok(());
        }
    };

    if eval.action == EgressAction::Deny {
        write_error(&mut client, 403, "Egress denied by ZeptoCapsule policy").await?;
        log_decision(
            &state,
            method,
            &format!("{host}{}", head.path),
            EgressAction::Deny,
            eval.matched_rule,
            eval.judge_reason,
            started,
        );
        return Ok(());
    }

    // Allow path: connect to pinned IP, replay original request bytes, copy bidi.
    let upstream_addr = SocketAddr::new(eval.ip, port);
    let mut upstream =
        match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(upstream_addr))
            .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                write_error(&mut client, 502, "upstream connect failed").await?;
                log_decision(
                    &state,
                    method,
                    &format!("{host}{}", head.path),
                    EgressAction::Deny,
                    eval.matched_rule,
                    Some(format!("upstream: {e}")),
                    started,
                );
                return Ok(());
            }
            Err(_) => {
                write_error(&mut client, 504, "upstream timeout").await?;
                log_decision(
                    &state,
                    method,
                    &format!("{host}{}", head.path),
                    EgressAction::Deny,
                    eval.matched_rule,
                    Some("upstream timeout".into()),
                    started,
                );
                return Ok(());
            }
        };
    let _ = upstream.set_nodelay(true);

    // Forward the request bytes, replacing the request-line target with
    // origin-form (servers expect "/path", not "http://host/path") and
    // stripping proxy-only headers.
    let forwarded_head = rewrite_request_for_origin(&raw_head, &head)?;
    upstream.write_all(&forwarded_head).await?;

    log_decision(
        &state,
        method,
        &format!("{host}{}", head.path),
        EgressAction::Allow,
        eval.matched_rule,
        eval.judge_reason,
        started,
    );

    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

/// Strip proxy-only headers and rewrite the request-line target to
/// origin-form. Pre-allocates one buffer; never resizes the body section.
fn rewrite_request_for_origin(raw: &[u8], head: &ParsedHead) -> Result<Vec<u8>, ProxyError> {
    let head_slice = &raw[..head.head_len];
    let head_str = std::str::from_utf8(head_slice)
        .map_err(|_| ProxyError::BadRequest("non-utf8 header".into()))?;
    let mut out = String::with_capacity(head_str.len());
    let mut lines = head_str.split("\r\n");

    if let Some(_request_line) = lines.next() {
        let path = if head.path.is_empty() {
            "/"
        } else {
            &head.path
        };
        let v = match head.http_version {
            0 => "HTTP/1.0",
            _ => "HTTP/1.1",
        };
        out.push_str(&format!("{} {} {}\r\n", head.method, path, v));
    }

    for line in lines {
        if line.is_empty() {
            break;
        }
        let lname = line.split(':').next().unwrap_or("").trim();
        if lname.eq_ignore_ascii_case("proxy-connection")
            || lname.eq_ignore_ascii_case("proxy-authorization")
        {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");

    let mut bytes = out.into_bytes();
    if raw.len() > head.head_len {
        bytes.extend_from_slice(&raw[head.head_len..]);
    }
    Ok(bytes)
}

async fn handle_connect(
    mut client: TcpStream,
    head: ParsedHead,
    state: Arc<ProxyState>,
) -> Result<(), ProxyError> {
    let started = Instant::now();
    let (host, port) = parse_authority(&head, 443)?;

    // Phase 1: host-level check at CONNECT time. Path is unknown — use "/".
    let phase1 = match resolve_and_eval(&state, Method::Connect, &host, "/", port).await {
        Ok(e) => e,
        Err(e) => {
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            log_decision(
                &state,
                Method::Connect,
                &format!("{host}:{port}"),
                EgressAction::Deny,
                None,
                Some(format!("resolve: {e}")),
                started,
            );
            return Ok(());
        }
    };

    if phase1.action == EgressAction::Deny {
        let _ = client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await;
        log_decision(
            &state,
            Method::Connect,
            &format!("{host}:{port}"),
            EgressAction::Deny,
            phase1.matched_rule,
            phase1.judge_reason,
            started,
        );
        return Ok(());
    }

    log_decision(
        &state,
        Method::Connect,
        &format!("{host}:{port}"),
        EgressAction::Allow,
        phase1.matched_rule.clone(),
        phase1.judge_reason.clone(),
        started,
    );
    let ip = phase1.ip;

    // Tell the client the tunnel is up, then start the TLS MITM.
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let leaf = state
        .ca
        .leaf_for(&host)
        .map_err(|e| ProxyError::Ca(e.to_string()))?;
    let (chain, key) = leaf.into_rustls_key();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let mut tls_client =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(client)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(ProxyError::Io(e)),
            Err(_) => {
                return Err(ProxyError::BadRequest(
                    "client TLS handshake timeout".into(),
                ));
            }
        };

    // Phase 2: read inner request line + headers, re-eval with full path.
    let inner_head_bytes = read_until_double_crlf_tls(&mut tls_client).await?;
    let inner_head = parse_request_head(&inner_head_bytes)?;
    let inner_method = Method::parse(&inner_head.method).unwrap_or(Method::Get);
    let inner_path = if inner_head.path.is_empty() {
        "/"
    } else {
        &inner_head.path
    };

    let inner_started = Instant::now();
    let inner_eval = state.policy.evaluate(&RuleRequest {
        method: inner_method,
        host: &host,
        path: inner_path,
    });
    let (inner_decision, inner_judge_reason) =
        resolve_judge(&state, inner_eval.action, inner_method, &host, inner_path).await;

    if inner_decision == EgressAction::Deny {
        let _ = tls_client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await;
        log_decision(
            &state,
            inner_method,
            &format!("{host}{inner_path}"),
            EgressAction::Deny,
            inner_eval.matched_rule,
            inner_judge_reason,
            inner_started,
        );
        return Ok(());
    }

    // Connect to upstream IP-pinned, then TLS handshake using the original
    // hostname for SNI + cert validation.
    let upstream_tcp = match tokio::time::timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        TcpStream::connect(SocketAddr::new(ip, port)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            let _ = tls_client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            log_decision(
                &state,
                inner_method,
                &format!("{host}{inner_path}"),
                EgressAction::Deny,
                inner_eval.matched_rule,
                Some("upstream connect/timeout".into()),
                inner_started,
            );
            return Ok(());
        }
    };
    let _ = upstream_tcp.set_nodelay(true);

    let connector = TlsConnector::from(state.upstream_tls.clone());
    let server_name = ServerName::try_from(host.clone())
        .map_err(|e| ProxyError::BadRequest(format!("invalid SNI: {e}")))?;
    let mut tls_upstream = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        connector.connect(server_name, upstream_tcp),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(ProxyError::Io(e)),
        Err(_) => return Err(ProxyError::BadRequest("upstream TLS timeout".into())),
    };

    let forwarded_head = rewrite_request_for_origin(&inner_head_bytes, &inner_head)?;
    tls_upstream.write_all(&forwarded_head).await?;

    log_decision(
        &state,
        inner_method,
        &format!("{host}{inner_path}"),
        EgressAction::Allow,
        inner_eval.matched_rule,
        None,
        inner_started,
    );

    let _ = tokio::io::copy_bidirectional(&mut tls_client, &mut tls_upstream).await;
    Ok(())
}

async fn read_until_double_crlf_tls<S>(stream: &mut S) -> Result<Vec<u8>, ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(ProxyError::BadRequest("eof before inner headers".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(ProxyError::BadRequest("inner headers too large".into()));
        }
    }
}

async fn write_error(stream: &mut TcpStream, status: u16, body: &str) -> Result<(), ProxyError> {
    let line = match status {
        403 => "HTTP/1.1 403 Forbidden",
        404 => "HTTP/1.1 404 Not Found",
        502 => "HTTP/1.1 502 Bad Gateway",
        504 => "HTTP/1.1 504 Gateway Timeout",
        _ => "HTTP/1.1 500 Internal Server Error",
    };
    let payload = format!(
        "{line}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(payload.as_bytes()).await?;
    Ok(())
}

/// Parse `host[:port]` from CONNECT target or a Host header. Returns
/// `(host, port)`.
fn parse_authority(head: &ParsedHead, default_port: u16) -> Result<(String, u16), ProxyError> {
    let raw = if head.method.eq_ignore_ascii_case("CONNECT") {
        head.target.as_str()
    } else if head.target.starts_with("http://") || head.target.starts_with("https://") {
        let after = head
            .target
            .split_once("://")
            .map(|(_, r)| r)
            .unwrap_or(&head.target);
        after.split('/').next().unwrap_or(after)
    } else {
        head.host_header
            .as_deref()
            .ok_or_else(|| ProxyError::BadRequest("missing Host header".into()))?
    };
    let raw = raw.trim();
    if let Some(idx) = raw.rfind(':') {
        // Reject IPv6 bracketed form for v1 — uncommon, simpler this way.
        if raw.starts_with('[') {
            return Err(ProxyError::BadRequest("IPv6 literal not supported".into()));
        }
        let (h, p) = raw.split_at(idx);
        let port: u16 = p[1..]
            .parse()
            .map_err(|_| ProxyError::BadRequest("invalid port".into()))?;
        Ok((h.to_owned(), port))
    } else {
        Ok((raw.to_owned(), default_port))
    }
}

/// Combined DNS resolution + SSRF check + rule evaluation. The returned
/// `judge_reason` is populated whenever the judge was consulted.
async fn resolve_and_eval(
    state: &ProxyState,
    method: Method,
    host: &str,
    path: &str,
    port: u16,
) -> Result<ResolvedEval, ProxyError> {
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| ProxyError::BadRequest(format!("dns: {e}")))?;
    let addr = addrs
        .next()
        .ok_or_else(|| ProxyError::BadRequest("dns returned no addrs".into()))?;
    let ip = addr.ip();
    if state.block_private_networks && is_private_or_metadata(ip) {
        return Ok(ResolvedEval {
            action: EgressAction::Deny,
            matched_rule: Some("ssrf-block".into()),
            judge_reason: None,
            ip,
        });
    }
    let eval = state.policy.evaluate(&RuleRequest { method, host, path });
    let (action, judge_reason) = resolve_judge(state, eval.action, method, host, path).await;
    Ok(ResolvedEval {
        action,
        matched_rule: eval.matched_rule,
        judge_reason,
        ip,
    })
}

struct ResolvedEval {
    action: EgressAction,
    matched_rule: Option<String>,
    judge_reason: Option<String>,
    ip: IpAddr,
}

/// Resolve a `Judge` action: consult the LLM judge if one is configured,
/// otherwise fall back to `default_action`. Returns the final action plus
/// the judge's reason string (when applicable).
async fn resolve_judge(
    state: &ProxyState,
    action: EgressAction,
    method: Method,
    host: &str,
    path: &str,
) -> (EgressAction, Option<String>) {
    match action {
        EgressAction::Judge => match &state.judge {
            Some(j) => {
                let outcome = j
                    .decide(&JudgeRequest {
                        method,
                        host,
                        path,
                        body_excerpt: None,
                    })
                    .await;
                (outcome.decision, Some(outcome.reason))
            }
            None => (state.default_action, None),
        },
        other => (other, None),
    }
}

fn log_decision(
    state: &ProxyState,
    method: Method,
    url: &str,
    decision: EgressAction,
    matched_rule: Option<String>,
    judge_reason: Option<String>,
    started: Instant,
) {
    let dec = EgressDecision {
        ts: SystemTime::now(),
        method,
        url: url.to_owned(),
        decision,
        matched_rule,
        judge_reason,
        latency_us: started.elapsed().as_micros() as u64,
    };
    let _ = state.audit_tx.send(dec);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::types::{EgressPolicy, EgressRule, HostMatch, PathMatch};
    use std::time::Duration;
    use tokio::net::TcpListener as MockListener;

    /// Build a minimal proxy with the given policy and no SSRF block (so
    /// loopback test servers work).
    async fn spawn_test_proxy(policy: EgressPolicy) -> ProxyHandle {
        let compiled = CompiledPolicy::compile(&policy).unwrap();
        let ca = CapsuleCa::generate().unwrap();
        spawn(ProxyConfig {
            policy: compiled,
            ca,
            block_private_networks: false,
            default_action: policy.default_action,
            judge: None,
        })
        .unwrap()
    }

    /// Tiny upstream that returns a fixed body for plain HTTP.
    async fn spawn_http_echo() -> SocketAddr {
        let listener = MockListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = s.read(&mut buf).await;
                    let _ = s
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
                        .await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn parse_request_head_origin_form() {
        let raw = b"GET /v1/x HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let h = parse_request_head(raw).unwrap();
        assert_eq!(h.method, "GET");
        assert_eq!(h.path, "/v1/x");
        assert_eq!(h.host_header.as_deref(), Some("api.example.com"));
    }

    #[tokio::test]
    async fn parse_request_head_absolute_uri() {
        let raw = b"GET http://api.example.com/v1/x HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let h = parse_request_head(raw).unwrap();
        assert_eq!(h.path, "/v1/x");
    }

    #[tokio::test]
    async fn parse_authority_host_port() {
        let head = ParsedHead {
            method: "CONNECT".into(),
            target: "api.openai.com:443".into(),
            path: String::new(),
            host_header: None,
            head_len: 0,
            http_version: 1,
        };
        let (h, p) = parse_authority(&head, 443).unwrap();
        assert_eq!(h, "api.openai.com");
        assert_eq!(p, 443);
    }

    #[tokio::test]
    async fn parse_authority_host_only_uses_default() {
        let head = ParsedHead {
            method: "GET".into(),
            target: "/".into(),
            path: "/".into(),
            host_header: Some("example.com".into()),
            head_len: 0,
            http_version: 1,
        };
        let (h, p) = parse_authority(&head, 80).unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 80);
    }

    #[tokio::test]
    async fn rewrite_origin_form_strips_proxy_headers_and_rewrites_url() {
        let raw = b"GET http://api.example.com/v1/x HTTP/1.1\r\n\
                   Host: api.example.com\r\n\
                   Proxy-Connection: keep-alive\r\n\
                   Proxy-Authorization: Bearer x\r\n\
                   User-Agent: zk-test\r\n\r\nBODYBYTES";
        let head = parse_request_head(raw).unwrap();
        let out = rewrite_request_for_origin(raw, &head).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("GET /v1/x HTTP/1.1\r\n"));
        assert!(!s.contains("Proxy-Connection"));
        assert!(!s.contains("Proxy-Authorization"));
        assert!(s.contains("User-Agent: zk-test"));
        assert!(s.ends_with("BODYBYTES"));
    }

    #[tokio::test]
    async fn plain_http_allow_forwards_to_upstream() {
        let upstream = spawn_http_echo().await;
        let policy = EgressPolicy {
            default_action: EgressAction::Allow,
            rules: vec![],
            judge: None,
            block_private_networks: false,
        };
        let proxy = spawn_test_proxy(policy).await;

        let mut s = TcpStream::connect(proxy.addr).await.unwrap();
        let req = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            upstream
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).await.unwrap();
        assert!(resp.contains("hello"), "resp: {resp}");

        // Decision logged.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let log = proxy.drain_audit_log();
        assert!(!log.is_empty(), "audit log empty");
        assert_eq!(log[0].decision, EgressAction::Allow);

        proxy.shutdown();
    }

    #[tokio::test]
    async fn plain_http_deny_returns_403_and_logs() {
        let upstream = spawn_http_echo().await;
        let policy = EgressPolicy {
            default_action: EgressAction::Deny,
            rules: vec![],
            judge: None,
            block_private_networks: false,
        };
        let proxy = spawn_test_proxy(policy).await;

        let mut s = TcpStream::connect(proxy.addr).await.unwrap();
        let req = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            upstream
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 403"), "resp: {resp}");

        tokio::time::sleep(Duration::from_millis(50)).await;
        let log = proxy.drain_audit_log();
        assert_eq!(log[0].decision, EgressAction::Deny);

        proxy.shutdown();
    }

    #[tokio::test]
    async fn judge_action_falls_back_to_default_until_step7() {
        // Default Allow + a Judge rule means: matched-by-rule -> Judge ->
        // resolve_judge -> default_action (Allow).
        let upstream = spawn_http_echo().await;
        let policy = EgressPolicy {
            default_action: EgressAction::Allow,
            rules: vec![EgressRule {
                id: "ambig".into(),
                host_match: HostMatch::Suffix(".0.0.1".into()),
                method_match: None,
                path_match: Some(PathMatch::Prefix("/".into())),
                action: EgressAction::Judge,
            }],
            judge: None,
            block_private_networks: false,
        };
        let proxy = spawn_test_proxy(policy).await;

        let mut s = TcpStream::connect(proxy.addr).await.unwrap();
        let req = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            upstream
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).await.unwrap();
        assert!(
            resp.contains("hello"),
            "expected upstream body, got: {resp}"
        );

        proxy.shutdown();
    }

    #[tokio::test]
    async fn shutdown_stops_accept_loop() {
        let policy = EgressPolicy::allow_all();
        let proxy = spawn_test_proxy(policy).await;
        proxy.shutdown();
        // Give the runtime a tick to drop the listener.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let res = TcpStream::connect(proxy.addr).await;
        assert!(
            res.is_err(),
            "expected connect failure after shutdown, got: {:?}",
            res
        );
    }
}
