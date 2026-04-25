//! Per-capsule certificate authority for TLS MITM.
//!
//! Each [`crate::Capsule`] gets a freshly-generated CA at creation time.
//! The CA certificate is exported to the guest (via `SSL_CERT_FILE` and
//! friends) so the agent's HTTP libraries trust it; the proxy uses the
//! matching key to sign leaf certs for whatever hostname the agent
//! connects to. CA + key + leaf cache live entirely in memory and are
//! dropped together with the capsule — no key material survives teardown.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("rustls: {0}")]
    Rustls(String),
    #[error("invalid hostname: {0}")]
    InvalidHostname(String),
}

/// Per-capsule CA. Wrap in `Arc` to share across proxy tasks.
pub struct CapsuleCa {
    ca_cert: rcgen::Certificate,
    ca_key_pair: KeyPair,
    ca_cert_pem: String,
    ca_cert_der: CertificateDer<'static>,
    ca_key_pem: String,
    leaf_cache: Mutex<HashMap<String, LeafEntry>>,
}

#[derive(Clone)]
struct LeafEntry {
    chain: Vec<CertificateDer<'static>>,
    key_der: Vec<u8>,
}

impl CapsuleCa {
    /// Generate a fresh CA. Keys live in memory only.
    pub fn generate() -> Result<Self, CaError> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "ZeptoCapsule Per-Capsule CA");
        dn.push(DnType::OrganizationName, "ZeptoCapsule");
        params.distinguished_name = dn;
        params.not_before = time_offset(SystemTime::now(), -60);
        // 30 days is plenty — CA never outlives the capsule.
        params.not_after = time_offset(SystemTime::now(), 60 * 60 * 24 * 30);

        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;
        let ca_cert_pem = cert.pem();
        let ca_cert_der = cert.der().clone();
        let ca_key_pem = key_pair.serialize_pem();

        Ok(Self {
            ca_cert: cert,
            ca_key_pair: key_pair,
            ca_cert_pem,
            ca_cert_der,
            ca_key_pem,
            leaf_cache: Mutex::new(HashMap::new()),
        })
    }

    /// PEM-encoded CA certificate. Drop this into a temp file and point
    /// `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS` at it.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// PEM-encoded CA private key. **Never** export this outside the proxy
    /// process — exposed here only so a caller can place it on a
    /// memfd_create-style ephemeral path if needed.
    pub fn ca_key_pem(&self) -> &str {
        &self.ca_key_pem
    }

    /// DER-encoded CA certificate.
    pub fn ca_cert_der(&self) -> &CertificateDer<'static> {
        &self.ca_cert_der
    }

    /// Sign a leaf certificate for `hostname`. The key is freshly generated
    /// per hostname; cached so a second TLS handshake to the same host
    /// reuses the same leaf.
    pub fn leaf_for(&self, hostname: &str) -> Result<LeafCert, CaError> {
        if hostname.is_empty() || hostname.len() > 253 {
            return Err(CaError::InvalidHostname(hostname.into()));
        }

        if let Some(entry) = self
            .leaf_cache
            .lock()
            .map_err(|_| CaError::Rustls("leaf cache mutex poisoned".into()))?
            .get(hostname)
            .cloned()
        {
            return Ok(LeafCert {
                chain: entry.chain,
                key_der: entry.key_der,
            });
        }

        let mut leaf_params = CertificateParams::new(vec![hostname.to_owned()])?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, hostname);
        leaf_params.distinguished_name = dn;
        leaf_params.not_before = time_offset(SystemTime::now(), -60);
        leaf_params.not_after = time_offset(SystemTime::now(), 60 * 60 * 24 * 30);

        let leaf_key = KeyPair::generate()?;
        let leaf_cert = leaf_params.signed_by(&leaf_key, &self.ca_cert, &self.ca_key_pair)?;

        let chain = vec![leaf_cert.der().clone(), self.ca_cert_der.clone()];
        let key_der = leaf_key.serialize_der();

        let entry = LeafEntry {
            chain: chain.clone(),
            key_der: key_der.clone(),
        };
        self.leaf_cache
            .lock()
            .map_err(|_| CaError::Rustls("leaf cache mutex poisoned".into()))?
            .insert(hostname.to_owned(), entry);

        Ok(LeafCert { chain, key_der })
    }

    /// Number of cached leaf certs (for tests/diagnostics).
    pub fn leaf_cache_size(&self) -> usize {
        self.leaf_cache.lock().map(|c| c.len()).unwrap_or(0)
    }
}

impl std::fmt::Debug for CapsuleCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapsuleCa")
            .field("leaf_cache_size", &self.leaf_cache_size())
            .finish_non_exhaustive()
    }
}

/// Leaf cert + key in DER form, ready for `rustls::ServerConfig`.
#[derive(Clone)]
pub struct LeafCert {
    pub chain: Vec<CertificateDer<'static>>,
    pub key_der: Vec<u8>,
}

impl LeafCert {
    /// Convert the key bytes into a rustls `PrivateKeyDer`. Consumes the
    /// caller's `LeafCert` since rustls takes ownership.
    pub fn into_rustls_key(self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der));
        (self.chain, key)
    }
}

fn time_offset(base: SystemTime, secs: i64) -> time::OffsetDateTime {
    let unix = base
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    time::OffsetDateTime::from_unix_timestamp(unix + secs)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_generates_self_signed_cert() {
        let ca = CapsuleCa::generate().unwrap();
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(ca.ca_key_pem().contains("PRIVATE KEY"));
        assert!(!ca.ca_cert_der().is_empty());
    }

    #[test]
    fn leaf_for_returns_chain_with_ca_at_root() {
        let ca = CapsuleCa::generate().unwrap();
        let leaf = ca.leaf_for("api.openai.com").unwrap();
        assert_eq!(leaf.chain.len(), 2, "chain = leaf + CA");
        assert_eq!(&leaf.chain[1], ca.ca_cert_der());
    }

    #[test]
    fn leaf_cache_reuses_certificate_per_host() {
        let ca = CapsuleCa::generate().unwrap();
        assert_eq!(ca.leaf_cache_size(), 0);
        let l1 = ca.leaf_for("a.com").unwrap();
        assert_eq!(ca.leaf_cache_size(), 1);
        let l2 = ca.leaf_for("a.com").unwrap();
        assert_eq!(ca.leaf_cache_size(), 1);
        assert_eq!(l1.chain[0], l2.chain[0], "same leaf returned");
        let _l3 = ca.leaf_for("b.com").unwrap();
        assert_eq!(ca.leaf_cache_size(), 2);
    }

    #[test]
    fn leaf_for_rejects_empty_hostname() {
        let ca = CapsuleCa::generate().unwrap();
        assert!(matches!(ca.leaf_for(""), Err(CaError::InvalidHostname(_))));
    }

    #[test]
    fn distinct_capsules_get_distinct_cas() {
        let ca1 = CapsuleCa::generate().unwrap();
        let ca2 = CapsuleCa::generate().unwrap();
        assert_ne!(
            ca1.ca_cert_der(),
            ca2.ca_cert_der(),
            "each capsule must have a fresh CA"
        );
    }

    #[test]
    fn leaf_can_be_converted_to_rustls_key() {
        let ca = CapsuleCa::generate().unwrap();
        let leaf = ca.leaf_for("example.com").unwrap();
        let (chain, _key) = leaf.into_rustls_key();
        assert_eq!(chain.len(), 2);
    }
}
