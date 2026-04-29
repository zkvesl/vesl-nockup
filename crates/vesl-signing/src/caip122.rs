//! Sign-In-With-Nockchain (SIWN) per `11-extensions.md §11.2`.
//!
//! - CAIP-122-style message body (`build_caip122_message`)
//! - Tip5 hash under the `"siwn-v1"` domain separator
//! - Schnorr sign/verify on top of that digest
//! - Replay protection via [`ReplayCache`]
//!
//! The full wire shape of the SIWN header is:
//!
//! ```text
//! SIGN-IN-WITH-X: base64(JSON({ "message": <caip122>, "signature": SchnorrSignatureJson }))
//! ```

use std::time::Duration;

use crate::domain::{tip5_with_domain, SIWN_DOMAIN_SEPARATOR};
use crate::math::cheetah::CheetahPoint;
use crate::replay_cache::{domains as replay_domains, prefixed, ReplayCache};
use crate::schnorr::SchnorrSignatureJson;
use crate::schnorr::{
    decode_signature, encode_signature, schnorr_sign, schnorr_verify, SchnorrPrivateKey,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Parameters & errors
// ---------------------------------------------------------------------------

/// Inputs to the CAIP-122 message body. `address` is the base58-encoded
/// Cheetah public key; `chain_id` typically resolves to something like
/// `"nockchain:mainnet"`.
#[derive(Clone, Debug)]
pub struct SiwnParams {
    pub domain: String,
    pub address: String,
    pub uri: String,
    pub version: String,
    pub chain_id: String,
    pub nonce: String,
    pub issued_at: DateTime<Utc>,
    pub expiration_time: DateTime<Utc>,
}

/// Bundle carried on the wire.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SiwnHeader {
    pub message: String,
    pub signature: SchnorrSignatureJson,
}

/// Parsed + verified identity returned by [`verify`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub address: String,
    pub nonce: String,
    pub issued_at: DateTime<Utc>,
    pub expiration_time: DateTime<Utc>,
}

#[derive(Debug, Error)]
pub enum SiwnError {
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("malformed timestamp: {0}")]
    BadTimestamp(String),
    #[error("domain mismatch: expected {expected}, got {got}")]
    DomainMismatch { expected: String, got: String },
    #[error("message is expired")]
    Expired,
    #[error("message is not yet valid (issuedAt > now)")]
    NotYetValid,
    #[error("nonce has been seen before")]
    Replay,
    #[error("signature does not verify")]
    BadSignature,
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// CAIP-122 message construction & parsing
// ---------------------------------------------------------------------------

/// Build the exact CAIP-122 message body per `11.2.3`. Newline layout is
/// load-bearing — both signer and verifier rebuild the bytes through this
/// function so drift is impossible.
pub fn build_caip122_message(p: &SiwnParams) -> String {
    format!(
        "{domain} wants you to sign in with your Nockchain account:\n\
         {address}\n\
         \n\
         URI: {uri}\n\
         Version: {version}\n\
         Chain ID: {chain_id}\n\
         Nonce: {nonce}\n\
         Issued At: {issued_at}\n\
         Expiration Time: {expiration_time}",
        domain = p.domain,
        address = p.address,
        uri = p.uri,
        version = p.version,
        chain_id = p.chain_id,
        nonce = p.nonce,
        issued_at = p
            .issued_at
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        expiration_time = p
            .expiration_time
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    )
}

/// Parse a CAIP-122 body back into [`SiwnParams`]. Rejects inputs that
/// don't match the exact layout produced by [`build_caip122_message`].
pub fn parse_caip122_message(body: &str) -> Result<SiwnParams, SiwnError> {
    let mut lines = body.lines();
    let first = lines
        .next()
        .ok_or(SiwnError::MissingField("domain header"))?;
    let domain = first
        .strip_suffix(" wants you to sign in with your Nockchain account:")
        .ok_or(SiwnError::MissingField("domain header"))?
        .to_string();
    let address = lines
        .next()
        .ok_or(SiwnError::MissingField("address"))?
        .to_string();
    let _blank = lines
        .next()
        .ok_or(SiwnError::MissingField("blank separator"))?;
    let uri = pop_field(&mut lines, "URI")?;
    let version = pop_field(&mut lines, "Version")?;
    let chain_id = pop_field(&mut lines, "Chain ID")?;
    let nonce = pop_field(&mut lines, "Nonce")?;
    let issued_at_s = pop_field(&mut lines, "Issued At")?;
    let expiration_s = pop_field(&mut lines, "Expiration Time")?;

    let issued_at = DateTime::parse_from_rfc3339(&issued_at_s)
        .map_err(|e| SiwnError::BadTimestamp(e.to_string()))?
        .with_timezone(&Utc);
    let expiration_time = DateTime::parse_from_rfc3339(&expiration_s)
        .map_err(|e| SiwnError::BadTimestamp(e.to_string()))?
        .with_timezone(&Utc);

    Ok(SiwnParams {
        domain,
        address,
        uri,
        version,
        chain_id,
        nonce,
        issued_at,
        expiration_time,
    })
}

fn pop_field<'a, I: Iterator<Item = &'a str>>(
    it: &mut I,
    label: &'static str,
) -> Result<String, SiwnError> {
    let line = it.next().ok_or(SiwnError::MissingField(label))?;
    let prefix = format!("{label}: ");
    line.strip_prefix(&prefix)
        .map(str::to_string)
        .ok_or(SiwnError::MissingField(label))
}

// ---------------------------------------------------------------------------
// SiwnSigner
// ---------------------------------------------------------------------------

/// Signer for SIWN messages. Produces a base64-encoded JSON bundle
/// suitable for the `SIGN-IN-WITH-X` header value.
pub struct SiwnSigner {
    sk: SchnorrPrivateKey,
    pk: CheetahPoint,
}

impl SiwnSigner {
    pub fn new(sk: SchnorrPrivateKey) -> Self {
        let pk = sk.public_key();
        Self { sk, pk }
    }

    /// Sign `params` and return the header bundle (not base64-encoded).
    pub fn sign(&self, params: &SiwnParams) -> Result<SiwnHeader> {
        let body = build_caip122_message(params);
        let digest = tip5_with_domain(SIWN_DOMAIN_SEPARATOR, body.as_bytes());
        let (chal, sig) = schnorr_sign(&self.sk, &digest).map_err(|e| anyhow!("siwn sign: {e}"))?;
        let signature = encode_signature(&self.pk, &chal, &sig)
            .map_err(|e| anyhow!("encode signature: {e}"))?;
        Ok(SiwnHeader {
            message: body,
            signature,
        })
    }

    /// Sign and render the full `SIGN-IN-WITH-X` header value
    /// (`base64(JSON(SiwnHeader))`).
    pub fn sign_header(&self, params: &SiwnParams) -> Result<String> {
        let bundle = self.sign(params)?;
        let json = serde_json::to_vec(&bundle).context("serialize SiwnHeader")?;
        Ok(B64.encode(json))
    }
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

/// Decode a `SIGN-IN-WITH-X` header value and verify it. Enforces:
/// domain match, signature validity, timestamp window, and nonce freshness
/// (via the supplied [`ReplayCache`]).
pub fn verify<C: ReplayCache>(
    header_b64: &str,
    expected_domain: &str,
    cache: &C,
    now: DateTime<Utc>,
) -> Result<VerifiedIdentity, SiwnError> {
    let json = B64.decode(header_b64.as_bytes())?;
    let bundle: SiwnHeader = serde_json::from_slice(&json)?;
    let params = parse_caip122_message(&bundle.message)?;

    if params.domain != expected_domain {
        return Err(SiwnError::DomainMismatch {
            expected: expected_domain.to_string(),
            got: params.domain,
        });
    }
    if params.issued_at > now {
        return Err(SiwnError::NotYetValid);
    }
    if params.expiration_time <= now {
        return Err(SiwnError::Expired);
    }

    let (pk, chal, sig) = decode_signature(&bundle.signature)
        .map_err(|e| SiwnError::Other(format!("signature decode: {e}")))?;

    if pk
        .into_base58()
        .map_err(|e| SiwnError::Other(e.to_string()))?
        != params.address
    {
        return Err(SiwnError::Other(
            "signature pubkey does not match CAIP-122 address".into(),
        ));
    }

    let digest = tip5_with_domain(SIWN_DOMAIN_SEPARATOR, bundle.message.as_bytes());
    schnorr_verify(&pk, &digest, &chal, &sig).map_err(|_| SiwnError::BadSignature)?;

    let window = (params.expiration_time - params.issued_at)
        .to_std()
        .unwrap_or(Duration::from_secs(3600));
    // Domain-prefix the nonce so a future shared cache (that also
    // tracks `Authorization.nonce` per `06-facilitator.md §6.6`) cannot
    // collide SIWN nonces with payment-payload nonces.
    let key = prefixed(replay_domains::SIWN, params.nonce.as_bytes());
    if cache.seen(&key, window) {
        return Err(SiwnError::Replay);
    }

    Ok(VerifiedIdentity {
        address: params.address,
        nonce: params.nonce,
        issued_at: params.issued_at,
        expiration_time: params.expiration_time,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay_cache::InMemoryReplayCache;
    use ibig::UBig;

    fn signer() -> SiwnSigner {
        SiwnSigner::new(SchnorrPrivateKey::new(UBig::from(999_888_777u64)).unwrap())
    }

    fn params(signer: &SiwnSigner, now: DateTime<Utc>, nonce: &str) -> SiwnParams {
        SiwnParams {
            domain: "api.example.com".into(),
            address: signer.sk.public_key().into_base58().unwrap(),
            uri: "https://api.example.com/weather".into(),
            version: "1".into(),
            chain_id: "nockchain:mainnet".into(),
            nonce: nonce.into(),
            issued_at: now,
            expiration_time: now + chrono::Duration::minutes(10),
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let s = signer();
        let now = Utc::now();
        let p = params(&s, now, "abc123");
        let header = s.sign_header(&p).unwrap();

        let cache = InMemoryReplayCache::new();
        let verified = verify(&header, "api.example.com", &cache, now).unwrap();
        assert_eq!(verified.address, p.address);
        assert_eq!(verified.nonce, "abc123");
    }

    #[test]
    fn replay_rejected() {
        let s = signer();
        let now = Utc::now();
        let p = params(&s, now, "only-once");
        let header = s.sign_header(&p).unwrap();
        let cache = InMemoryReplayCache::new();
        assert!(verify(&header, "api.example.com", &cache, now).is_ok());
        assert!(matches!(
            verify(&header, "api.example.com", &cache, now),
            Err(SiwnError::Replay),
        ));
    }

    #[test]
    fn domain_mismatch_rejected() {
        let s = signer();
        let now = Utc::now();
        let p = params(&s, now, "n1");
        let header = s.sign_header(&p).unwrap();
        let cache = InMemoryReplayCache::new();
        let err = verify(&header, "evil.example.com", &cache, now).unwrap_err();
        assert!(matches!(err, SiwnError::DomainMismatch { .. }));
    }

    #[test]
    fn expired_rejected() {
        let s = signer();
        let now = Utc::now();
        let p = params(&s, now, "n2");
        let header = s.sign_header(&p).unwrap();
        let cache = InMemoryReplayCache::new();
        let later = p.expiration_time + chrono::Duration::seconds(1);
        assert!(matches!(
            verify(&header, "api.example.com", &cache, later),
            Err(SiwnError::Expired),
        ));
    }

    #[test]
    fn tampered_body_rejected() {
        let s = signer();
        let now = Utc::now();
        let p = params(&s, now, "n3");
        let bundle = s.sign(&p).unwrap();
        let tampered = SiwnHeader {
            message: bundle.message.replace("weather", "secrets"),
            signature: bundle.signature,
        };
        let header = B64.encode(serde_json::to_vec(&tampered).unwrap());
        let cache = InMemoryReplayCache::new();
        assert!(matches!(
            verify(&header, "api.example.com", &cache, now),
            Err(SiwnError::BadSignature),
        ));
    }

    #[test]
    fn parse_roundtrip() {
        let s = signer();
        let now = Utc::now();
        let p = params(&s, now, "roundtrip");
        let body = build_caip122_message(&p);
        let parsed = parse_caip122_message(&body).unwrap();
        assert_eq!(parsed.domain, p.domain);
        assert_eq!(parsed.address, p.address);
        assert_eq!(parsed.uri, p.uri);
        assert_eq!(parsed.nonce, p.nonce);
    }
}
