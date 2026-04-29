//! A non-x402 consumer of the SIWN (CAIP-122) machinery.
//!
//! Mocks a hypothetical trust-anchor service ("Hull Authority") that uses
//! Sign-In-With-Nockchain to gate access to a privileged operation. This
//! example exists to prove that vesl-signing's API generalizes beyond x402
//! envelopes — same crate, same surface, completely different domain
//! string and consumer.
//!
//! Run with: `cargo run --example mock_trust_anchor`.
//!
//! Future Vesl Labs trust-anchor service work (Phase 0 W11-12, see
//! `vesl-labs/docs/plans/shared-infrastructure/10-PHASE-0-NOW.md`) will
//! follow this exact pattern.

use chrono::{Duration, Utc};
use ibig::UBig;
use vesl_signing::caip122::{verify, SiwnParams, SiwnSigner};
use vesl_signing::replay_cache::InMemoryReplayCache;
use vesl_signing::schnorr::SchnorrPrivateKey;

fn main() -> anyhow::Result<()> {
    // === Issuer side: Hull Authority operator with a long-lived key. ===
    let sk = SchnorrPrivateKey::new(UBig::from(7_777_777_777_u64))?;

    // The pubkey-as-base58 doubles as the address in SIWN. Compute it
    // before handing the key to the signer (which consumes the key).
    let address = sk
        .public_key()
        .into_base58()
        .map_err(|e| anyhow::anyhow!("base58: {e}"))?;
    let signer = SiwnSigner::new(sk);

    // The trust-anchor service domain. NOT x402 — this is what makes the
    // example interesting: same crypto surface, completely different
    // protocol context.
    let trust_anchor_domain = "trust.example.org";

    // === Client side: requesting access to a Hull Authority operation. ===
    let now = Utc::now();
    let params = SiwnParams {
        domain: trust_anchor_domain.into(),
        address: address.clone(),
        uri: "https://trust.example.org/admin/rotate-key".into(),
        version: "1".into(),
        chain_id: "nockchain:mainnet".into(),
        nonce: "operator-sess-2026-04-29-001".into(),
        issued_at: now,
        expiration_time: now + Duration::minutes(15),
    };

    let header = signer.sign_header(&params)?;
    println!("Issued SIWN header (base64, truncated): {}…", &header[..40]);

    // === Verifier side: Hull Authority gate. ===
    let cache = InMemoryReplayCache::new();
    let identity = verify(&header, trust_anchor_domain, &cache, now)
        .map_err(|e| anyhow::anyhow!("siwn verify: {e}"))?;

    assert_eq!(identity.address, address);
    assert_eq!(identity.nonce, "operator-sess-2026-04-29-001");

    println!("Verified identity for trust-anchor session.");
    println!("  address:  {}", identity.address);
    println!("  nonce:    {}", identity.nonce);
    println!("  expires:  {}", identity.expiration_time);

    // Replay rejection — second attempt with the same nonce must fail.
    let replay = verify(&header, trust_anchor_domain, &cache, now);
    assert!(
        replay.is_err(),
        "second verify attempt should be replay-rejected"
    );

    println!("Replay correctly rejected on second attempt.");
    println!();
    println!("vesl-signing's CAIP-122 surface generalizes to non-x402 consumers.");
    Ok(())
}
