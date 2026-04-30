//! Black-box smoke test for the `vesl-signing` public API.
//!
//! Imports only what's reachable from `vesl_signing::*` (no `crate::`
//! paths). This guards the surface against accidentally re-introducing
//! a private symbol — if a future refactor leaks a `pub(crate)` item
//! into the public API, that change would have to update this file too.
//!
//! Run with: `cargo test --test api_smoke --all-features`.

use ibig::UBig;
use vesl_signing::domain::{
    domain_separators, hash_canonical, tip5_with_domain, X402_DOMAIN_SEPARATOR,
};
use vesl_signing::prelude::Belt;
use vesl_signing::replay_cache::{
    domains as replay_domains, prefixed, InMemoryReplayCache, ReplayCache,
};
use vesl_signing::schnorr::{
    decode_signature, encode_signature, schnorr_sign, schnorr_verify, SchnorrPrivateKey,
};

#[test]
fn the_reserved_separators_are_distinct() {
    let dseps = domain_separators::ALL;
    assert_eq!(dseps.len(), 6);
    assert!(dseps.contains(&domain_separators::X402));
    assert!(dseps.contains(&domain_separators::SIWN));
    assert!(dseps.contains(&domain_separators::VESL_INTENT));
    assert!(dseps.contains(&domain_separators::VESL_RECEIPT));
    assert!(dseps.contains(&domain_separators::VESL_AUTHORITY));
    assert!(dseps.contains(&domain_separators::VESL_HD));
}

#[test]
fn vesl_hd_separator_is_isolated_from_signing_separators() {
    // VESL_HD is reserved for the wallet's BIP32-analog derivation
    // transcript. It must produce digests distinct from every signing
    // separator so a derivation transcript can never be confused for a
    // signed message.
    let bytes = b"sample-derivation-input";
    let dhd = tip5_with_domain(domain_separators::VESL_HD, bytes);
    for tag in domain_separators::ALL {
        if *tag == domain_separators::VESL_HD {
            continue;
        }
        assert_ne!(
            dhd,
            tip5_with_domain(tag, bytes),
            "VESL_HD digest must differ from {tag}",
        );
    }
}

#[test]
fn end_to_end_signature_via_public_api() {
    // Build a key, hash a payload under a domain, sign, encode, decode,
    // verify. No crate-internals reached.
    let sk = SchnorrPrivateKey::new(UBig::from(42_424_242_u64)).unwrap();
    let pk = sk.public_key();

    let payload = serde_json::json!({ "intent_id": "abc", "value": "100" });
    let digest = hash_canonical(domain_separators::VESL_INTENT, &payload).unwrap();

    let (chal, sig) = schnorr_sign(&sk, &digest).unwrap();
    schnorr_verify(&pk, &digest, &chal, &sig).unwrap();

    let wire = encode_signature(&pk, &chal, &sig).unwrap();
    let (pk2, chal2, sig2) = decode_signature(&wire).unwrap();
    assert_eq!(pk2.into_base58().unwrap(), pk.into_base58().unwrap());
    assert_eq!(chal2, chal);
    assert_eq!(sig2, sig);
}

#[test]
fn replay_cache_isolates_domains() {
    let cache = InMemoryReplayCache::new();
    let nonce = b"shared-nonce";

    let siwn_key = prefixed(replay_domains::SIWN, nonce);
    let auth_key = prefixed(replay_domains::AUTHORIZATION, nonce);

    assert!(!cache.seen(&siwn_key, std::time::Duration::from_secs(60)));
    assert!(!cache.seen(&auth_key, std::time::Duration::from_secs(60)));
    assert!(cache.seen(&siwn_key, std::time::Duration::from_secs(60)));
    assert!(cache.seen(&auth_key, std::time::Duration::from_secs(60)));
}

#[test]
fn from_belts_shim_path() {
    // The vesl-core signing.rs shim needs Belt-flavored construction. This
    // tests the shim seam contract.
    let mut belts = [Belt(0); 8];
    belts[0] = Belt(0xAAAA_BBBBu64);
    belts[1] = Belt(0xCCCC_DDDDu64);
    let sk = SchnorrPrivateKey::from_belts(&belts).unwrap();
    let belts2 = sk.to_belts();
    let sk2 = SchnorrPrivateKey::from_belts(&belts2).unwrap();
    let m = [Belt(1), Belt(2), Belt(3), Belt(4), Belt(5)];
    let (c, s) = schnorr_sign(&sk, &m).unwrap();
    let (c2, s2) = schnorr_sign(&sk2, &m).unwrap();
    assert_eq!(c, c2);
    assert_eq!(s, s2);
}

#[test]
fn legacy_x402_alias_still_resolves() {
    // x402-nockchain-crypto's source-compat seam relies on this re-export
    // staying pub.
    let bytes = b"some bytes";
    let a = tip5_with_domain(X402_DOMAIN_SEPARATOR, bytes);
    let b = tip5_with_domain(domain_separators::X402, bytes);
    assert_eq!(a, b);
}
