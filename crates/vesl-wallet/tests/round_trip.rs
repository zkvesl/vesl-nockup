//! Black-box integration tests for the `vesl-wallet` public API.
//!
//! Imports only what's reachable from `vesl_wallet::*` and `vesl_signing::*`
//! (no `crate::` paths). Guards the surface against regressions and
//! exercises the BIP-39 + Cheetah-BIP32-over-Tip5 path end-to-end.

use vesl_signing::domain::{domain_separators, hash_canonical};
use vesl_signing::prelude::Belt;
use vesl_signing::schnorr::{schnorr_sign, schnorr_verify};
use vesl_wallet::{
    DerivationPath, VeslWallet, WalletError, ROLE_ENCRYPTION, ROLE_INTENT, ROLE_RECEIVING,
    ROLE_SESSION, ROLE_X402, VESL_COIN_TYPE_PLACEHOLDER,
};

const CANONICAL_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon about";

fn wallet() -> VeslWallet {
    VeslWallet::from_seed_phrase(CANONICAL_MNEMONIC, "", VESL_COIN_TYPE_PLACEHOLDER).unwrap()
}

#[test]
fn invalid_mnemonic_rejected() {
    match VeslWallet::from_seed_phrase("not actually a mnemonic", "", 0) {
        Err(WalletError::InvalidMnemonic(_)) => {}
        other => panic!("expected InvalidMnemonic, got {:?}", other.is_ok()),
    }
}

#[test]
fn from_seed_phrase_is_deterministic() {
    let w1 = wallet();
    let w2 = wallet();
    let s1 = w1.intent_signer(0, 0).unwrap();
    let s2 = w2.intent_signer(0, 0).unwrap();
    assert_eq!(s1.to_belts(), s2.to_belts());
}

#[test]
fn passphrase_changes_keys() {
    let w_no_pp = VeslWallet::from_seed_phrase(CANONICAL_MNEMONIC, "", 0).unwrap();
    let w_pp = VeslWallet::from_seed_phrase(CANONICAL_MNEMONIC, "trezor", 0).unwrap();
    let s_no = w_no_pp.intent_signer(0, 0).unwrap();
    let s_pp = w_pp.intent_signer(0, 0).unwrap();
    assert_ne!(s_no.to_belts(), s_pp.to_belts());
}

#[test]
fn each_role_yields_a_distinct_key() {
    let w = wallet();
    let mut bytes = Vec::new();
    for role in [
        ROLE_INTENT,
        ROLE_RECEIVING,
        ROLE_ENCRYPTION,
        ROLE_SESSION,
        ROLE_X402,
    ] {
        let dk = w
            .derive(DerivationPath::new(VESL_COIN_TYPE_PLACEHOLDER, 0, role, 0))
            .unwrap();
        bytes.push(dk.private_key.to_belts());
    }
    let mut sorted = bytes.clone();
    sorted.sort_by_key(|b| {
        (
            b[0].0, b[1].0, b[2].0, b[3].0, b[4].0, b[5].0, b[6].0, b[7].0,
        )
    });
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        5,
        "each of the five reserved roles must derive a distinct scalar"
    );
}

#[test]
fn account_isolation() {
    let w = wallet();
    let a0 = w.intent_signer(0, 0).unwrap();
    let a1 = w.intent_signer(1, 0).unwrap();
    let a2 = w.intent_signer(2, 0).unwrap();
    assert_ne!(a0.to_belts(), a1.to_belts());
    assert_ne!(a1.to_belts(), a2.to_belts());
    assert_ne!(a0.to_belts(), a2.to_belts());
}

#[test]
fn index_rotation_yields_distinct_keys() {
    let w = wallet();
    let i0 = w.intent_signer(0, 0).unwrap();
    let i1 = w.intent_signer(0, 1).unwrap();
    assert_ne!(i0.to_belts(), i1.to_belts());
}

#[test]
fn sign_intent_round_trip_via_schnorr() {
    let w = wallet();
    let payload = serde_json::json!({ "intent_id": "abc", "value": "100" });
    let digest = hash_canonical(domain_separators::VESL_INTENT, &payload).unwrap();
    let (chal, sig) = w.sign_intent(0, &digest).unwrap();

    // Reconstruct the same key via the public derive() path and use it
    // to verify — proves sign_intent uses the same key the public
    // derive() returns.
    let signer = w.intent_signer(0, 0).unwrap();
    let pk = signer.public_key().unwrap();
    schnorr_verify(&pk, &digest, &chal, &sig).unwrap();
}

#[test]
fn payment_signer_matches_x402_path() {
    let w = wallet();
    let direct = w.payment_signer(0, 0).unwrap();
    let via_path = w
        .derive(DerivationPath::new(
            VESL_COIN_TYPE_PLACEHOLDER,
            0,
            ROLE_X402,
            0,
        ))
        .unwrap();
    assert_eq!(direct.to_belts(), via_path.private_key.to_belts());
}

#[test]
fn intent_signer_matches_intent_path() {
    let w = wallet();
    let direct = w.intent_signer(0, 0).unwrap();
    let via_path = w
        .derive(DerivationPath::new(
            VESL_COIN_TYPE_PLACEHOLDER,
            0,
            ROLE_INTENT,
            0,
        ))
        .unwrap();
    assert_eq!(direct.to_belts(), via_path.private_key.to_belts());
}

#[test]
fn intent_and_payment_signer_are_distinct() {
    // The TOML config-toggle pattern depends on this: same code, different
    // role, different key.
    let w = wallet();
    let intent = w.intent_signer(0, 0).unwrap();
    let payment = w.payment_signer(0, 0).unwrap();
    assert_ne!(intent.to_belts(), payment.to_belts());
}

#[test]
fn sign_with_intent_then_payment_keys_under_their_separators() {
    // End-to-end on the role-toggle pattern: an intent app signs under
    // VESL_INTENT with the intent key, a payment app signs under X402
    // with the payment key. Both signatures verify, neither key
    // verifies the other side's signature.
    let w = wallet();
    let intent_key = w.intent_signer(0, 0).unwrap();
    let payment_key = w.payment_signer(0, 0).unwrap();

    let intent_msg = [Belt(11), Belt(22), Belt(33), Belt(44), Belt(55)];
    let payment_msg = [Belt(99), Belt(98), Belt(97), Belt(96), Belt(95)];

    let (i_chal, i_sig) = schnorr_sign(&intent_key, &intent_msg).unwrap();
    let (p_chal, p_sig) = schnorr_sign(&payment_key, &payment_msg).unwrap();

    schnorr_verify(
        &intent_key.public_key().unwrap(),
        &intent_msg,
        &i_chal,
        &i_sig,
    )
    .unwrap();
    schnorr_verify(
        &payment_key.public_key().unwrap(),
        &payment_msg,
        &p_chal,
        &p_sig,
    )
    .unwrap();

    // Cross-check: intent pubkey does not verify the payment signature.
    assert!(schnorr_verify(
        &intent_key.public_key().unwrap(),
        &payment_msg,
        &p_chal,
        &p_sig
    )
    .is_err());
}

#[test]
fn coin_type_mismatch_rejected() {
    let w = wallet();
    // Build a path with a different coin_type than the wallet was
    // configured with — the wallet must reject it rather than silently
    // re-coining the derivation.
    let path = DerivationPath::new(VESL_COIN_TYPE_PLACEHOLDER ^ 1, 0, ROLE_INTENT, 0);
    match w.derive(path) {
        Err(WalletError::NonBip44Purpose(_)) => {}
        other => panic!("expected NonBip44Purpose, got is_ok={}", other.is_ok()),
    }
}

#[test]
fn receiving_pubkey_is_deterministic() {
    let w = wallet();
    let p1 = w.receiving_pubkey(0).unwrap();
    let p2 = w.receiving_pubkey(0).unwrap();
    assert_eq!(p1.x.0, p2.x.0);
    assert_eq!(p1.y.0, p2.y.0);
    assert_eq!(p1.inf, p2.inf);
}

#[test]
fn receiving_fingerprint_changes_with_account() {
    let w = wallet();
    let f0 = w.receiving_fingerprint(0).unwrap();
    let f1 = w.receiving_fingerprint(1).unwrap();
    assert_ne!(f0, f1);
}

#[test]
fn from_seed_matches_from_seed_phrase() {
    use bip39::Mnemonic;
    let mnemonic = Mnemonic::parse(CANONICAL_MNEMONIC).unwrap();
    let seed = mnemonic.to_seed_normalized("");
    let w_phrase = wallet();
    let w_seed = VeslWallet::from_seed(&seed, VESL_COIN_TYPE_PLACEHOLDER).unwrap();
    let s_phrase = w_phrase.intent_signer(0, 0).unwrap();
    let s_seed = w_seed.intent_signer(0, 0).unwrap();
    assert_eq!(s_phrase.to_belts(), s_seed.to_belts());
}

#[test]
fn distinct_mnemonics_distinct_master_keys() {
    let mnemonic_a = CANONICAL_MNEMONIC;
    let mnemonic_b = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let w_a = VeslWallet::from_seed_phrase(mnemonic_a, "", 0).unwrap();
    let w_b = VeslWallet::from_seed_phrase(mnemonic_b, "", 0).unwrap();
    let s_a = w_a.intent_signer(0, 0).unwrap();
    let s_b = w_b.intent_signer(0, 0).unwrap();
    assert_ne!(s_a.to_belts(), s_b.to_belts());
}
