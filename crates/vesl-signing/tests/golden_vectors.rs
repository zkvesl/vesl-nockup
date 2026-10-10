//! Byte-identity against signatures captured before the public scalar type
//! changed.
//!
//! `fixtures/signing_golden.json` was produced by vesl-signing
//! 0.1.0-beta.1, whose public API spoke `ibig::UBig`, at vesl-wallet commit
//! `2ff444d`. 0.2.0 replaced that type with [`Scalar`] and [`SchnorrSig`]
//! and left the arithmetic untouched; this test is the proof. Every key,
//! public key, challenge, signature scalar, JSON encoding and
//! `trunc_g_order` output must come out byte for byte as captured.
//!
//! ⛔ Never regenerate the fixture. A mismatch here means a signature or an
//! encoding moved, which is the one thing the change must not do.

use serde_json::Value;
use vesl_signing::prelude::Belt;
use vesl_signing::schnorr::{
    decode_signature, encode_signature, schnorr_sign, schnorr_verify, trunc_g_order, Scalar,
    SchnorrPrivateKey, SchnorrSig, SchnorrSignatureJson, G_ORDER,
};

const FIXTURE: &str = include_str!("fixtures/signing_golden.json");

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("fixture is valid JSON")
}

fn t8(v: &Value) -> [u32; 8] {
    let limbs: Vec<u32> = v
        .as_array()
        .expect("t8 is an array")
        .iter()
        .map(|x| u32::try_from(x.as_u64().expect("limb is an integer")).expect("limb fits u32"))
        .collect();
    limbs.try_into().expect("t8 has eight limbs")
}

fn u64s(v: &Value) -> Vec<u64> {
    v.as_array()
        .expect("an array")
        .iter()
        .map(|x| x.as_u64().expect("an integer"))
        .collect()
}

fn msg(v: &Value) -> [Belt; 5] {
    let m = u64s(v);
    std::array::from_fn(|i| Belt(m[i]))
}

#[test]
fn g_order_is_unchanged() {
    assert_eq!(G_ORDER.to_t8(), t8(&fixture()["g_order_t8"]));
}

#[test]
fn every_signature_and_encoding_is_byte_identical() {
    let f = fixture();
    let vectors = f["signatures"].as_array().expect("signatures");
    assert_eq!(vectors.len(), 85, "the fixture holds 17 keys x 5 messages");
    for v in vectors {
        let label = format!("{} / {}", v["key"], v["msg"]);
        let sk = SchnorrPrivateKey::new(Scalar::from_t8(t8(&v["sk_t8"]))).expect("valid key");
        let pk = sk.public_key().expect("public key");
        assert_eq!(
            pk.into_base58().unwrap(),
            v["pubkey"].as_str().unwrap(),
            "{label}: pubkey"
        );

        let m = msg(&v["msg_belts"]);
        let sig = schnorr_sign(&sk, &m).expect("signs");
        let want = SchnorrSig {
            chal: Scalar::from_t8(t8(&v["chal_t8"])),
            sig: Scalar::from_t8(t8(&v["sig_t8"])),
        };
        assert_eq!(sig, want, "{label}: signature");
        schnorr_verify(&pk, &m, &want).expect("the captured signature verifies");

        let wire = encode_signature(&pk, &sig).expect("encodes");
        let encoded = serde_json::to_string(&wire).unwrap();
        assert_eq!(
            encoded,
            v["encoding"].as_str().unwrap(),
            "{label}: encoding"
        );

        let captured: SchnorrSignatureJson =
            serde_json::from_str(v["encoding"].as_str().unwrap()).unwrap();
        let (pk2, sig2) = decode_signature(&captured).expect("decodes");
        assert_eq!(
            pk2.into_base58().unwrap(),
            v["pubkey"].as_str().unwrap(),
            "{label}"
        );
        assert_eq!(sig2, want, "{label}: decode");
    }
}

#[test]
fn rejected_keys_are_still_rejected() {
    let f = fixture();
    for v in f["rejected_keys"].as_array().expect("rejected_keys") {
        let limbs = t8(&v["sk_t8"]);
        assert!(
            SchnorrPrivateKey::new(Scalar::from_t8(limbs)).is_err(),
            "{}",
            v["key"]
        );
        assert!(SchnorrPrivateKey::from_t8(&limbs).is_err(), "{}", v["key"]);
    }
}

#[test]
fn trunc_g_order_is_byte_identical() {
    let f = fixture();
    for v in f["trunc_g_order"].as_array().expect("trunc_g_order") {
        assert_eq!(
            trunc_g_order(&u64s(&v["input"])).to_t8(),
            t8(&v["out_t8"]),
            "{}",
            v["name"]
        );
    }
}
