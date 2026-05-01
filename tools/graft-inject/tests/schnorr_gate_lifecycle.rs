//! Schnorr-gate lifecycle integration test (R2-03B).
//!
//! Closes R2-03's deferred success criterion #4: compose a kernel with
//! `[graft.gates] gate = "sig-verify-schnorr"`, compile it via hoonc,
//! boot it through `vesl-test`, sign a 32-byte message with the
//! Cheetah-Schnorr signing path, settle-note via the schnorr poke
//! builder, and assert `%settle-noted` with a matching expected-root.
//!
//! Pre-R2-03B the gate's `(hash-hashable:tip5 leaf+data)` digest crashed
//! on any payload over ~7 bytes, so this happy path was unreachable.
//! Verifies the chunked `hash-leaf-digest` reduction the fix put in
//! place: the signing helper and the gate must agree on a digest for
//! arbitrary `&[u8]` so the signature verifies.

mod fixtures;

use std::fs;

use anyhow::Result;
use nockchain_math::belt::Belt;
use vesl_core::{
    Mint, Tip5Hash, build_settle_note_schnorr_poke, build_settle_register_poke,
    derive_pubkey, pubkey_canonical_bytes, schnorr_message_digest_for_data, sign,
};
use vesl_test::GraftTestHarness;

const HULL: u64 = 1;
const NOTE_ID: u64 = 101;
const MESSAGE: &[u8; 32] = b"attest: 32-byte hash fingerprint";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn schnorr_gate_register_then_note_happy_path() -> Result<()> {
    let canonical = fs::read_to_string(
        fixtures::repo_root().join("hoon/lib/settle-graft.toml"),
    )?;
    let with_gate = format!(
        "{canonical}\n[graft.gates]\ngate = \"sig-verify-schnorr\"\n"
    );
    let jam_path = fixtures::compose_and_compile_with_manifest_overrides(
        "schnorr_gate_lifecycle",
        &["settle-graft", "mint-graft"],
        &[fixtures::ManifestOverride {
            name: "settle-graft",
            toml: with_gate,
        }],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    let mut sk = [Belt(0); 8];
    sk[0] = Belt(0xabad_f00d);
    let pubkey = derive_pubkey(&sk);
    let pk_bytes = pubkey_canonical_bytes(&pubkey);
    let leaf_root = commit_pubkey(&pk_bytes);

    let tags = harness
        .poke_slab(build_settle_register_poke(HULL, &leaf_root))
        .await?;
    assert!(
        tags.iter().any(|t| t == "settle-registered"),
        "settle-register: expected %settle-registered; got {tags:?}",
    );

    let digest = schnorr_message_digest_for_data(MESSAGE);
    let sig = sign(&sk, &digest)?;
    let slab = build_settle_note_schnorr_poke(
        NOTE_ID,
        HULL,
        &leaf_root,
        MESSAGE,
        &sig,
        &pubkey,
    );
    let tags = harness.poke_slab(slab).await?;
    assert!(
        tags.iter().any(|t| t == "settle-noted"),
        "settle-note (valid 32-byte schnorr): expected %settle-noted; got {tags:?}",
    );

    // Tampered signature flips one bit; gate returns %.n via the
    // affine-schnorr verify, settle-graft's `?> p.veri-result` then
    // crashes the kernel ("preserves STARK unprovability" per the
    // graft's docs). The kernel-level Exit emits no effects — distinct
    // from a malformed-payload mule-catch which would emit
    // %settle-error. We assert no %settle-noted leaked through.
    let mut tampered = sig.clone();
    tampered.sig[0] = Belt(tampered.sig[0].0 ^ 1);
    let bad_slab = build_settle_note_schnorr_poke(
        NOTE_ID + 1,
        HULL,
        &leaf_root,
        MESSAGE,
        &tampered,
        &pubkey,
    );
    let tags = harness.poke_slab(bad_slab).await?;
    assert!(
        !tags.iter().any(|t| t == "settle-noted"),
        "settle-note (tampered sig): %settle-noted must NOT appear; got {tags:?}",
    );

    Ok(())
}

fn commit_pubkey(pk_bytes: &[u8]) -> Tip5Hash {
    let mut mint = Mint::new();
    mint.commit(&[pk_bytes])
}
