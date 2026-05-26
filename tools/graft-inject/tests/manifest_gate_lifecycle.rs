//! manifest-verify gate lifecycle integration test.
//!
//! Compose a kernel with `[graft.gates] gate = "manifest-verify"`,
//! compile it via hoonc, boot it through `vesl-test`, register a
//! multi-leaf Merkle root, settle-note via the manifest poke builder,
//! and assert `%settle-noted`.
//!
//! Regression guard: `build_settle_note_manifest_poke` once emitted a
//! 5-element cause `[%settle-note note hull root data]` instead of the
//! 2-element `[%settle-note payload=@]` the kernel's `+$ settle-cause`
//! accepts. The malformed cause failed the soft-cast and the settle
//! emitted no effects — so this happy path was unreachable.

mod fixtures;

use std::fs;

use anyhow::Result;
use vesl_core::{Mint, build_settle_note_manifest_poke, build_settle_register_poke};
use vesl_test::GraftTestHarness;

const HULL: u64 = 1;
const NOTE_ID: u64 = 101;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manifest_gate_register_then_note_happy_path() -> Result<()> {
    let canonical =
        fs::read_to_string(fixtures::repo_root().join("hoon/lib/settle-graft.toml"))?;
    let with_gate = format!("{canonical}\n[graft.gates]\ngate = \"manifest-verify\"\n");
    let jam_path = fixtures::compose_and_compile_with_manifest_overrides(
        "manifest_gate_lifecycle",
        &["settle-graft", "mint-graft"],
        &[fixtures::ManifestOverride {
            name: "settle-graft",
            toml: with_gate,
        }],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // manifest-verify commits one Merkle leaf per field value; the gate
    // AND-folds verify-chunk(value, proof, root) over every field.
    let values: [&[u8]; 2] = [b"alice@example.com".as_slice(), b"admin".as_slice()];
    let mut mint = Mint::new();
    let root = mint.commit(&values);

    let tags = harness
        .poke_slab(build_settle_register_poke(HULL, &root))
        .await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "settle-registered"),
        "settle-register: expected %settle-registered; got {tags:?}",
    );

    // One Merkle proof per field, in field order.
    let mut proofs = Vec::new();
    for i in 0..values.len() {
        proofs.push(mint.proof(i)?);
    }
    let fields: [(&[u8], &[u8]); 2] = [
        (b"email".as_slice(), values[0]),
        (b"role".as_slice(), values[1]),
    ];

    let tags = harness
        .poke_slab(build_settle_note_manifest_poke(
            NOTE_ID, HULL, &root, &fields, &proofs,
        ))
        .await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "settle-noted"),
        "settle-note (manifest-verify, valid proofs): expected %settle-noted; got {tags:?}",
    );

    Ok(())
}
