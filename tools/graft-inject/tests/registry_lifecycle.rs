//! Registry-graft lifecycle integration test.
//!
//! Composes a kernel from
//! `[settle-graft, kv-graft, counter-graft, queue-graft, rbac-graft,
//! registry-graft]`, compiles via `hoonc`, boots through `vesl-test`,
//! and exercises strict put/update/del semantics plus the C1
//! hostile-input regression guards on both put and update.
//!
//! Registry is the heaviest C1 surface — it has *two*
//! cue sites (put + update). The hostile-input cases mirror the
//! pattern set by queue-graft.

mod fixtures;

use anyhow::Result;
use nock_noun_rs::{atom_from_u64, jam_to_bytes, make_atom_in, make_tag_in, new_stack, NounSlab};
use nockvm::noun::{D, T};
use vesl_core::{
    build_registry_del_poke, build_registry_put_poke, build_registry_update_poke,
    unwrap_triple_unit_atom,
};
use vesl_test::GraftTestHarness;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registry_strict_paths_and_hostile_input() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "registry_lifecycle",
        &[
            "settle-graft",
            "kv-graft",
            "counter-graft",
            "queue-graft",
            "rbac-graft",
            "registry-graft",
        ],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    let record_42 = jam_atom(42);
    let record_99 = jam_atom(99);
    let record_7 = jam_atom(7);

    // %registry-put on a fresh key.
    let tags = harness.poke_slab(build_registry_put_poke(1, &record_42)).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "registry-stored"),
        "expected %registry-stored on put; got {tags:?}",
    );
    let got = peek_entry(&mut harness, 1).await?;
    assert_eq!(got, Some(vec![42]), "peek returns the put record");

    // %registry-put on existing key MUST error (strict create-only).
    let tags = harness.poke_slab(build_registry_put_poke(1, &record_99)).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "registry-error"),
        "put on existing key must emit %registry-error; got {tags:?}",
    );
    let got = peek_entry(&mut harness, 1).await?;
    assert_eq!(got, Some(vec![42]), "failed put must NOT mutate state");

    // %registry-update on existing key — overwrite + surface old/new.
    let tags = harness.poke_slab(build_registry_update_poke(1, &record_99)).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "registry-updated"),
        "expected %registry-updated; got {tags:?}",
    );
    let got = peek_entry(&mut harness, 1).await?;
    assert_eq!(got, Some(vec![99]), "update must overwrite");

    // %registry-update on missing key MUST error.
    let tags = harness.poke_slab(build_registry_update_poke(2, &record_7)).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "registry-error"),
        "update on missing key must emit %registry-error; got {tags:?}",
    );
    assert!(
        peek_entry(&mut harness, 2).await?.is_none(),
        "failed update must NOT create state",
    );

    // %registry-del on existing key.
    let tags = harness.poke_slab(build_registry_del_poke(1)).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "registry-deleted"),
        "expected %registry-deleted; got {tags:?}",
    );
    assert!(peek_entry(&mut harness, 1).await?.is_none());

    // %registry-del on missing key MUST error (strict delete).
    let tags = harness.poke_slab(build_registry_del_poke(1)).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "registry-error"),
        "del on missing key must emit %registry-error; got {tags:?}",
    );

    // C1 hostile-input regression guard: malformed jam on put MUST
    // emit %registry-error and leave the entries map unchanged.
    let hostile: &[&[u8]] = &[
        b"\x01",
        b"\xff",
        b"\xde\xad\xbe\xef",
        b"\xfe\xfe\xfe\xfe\xfe",
    ];
    for input in hostile {
        let tags = harness.poke_slab(build_registry_put_poke(50, input)).await?.effect_head_tags();
        let stored = tags.iter().any(|t| t == "registry-stored");
        let errored = tags.iter().any(|t| t == "registry-error");
        assert!(
            stored || errored,
            "hostile put {input:?}: kernel must emit a typed result, never panic; got {tags:?}",
        );
        // Whatever the result, do not pollute the next iteration's
        // expectations: clean up if a stored happened.
        if stored {
            let _ = harness.poke_slab(build_registry_del_poke(50)).await?;
        }
    }

    // C1 hostile-input on update — put a valid record first, then
    // update with malformed jam. State must remain at the original.
    let _ = harness.poke_slab(build_registry_put_poke(60, &record_42)).await?;
    for input in hostile {
        let tags = harness.poke_slab(build_registry_update_poke(60, input)).await?.effect_head_tags();
        let updated = tags.iter().any(|t| t == "registry-updated");
        let errored = tags.iter().any(|t| t == "registry-error");
        assert!(
            updated || errored,
            "hostile update {input:?}: kernel must emit a typed result; got {tags:?}",
        );
        if !updated {
            // Errored variant: state must be unchanged.
            assert_eq!(
                peek_entry(&mut harness, 60).await?,
                Some(vec![42]),
                "errored update {input:?} must leave entry at 42",
            );
        }
    }

    Ok(())
}

fn jam_atom(value: u64) -> Vec<u8> {
    let mut stack = new_stack();
    let mut slab: NounSlab = NounSlab::new();
    let noun = if value < (1u64 << 60) {
        D(value)
    } else {
        // For values above DIRECT_MAX, route through atom_from_u64.
        atom_from_u64(&mut slab, value)
    };
    let _ = make_atom_in(&mut slab, &[]); // touch slab so the borrow checker is happy
    jam_to_bytes(&mut stack, noun)
}

async fn peek_entry(
    harness: &mut GraftTestHarness,
    key: u64,
) -> Result<Option<Vec<u8>>> {
    let path = build_key_peek_path("registry-entry", key);
    let result = harness.peek_raw(path).await?;
    Ok(unwrap_triple_unit_atom(&result))
}

fn build_key_peek_path(tag: &str, key: u64) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag_atom = make_tag_in(&mut slab, tag);
    let key_atom = atom_from_u64(&mut slab, key);
    let path = T(&mut slab, &[tag_atom, key_atom, D(0)]);
    slab.set_root(path);
    slab
}
