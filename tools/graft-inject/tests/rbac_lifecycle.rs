//! RBAC-graft lifecycle integration test (Phase 02 P2.4).
//!
//! Composes a kernel from `[settle-graft, kv-graft, counter-graft,
//! queue-graft, rbac-graft]`, compiles via `hoonc`, boots through
//! `vesl-test`, and exercises grant/revoke/auto-clear plus the
//! peek surface (perm count, individual perm membership).
//!
//! No hostile-input case: rbac-graft has no `cue payload` site —
//! the cause shape (`pubkey=@`, `perms=(list @t)`) carries typed
//! atoms / cords / list cells; structural matching at the cause
//! switch handles malformed shapes without reaching graft code.

mod fixtures;

use anyhow::{anyhow, Result};
use nock_noun_rs::{atom_from_u64, make_tag_in};
use nockapp::noun::slab::NounSlab;
use nockvm::noun::{D, T};
use vesl_core::{build_rbac_grant_poke, build_rbac_revoke_poke};
use vesl_test::GraftTestHarness;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rbac_grant_revoke_auto_clear_paths() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "rbac_lifecycle",
        &[
            "settle-graft",
            "kv-graft",
            "counter-graft",
            "queue-graft",
            "rbac-graft",
        ],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // Grant {read, write} to pubkey 1.
    let tags = harness
        .poke_slab(build_rbac_grant_poke(1, &["read", "write"]))
        .await?;
    assert!(
        tags.iter().any(|t| t == "rbac-granted"),
        "expected %rbac-granted on initial grant; got {tags:?}",
    );

    assert_eq!(perm_count(&mut harness, 1).await?, 2, "1 holds 2 perms");
    assert!(has_perm(&mut harness, 1, "read").await?);
    assert!(has_perm(&mut harness, 1, "write").await?);
    assert!(!has_perm(&mut harness, 1, "audit").await?);

    // Re-grant {write, audit}: union → {read, write, audit}, count 3.
    let tags = harness
        .poke_slab(build_rbac_grant_poke(1, &["write", "audit"]))
        .await?;
    assert!(
        tags.iter().any(|t| t == "rbac-granted"),
        "expected %rbac-granted on union; got {tags:?}",
    );
    assert_eq!(perm_count(&mut harness, 1).await?, 3);
    assert!(has_perm(&mut harness, 1, "audit").await?);

    // Revoke {write}: count drops to 2.
    let tags = harness.poke_slab(build_rbac_revoke_poke(1, &["write"])).await?;
    assert!(
        tags.iter().any(|t| t == "rbac-revoked"),
        "expected %rbac-revoked; got {tags:?}",
    );
    assert_eq!(perm_count(&mut harness, 1).await?, 2);
    assert!(!has_perm(&mut harness, 1, "write").await?);

    // Revoke an unheld perm — must noop, not error.
    let tags = harness.poke_slab(build_rbac_revoke_poke(1, &["never-held"])).await?;
    assert!(
        tags.iter().any(|t| t == "rbac-revoked"),
        "revoke-unheld must emit %rbac-revoked (noop), not %rbac-error; got {tags:?}",
    );
    assert!(
        !tags.iter().any(|t| t == "rbac-error"),
        "revoke-unheld must not emit %rbac-error; got {tags:?}",
    );
    assert_eq!(perm_count(&mut harness, 1).await?, 2);

    // Revoke remaining perms: pubkey must auto-clear from roles map.
    let _ = harness
        .poke_slab(build_rbac_revoke_poke(1, &["read", "audit"]))
        .await?;
    assert_eq!(
        perm_count(&mut harness, 1).await?,
        0,
        "after full revoke, perm-count must be 0 (auto-cleared)",
    );
    // Granting again after auto-clear must succeed (re-registration).
    let _ = harness.poke_slab(build_rbac_grant_poke(1, &["fresh"])).await?;
    assert_eq!(perm_count(&mut harness, 1).await?, 1);

    // Empty perms list grant — noop, no error.
    let tags = harness.poke_slab(build_rbac_grant_poke(2, &[])).await?;
    assert!(
        tags.iter().any(|t| t == "rbac-granted"),
        "empty-perms grant must emit %rbac-granted (noop), got {tags:?}",
    );
    assert_eq!(perm_count(&mut harness, 2).await?, 0, "empty grant must not register");

    Ok(())
}

/// Decode `[%rbac-perm-count pubkey=@ ~]` as `u64`.
async fn perm_count(harness: &mut GraftTestHarness, pubkey: u64) -> Result<u64> {
    let path = build_pubkey_peek_path("rbac-perm-count", pubkey);
    let bytes = unwrap_keyed_atom(harness, path).await?.unwrap_or_default();
    let mut buf = [0u8; 8];
    for (i, byte) in bytes.iter().take(8).enumerate() {
        buf[i] = *byte;
    }
    Ok(u64::from_le_bytes(buf))
}

/// Decode `[%rbac-has-perm pubkey=@ perm=@t ~]` as a loobean.
///
/// Hoon's `?` is `0` for `%.y` (true) / `1` for `%.n` (false). After
/// the canonical trim_trailing_zeros pass, true round-trips as an
/// empty byte vec (atom 0), false as `[1]`.
async fn has_perm(harness: &mut GraftTestHarness, pubkey: u64, perm: &str) -> Result<bool> {
    let path = build_pubkey_perm_peek_path("rbac-has-perm", pubkey, perm);
    let bytes = unwrap_keyed_atom(harness, path).await?.unwrap_or_default();
    if bytes.is_empty() {
        Ok(true)
    } else if bytes == [1] {
        Ok(false)
    } else {
        Err(anyhow!("unexpected has-perm bytes: {bytes:?}"))
    }
}

fn build_pubkey_peek_path(tag: &str, pubkey: u64) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag_atom = make_tag_in(&mut slab, tag);
    let pk_atom = atom_from_u64(&mut slab, pubkey);
    let path = T(&mut slab, &[tag_atom, pk_atom, D(0)]);
    slab.set_root(path);
    slab
}

fn build_pubkey_perm_peek_path(tag: &str, pubkey: u64, perm: &str) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag_atom = make_tag_in(&mut slab, tag);
    let pk_atom = atom_from_u64(&mut slab, pubkey);
    let perm_atom = make_tag_in(&mut slab, perm);
    let path = T(&mut slab, &[tag_atom, pk_atom, perm_atom, D(0)]);
    slab.set_root(path);
    slab
}

/// Mirror of `fixtures::unwrap_triple_unit_atom` for paths that
/// the fixtures helpers don't have a one-key/zero-key shape for.
async fn unwrap_keyed_atom(
    harness: &mut GraftTestHarness,
    path: NounSlab,
) -> Result<Option<Vec<u8>>> {
    let res = harness.peek_raw(path).await?;
    let noun = unsafe { *res.root() };

    let outer = noun
        .as_cell()
        .map_err(|e| anyhow!("peek outer not a cell: {e:?}"))?;
    let inner_unit = outer.tail();
    let inner_cell = inner_unit
        .as_cell()
        .map_err(|e| anyhow!("peek inner-unit not a cell: {e:?}"))?;
    let maybe_value = inner_cell.tail();

    if let Ok(atom) = maybe_value.as_atom() {
        let bytes = atom.as_ne_bytes();
        if bytes.iter().all(|&b| b == 0) {
            return Ok(None);
        }
        return Ok(Some(trim_trailing_zeros(bytes)));
    }

    let value_cell = maybe_value
        .as_cell()
        .map_err(|e| anyhow!("maybe-value not a cell: {e:?}"))?;
    let inner_atom = value_cell
        .tail()
        .as_atom()
        .map_err(|e| anyhow!("inner not an atom: {e:?}"))?;
    Ok(Some(trim_trailing_zeros(inner_atom.as_ne_bytes())))
}

fn trim_trailing_zeros(bytes: &[u8]) -> Vec<u8> {
    let len = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    bytes[..len].to_vec()
}
