//! Guard-graft lifecycle integration test (Phase 8b).
//!
//! Composes a kernel from `[vesl-graft, mint-graft, guard-graft]`,
//! compiles it with `hoonc`, boots it through `vesl-test`, and drives
//! the full mint → guard-register → guard-check flow. ~30-40s runtime
//! (most of it `hoonc`); treat accordingly in CI.
//!
//! Scaffolding mirrors `mint_lifecycle.rs` — each test tears down its
//! own scratch dir under `target/` to avoid stale injections. Phase 11
//! will factor this into `tests/fixtures/` and let 7b/8b/9b share.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use nock_noun_rs::{atom_from_u64, make_tag_in};
use nockapp::noun::slab::NounSlab;
use nockvm::noun::{D, T};
use vesl_core::{
    Mint, Tip5Hash, build_guard_check_poke, build_guard_register_poke,
    build_mint_commit_poke, tip5_to_atom_le_bytes,
};
use vesl_test::GraftTestHarness;

const SCRATCH_SUBDIR: &str = "guard_lifecycle";
const LEAF: &[u8] = b"guard-graft fixture leaf";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guard_register_check_happy_and_error_paths() -> Result<()> {
    let jam_path = compose_and_compile()?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    let root = commit_root(LEAF);

    // Mint first — gives us a committed root under hull 1. Guard then
    // mirrors that registration for its own lookup.
    let tags = harness.poke_slab(build_mint_commit_poke(1, &root)).await?;
    assert!(
        tags.iter().any(|t| t == "mint-committed"),
        "mint-commit: expected %mint-committed; got {tags:?}",
    );

    // Guard-register with the same hull+root.
    let tags = harness.poke_slab(build_guard_register_poke(1, &root)).await?;
    assert!(
        tags.iter().any(|t| t == "guard-registered"),
        "guard-register: expected %guard-registered; got {tags:?}",
    );

    // Guard-check with the valid leaf — soft ok=%.y result.
    let tags = harness.poke_slab(build_guard_check_poke(1, LEAF)).await?;
    assert!(
        tags.iter().any(|t| t == "guard-checked"),
        "guard-check valid leaf: expected %guard-checked; got {tags:?}",
    );

    // Guard-check with mismatched data — still %guard-checked (soft),
    // not an error. The Hoon side emits ok=%.n; the tag itself is the
    // same whether the hash matches or not, matching the design call
    // in protocol/lib/guard-graft.hoon (crash-on-bad-leaf is vesl-
    // graft's job, not guard's).
    let tags = harness.poke_slab(build_guard_check_poke(1, b"tampered")).await?;
    assert!(
        tags.iter().any(|t| t == "guard-checked"),
        "guard-check tampered: expected %guard-checked (soft mismatch); got {tags:?}",
    );

    // Guard-check against an unregistered hull — %guard-error, not a
    // silent %guard-checked ok=%.n. Register-first is an explicit
    // signal.
    let tags = harness.poke_slab(build_guard_check_poke(99, LEAF)).await?;
    assert!(
        tags.iter().any(|t| t == "guard-error"),
        "guard-check hull 99: expected %guard-error; got {tags:?}",
    );

    // Cross-graft peek: guard's %guard-root for hull 1 returns the
    // same root that mint committed. Uses the triple-unit convention
    // (`` `` `` `` around `(~(get by roots) hull)`), same as mint's
    // %mint-commit peek; parse via peek_raw + three-layer strip.
    let got_root = peek_guard_root(&mut harness, 1).await?;
    assert_eq!(
        got_root.as_ref().map(Vec::as_slice),
        Some(tip5_to_atom_le_bytes(&root).as_slice()),
        "guard-root peek for hull 1 should return the registered root",
    );

    // Peek against an unregistered hull → None.
    let missing = peek_guard_root(&mut harness, 99).await?;
    assert!(missing.is_none(), "guard-root peek hull 99: {missing:?}");

    Ok(())
}

// -- helpers --------------------------------------------------------------

fn commit_root(payload: &[u8]) -> Tip5Hash {
    let mut mint = Mint::new();
    mint.commit(&[payload])
}

/// Build the scratch project, run graft-inject, run hoonc, return
/// the path to the produced `out.jam`.
fn compose_and_compile() -> Result<PathBuf> {
    let repo_root = repo_root();
    let scratch = repo_root.join("target").join(SCRATCH_SUBDIR);

    if scratch.exists() {
        fs::remove_dir_all(&scratch).with_context(|| format!("clean {}", scratch.display()))?;
    }
    let hoon_app = scratch.join("hoon/app");
    let hoon_lib = scratch.join("hoon/lib");
    let hoon_common = scratch.join("hoon/common");
    let hoon_dat = scratch.join("hoon/dat");
    let hoon_jams = scratch.join("hoon/jams");
    fs::create_dir_all(&hoon_app)?;
    fs::create_dir_all(&hoon_lib)?;
    fs::create_dir_all(&hoon_common)?;
    fs::create_dir_all(&hoon_dat)?;
    fs::create_dir_all(&hoon_jams)?;

    // hoon/dat + hoon/jams are required even on grafts that don't
    // invoke the prover — hoonc eager-parses files in common/, some
    // of which transitively `/#` softed-constraints. See comment in
    // mint_lifecycle.rs for the full story.
    fs::copy(
        repo_root.join("templates/app.hoon"),
        hoon_app.join("app.hoon"),
    )?;
    copy_dir_contents(&repo_root.join("hoon/lib"), &hoon_lib)?;
    copy_dir_contents(&repo_root.join("hoon/common"), &hoon_common)?;
    copy_dir_contents(&repo_root.join("hoon/dat"), &hoon_dat)?;
    copy_dir_contents(&repo_root.join("hoon/jams"), &hoon_jams)?;

    let graft_inject = PathBuf::from(env!("CARGO_BIN_EXE_graft-inject"));
    let status = Command::new(&graft_inject)
        .arg("--lib-dir")
        .arg(&hoon_lib)
        // Explicit --grafts so auto-discovery doesn't pull in
        // forge-graft.toml (which arrived in Phase 9b and would
        // drag in prover deps this test doesn't stage).
        .arg("--grafts")
        .arg("vesl-graft,mint-graft,guard-graft")
        .arg(hoon_app.join("app.hoon"))
        .status()
        .with_context(|| format!("spawn {}", graft_inject.display()))?;
    if !status.success() {
        bail!("graft-inject exited with status {status}");
    }

    let hoonc_status = Command::new("hoonc")
        .arg("--new")
        .arg("hoon/app/app.hoon")
        .arg("hoon/")
        .current_dir(&scratch)
        .status()
        .with_context(|| "spawn hoonc")?;
    if !hoonc_status.success() {
        bail!("hoonc exited with status {hoonc_status}");
    }

    let jam = scratch.join("out.jam");
    if !jam.exists() {
        bail!("hoonc succeeded but {} is missing", jam.display());
    }
    Ok(jam)
}

/// Peek `[%guard-root hull ~]` and extract the registered root.
///
/// guard-peek wraps `(~(get by roots) hull)` with `` `` `` `` just like
/// vesl-graft's %root and mint-graft's %mint-commit — the kernel
/// returns `[~ [~ (unit @)]]`:
///   * present hull → `[~ [~ [~ root]]]`
///   * missing hull → `[~ [~ ~]]`
async fn peek_guard_root(harness: &mut GraftTestHarness, hull: u64) -> Result<Option<Vec<u8>>> {
    let path = build_guard_root_peek_path(hull);
    let res = harness.peek_raw(path).await?;
    let noun = unsafe { *res.root() };

    let outer = noun.as_cell().map_err(|e| anyhow::anyhow!("peek outer: {e:?}"))?;
    let inner_unit = outer.tail();
    let inner_cell = inner_unit
        .as_cell()
        .map_err(|e| anyhow::anyhow!("peek inner-unit: {e:?}"))?;
    let maybe_value = inner_cell.tail();

    if let Ok(atom) = maybe_value.as_atom() {
        let bytes = atom.as_ne_bytes();
        if bytes.iter().all(|&b| b == 0) {
            return Ok(None);
        }
        return Ok(Some(bytes.to_vec()));
    }
    let value_cell = maybe_value
        .as_cell()
        .map_err(|e| anyhow::anyhow!("maybe-value cell: {e:?}"))?;
    let root_atom = value_cell
        .tail()
        .as_atom()
        .map_err(|e| anyhow::anyhow!("root atom: {e:?}"))?;
    Ok(Some(root_atom.as_ne_bytes().to_vec()))
}

fn build_guard_root_peek_path(hull: u64) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "guard-root");
    let hull_noun = atom_from_u64(&mut slab, hull);
    let path = T(&mut slab, &[tag, hull_noun, D(0)]);
    slab.set_root(path);
    slab
}

fn copy_dir_contents(src: &Path, dst: &Path) -> Result<()> {
    for entry in fs::read_dir(src).with_context(|| format!("read_dir {}", src.display()))? {
        let entry = entry?;
        let dst_path = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            fs::create_dir_all(&dst_path)?;
            copy_dir_contents(&entry.path(), &dst_path)?;
        } else {
            fs::copy(entry.path(), &dst_path)?;
        }
    }
    Ok(())
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("graft-inject manifest dir has a grandparent")
}
