//! Mint-graft lifecycle integration test (Phase 7b).
//!
//! Composes a kernel from `[vesl-graft, mint-graft]`, compiles it with
//! `hoonc`, boots it through `vesl-test`, and exercises the full
//! mint-commit / peek flow. Runs end-to-end in ~10-20s (the bulk is
//! `hoonc`); treat accordingly in CI.
//!
//! Layout: assembles a scratch project under `target/mint_lifecycle/`,
//! populated from the repo's `templates/`, `hoon/lib/`, and
//! `hoon/common/`. `target/` is gitignored, and the whole directory
//! is torn down on each run so stale injections can't bleed in.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use nock_noun_rs::{atom_from_u64, make_tag_in};
use nockapp::noun::slab::NounSlab;
use nockvm::noun::{D, T};
use vesl_core::{Mint, Tip5Hash, build_mint_commit_poke, tip5_to_atom_le_bytes};
use vesl_test::GraftTestHarness;

const SCRATCH_SUBDIR: &str = "mint_lifecycle";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mint_commit_two_hulls_then_peek() -> Result<()> {
    let jam_path = compose_and_compile()?;

    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // Two distinct commits under different hulls.
    let root1 = commit_root(b"mint-graft fixture payload A");
    let root2 = commit_root(b"mint-graft fixture payload B");

    let tags = harness.poke_slab(build_mint_commit_poke(1, &root1)).await?;
    assert!(
        tags.iter().any(|t| t == "mint-committed"),
        "expected %mint-committed for hull 1; got {tags:?}",
    );

    let tags = harness.poke_slab(build_mint_commit_poke(2, &root2)).await?;
    assert!(
        tags.iter().any(|t| t == "mint-committed"),
        "expected %mint-committed for hull 2; got {tags:?}",
    );

    // Re-committing hull 1 must report %mint-error (append-only trellis).
    let tags = harness.poke_slab(build_mint_commit_poke(1, &root1)).await?;
    assert!(
        tags.iter().any(|t| t == "mint-error"),
        "expected %mint-error on re-commit of hull 1; got {tags:?}",
    );

    // Peek both committed hulls.
    let got1 = peek_mint_commit(&mut harness, 1).await?;
    assert_eq!(
        got1.as_ref().map(Vec::as_slice),
        Some(tip5_to_atom_le_bytes(&root1).as_slice()),
        "peek for hull 1 should return root1",
    );
    let got2 = peek_mint_commit(&mut harness, 2).await?;
    assert_eq!(
        got2.as_ref().map(Vec::as_slice),
        Some(tip5_to_atom_le_bytes(&root2).as_slice()),
        "peek for hull 2 should return root2",
    );

    // Peek an unregistered hull: None (path recognized, value absent).
    let missing = peek_mint_commit(&mut harness, 99).await?;
    assert!(missing.is_none(), "peek for hull 99 should be empty; got {missing:?}");

    Ok(())
}

// -- helpers --------------------------------------------------------------

fn commit_root(payload: &[u8]) -> Tip5Hash {
    let mut mint = Mint::new();
    mint.commit(&[payload])
}

/// Build the scratch project, run graft-inject, run hoonc, return the
/// path to the produced `out.jam`.
fn compose_and_compile() -> Result<PathBuf> {
    let repo_root = repo_root();
    let scratch = repo_root
        .join("target")
        .join(SCRATCH_SUBDIR);

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

    // Scaffold + libraries. `templates/app.hoon` carries the 5 nockup
    // markers; graft-inject seeds its composition from there.
    //
    // hoon/dat and hoon/jams carry the STARK constraint artifacts
    // (softed-constraints + pre-jammed constraint tables). hoonc
    // eager-parses common/ — including forge-graft's prover deps —
    // even on a 2-graft compose, so every scratch needs those trees
    // present to avoid "need" failures.
    fs::copy(
        repo_root.join("templates/app.hoon"),
        hoon_app.join("app.hoon"),
    )?;
    copy_dir_contents(&repo_root.join("hoon/lib"), &hoon_lib)?;
    copy_dir_contents(&repo_root.join("hoon/common"), &hoon_common)?;
    copy_dir_contents(&repo_root.join("hoon/dat"), &hoon_dat)?;
    copy_dir_contents(&repo_root.join("hoon/jams"), &hoon_jams)?;

    // graft-inject: bin is built automatically by cargo test and its
    // path lives in CARGO_BIN_EXE_graft-inject.
    let graft_inject = PathBuf::from(env!("CARGO_BIN_EXE_graft-inject"));
    let status = Command::new(&graft_inject)
        .arg("--lib-dir")
        .arg(&hoon_lib)
        // Explicit --grafts so auto-discovery doesn't pull in
        // forge-graft.toml (which arrived in Phase 9b and would
        // drag in prover deps this test doesn't stage).
        .arg("--grafts")
        .arg("vesl-graft,mint-graft")
        .arg(hoon_app.join("app.hoon"))
        .status()
        .with_context(|| format!("spawn {}", graft_inject.display()))?;
    if !status.success() {
        bail!("graft-inject exited with status {status}");
    }

    // hoonc: expected on PATH (the repo's README already requires it).
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

/// Send `[%mint-commit hull=@ ~]` to the kernel's peek arm and return
/// the committed root bytes (`Some`) or `None` if the hull was never
/// committed.
/// Peek `[%mint-commit hull ~]` and extract the committed root.
///
/// mint-graft's peek wraps the `(unit @)` returned by `~(get by commits)`
/// in another unit via `` ``(...)``, so the full kernel peek result is
/// `[~ [~ (unit @)]]`:
///   * present hull → `[~ [~ [~ root]]]`
///   * missing hull → `[~ [~ ~]]`
/// Return `Some(root_bytes)` for the former, `None` for the latter.
async fn peek_mint_commit(
    harness: &mut GraftTestHarness,
    hull: u64,
) -> Result<Option<Vec<u8>>> {
    let path = build_mint_commit_peek_path(hull);
    let res = harness.peek_raw(path).await?;
    let noun = unsafe { *res.root() };

    // Strip outer `[~ X]`.
    let outer = noun
        .as_cell()
        .map_err(|e| anyhow!("peek result not a cell: {e:?}"))?;
    let inner_unit = outer.tail();

    // Strip second `[~ Y]` — after this we have the raw `(unit @)` that
    // mint-peek emits: either `~` (missing) or `[~ root]` (present).
    let inner_cell = inner_unit
        .as_cell()
        .map_err(|e| anyhow!("inner unit not a cell: {e:?}"))?;
    let maybe_value = inner_cell.tail();

    if let Ok(_) = maybe_value.as_atom() {
        // `maybe_value` is an atom. If it's 0 (~), value is absent.
        let atom = maybe_value.as_atom().unwrap();
        let bytes = atom.as_ne_bytes();
        if bytes.iter().all(|&b| b == 0) {
            return Ok(None);
        }
        // Atom that isn't zero — unusual for mint-peek (which always
        // returns a unit), but treat as a raw value.
        return Ok(Some(bytes.to_vec()));
    }

    // `maybe_value` is a cell `[~ root]` — present value.
    let value_cell = maybe_value
        .as_cell()
        .map_err(|e| anyhow!("maybe-value cell parse failed: {e:?}"))?;
    let root_atom = value_cell
        .tail()
        .as_atom()
        .map_err(|e| anyhow!("root not an atom: {e:?}"))?;
    Ok(Some(root_atom.as_ne_bytes().to_vec()))
}

fn build_mint_commit_peek_path(hull: u64) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "mint-commit");
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
    // CARGO_MANIFEST_DIR = .../vesl-nockup/tools/graft-inject.
    // Repo root is two levels up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("graft-inject manifest dir has a grandparent")
}

