//! Shared scaffolding for graft-inject integration tests.
//!
//! Every integration test under `tests/` needs the same three-step
//! dance: (1) build a scratch project under `target/<name>/` with the
//! repo's `hoon/lib`, `hoon/common`, `hoon/dat`, `hoon/jams`, and the
//! scaffold `templates/app.hoon` copied in; (2) run `graft-inject`
//! against the scratch app with a chosen graft set; (3) run `hoonc`
//! and return the path to the produced `out.jam`. This module
//! packages that sequence as [`compose_and_compile`], plus a handful
//! of helpers that were duplicated across the three lifecycle tests
//! before Phase 11 extracted them.
//!
//! Peek-path helpers (`build_hull_peek_path`, `peek_hull_value`)
//! encode the triple-unit convention the commitment grafts all use
//! (mint/guard/settle wrap `(~(get by map) hull)` with `` `` `` so
//! the kernel peek result is `[~ [~ (unit @)]]`). Callers pass the
//! graft's peek-path tag (`"mint-commit"`, `"guard-root"`,
//! `"vesl-root"`) and a hull-id; the helper strips three unit
//! layers to surface the raw root bytes.

#![allow(dead_code)] // tests use different subsets

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use nock_noun_rs::{atom_from_u64, make_tag_in};
use nockapp::noun::slab::NounSlab;
use nockvm::noun::{D, T};
use vesl_test::GraftTestHarness;

/// Repo root derived from `CARGO_MANIFEST_DIR` (= `.../vesl-nockup/tools/graft-inject`).
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("graft-inject manifest dir has a grandparent")
}

/// Path to the `graft-inject` binary built by cargo-test.
pub fn graft_inject_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_graft-inject"))
}

/// Recursively copy every entry under `src` into `dst`.
pub fn copy_dir_contents(src: &Path, dst: &Path) -> Result<()> {
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

/// Compose a graft-injected kernel and hoonc-compile it.
///
/// Creates (and destroys) a scratch tree at `target/<scratch_subdir>/`
/// populated from the repo's canonical `templates/app.hoon` and
/// `hoon/{lib,common,dat,jams}` trees, runs `graft-inject --grafts
/// <csv> …`, then shells to `hoonc --new …`. Returns the produced
/// `out.jam` path.
///
/// `grafts` selects which manifests graft-inject consumes. Pass
/// explicit names (e.g. `&["settle-graft", "mint-graft"]`) so a future
/// graft dropping into `hoon/lib/` doesn't silently join the test's
/// composed kernel via auto-discovery.
///
/// `hoonc` must be on `PATH` — same pre-req as every other build
/// route in this repo.
pub fn compose_and_compile(scratch_subdir: &str, grafts: &[&str]) -> Result<PathBuf> {
    let repo_root = repo_root();
    let scratch = repo_root.join("target").join(scratch_subdir);

    if scratch.exists() {
        fs::remove_dir_all(&scratch)
            .with_context(|| format!("clean {}", scratch.display()))?;
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

    // hoon/dat + hoon/jams are mandatory even on grafts that don't
    // touch the prover: hoonc eager-parses files in common/, some of
    // which transitively `/#` softed-constraints.jam. Dropping the
    // tree turns forge compositions into "missing dependency
    // /jams/constraints-0-1.jam".
    fs::copy(
        repo_root.join("templates/app.hoon"),
        hoon_app.join("app.hoon"),
    )?;
    copy_dir_contents(&repo_root.join("hoon/lib"), &hoon_lib)?;
    copy_dir_contents(&repo_root.join("hoon/common"), &hoon_common)?;
    copy_dir_contents(&repo_root.join("hoon/dat"), &hoon_dat)?;
    copy_dir_contents(&repo_root.join("hoon/jams"), &hoon_jams)?;

    let graft_inject = graft_inject_bin();
    let status = Command::new(&graft_inject)
        .arg("--lib-dir")
        .arg(&hoon_lib)
        .arg("--grafts")
        .arg(grafts.join(","))
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

/// Build a `[%<tag> hull=@ ~]` peek path slab.
pub fn build_hull_peek_path(tag: &str, hull: u64) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag_atom = make_tag_in(&mut slab, tag);
    let hull_atom = atom_from_u64(&mut slab, hull);
    let path = T(&mut slab, &[tag_atom, hull_atom, D(0)]);
    slab.set_root(path);
    slab
}

/// Peek `[%<tag> hull ~]` on a commitment graft and extract the
/// stored root (if any).
///
/// Commitment grafts (mint/guard/settle) wrap `(~(get by …) hull)`
/// with `` `` `` `` so the peek result shape is `[~ [~ (unit @)]]`:
///   * present hull → `[~ [~ [~ root]]]`
///   * missing hull → `[~ [~ ~]]`
///
/// Returns `Some(root_bytes)` for the former, `None` for the latter.
pub async fn peek_hull_value(
    harness: &mut GraftTestHarness,
    tag: &str,
    hull: u64,
) -> Result<Option<Vec<u8>>> {
    let path = build_hull_peek_path(tag, hull);
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
        return Ok(Some(bytes.to_vec()));
    }

    let value_cell = maybe_value
        .as_cell()
        .map_err(|e| anyhow!("maybe-value not a cell: {e:?}"))?;
    let root_atom = value_cell
        .tail()
        .as_atom()
        .map_err(|e| anyhow!("root not an atom: {e:?}"))?;
    Ok(Some(root_atom.as_ne_bytes().to_vec()))
}
