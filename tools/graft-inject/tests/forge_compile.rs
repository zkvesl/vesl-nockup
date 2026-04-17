//! Forge-graft compile-only test (Phase 9b).
//!
//! The purpose here is narrow: prove that a kernel composed from ALL
//! FOUR grafts — vesl + mint + guard + forge — actually compiles to
//! an `out.jam` and boots through `vesl-test`, AND that
//! `build_forge_prove_poke` emits a well-formed slab the kernel
//! accepts at the `?-` dispatch level.
//!
//! We deliberately do NOT send a forge-prove poke. Actual proof
//! generation runs 5-40s per attempt and requires the full STARK
//! setup — that's out of scope for this PR. What we're guarding
//! against is: stale syncs, missing prover/lower/merkle deps,
//! mis-composed manifest blocks (e.g., cause-union forgot %forge-
//! prove), and shape mismatches in the poke builder.
//!
//! Regression check: mint-commit still dispatches on the same
//! composed kernel, so adding forge doesn't clobber earlier grafts.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use nock_noun_rs::{jam_to_bytes, new_stack};
use vesl_core::{
    Mint, build_forge_prove_poke, build_mint_commit_poke,
};
use vesl_test::GraftTestHarness;

const SCRATCH_SUBDIR: &str = "forge_compile";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn four_graft_compose_boots_and_accepts_forge_shape() -> Result<()> {
    let jam_path = compose_and_compile()?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // Regression: mint still works on the 4-graft kernel.
    let root = {
        let mut mint = Mint::new();
        mint.commit(&[b"forge_compile fixture".as_ref()])
    };
    let tags = harness.poke_slab(build_mint_commit_poke(1, &root)).await?;
    assert!(
        tags.iter().any(|t| t == "mint-committed"),
        "mint-commit regression on four-graft kernel; got {tags:?}",
    );

    // Shape check: build a forge-prove poke, confirm the slab is
    // non-empty and has the expected head tag.
    let slab = build_forge_prove_poke(1, 101, b"forge_compile data");
    let mut stack = new_stack();
    let jam = jam_to_bytes(&mut stack, unsafe { *slab.root() });
    assert!(!jam.is_empty(), "build_forge_prove_poke jam should be non-empty");

    // Sanity: head of the poke noun is the tag atom "forge-prove".
    let noun = unsafe { *slab.root() };
    let cell = noun.as_cell().expect("forge-prove poke is a cell");
    let tag_atom = cell.head().as_atom().expect("forge-prove tag is an atom");
    let tag_bytes = tag_atom.as_ne_bytes();
    let tag_str = std::str::from_utf8(tag_bytes)
        .unwrap_or("?")
        .trim_end_matches('\0');
    assert_eq!(tag_str, "forge-prove", "poke tag should be 'forge-prove'");

    // Intentionally NOT pokeing the slab — that triggers the
    // prover (5-40s, not suitable for CI). The real verification
    // that the kernel accepts the shape is the fact that hoonc
    // produced out.jam: if the composed ?- didn't have a
    // %forge-prove arm, compilation would have failed.

    Ok(())
}

// -- helpers --------------------------------------------------------------

/// Build the scratch project, run graft-inject, run hoonc, return
/// the path to the produced `out.jam`.
///
/// Four-graft compose pulls in the STARK prover tree, so the
/// hoon/common and hoon/dat and hoon/jams subdirs must be present
/// in the repo root for sync.sh to have carried them over. If hoonc
/// emits `missing dependency /jams/...` or similar, the sync is stale.
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
        // Explicit all four grafts. The auto-discover default
        // would land the same set today, but future grafts
        // shouldn't silently join the forge test's kernel.
        .arg("--grafts")
        .arg("vesl-graft,mint-graft,guard-graft,forge-graft")
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
