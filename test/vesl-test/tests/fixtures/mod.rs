//! Compose-and-compile scaffold for vesl-test integration tests.
//!
//! Trimmed mirror of `vesl-nockup/tools/graft-inject/tests/fixtures/mod.rs`.
//! Cross-crate `CARGO_BIN_EXE_<name>` is not set for vesl-test's tests
//! (Cargo only sets it for bins in the same package), so we shell to
//! `cargo build -p graft-inject` and locate the workspace target dir
//! by hand. The shell-out is cached: on subsequent test runs cargo
//! short-circuits when graft-inject is already built.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// `vesl-nockup/` repo root, derived from this crate's manifest dir
/// (`vesl-nockup/test/vesl-test/`). Two parents up.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("vesl-test manifest dir has two parents (= vesl-nockup root)")
}

fn graft_inject_bin() -> Result<PathBuf> {
    let status = Command::new("cargo")
        .args(["build", "-p", "graft-inject", "--bin", "graft-inject"])
        .status()
        .context("spawn cargo build for graft-inject")?;
    if !status.success() {
        bail!("cargo build graft-inject failed: {status}");
    }
    let bin = repo_root().join("target").join("debug").join("graft-inject");
    if !bin.exists() {
        bail!(
            "graft-inject bin not found at {} after cargo build",
            bin.display()
        );
    }
    Ok(bin)
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

/// Compose a graft-injected kernel under `target/<scratch_subdir>/`
/// and hoonc-compile it. Returns the produced `out.jam` path. Mirrors
/// the canonical `compose_and_compile` from graft-inject's fixtures
/// (single-graft form only — extras / manifest overrides aren't needed
/// here).
pub fn compose_and_compile(scratch_subdir: &str, grafts: &[&str]) -> Result<PathBuf> {
    let repo_root = repo_root();
    let scratch = repo_root.join("target").join(scratch_subdir);

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

    fs::copy(repo_root.join("templates/app.hoon"), hoon_app.join("app.hoon"))?;
    copy_dir_contents(&repo_root.join("hoon/lib"), &hoon_lib)?;
    copy_dir_contents(&repo_root.join("hoon/common"), &hoon_common)?;
    copy_dir_contents(&repo_root.join("hoon/dat"), &hoon_dat)?;
    copy_dir_contents(&repo_root.join("hoon/jams"), &hoon_jams)?;

    let graft_inject = graft_inject_bin()?;
    // --accept-untrusted-libs: scratch dirs under target/ have no
    // ancestor `nockapp.toml`, so the trust-posture guard added in
    // 94fae22 rejects the inject by default. The fixture is fully
    // synthesized from in-tree templates and known-good manifests, so
    // the trust gate is safe to bypass.
    let status = Command::new(&graft_inject)
        .arg("--accept-untrusted-libs")
        .arg("--lib-dir")
        .arg(&hoon_lib)
        .arg("--grafts")
        .arg(grafts.join(","))
        .arg("--apply")
        .arg(hoon_app.join("app.hoon"))
        .status()
        .with_context(|| format!("spawn {}", graft_inject.display()))?;
    if !status.success() {
        bail!("graft-inject exited with status {status}");
    }

    // honk, the primary Hoon compiler: no shared data dir, so parallel
    // tests cannot collide on it. Mirrors graft-inject's fixture.
    let honk_status = Command::new("honk")
        .arg("--new")
        .arg("--output")
        .arg("out.jam")
        .arg("--prelude")
        .arg("hoon/common/hoon.hoon")
        .arg("hoon/app/app.hoon")
        .arg("hoon")
        .current_dir(&scratch)
        .status()
        .context("spawn honk")?;
    if !honk_status.success() {
        bail!("honk exited with status {honk_status}");
    }

    let jam = scratch.join("out.jam");
    if !jam.exists() {
        bail!("honk succeeded but {} is missing", jam.display());
    }
    Ok(jam)
}
