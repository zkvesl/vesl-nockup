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
//! Peek-path helpers (`peek_hull_value`, `peek_keyed_value`,
//! `peek_keyless_atom`) are thin async wrappers over `vesl_core::peek`'s
//! path-builders + triple-unit decoder. They keep their harness-bound
//! signatures so test call sites stay terse; the underlying mechanics
//! (build path slab → `harness.peek_raw(slab).await` → strip
//! `[~ [~ (unit @)]]` → atom bytes) live canonically in vesl-core.

#![allow(dead_code)] // tests use different subsets

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use vesl_core::{
    build_hull_peek_path, build_keyed_peek_path, build_keyless_peek_path,
    unwrap_triple_unit_atom,
};
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

/// Paths produced by a single `compose_and_compile_*` run.
///
/// The basic [`compose_and_compile`] entry-point still hands back just
/// the jam path because that's all 17+ lifecycle tests need. The
/// extras-variant (phase03 prelude/postlude integration) needs to
/// reach into the composed source to assert banner provenance and
/// idempotence, so its wrapper returns this struct instead. `lib_dir`
/// is exposed too: the idempotence re-runs need it for
/// `graft-inject --lib-dir`.
pub struct ComposedArtifacts {
    pub jam_path: PathBuf,
    pub source_path: PathBuf,
    pub lib_dir: PathBuf,
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
    Ok(compose_and_compile_inner(scratch_subdir, grafts, &[], &[])?.jam_path)
}

/// Synthetic graft fixture inlined into a test's scratch hoon/lib/.
///
/// Phase 03b prelude/postlude integration tests need synthetic grafts
/// that exist only for the duration of the test — writing them into
/// the shared `vesl-nockup/hoon/lib/` would pollute the discovery tree
/// for every other test. This struct lets a test ship its own
/// `(name, hoon_body, toml_body)` triples that get written into the
/// scratch before graft-inject runs.
pub struct SyntheticGraft<'a> {
    pub name: &'a str,
    pub hoon: &'a str,
    pub toml: &'a str,
}

/// Replacement TOML manifest for an existing graft already in the
/// scratch hoon/lib/.
///
/// Used by tests that need to inject manifest-level toggles
/// (e.g. `[graft.gates]`) into a stock manifest without modifying
/// the shared `vesl-nockup/hoon/lib/` tree. The override writes
/// `<name>.toml` after `copy_dir_contents` runs, so the canonical
/// file is overwritten rather than duplicated. Only the TOML is
/// replaced — the matching `<name>.hoon` library stays as-is.
pub struct ManifestOverride<'a> {
    pub name: &'a str,
    pub toml: String,
}

/// Compose a graft-injected kernel with extra synthetic grafts written
/// into the scratch's `hoon/lib/`, then hoonc-compile it.
///
/// Use this when a test needs a graft that doesn't (and shouldn't)
/// live in the shared discovery tree — e.g. the Phase 03b prelude /
/// postlude tests, which exercise the new graft-inject markers via
/// minimal synthetic grafts rather than waiting on real Phase 03c
/// consumers (validate / fsm) to land.
pub fn compose_and_compile_with_extras(
    scratch_subdir: &str,
    grafts: &[&str],
    extras: &[SyntheticGraft<'_>],
) -> Result<ComposedArtifacts> {
    compose_and_compile_inner(scratch_subdir, grafts, extras, &[])
}

/// Compose a graft-injected kernel after replacing one or more
/// canonical manifest TOMLs in the scratch hoon/lib/.
///
/// Use this when a test needs to exercise a manifest-level toggle
/// — e.g. `[graft.gates] gate = "..."` on settle-graft — without
/// committing the toggle to `vesl-nockup/hoon/lib/` (which would
/// affect every other test that consumes the same stock manifest).
pub fn compose_and_compile_with_manifest_overrides(
    scratch_subdir: &str,
    grafts: &[&str],
    overrides: &[ManifestOverride<'_>],
) -> Result<PathBuf> {
    Ok(compose_and_compile_inner(scratch_subdir, grafts, &[], overrides)?.jam_path)
}

fn compose_and_compile_inner(
    scratch_subdir: &str,
    grafts: &[&str],
    extras: &[SyntheticGraft<'_>],
    overrides: &[ManifestOverride<'_>],
) -> Result<ComposedArtifacts> {
    let repo_root = repo_root();
    // Per-test tempdir prevents parallel test workers from racing on a
    // shared `target/<scratch_subdir>/` tree. `into_path()` persists the
    // directory so it survives the function's lifetime; /tmp rotation
    // handles cleanup. The `scratch_subdir` becomes a debug-readable
    // prefix on failure.
    let scratch = tempfile::Builder::new()
        .prefix(&format!("graft-inject-{}-", scratch_subdir))
        .tempdir()
        .with_context(|| format!("create tempdir for {}", scratch_subdir))?
        .keep();
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

    // Write any synthetic graft fixtures into the scratch's hoon/lib/
    // before graft-inject discovers manifests. These exist only for
    // this test run.
    for extra in extras {
        fs::write(hoon_lib.join(format!("{}.hoon", extra.name)), extra.hoon)
            .with_context(|| format!("writing synthetic {}.hoon", extra.name))?;
        fs::write(hoon_lib.join(format!("{}.toml", extra.name)), extra.toml)
            .with_context(|| format!("writing synthetic {}.toml", extra.name))?;
    }

    // Manifest overrides land last so they win over any cp'd or
    // synthetic file with the same name.
    for ov in overrides {
        fs::write(hoon_lib.join(format!("{}.toml", ov.name)), &ov.toml)
            .with_context(|| format!("writing manifest override {}.toml", ov.name))?;
    }

    let graft_inject = graft_inject_bin();
    let status = Command::new(&graft_inject)
        .arg("--accept-untrusted-libs").arg("--lib-dir")
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
    Ok(ComposedArtifacts {
        jam_path: jam,
        source_path: hoon_app.join("app.hoon"),
        lib_dir: hoon_lib,
    })
}

/// Peek `[%<tag> hull ~]` on a commitment graft and extract the
/// stored root. Thin wrapper over `vesl_core::peek` for harness-bound
/// test code.
pub async fn peek_hull_value(
    harness: &mut GraftTestHarness,
    tag: &str,
    hull: u64,
) -> Result<Option<Vec<u8>>> {
    let result = harness.peek_raw(build_hull_peek_path(tag, hull)).await?;
    Ok(unwrap_triple_unit_atom(&result))
}

/// Peek `[%<tag> key ~]` on a state graft and extract the stored
/// value. Thin wrapper over `vesl_core::peek`.
pub async fn peek_keyed_value(
    harness: &mut GraftTestHarness,
    tag: &str,
    key: &str,
) -> Result<Option<Vec<u8>>> {
    let result = harness.peek_raw(build_keyed_peek_path(tag, key)).await?;
    Ok(unwrap_triple_unit_atom(&result))
}

/// Peek `[%<tag> ~]` on a state graft and extract the inner atom.
/// Thin wrapper over `vesl_core::peek`.
pub async fn peek_keyless_atom(
    harness: &mut GraftTestHarness,
    tag: &str,
) -> Result<Option<Vec<u8>>> {
    let result = harness.peek_raw(build_keyless_peek_path(tag)).await?;
    Ok(unwrap_triple_unit_atom(&result))
}
