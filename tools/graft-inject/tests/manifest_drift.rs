//! Manifest-drift detection in graft-inject's idempotence layer.
//!
//! An earlier graft-inject treated banner-pair presence as the skip signal:
//! re-running `--apply` after editing a manifest's TOML (e.g. swapping
//! `[graft.gates] gate = "sig-verify-schnorr"` to `"sig-verify-ed25519"`)
//! left the old composed body in place. The corrected behavior embeds
//! the manifest sha256
//! in each begin banner and strips/reinjects the pair when the embedded
//! prefix doesn't match the current manifest digest.
//!
//! These tests run graft-inject directly (no hoonc compile) against a
//! tmpdir scratch tree built from the repo's canonical `hoon/lib`,
//! `templates/app.hoon`, etc. They focus on the change: banner
//! emission and the strip-and-reinject path. Compile-time correctness
//! of the produced kernels is exercised by the `*_lifecycle.rs` tests.

use std::fs;
use std::process::Command;

use anyhow::{Context, Result};

mod fixtures;
use fixtures::{copy_dir_contents, graft_inject_bin, repo_root};

/// Build a tmpdir scratch tree with the repo's canonical hoon/lib,
/// hoon/common, hoon/dat, and templates/app.hoon. hoon/common and
/// hoon/dat are needed because the transitive-imports lint resolves
/// `/= * /common/wrapper` (and its `/# softed-constraints` chain)
/// before `graft-inject --apply` writes; without them, the lint
/// refuses the write.
fn setup_scratch(scratch_subdir: &str) -> Result<std::path::PathBuf> {
    let repo_root = repo_root();
    let scratch = repo_root.join("target").join(scratch_subdir);
    if scratch.exists() {
        fs::remove_dir_all(&scratch)?;
    }
    let hoon_app = scratch.join("hoon/app");
    let hoon_lib = scratch.join("hoon/lib");
    let hoon_common = scratch.join("hoon/common");
    let hoon_dat = scratch.join("hoon/dat");
    fs::create_dir_all(&hoon_app)?;
    fs::create_dir_all(&hoon_lib)?;
    fs::create_dir_all(&hoon_common)?;
    fs::create_dir_all(&hoon_dat)?;
    fs::copy(
        repo_root.join("templates/app.hoon"),
        hoon_app.join("app.hoon"),
    )?;
    copy_dir_contents(&repo_root.join("hoon/lib"), &hoon_lib)?;
    copy_dir_contents(&repo_root.join("hoon/common"), &hoon_common)?;
    copy_dir_contents(&repo_root.join("hoon/dat"), &hoon_dat)?;
    Ok(scratch)
}

fn run_graft_inject(scratch: &std::path::Path, grafts: &str) -> Result<std::process::Output> {
    Command::new(graft_inject_bin())
        .arg("--accept-untrusted-libs").arg("--lib-dir")
        .arg(scratch.join("hoon/lib"))
        .arg("--grafts")
        .arg(grafts)
        .arg("--apply")
        .arg(scratch.join("hoon/app/app.hoon"))
        .output()
        .context("spawn graft-inject")
}

/// Extract the `sha256:<hex>` token from a begin banner line. Returns
/// `None` for legacy banners that don't carry one.
fn banner_sha(line: &str) -> Option<String> {
    line.split(" sha256:").nth(1).map(|tail| {
        tail.split_whitespace()
            .next()
            .unwrap_or("")
            .to_string()
    })
}

fn first_settle_imports_banner(source: &str) -> Option<String> {
    source
        .lines()
        .find(|l| {
            l.trim_start()
                .starts_with("::  graft-inject:settle-graft:imports:begin")
        })
        .map(String::from)
}

/// Headline test: editing settle-graft's manifest after the first
/// inject and re-running `--apply` MUST update the composed body to
/// reflect the new manifest. Verified by:
/// 1. The begin banner's embedded sha256 changes between the two runs.
/// 2. The first run's sha256 is no longer present anywhere in the file.
/// 3. graft-inject's stderr names the drift event.
#[test]
fn manifest_drift_triggers_reinjection() -> Result<()> {
    let scratch = setup_scratch("manifest_drift_reinjection")?;
    let app_hoon = scratch.join("hoon/app/app.hoon");
    let manifest = scratch.join("hoon/lib/settle-graft.toml");

    let initial = run_graft_inject(&scratch, "settle-graft")?;
    assert!(initial.status.success(), "first inject failed");

    let initial_app = fs::read_to_string(&app_hoon)?;
    let initial_banner = first_settle_imports_banner(&initial_app)
        .expect("first inject must emit a settle-graft imports banner");
    let initial_sha = banner_sha(&initial_banner)
        .expect("first inject must emit a banner with ` sha256:<hex>` suffix");
    assert_eq!(
        initial_sha.len(),
        12,
        "short sha256 prefix is exactly 12 hex chars"
    );

    // Drift the manifest by appending a comment. graft-inject's sha256
    // is over the raw TOML bytes, so any byte change shifts the digest.
    let original_manifest = fs::read_to_string(&manifest)?;
    fs::write(
        &manifest,
        format!("{original_manifest}\n# drift-test cookie\n"),
    )?;

    let drift = run_graft_inject(&scratch, "settle-graft")?;
    assert!(
        drift.status.success(),
        "second graft-inject run failed; stderr:\n{}",
        String::from_utf8_lossy(&drift.stderr)
    );
    let stderr = String::from_utf8_lossy(&drift.stderr);
    assert!(
        stderr.contains("manifest drift"),
        "drift re-run must log a `manifest drift` line; stderr was:\n{stderr}"
    );

    let updated_app = fs::read_to_string(&app_hoon)?;
    let updated_banner = first_settle_imports_banner(&updated_app)
        .expect("re-inject must leave a settle-graft imports banner");
    let updated_sha = banner_sha(&updated_banner)
        .expect("re-inject must emit a banner with ` sha256:<hex>` suffix");

    assert_ne!(
        initial_sha, updated_sha,
        "banner sha256 must change after manifest drift"
    );
    assert!(
        !updated_app.contains(&initial_sha),
        "post-reinject app.hoon should not contain the stale sha256 prefix `{initial_sha}`"
    );
    Ok(())
}

/// Idempotence regression: when the manifest is unchanged between runs,
/// the second run must NOT log drift and must NOT modify the file.
#[test]
fn unchanged_manifest_skips_silently() -> Result<()> {
    let scratch = setup_scratch("manifest_drift_no_change")?;
    let app_hoon = scratch.join("hoon/app/app.hoon");

    run_graft_inject(&scratch, "settle-graft")?;
    let before = fs::read_to_string(&app_hoon)?;

    let second = run_graft_inject(&scratch, "settle-graft")?;
    assert!(second.status.success(), "second run failed");
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        !stderr.contains("manifest drift"),
        "unchanged manifest must not log drift; stderr was:\n{stderr}"
    );

    let after = fs::read_to_string(&app_hoon)?;
    assert_eq!(
        before, after,
        "unchanged manifest must leave app.hoon byte-identical"
    );
    Ok(())
}

/// Legacy banner format (no `sha256:` suffix) must trigger a one-time
/// force-reinject so the new format gets stamped. Simulates upgrading
/// a project that was last composed with an older graft-inject.
#[test]
fn legacy_banner_force_reinjects_once() -> Result<()> {
    let scratch = setup_scratch("manifest_drift_legacy_banner")?;
    let app_hoon = scratch.join("hoon/app/app.hoon");

    run_graft_inject(&scratch, "settle-graft")?;
    let modern = fs::read_to_string(&app_hoon)?;

    // Strip every ` sha256:<hex>` suffix from begin banners to simulate
    // a project last composed with an older graft-inject.
    let mut legacy: String = modern
        .lines()
        .map(|l| match l.split_once(":begin sha256:") {
            Some((head, _)) => format!("{head}:begin"),
            None => l.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n");
    if modern.ends_with('\n') {
        legacy.push('\n');
    }
    assert_ne!(
        modern, legacy,
        "test fixture invariant: stripping sha256 must change the source"
    );
    fs::write(&app_hoon, &legacy)?;

    let restamp = run_graft_inject(&scratch, "settle-graft")?;
    assert!(restamp.status.success(), "legacy-banner re-run failed");
    let stderr = String::from_utf8_lossy(&restamp.stderr);
    assert!(
        stderr.contains("legacy banner"),
        "legacy-banner re-run must log a `legacy banner` line; stderr was:\n{stderr}"
    );

    let restamped = fs::read_to_string(&app_hoon)?;
    let banner = first_settle_imports_banner(&restamped)
        .expect("re-inject must leave a settle-graft imports banner");
    assert!(
        banner_sha(&banner).is_some(),
        "post-reinject banner must carry a fresh sha256 suffix"
    );
    Ok(())
}

/// Binary-level drop+readd regression guard: drop a graft from the
/// active set and re-add it on the next run; the third run's
/// `app.hoon` must be byte-identical to the first. The unit test of
/// the same shape exercises `inject()` directly; this one hits the
/// spawned binary against real graft manifests.
#[test]
fn drop_readd_round_trip_byte_identity() -> Result<()> {
    let scratch = setup_scratch("rh2_drop_readd_byte_identity")?;
    let app_hoon = scratch.join("hoon/app/app.hoon");

    let full_set = "settle-graft,registry-graft,log-graft,validate-graft";
    let dropped = "settle-graft,registry-graft,log-graft";

    let initial = run_graft_inject(&scratch, full_set)?;
    assert!(initial.status.success(), "initial inject failed");
    let baseline = fs::read_to_string(&app_hoon)?;

    let drop = run_graft_inject(&scratch, dropped)?;
    assert!(drop.status.success(), "drop run failed");
    let drop_stderr = String::from_utf8_lossy(&drop.stderr);
    assert!(
        drop_stderr.contains("validate-graft: orphan banner pair"),
        "drop run must orphan-prune validate-graft; stderr was:\n{drop_stderr}"
    );

    let readd = run_graft_inject(&scratch, full_set)?;
    assert!(readd.status.success(), "readd run failed");
    let final_state = fs::read_to_string(&app_hoon)?;

    assert_eq!(
        baseline, final_state,
        "drop+readd round trip must leave app.hoon byte-identical \
         (byte-identity invariant)"
    );
    Ok(())
}
