//! Workstream A — manifest-schema version handshake (P2).
//!
//! A graft manifest may declare `schema_version` in its `[graft]` table.
//! When a discovered manifest targets a version newer than this binary's
//! `MANIFEST_SCHEMA_VERSION`, the compose path (`inject`) hard-errors
//! rather than mis-composing a schema it cannot model. `list` is
//! read-only and stays non-erroring. An absent or equal `schema_version`
//! is always compatible — the schema is append-only.
//!
//! These tests spawn `graft-inject` directly (no hoonc compile) against
//! a tmpdir scratch tree built from the repo's canonical `hoon/lib` and
//! `templates/app.hoon`. The handshake check fires before any source is
//! read or written, so the tests do not need `hoon/common,dat,jams`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result};

mod fixtures;
use fixtures::{copy_dir_contents, graft_inject_bin, repo_root};

/// Build a tmpdir scratch tree with the repo's canonical hoon/lib +
/// templates/app.hoon.
fn setup_scratch(scratch_subdir: &str) -> Result<PathBuf> {
    let repo_root = repo_root();
    let scratch = repo_root.join("target").join(scratch_subdir);
    if scratch.exists() {
        fs::remove_dir_all(&scratch)?;
    }
    let hoon_app = scratch.join("hoon/app");
    let hoon_lib = scratch.join("hoon/lib");
    fs::create_dir_all(&hoon_app)?;
    fs::create_dir_all(&hoon_lib)?;
    fs::copy(
        repo_root.join("templates/app.hoon"),
        hoon_app.join("app.hoon"),
    )?;
    copy_dir_contents(&repo_root.join("hoon/lib"), &hoon_lib)?;
    Ok(scratch)
}

/// Insert `schema_version = <version>` as the first key of a manifest's
/// `[graft]` table. graft-inject's loader reads it via `#[serde(default)]`.
fn set_schema_version(manifest: &Path, version: u32) -> Result<()> {
    let raw = fs::read_to_string(manifest)
        .with_context(|| format!("reading {}", manifest.display()))?;
    let patched = raw.replacen(
        "[graft]\n",
        &format!("[graft]\nschema_version = {version}\n"),
        1,
    );
    assert_ne!(
        raw, patched,
        "fixture invariant: manifest must contain a `[graft]` table header"
    );
    fs::write(manifest, patched)?;
    Ok(())
}

fn run(args: &[&str]) -> Result<Output> {
    Command::new(graft_inject_bin())
        .arg("--accept-untrusted-libs")
        .args(args)
        .output()
        .context("spawn graft-inject")
}

/// `inject` against a manifest declaring a schema newer than the binary
/// supports must hard-error — naming the graft — and write nothing.
#[test]
fn inject_errors_on_future_schema() -> Result<()> {
    let scratch = setup_scratch("schema_handshake_future")?;
    set_schema_version(&scratch.join("hoon/lib/settle-graft.toml"), 9999)?;
    let app = scratch.join("hoon/app/app.hoon");

    let out = run(&[
        "inject",
        app.to_str().unwrap(),
        "--lib-dir",
        scratch.join("hoon/lib").to_str().unwrap(),
        "--grafts",
        "settle-graft",
        "--apply",
    ])?;
    assert!(
        !out.status.success(),
        "a future-schema manifest must fail the compose path"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("manifest schema too new"),
        "stderr must name the handshake failure; got:\n{stderr}"
    );
    assert!(
        stderr.contains("settle-graft"),
        "stderr must name the offending graft; got:\n{stderr}"
    );
    assert!(
        !fs::read_to_string(&app)?.contains("graft-inject:settle-graft"),
        "the handshake must bail before any banner is written"
    );
    Ok(())
}

/// Stock manifests carry no `schema_version`; `inject` must still succeed.
#[test]
fn inject_ok_on_absent_schema() -> Result<()> {
    let scratch = setup_scratch("schema_handshake_absent")?;
    let out = run(&[
        "inject",
        scratch.join("hoon/app/app.hoon").to_str().unwrap(),
        "--lib-dir",
        scratch.join("hoon/lib").to_str().unwrap(),
        "--grafts",
        "settle-graft",
        "--apply",
    ])?;
    assert!(
        out.status.success(),
        "an absent schema_version must be treated as compatible; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

/// A manifest declaring exactly the binary's supported schema is
/// compatible — the check fires only on a strictly greater version.
#[test]
fn inject_ok_on_equal_schema() -> Result<()> {
    let scratch = setup_scratch("schema_handshake_equal")?;
    set_schema_version(&scratch.join("hoon/lib/settle-graft.toml"), 1)?;
    let out = run(&[
        "inject",
        scratch.join("hoon/app/app.hoon").to_str().unwrap(),
        "--lib-dir",
        scratch.join("hoon/lib").to_str().unwrap(),
        "--grafts",
        "settle-graft",
        "--apply",
    ])?;
    assert!(
        out.status.success(),
        "schema_version equal to the binary's must be compatible; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

/// `list` is read-only; a future-schema manifest in the discovery set
/// must not make it error.
#[test]
fn list_does_not_error_on_future_schema() -> Result<()> {
    let scratch = setup_scratch("schema_handshake_list")?;
    set_schema_version(&scratch.join("hoon/lib/settle-graft.toml"), 9999)?;
    let out = run(&[
        "list",
        "--lib-dir",
        scratch.join("hoon/lib").to_str().unwrap(),
    ])?;
    assert!(
        out.status.success(),
        "list must not error on a future-schema manifest; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}
