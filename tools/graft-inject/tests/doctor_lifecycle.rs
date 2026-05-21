//! Workstream B — `nockup graft doctor` project-health checks.
//!
//! `doctor` runs four checks against a composed kernel: the
//! schema-version handshake, Cargo `[patch]` consistency, hand-edited
//! injected blocks, and a missing `nockup:load-defaults` marker. These
//! tests compose a real kernel with `graft-inject inject --apply`, then
//! spawn `graft-inject doctor` against it — no hoonc compile, so they
//! stay fast.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};

mod fixtures;
use fixtures::{copy_dir_contents, graft_inject_bin, repo_root};

/// Build a scratch tree (hoon/lib + templates/app.hoon) and compose
/// `grafts` into the kernel with `graft-inject inject --apply`.
fn setup_composed(subdir: &str, grafts: &str) -> Result<PathBuf> {
    let repo_root = repo_root();
    let scratch = repo_root.join("target").join(subdir);
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
    let app = hoon_app.join("app.hoon");
    let status = Command::new(graft_inject_bin())
        .args([
            "--accept-untrusted-libs",
            "inject",
            app.to_str().unwrap(),
            "--lib-dir",
            hoon_lib.to_str().unwrap(),
            "--grafts",
            grafts,
            "--apply",
        ])
        .status()
        .context("spawn graft-inject inject")?;
    if !status.success() {
        bail!("setup compose failed");
    }
    Ok(scratch)
}

/// Run `graft-inject doctor` against the scratch kernel.
fn doctor(scratch: &Path, extra: &[&str]) -> Result<Output> {
    let app = scratch.join("hoon/app/app.hoon");
    let lib = scratch.join("hoon/lib");
    let mut args: Vec<String> = vec![
        "doctor".into(),
        app.to_str().unwrap().into(),
        "--lib-dir".into(),
        lib.to_str().unwrap().into(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    Command::new(graft_inject_bin())
        .args(&args)
        .output()
        .context("spawn graft-inject doctor")
}

fn app_path(scratch: &Path) -> PathBuf {
    scratch.join("hoon/app/app.hoon")
}

/// Index of the first non-blank line strictly inside settle-graft's
/// `poke` banner pair.
fn settle_poke_body_line(app: &str) -> usize {
    let lines: Vec<&str> = app.lines().collect();
    let begin = lines
        .iter()
        .position(|l| {
            l.trim()
                .starts_with("::  graft-inject:settle-graft:poke:begin")
        })
        .expect("settle-graft poke begin banner");
    let end = lines
        .iter()
        .enumerate()
        .skip(begin + 1)
        .find(|(_, l)| l.trim() == "::  graft-inject:settle-graft:poke:end")
        .map(|(i, _)| i)
        .expect("settle-graft poke end banner");
    (begin + 1..end)
        .find(|&i| !lines[i].trim().is_empty())
        .expect("settle-graft poke block has a body line")
}

/// Insert `schema_version = <v>` as the first key of a manifest's
/// `[graft]` table.
fn set_schema_version(manifest: &Path, version: u32) -> Result<()> {
    let raw = fs::read_to_string(manifest)?;
    let patched = raw.replacen(
        "[graft]\n",
        &format!("[graft]\nschema_version = {version}\n"),
        1,
    );
    assert_ne!(raw, patched, "manifest must contain a `[graft]` header");
    fs::write(manifest, patched)?;
    Ok(())
}

/// A freshly-composed kernel with stock manifests is healthy — `doctor`
/// exits 0 and reports no findings.
#[test]
fn doctor_clean_project_exits_zero() -> Result<()> {
    let scratch = setup_composed("doctor_clean", "settle-graft")?;
    let out = doctor(&scratch, &["--json"])?;
    assert!(
        out.status.success(),
        "a clean project must exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"findings\": []"),
        "clean project must report an empty findings array; got:\n{stdout}"
    );
    Ok(())
}

/// An edit inside a graft's banner pair is flagged as a hand-edited
/// block, and `doctor` exits nonzero so CI can gate on it.
#[test]
fn doctor_flags_hand_edited_block() -> Result<()> {
    let scratch = setup_composed("doctor_hand_edit", "settle-graft")?;
    let app = app_path(&scratch);
    let original = fs::read_to_string(&app)?;
    let idx = settle_poke_body_line(&original);

    let mut lines: Vec<String> = original.lines().map(String::from).collect();
    lines[idx] = format!("{}  :: doctor-test hand-edit", lines[idx]);
    fs::write(&app, lines.join("\n"))?;

    let out = doctor(&scratch, &["--json"])?;
    assert!(
        !out.status.success(),
        "a hand-edited block must make doctor exit nonzero"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("hand_edited_block"),
        "doctor must report a hand_edited_block finding; got:\n{stdout}"
    );
    assert!(
        stdout.contains("settle-graft"),
        "the finding must name the edited graft; got:\n{stdout}"
    );
    Ok(())
}

/// `doctor` tracks the live file: a hand-edit is flagged, and once the
/// exact original line is restored the project is clean again.
#[test]
fn doctor_clean_after_hand_edit_reverted() -> Result<()> {
    let scratch = setup_composed("doctor_revert", "settle-graft")?;
    let app = app_path(&scratch);
    let original = fs::read_to_string(&app)?;
    let idx = settle_poke_body_line(&original);
    let original_line = original.lines().nth(idx).unwrap().to_string();

    let mut lines: Vec<String> = original.lines().map(String::from).collect();
    lines[idx] = format!("{original_line}  :: doctor-test");
    fs::write(&app, lines.join("\n"))?;
    assert!(
        !doctor(&scratch, &[])?.status.success(),
        "doctor must flag the hand-edit"
    );

    // Restore the exact original line.
    lines[idx] = original_line;
    fs::write(&app, lines.join("\n"))?;
    assert!(
        doctor(&scratch, &[])?.status.success(),
        "doctor must be clean once the edit is reverted"
    );
    Ok(())
}

/// A discovered manifest declaring a future schema is an error-severity
/// finding; `doctor` exits nonzero.
#[test]
fn doctor_flags_future_schema() -> Result<()> {
    let scratch = setup_composed("doctor_future_schema", "settle-graft")?;
    set_schema_version(&scratch.join("hoon/lib/settle-graft.toml"), 9999)?;

    let out = doctor(&scratch, &["--json"])?;
    assert!(
        !out.status.success(),
        "a future-schema manifest must make doctor exit nonzero"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("schema_version") && stdout.contains("\"error\""),
        "doctor must report an error-severity schema_version finding; got:\n{stdout}"
    );
    Ok(())
}

/// A grafted kernel missing the `nockup:load-defaults` marker is
/// flagged — schema-extension resume would silently drop effects.
#[test]
fn doctor_flags_missing_load_defaults() -> Result<()> {
    let scratch = setup_composed("doctor_no_load_defaults", "settle-graft")?;
    let app = app_path(&scratch);
    let stripped: String = fs::read_to_string(&app)?
        .lines()
        .filter(|l| !l.contains("nockup:load-defaults"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&app, stripped)?;

    let out = doctor(&scratch, &["--json"])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("missing_load_defaults"),
        "doctor must report a missing_load_defaults finding; got:\n{stdout}"
    );
    Ok(())
}

/// `--format build-warnings` emits a `doctor:` line per finding to
/// stdout and always exits 0 — the contract the scaffold build.rs
/// depends on (a build script must never fail the build).
#[test]
fn doctor_build_warnings_exits_zero_with_findings() -> Result<()> {
    let scratch = setup_composed("doctor_build_warnings", "settle-graft")?;
    let app = app_path(&scratch);
    let original = fs::read_to_string(&app)?;
    let idx = settle_poke_body_line(&original);
    let mut lines: Vec<String> = original.lines().map(String::from).collect();
    lines[idx] = format!("{}  :: doctor-test", lines[idx]);
    fs::write(&app, lines.join("\n"))?;

    let out = doctor(&scratch, &["--format", "build-warnings"])?;
    assert!(
        out.status.success(),
        "build-warnings format must exit 0 even with findings; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.lines().any(|l| l.starts_with("doctor: ")),
        "build-warnings format must emit a `doctor: ` line per finding; got:\n{stdout}"
    );
    Ok(())
}

/// A `Cargo.toml` pinning two different nockchain revs is flagged —
/// the partial-update state behind the `ibig`/`UBig` build failure.
#[test]
fn doctor_patch_consistency_flags_mismatched_revs() -> Result<()> {
    let scratch = setup_composed("doctor_patch_mismatch", "settle-graft")?;
    fs::write(scratch.join("nockapp.toml"), "# doctor patch-consistency test\n")?;
    fs::write(
        scratch.join("Cargo.toml"),
        r#"[package]
name = "doctor-patch-test"
version = "0.0.0"

[dependencies]
nockapp = { git = "https://github.com/nockchain/nockchain.git", rev = "1111111111111111111111111111111111111111" }
nockvm = { git = "https://github.com/nockchain/nockchain.git", rev = "2222222222222222222222222222222222222222" }
"#,
    )?;

    let out = doctor(&scratch, &["--json"])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("patch_consistency"),
        "doctor must flag a Cargo.toml pinning two nockchain revs; got:\n{stdout}"
    );
    Ok(())
}

/// A `Cargo.toml` whose nockchain revs all agree raises no
/// patch-consistency finding.
#[test]
fn doctor_patch_consistency_silent_on_agreeing_revs() -> Result<()> {
    let scratch = setup_composed("doctor_patch_agree", "settle-graft")?;
    fs::write(scratch.join("nockapp.toml"), "# doctor patch-consistency test\n")?;
    fs::write(
        scratch.join("Cargo.toml"),
        r#"[package]
name = "doctor-patch-test"
version = "0.0.0"

[dependencies]
nockapp = { git = "https://github.com/nockchain/nockchain.git", rev = "1111111111111111111111111111111111111111" }
nockvm = { git = "https://github.com/nockchain/nockchain.git", rev = "1111111111111111111111111111111111111111" }
"#,
    )?;

    let out = doctor(&scratch, &["--json"])?;
    assert!(
        out.status.success(),
        "agreeing nockchain revs must leave doctor clean; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("patch_consistency"),
        "no patch-consistency finding expected; got:\n{stdout}"
    );
    Ok(())
}
