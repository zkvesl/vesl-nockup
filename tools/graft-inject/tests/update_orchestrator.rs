//! `nockup graft update` orchestrator — integration tests.
//!
//! `update` chains schema preflight → `nockup package install` →
//! re-check → inject preview + doctor report → confirm → `inject
//! --apply`. These tests stub `nockup` via `NOCKUP_BIN` (a tiny shell
//! script) so the orchestration runs without a real nockup install,
//! and spawn `graft-inject update` against a tmpdir scratch project.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use anyhow::{Context, Result, bail};

mod fixtures;
use fixtures::{copy_dir_contents, graft_inject_bin, repo_root};

/// Build a minimal scratch project: templates/app.hoon as the kernel,
/// settle-graft.toml as the only manifest, and the hoon/common + hoon/dat
/// trees so the transitive-imports lint that gates `--apply` resolves
/// `/= * /common/wrapper` and its `/# softed-constraints` chain.
fn setup(subdir: &str) -> Result<PathBuf> {
    let repo_root = repo_root();
    let scratch = repo_root.join("target").join(subdir);
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
    fs::copy(
        repo_root.join("hoon/lib/settle-graft.toml"),
        hoon_lib.join("settle-graft.toml"),
    )?;
    // The template kernel imports `/+ lib` — stub the target so the
    // transitive-imports lint that gates `inject --apply` resolves.
    fs::write(hoon_lib.join("lib.hoon"), "")?;
    copy_dir_contents(&repo_root.join("hoon/common"), &hoon_common)?;
    copy_dir_contents(&repo_root.join("hoon/dat"), &hoon_dat)?;
    Ok(scratch)
}

/// Write an executable `nockup` stub that exits with `code`.
fn nockup_stub(scratch: &Path, code: i32) -> Result<PathBuf> {
    let stub = scratch.join("nockup-stub.sh");
    fs::write(&stub, format!("#!/bin/sh\nexit {code}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755))?;
    }
    Ok(stub)
}

fn app_path(scratch: &Path) -> PathBuf {
    scratch.join("hoon/app/app.hoon")
}

/// Compose settle-graft into the scratch kernel via `inject --apply`.
fn compose(scratch: &Path) -> Result<()> {
    let status = Command::new(graft_inject_bin())
        .args([
            "--accept-untrusted-libs",
            "inject",
            app_path(scratch).to_str().unwrap(),
            "--lib-dir",
            scratch.join("hoon/lib").to_str().unwrap(),
            "--grafts",
            "settle-graft",
            "--apply",
        ])
        .status()
        .context("spawn graft-inject inject")?;
    if !status.success() {
        bail!("compose failed");
    }
    Ok(())
}

/// Run `graft-inject update` with `nockup` stubbed to exit `stub_code`,
/// optionally piping `stdin` to the confirm prompt.
fn run_update(
    scratch: &Path,
    stub_code: i32,
    extra: &[&str],
    stdin: Option<&str>,
) -> Result<Output> {
    let stub = nockup_stub(scratch, stub_code)?;
    let mut cmd = Command::new(graft_inject_bin());
    cmd.args([
        "update",
        app_path(scratch).to_str().unwrap(),
        "--lib-dir",
        scratch.join("hoon/lib").to_str().unwrap(),
    ])
    .args(extra)
    .env("NOCKUP_BIN", &stub)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .stdin(Stdio::piped());
    let mut child = cmd.spawn().context("spawn graft-inject update")?;
    {
        let mut child_stdin = child.stdin.take().expect("piped stdin");
        if let Some(input) = stdin {
            child_stdin.write_all(input.as_bytes())?;
        }
        // child_stdin drops here — closing it gives the confirm read an EOF.
    }
    child
        .wait_with_output()
        .context("wait for graft-inject update")
}

/// First non-blank line strictly inside settle-graft's poke banner pair.
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

/// Insert `schema_version = <v>` as the first key of a `[graft]` table.
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

/// `update --yes` runs the full sequence and recomposes the kernel.
#[test]
fn update_yes_runs_full_sequence() -> Result<()> {
    let scratch = setup("update_yes")?;
    let out = run_update(&scratch, 0, &["--yes"], None)?;
    assert!(
        out.status.success(),
        "update --yes must succeed; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let app = fs::read_to_string(app_path(&scratch))?;
    assert!(
        app.contains("::  graft-inject:settle-graft:"),
        "update --yes must recompose the kernel (settle-graft banners present)"
    );
    Ok(())
}

/// Answering `n` at the confirm prompt aborts cleanly — exit 0, kernel
/// untouched.
#[test]
fn update_aborts_on_no() -> Result<()> {
    let scratch = setup("update_no")?;
    let before = fs::read_to_string(app_path(&scratch))?;
    let out = run_update(&scratch, 0, &[], Some("n\n"))?;
    assert!(out.status.success(), "an aborted update still exits 0");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("aborted") || stderr.contains("no changes"),
        "stderr must report the run was aborted; got:\n{stderr}"
    );
    assert_eq!(
        fs::read_to_string(app_path(&scratch))?,
        before,
        "an aborted update must leave app.hoon untouched"
    );
    Ok(())
}

/// A future-schema manifest stops `update` at preflight — before
/// `nockup package install` and before app.hoon is touched.
#[test]
fn update_stops_on_future_schema() -> Result<()> {
    let scratch = setup("update_future_schema")?;
    set_schema_version(&scratch.join("hoon/lib/settle-graft.toml"), 9999)?;
    let before = fs::read_to_string(app_path(&scratch))?;
    let out = run_update(&scratch, 0, &["--yes"], None)?;
    assert!(
        !out.status.success(),
        "a future-schema manifest must stop update"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("schema_version") && stderr.contains("cargo install"),
        "stderr must name the skew and the binary-update fix; got:\n{stderr}"
    );
    assert_eq!(
        fs::read_to_string(app_path(&scratch))?,
        before,
        "update must not touch app.hoon when preflight stops the run"
    );
    Ok(())
}

/// A failing `nockup package install` aborts `update` before app.hoon
/// is touched.
#[test]
fn update_stops_when_package_install_fails() -> Result<()> {
    let scratch = setup("update_install_fails")?;
    let before = fs::read_to_string(app_path(&scratch))?;
    let out = run_update(&scratch, 1, &["--yes"], None)?;
    assert!(
        !out.status.success(),
        "a failing package install must abort update"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("package install") && stderr.contains("failed"),
        "stderr must name the package-install failure; got:\n{stderr}"
    );
    assert_eq!(
        fs::read_to_string(app_path(&scratch))?,
        before,
        "update must not touch app.hoon when package install fails"
    );
    Ok(())
}

/// `update`'s preview surfaces a hand-edited block (the doctor report)
/// before the apply step.
#[test]
fn update_preview_surfaces_hand_edit() -> Result<()> {
    let scratch = setup("update_preview_hand_edit")?;
    compose(&scratch)?;
    let app = app_path(&scratch);
    let composed = fs::read_to_string(&app)?;
    let idx = settle_poke_body_line(&composed);
    let mut lines: Vec<String> = composed.lines().map(String::from).collect();
    lines[idx] = format!("{}  :: update-test hand-edit", lines[idx]);
    fs::write(&app, lines.join("\n"))?;

    let out = run_update(&scratch, 0, &["--yes"], None)?;
    assert!(
        out.status.success(),
        "update --yes must succeed; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("hand-edited"),
        "update's preview must surface the hand-edited block; got:\n{stderr}"
    );
    Ok(())
}
