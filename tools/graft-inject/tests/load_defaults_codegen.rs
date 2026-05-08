//! RM4 §1 v0.2 — `nockup:load-defaults` codegen.
//!
//! Walks the structural surfaces of the load-defaults marker:
//!
//! - The marker template ships with an identity `++load` body
//!   (`old-state` placeholder). After graft-inject runs, the placeholder
//!   is replaced with a `=/  defaults  ^*(versioned-state)` + `%_
//!   defaults  <field>  ^*(<field>-state) ...  ==` overlay block bracketed
//!   by codegen banners.
//! - Re-running graft-inject on the already-injected file is byte-
//!   identical (idempotent).
//! - Adding a graft to the composition grows the overlay; removing a
//!   graft shrinks it. Both happen in priority order.
//! - The injected app.hoon hoonc-compiles to an `out.jam`. (Per
//!   memory, hoonc exits 0 on garbage; the artifact is what proves
//!   structural validity.)

mod fixtures;

use anyhow::Result;
use std::fs;
use std::path::Path;
use std::process::Command;

use fixtures::{compose_and_compile, copy_dir_contents, graft_inject_bin, repo_root};

#[test]
fn load_defaults_codegen_three_grafts_emits_overlay() -> Result<()> {
    let jam = compose_and_compile(
        "load_defaults_three",
        &["settle-graft", "mint-graft", "guard-graft"],
    )?;
    let app_hoon = jam
        .parent()
        .expect("out.jam has a parent")
        .join("hoon/app/app.hoon");
    let body = fs::read_to_string(&app_hoon)?;

    assert!(
        body.contains("::  graft-inject:load-defaults:begin"),
        "begin banner missing\n{body}",
    );
    assert!(
        body.contains("::  graft-inject:load-defaults:end"),
        "end banner missing\n{body}",
    );
    assert!(
        body.contains("=/  defaults  ^*(versioned-state)"),
        "defaults binding missing\n{body}",
    );
    assert!(
        body.contains("%_  defaults"),
        "%_ overlay opener missing\n{body}",
    );
    // Each stub gets a `mole`-probed overlay line: the field-access
    // wraps in `(mole |.(;;(<type> <field>.old-state)))` so same-
    // composition resume preserves data and schema-extension resume
    // falls back to defaults.
    for stub in ["settle", "mint", "guard"] {
        let needle = format!("(mole |.(;;({stub}-state {stub}.old-state)))");
        assert!(
            body.contains(&needle),
            "expected `{needle}` in load-defaults overlay, body:\n{body}",
        );
    }

    Ok(())
}

#[test]
fn load_defaults_codegen_six_grafts_overlay_in_priority_order() -> Result<()> {
    let jam = compose_and_compile(
        "load_defaults_six",
        &[
            "settle-graft",
            "mint-graft",
            "guard-graft",
            "rbac-graft",
            "registry-graft",
            "log-graft",
        ],
    )?;
    let app_hoon = jam
        .parent()
        .expect("out.jam has a parent")
        .join("hoon/app/app.hoon");
    let body = fs::read_to_string(&app_hoon)?;

    let begin_idx = body
        .find("graft-inject:load-defaults:begin")
        .expect("begin banner present");
    let end_idx = body
        .find("graft-inject:load-defaults:end")
        .expect("end banner present");
    let block = &body[begin_idx..end_idx];

    // Each graft contributes one overlay line in priority order. The
    // shipped manifests have settle (60) < mint (70) < guard (75) <
    // rbac (80) < registry (90) < log (130), and graft-inject sorts by
    // priority then name.
    let stubs = ["settle", "mint", "guard", "rbac", "registry", "log"];
    let mut last_pos = 0usize;
    for stub in stubs {
        let needle = format!("(mole |.(;;({stub}-state {stub}.old-state)))");
        let pos = block
            .find(&needle)
            .unwrap_or_else(|| panic!("missing `{needle}` in:\n{block}"));
        assert!(
            pos >= last_pos,
            "graft `{stub}` out of priority order: pos {pos} < {last_pos}\nblock:\n{block}",
        );
        last_pos = pos;
    }

    Ok(())
}

#[test]
fn load_defaults_codegen_is_idempotent() -> Result<()> {
    let jam_first = compose_and_compile(
        "load_defaults_idempotent",
        &["settle-graft", "rbac-graft"],
    )?;
    let app_hoon = jam_first
        .parent()
        .expect("out.jam has a parent")
        .join("hoon/app/app.hoon");
    let first = fs::read_to_string(&app_hoon)?;

    // Re-run graft-inject on the already-injected app.hoon. Output must
    // be byte-identical.
    let lib_dir = jam_first
        .parent()
        .expect("scratch parent")
        .join("hoon/lib");
    let status = Command::new(graft_inject_bin())
        .arg("--lib-dir")
        .arg(&lib_dir)
        .arg("--grafts")
        .arg("settle-graft,rbac-graft")
        .arg("--apply")
        .arg(&app_hoon)
        .status()?;
    assert!(status.success(), "second graft-inject run failed: {status}");

    let second = fs::read_to_string(&app_hoon)?;
    assert_eq!(
        first, second,
        "second graft-inject run must produce byte-identical output",
    );

    Ok(())
}

#[test]
fn load_defaults_codegen_replaces_overlay_when_graft_added() -> Result<()> {
    // Compose with two grafts, then re-run with a third added. The
    // overlay block must shrink/grow rather than accumulate stale
    // entries.
    let jam = compose_and_compile(
        "load_defaults_replace",
        &["settle-graft", "rbac-graft"],
    )?;
    let app_hoon = jam
        .parent()
        .expect("out.jam has a parent")
        .join("hoon/app/app.hoon");
    let two_graft_body = fs::read_to_string(&app_hoon)?;
    assert!(two_graft_body.contains("(mole |.(;;(settle-state settle.old-state)))"));
    assert!(two_graft_body.contains("(mole |.(;;(rbac-state rbac.old-state)))"));
    assert!(!two_graft_body.contains("(mole |.(;;(registry-state registry.old-state)))"));

    let lib_dir = jam.parent().expect("scratch parent").join("hoon/lib");
    let status = Command::new(graft_inject_bin())
        .arg("--lib-dir")
        .arg(&lib_dir)
        .arg("--grafts")
        .arg("settle-graft,rbac-graft,registry-graft")
        .arg("--apply")
        .arg(&app_hoon)
        .status()?;
    assert!(status.success(), "second graft-inject run failed: {status}");

    let three_graft_body = fs::read_to_string(&app_hoon)?;
    assert!(three_graft_body.contains("(mole |.(;;(settle-state settle.old-state)))"));
    assert!(three_graft_body.contains("(mole |.(;;(rbac-state rbac.old-state)))"));
    assert!(
        three_graft_body.contains("(mole |.(;;(registry-state registry.old-state)))"),
        "registry overlay line missing after re-run, body:\n{three_graft_body}",
    );

    Ok(())
}

#[test]
fn load_defaults_codegen_skipped_when_marker_absent() -> Result<()> {
    // Custom scratch: copy templates/app.hoon then drop the
    // `::  nockup:load-defaults` marker line. The codegen must skip
    // silently — no banner appears in the output, and the identity
    // `old-state` body stays.
    let repo = repo_root();
    let scratch = repo.join("target").join("load_defaults_skipped");
    if scratch.exists() {
        fs::remove_dir_all(&scratch)?;
    }
    let hoon_app = scratch.join("hoon/app");
    let hoon_lib = scratch.join("hoon/lib");
    fs::create_dir_all(&hoon_app)?;
    fs::create_dir_all(&hoon_lib)?;
    copy_dir_contents(&repo.join("hoon/lib"), &hoon_lib)?;

    let raw = fs::read_to_string(repo.join("templates/app.hoon"))?;
    let stripped = raw
        .lines()
        .filter(|line| !line.contains("nockup:load-defaults"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(hoon_app.join("app.hoon"), stripped + "\n")?;

    let status = Command::new(graft_inject_bin())
        .arg("--lib-dir")
        .arg(&hoon_lib)
        .arg("--grafts")
        .arg("settle-graft")
        .arg("--apply")
        .arg(hoon_app.join("app.hoon"))
        .status()?;
    assert!(status.success(), "graft-inject failed: {status}");

    let body = fs::read_to_string(hoon_app.join("app.hoon"))?;
    assert!(
        !body.contains("graft-inject:load-defaults"),
        "load-defaults codegen must not emit when the marker is absent, body:\n{body}",
    );

    Ok(())
}

#[allow(dead_code)]
fn _retain_path(_: &Path) {}
