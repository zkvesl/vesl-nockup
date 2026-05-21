//! `update` — the graft-library update orchestrator.
//!
//! Collapses the safe-update sequence into one verb: schema preflight →
//! `nockup package install` → re-check → `inject` preview + doctor
//! report → confirm → `inject --apply`. Preview-by-default is preserved:
//! the preview prints before the y/N prompt and the kernel is rewritten
//! only after a `y` (or `--yes`).
//!
//! `update` cannot replace the running `nockup-graft` binary — on a
//! schema skew it stops and tells the operator to update the binary by
//! hand, then re-run. It does not compile: the recompile and the
//! cause-tag codegen are the next `cargo build`'s job (its `build.rs`
//! re-runs codegen and the doctor pass).

use std::fs;
use std::io::{BufRead, Write};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};

use crate::cli::print_report;
use crate::doctor::{collect_findings, emit_human};
use crate::inject::{inject, migrate_legacy_effect, print_migration_line};
use crate::manifest::{Graft, atomic_write, check_schema_compat, discover_grafts};

/// `nockup graft update` entry point.
pub(crate) fn run_update(path: &Path, lib_dir: &Path, yes: bool) -> Result<()> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("hoon") => {}
        Some(other) => bail!(
            "target {} has extension `.{}`; update only runs on Hoon source files",
            path.display(),
            other,
        ),
        None => bail!(
            "target {} has no file extension; update only runs on Hoon source files",
            path.display(),
        ),
    }

    // 1. Preflight — refuse early if the library *already* in the tree
    //    declares a schema this binary can't model.
    let pre_grafts = if lib_dir.is_dir() {
        discover_grafts(lib_dir)
            .with_context(|| format!("discovering grafts under {}", lib_dir.display()))?
    } else {
        Vec::new()
    };
    schema_preflight(&pre_grafts)?;

    // 2. Refresh the graft library.
    eprintln!("update: refreshing the graft library (nockup package install)");
    nockup_package_install()?;

    // 3. Re-discover and re-check — `package install` may have pulled a
    //    newer library that declares a newer schema.
    let grafts = discover_grafts(lib_dir)
        .with_context(|| format!("discovering grafts under {}", lib_dir.display()))?;
    schema_preflight(&grafts)?;

    // 4. Preview — compose without writing, and surface the doctor
    //    report (drift, hand-edited blocks) before anything lands.
    let raw_source = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let (source, migration) = migrate_legacy_effect(&raw_source);
    let (output, report) = inject(&source, &grafts)
        .with_context(|| format!("composing {}", path.display()))?;
    eprintln!();
    eprintln!("update: preview — `inject --apply` would compose:");
    print_migration_line(&migration);
    print_report(path, &report, &grafts, false);
    emit_human(path, &collect_findings(path, &source, &grafts));

    if output == source {
        eprintln!("update: app.hoon is already up to date; nothing to apply.");
        return Ok(());
    }

    // 5. Confirm — preview-by-default; the kernel is rewritten only
    //    after an explicit `y` (or `--yes`).
    if yes {
        eprintln!("update: --yes given; applying without a prompt.");
    } else if !confirm()? {
        eprintln!("update: aborted — no changes made.");
        return Ok(());
    }

    // 6. Apply.
    atomic_write(path, &output)
        .with_context(|| format!("writing {}", path.display()))?;
    eprintln!("update: {} recomposed.", path.display());
    eprintln!(
        "update: done. Recompile and rebuild:\n  \
         hoonc hoon/app/app.hoon hoon/ && [ -s out.jam ] && cargo +nightly build"
    );
    Ok(())
}

/// Stop the run when any graft targets a manifest schema newer than this
/// binary. `update` cannot replace its own running binary, so it tells
/// the operator how to do it and re-run.
fn schema_preflight(grafts: &[Graft]) -> Result<()> {
    if let Some(skew) = check_schema_compat(grafts).first() {
        bail!(
            "graft `{}` targets manifest schema_version {} but this \
             nockup-graft supports up to {}.\n  \
             update cannot replace the running binary — update it first:\n  \
             cargo install --git https://github.com/zkvesl/vesl-nockup \
             --bin nockup-graft --force\n  \
             then re-run `nockup graft update`.",
            skew.graft,
            skew.manifest_version,
            skew.binary_version,
        );
    }
    Ok(())
}

/// Run `nockup package install` to refresh `hoon/lib/`. Resolves the
/// `nockup` binary from `NOCKUP_BIN` when set, else from `PATH`. Aborts
/// the whole run on failure — before `app.hoon` is touched — so a
/// half-updated library is never composed.
fn nockup_package_install() -> Result<()> {
    let nockup = std::env::var("NOCKUP_BIN").unwrap_or_else(|_| "nockup".to_string());
    let status = Command::new(&nockup)
        .args(["package", "install"])
        .status()
        .map_err(|e| {
            anyhow!(
                "could not run `{nockup} package install`: {e}. \
                 Install nockup, or set NOCKUP_BIN to its path."
            )
        })?;
    if !status.success() {
        bail!(
            "`nockup package install` failed ({status}); aborting before \
             recomposing app.hoon."
        );
    }
    Ok(())
}

/// Interactive y/N confirmation, printed to stderr. Default is No; EOF
/// (a non-interactive stdin) is also No. Bypassed by `--yes`.
fn confirm() -> Result<bool> {
    eprint!("update: apply this recomposition? [y/N] ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    let n = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("reading confirmation from stdin")?;
    if n == 0 {
        eprintln!();
        return Ok(false);
    }
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}
