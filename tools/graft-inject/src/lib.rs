//! graft-inject: auto-wire vesl-flavored grafts into a nockup app.hoon
//! kernel.
//!
//! Discovers graft manifests under `--lib-dir` (default `./hoon/lib/`),
//! composes their blocks at the `::  nockup:{imports,state,cause,poke,peek}`
//! markers, and writes the result back. Idempotent per graft per marker.
//!
//! See `--help` for full CLI surface.
//!
//! Module map (audit §3.2 split, 2026-05-12):
//!
//! - [`manifest`] — `Graft` / `Block` schema, `load_manifest`,
//!   `discover_grafts`, name + type validators.
//! - [`gates`] — `TIER_1A_GATES` allowlist, `[graft.gates]`
//!   selection + chain logic.
//! - [`marker`] — `Marker` enum (`Marker::ALL`, `label()`),
//!   banner helpers, `find_marker`, `strip_banner_pair`.
//! - [`inject`] — marker-driven composer (`inject`, banner
//!   emission, drift / orphan detection, legacy-effect
//!   migration). Owns `binding_stub`.
//! - [`codegen`] — typed effect-union, load-defaults overlay,
//!   `kernel-cause-tags` Rust emission.
//! - [`lint`] — five advisory passes (weld-friction,
//!   bare-tilde, collision-check, transitive-imports,
//!   internal-dupes) + `run_lint` CLI driver.
//! - [`cli`] — clap definitions (`Cli` / `Command`), subcommand
//!   `dispatch`, `run_inject`, `run_rename_kernel`, report
//!   printers, `--list --json` schema.
//! - [`util`] — binary staleness check + `--lib-dir`
//!   trust-posture warning.
//!
//! The only public item is [`run`].

use clap::Parser;
use std::process::ExitCode;

const MARKER_PREFIX: &str = "::  nockup:";
const DEFAULT_LIB_DIR: &str = "hoon/lib";

mod cli;
mod codegen;
mod gates;
mod inject;
mod lint;
mod manifest;
mod marker;
mod util;

#[cfg(test)]
mod test_support;

use crate::cli::{Cli, dispatch};
use crate::util::warn_if_stale;

pub fn run() -> ExitCode {
    warn_if_stale();
    let cli = Cli::parse();
    let result = dispatch(cli);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("graft-inject: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::manifest::discover_grafts;
    use crate::test_support::*;
    use std::fs;

    // ---------- AUDIT 2026-04-19 H-11..H-14 regressions ----------

    /// H-11: two manifests claiming the same `name` must hard-error at
    /// discovery time, naming both source paths. The pre-audit loader let
    /// both through and panicked downstream with `expect("seeded above")`.
    #[test]
    fn duplicate_name_bails() {
        let dir = tempdir_for_test("duplicate_name");
        write_manifest(&dir, "a.toml", "shared");
        write_manifest(&dir, "b.toml", "shared");
        let err = discover_grafts(&dir).expect_err("duplicate name must bail");
        let msg = err.to_string();
        assert!(msg.contains("duplicate graft name `shared`"), "got: {msg}");
        assert!(msg.contains("a.toml"), "missing path a in: {msg}");
        assert!(msg.contains("b.toml"), "missing path b in: {msg}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// H-11 defense-in-depth: names interpolate into banner comments and
    /// internal paths, so a hostile manifest that sneaks a `.`/`/` into
    /// the name field would break idempotence and risk path traversal on
    /// consumers that key on the name. Reject at discovery.
    #[test]
    fn invalid_name_bails() {
        let dir = tempdir_for_test("invalid_name");
        write_manifest(&dir, "evil.toml", "../evil");
        let err = discover_grafts(&dir).expect_err("bad name must bail");
        assert!(
            err.to_string().contains("invalid graft name"),
            "got: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }


}
