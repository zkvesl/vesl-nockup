//! graft-inject: auto-wire vesl-flavored grafts into a nockup app.hoon
//! kernel.
//!
//! Discovers graft manifests under `--lib-dir` (default `./hoon/lib/`),
//! composes their blocks at the `::  nockup:{imports,state,cause,poke,peek}`
//! markers, and writes the result back. Idempotent per graft per marker.
//!
//! See `--help` for full CLI surface.
//!
//! Module map:
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
//! - [`doctor`] — project-health checks (schema-version
//!   handshake, Cargo `[patch]` consistency, hand-edited
//!   blocks, missing load-defaults marker) + `run_doctor` driver.
//! - [`lint`] — five advisory passes (weld-friction,
//!   bare-tilde, collision-check, transitive-imports,
//!   internal-dupes) + `run_lint` CLI driver.
//! - [`cli`] — clap definitions (`Cli` / `Command`), subcommand
//!   `dispatch`, `run_inject`, `run_rename_kernel`, report
//!   printers, `--list --json` schema.
//! - [`update`] — the `update` orchestrator: schema preflight,
//!   `nockup package install`, preview + confirm, `inject --apply`.
//! - [`util`] — binary staleness check + `--lib-dir`
//!   trust-posture warning.
//!
//! The only public item is [`run`].

use clap::Parser;
use std::process::ExitCode;

/// The marker namespace. A marker comment is `::`, one or more spaces,
/// then this string followed by a marker label (e.g. `::  nockup:poke`).
/// The templates emit two spaces as the canonical form.
const MARKER_PREFIX: &str = "nockup:";
const DEFAULT_LIB_DIR: &str = "hoon/lib";

/// Manifest-schema version this binary understands. A graft manifest may
/// declare `schema_version` in its `[graft]` table; a manifest targeting
/// a HIGHER version was authored for a newer nockup-graft. The compose
/// path (`inject`) hard-errors on such a manifest, `doctor` reports a
/// finding, and the scaffold `build.rs` warns. Absent or lower = always
/// compatible — the schema is append-only. Bump only on a manifest or
/// banner change an older binary cannot model correctly.
const MANIFEST_SCHEMA_VERSION: u32 = 1;

mod cli;
mod codegen;
mod doctor;
mod gates;
mod harness_bindings;
mod inject;
mod lint;
mod manifest;
mod marker;
mod update;
mod util;

#[cfg(test)]
mod test_support;

use crate::cli::{Cli, dispatch};
use crate::util::warn_if_stale;

pub fn run() -> ExitCode {
    warn_if_stale();
    let cli = Cli::parse();
    // Translate --quiet into a RUST_LOG default that propagates to any
    // subprocess this binary spawns (e.g. `nockup package install` from
    // the `update` subcommand). RUST_LOG (if already set) wins.
    if cli.is_quiet() && std::env::var_os("RUST_LOG").is_none() {
        // SAFETY: single-threaded — no tokio runtime or other threads
        // exist at this point in the process.
        unsafe { std::env::set_var("RUST_LOG", "warn") };
    }
    let result = dispatch(cli);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("graft-inject: {e:#}");
            ExitCode::FAILURE
        }
    }
}

