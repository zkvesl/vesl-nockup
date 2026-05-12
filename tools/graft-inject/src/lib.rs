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
    use clap::Parser;
    use crate::cli::{Cli, Command, GraftSummary, run_inject, select_grafts};
    use crate::manifest::discover_grafts;
    use crate::test_support::*;
    use std::fs;
    use std::path::{Path, PathBuf};


    // ---------- CLI tests ----------

    /// `graft-inject inject hoon/app/app.hoon --grafts foo,bar --apply`
    /// should parse cleanly into Command::Inject with the listed args.
    #[test]
    fn cli_parses_inject_subcommand() {
        let cli = Cli::try_parse_from([
            "graft-inject",
            "inject",
            "hoon/app/app.hoon",
            "--grafts",
            "foo,bar",
            "--apply",
        ])
        .expect("inject subcommand must parse");
        match cli.command {
            Some(Command::Inject {
                path,
                grafts,
                apply,
                no_migrate,
                ..
            }) => {
                assert_eq!(path, PathBuf::from("hoon/app/app.hoon"));
                assert_eq!(grafts, vec!["foo".to_string(), "bar".to_string()]);
                assert!(apply);
                assert!(!no_migrate);
            }
            other => panic!("expected Command::Inject, got {other:?}"),
        }
    }

    /// `graft-inject list --json` parses into Command::List with json on.
    #[test]
    fn cli_parses_list_subcommand() {
        let cli = Cli::try_parse_from(["graft-inject", "list", "--json"])
            .expect("list subcommand must parse");
        match cli.command {
            Some(Command::List { json, .. }) => assert!(json),
            other => panic!("expected Command::List, got {other:?}"),
        }
    }

    /// `graft-inject hoon/app/app.hoon --grafts foo` (legacy bare form)
    /// must still parse — `command` ends up `None` and the legacy fields
    /// carry the args. This is the back-compat path that prints the
    /// deprecation note in `dispatch`.
    #[test]
    fn cli_parses_legacy_bare_invocation() {
        let cli = Cli::try_parse_from([
            "graft-inject",
            "hoon/app/app.hoon",
            "--grafts",
            "foo",
        ])
        .expect("legacy bare form must still parse");
        assert!(cli.command.is_none());
        assert_eq!(cli.path.as_deref(), Some(Path::new("hoon/app/app.hoon")));
        assert_eq!(cli.grafts, vec!["foo".to_string()]);
    }



    #[test]
    fn unknown_graft_name_errors() {
        let dir = tempdir_with_two_manifests("unknown_graft");
        let mut cli = cli_with(dir.clone());
        cli.grafts = vec!["nosuch".to_string()];
        let err = select_grafts(&cli).expect_err("unknown name must error");
        assert!(
            err.to_string().contains("unknown graft `nosuch`"),
            "error should name the bad graft, got: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn exclude_flag_subtracts() {
        let dir = tempdir_with_two_manifests("exclude_flag");
        let mut cli = cli_with(dir.clone());
        cli.exclude = vec!["alpha".to_string()];
        let selected = select_grafts(&cli).unwrap();
        let names: Vec<&str> = selected.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, vec!["settle-graft"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_does_not_write() {
        // AUDIT 2026-04-19 H-10: the default is preview-only. Without
        // --apply, the file on disk must be unchanged regardless of what
        // `graft-inject` composed into stdout.
        let dir = tempdir_with_two_manifests("default_preview");
        let target = dir.join("app.hoon");
        fs::write(&target, BARE_SCAFFOLD).unwrap();
        let original = fs::read_to_string(&target).unwrap();

        let mut cli = cli_with(dir.clone());
        cli.path = Some(target.clone());
        cli.grafts = vec!["settle-graft".to_string()];
        run_inject(cli).unwrap();

        let after = fs::read_to_string(&target).unwrap();
        assert_eq!(after, original, "preview-only default must not modify the file");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_writes() {
        // --apply is the explicit write-enabler post-AUDIT 2026-04-19 H-10.
        let dir = tempdir_with_two_manifests("apply_writes");
        let target = dir.join("app.hoon");
        fs::write(&target, BARE_SCAFFOLD).unwrap();

        let mut cli = cli_with(dir.clone());
        cli.path = Some(target.clone());
        cli.grafts = vec!["settle-graft".to_string()];
        cli.apply = true;
        run_inject(cli).unwrap();

        let after = fs::read_to_string(&target).unwrap();
        assert_ne!(after, BARE_SCAFFOLD, "--apply must modify the file");
        assert!(after.contains("::  graft-inject:settle-graft:imports:begin"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dry_run_alias_still_parses() {
        // `--dry-run` is the deprecated alias of the preview-only default.
        // It should still parse and leave the file unchanged; the
        // deprecation note to stderr is best-effort.
        let dir = tempdir_with_two_manifests("dry_run_alias");
        let target = dir.join("app.hoon");
        fs::write(&target, BARE_SCAFFOLD).unwrap();

        let mut cli = cli_with(dir.clone());
        cli.path = Some(target.clone());
        cli.dry_run = true;
        cli.grafts = vec!["settle-graft".to_string()];
        run_inject(cli).unwrap();

        let after = fs::read_to_string(&target).unwrap();
        assert_eq!(after, BARE_SCAFFOLD);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_json_is_stable() {
        // Schema (documented in vesl/docs/graft-manifest.md):
        //   [{ name, version, priority, blocks: [...], applicable, deferred, sha256 }]
        //
        // `sha256` was added per AUDIT 2026-04-19 H-10 — additive per the
        // "append never reshape" contract this schema keeps.
        let grafts = settle_only_grafts();
        let summaries: Vec<GraftSummary> =
            grafts.iter().map(GraftSummary::from_graft).collect();
        let json = serde_json::to_string(&summaries).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = parsed.as_array().expect("top-level array");
        assert_eq!(arr.len(), 1);
        let first = &arr[0];
        assert_eq!(first["name"], "settle-graft");
        assert_eq!(first["version"], "0.1.0");
        assert_eq!(first["priority"], 10);
        assert_eq!(first["applicable"], 5);
        assert_eq!(first["deferred"], false);
        let blocks = first["blocks"].as_array().expect("blocks is array");
        assert_eq!(blocks.len(), 5);
        let block_names: Vec<&str> = blocks
            .iter()
            .map(|v| v.as_str().expect("block label is string"))
            .collect();
        assert_eq!(
            block_names,
            vec!["imports", "state", "cause", "poke", "peek"]
        );
        let sha = first["sha256"].as_str().expect("sha256 is a string");
        assert_eq!(sha.len(), 64, "sha256 hex length");
        assert!(
            sha.chars().all(|c| c.is_ascii_hexdigit()),
            "sha256 must be lowercase hex: {sha}"
        );
    }

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
