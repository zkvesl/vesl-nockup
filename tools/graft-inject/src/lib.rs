//! graft-inject: auto-wire vesl-flavored grafts into a nockup app.hoon
//! kernel.
//!
//! Discovers graft manifests under `--lib-dir` (default `./hoon/lib/`),
//! composes their blocks at the `::  nockup:{imports,state,cause,poke,peek}`
//! markers, and writes the result back. Idempotent per graft per marker.
//!
//! See `--help` for full CLI surface.

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
    use crate::codegen::{CodegenStatus, emit_kernel_cause_tags_rs};
    use crate::inject::{inject, migrate_legacy_effect};
    use crate::manifest::{
        Block, Graft, GraftBlocks, GraftTypes, discover_grafts, load_manifest, sha256_hex,
    };
    use crate::marker::{Marker, leading_whitespace};
    use std::fs;
    use std::path::{Path, PathBuf};

    const BARE_SCAFFOLD: &str = "\
::  test scaffold
/+  lib
::  nockup:imports
/=  *  /common/wrapper
::
=>
|%
+$  versioned-state
  $:  %v1
      ::  nockup:state
      ~
  ==
::
+$  effect  *
::
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
|%
++  moat  (keep versioned-state)
::
++  inner
  |_  state=versioned-state
  ++  load
    |=  old=versioned-state
    old
  ++  peek
    |=  =path
    ^-  (unit (unit *))
    ?+  path
      ::  nockup:peek
      ~
      [%count ~]  ``0
    ==
  ++  poke
    |=  =ovum:moat
    ^-  [(list effect) _state]
    =/  act  ((soft cause) cause.input.ovum)
    ?~  act  [~ state]
    ::  nockup:poke-prelude
    =/  out=[efx=(list effect) new=_state]
      ?-  -.u.act
          %cause  [~ state]
        ::  nockup:poke
      ==
    ::  nockup:poke-postlude
    out
  --
--
((moat |) inner)
";

    fn settle_only_grafts() -> Vec<Graft> {
        let path = settle_graft_manifest_path();
        let g = load_manifest(&path)
            .expect("load settle-graft.toml")
            .expect("settle-graft.toml has [graft] table");
        vec![g]
    }

    /// Build a minimal in-memory Graft for synthetic multi-graft tests.
    /// `name` doubles as the binding stub in the peek chain (no `-graft`
    /// suffix), so assertions can match `<name>-res` directly.
    fn synthetic_graft(name: &str, priority: i32) -> Graft {
        Graft {
            name: name.to_string(),
            version: "0.1.0".to_string(),
            priority,
            after: vec![],
            blocks: GraftBlocks {
                imports: Some(Block {
                    sentinel: format!("*{name}"),
                    body: format!("/+  *{name}"),
                }),
                state: Some(Block {
                    sentinel: format!("{name}={name}-state"),
                    body: format!("{name}={name}-state"),
                }),
                cause: Some(Block {
                    sentinel: format!("{name}-cause"),
                    body: format!("{name}-cause"),
                }),
                poke_prelude: None,
                poke: Some(Block {
                    sentinel: format!("%{name}-do"),
                    body: format!(
                        "  %{name}-do\n=/  lc=cause  [%{name}-do ~]\n[~ state]"
                    ),
                }),
                poke_postlude: None,
                peek: Some(Block {
                    sentinel: format!("{name}-peek"),
                    body: format!("({name}-peek state path)"),
                }),
            },
            gates: None,
            types: None,
            sha256: String::new(),
        }
    }

    fn settle_graft_manifest_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("hoon")
            .join("lib")
            .join("settle-graft.toml")
    }

    fn tempdir_for_test(label: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("graft-inject-test-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn injects_all_markers() {
        let grafts = settle_only_grafts();
        let (out, report) = inject(BARE_SCAFFOLD, &grafts).unwrap();
        assert!(out.contains("/+  *settle-graft"));
        assert!(out.contains("/+  *vesl-merkle"));
        assert!(out.contains("settle=settle-state"));
        assert!(out.contains("settle-cause"));
        assert!(out.contains("%settle-register"));
        assert!(out.contains("%settle-verify"));
        assert!(out.contains("%settle-note"));
        // Peek emits the chain shape: the legacy expression lives
        // inside the `=/ settle-res ...` binding.
        assert!(out.contains("=/  settle-res  (settle-peek settle.state path)"));
        assert!(out.contains("?.  =(~ settle-res)  settle-res"));

        // BARE_SCAFFOLD ships with the seven non-codegen markers (imports,
        // state, cause, poke-prelude, poke, poke-postlude, peek). The
        // three codegen markers (domain-effect, effect-union, load-defaults)
        // land via auto-migration and template refreshes, so they are
        // expected to be missing here.
        assert_eq!(report.markers_in_source.len(), 7);
        assert_eq!(report.markers_missing.len(), 3);
        let settle = &report.grafts[0];
        assert_eq!(settle.name, "settle-graft");
        // settle-graft contributes 5 of the 7 non-codegen markers
        // (no prelude / postlude). Codegen markers contribute no per-graft
        // blocks.
        assert_eq!(settle.injected.len(), 5);
        assert!(settle.skipped.is_empty());
    }

    #[test]
    fn is_idempotent() {
        let grafts = settle_only_grafts();
        let (first, _) = inject(BARE_SCAFFOLD, &grafts).unwrap();
        let (second, report) = inject(&first, &grafts).unwrap();
        assert_eq!(first, second, "second inject must produce identical output");
        let settle = &report.grafts[0];
        assert!(settle.injected.is_empty(), "no marker should re-inject");
        assert_eq!(settle.skipped.len(), 5, "all 5 markers should skip");
    }

    /// Regression: forge's poke sentinel (`%forge-prove`) landed past the
    /// old 60-line window once settle+mint+guard had injected their arms
    /// above it, so re-running graft-inject duplicated forge's poke block.
    /// Walking the `?-` switch to its `==` cap fixes it — this test guards
    /// the fix. It synthesizes four grafts with distinct, wide poke bodies
    /// so real-manifest paths aren't a prerequisite.
    #[test]
    fn poke_idempotence_four_grafts() {
        let grafts: Vec<Graft> = vec![
            synthetic_graft("settle", 10),
            synthetic_graft("mint", 20),
            synthetic_graft("guard", 30),
            synthetic_graft("forge", 40),
        ];
        let (first, first_report) = inject(BARE_SCAFFOLD, &grafts).unwrap();
        for g in &first_report.grafts {
            assert!(
                !g.injected.is_empty(),
                "pass 1: {} should inject at least one marker",
                g.name
            );
        }
        let (second, second_report) = inject(&first, &grafts).unwrap();
        assert_eq!(
            first, second,
            "second inject must produce byte-identical output across all four grafts"
        );
        for g in &second_report.grafts {
            assert!(
                g.injected.is_empty(),
                "pass 2: {} re-injected marker(s) {:?} — idempotence broken",
                g.name,
                g.injected
            );
        }
        let forge = second_report
            .grafts
            .iter()
            .find(|g| g.name == "forge")
            .expect("forge graft present");
        assert!(
            forge.skipped.contains(&Marker::Poke),
            "forge poke must be detected as already-wired on re-run"
        );
        let first_forge_count = first.matches("%forge-do").count();
        let second_forge_count = second.matches("%forge-do").count();
        assert_eq!(
            first_forge_count, second_forge_count,
            "forge sentinel count must not grow between runs (first={}, second={})",
            first_forge_count, second_forge_count
        );
    }

    #[test]
    fn preserves_two_space_law() {
        // The two-space law applies to every Hoon rune in the manifest
        // bodies. Scan the loaded `settle-graft.toml`.
        let graft = load_manifest(&settle_graft_manifest_path())
            .unwrap()
            .unwrap();
        let bodies: Vec<&str> = Marker::ALL
            .iter()
            .filter_map(|m| graft.block(*m).map(|b| b.trimmed_body()))
            .collect();
        for body in bodies {
            for line in body.lines() {
                let trimmed = line.trim_start();
                for rune in ["=/", "|=", "/+", "/-", "/=", "^-", ":_", "?-", "?+", "?~", "?."] {
                    if let Some(rest) = trimmed.strip_prefix(rune) {
                        let next_two: Vec<char> = rest.chars().take(2).collect();
                        match next_two.as_slice() {
                            [] => {}
                            [' ', ' '] => {}
                            [' ', _] => panic!("single-space `{rune}` in body line: {line:?}"),
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn missing_marker_is_warning_not_error() {
        let grafts = settle_only_grafts();
        let src = "::  just a comment\n";
        let result = inject(src, &grafts);
        assert!(result.is_ok());
        let (_, report) = result.unwrap();
        assert_eq!(report.markers_missing.len(), Marker::ALL.len());
        assert!(report.markers_in_source.is_empty());
    }

    #[test]
    fn does_not_match_nockup_pokemon() {
        let grafts = settle_only_grafts();
        let src = "::  nockup:pokemon\n";
        let (_, report) = inject(src, &grafts).unwrap();
        assert_eq!(report.markers_missing.len(), Marker::ALL.len());
        assert!(report.markers_in_source.is_empty());
    }

    #[test]
    fn single_graft_injection_pastes_body_verbatim() {
        // The data-driven inject() pastes the manifest body verbatim at
        // every non-peek marker, with the marker's leading whitespace
        // prepended and no other rewriting. Peek is excluded — see
        // peek_chain_n1_matches_legacy_replacement for that shape.
        let grafts = settle_only_grafts();
        let graft = &grafts[0];
        let (out, _) = inject(BARE_SCAFFOLD, &grafts).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        for marker in [Marker::Imports, Marker::State, Marker::Cause, Marker::Poke] {
            let needle = format!("::  nockup:{}", marker.label());
            let marker_idx = lines
                .iter()
                .position(|l| {
                    let t = l.trim_start();
                    if !t.starts_with(&needle) {
                        return false;
                    }
                    // Word-boundary guard: `nockup:poke` must not match
                    // `nockup:poke-prelude` / `nockup:poke-postlude` —
                    // mirrors find_marker's tail check.
                    let tail = &t[needle.len()..];
                    tail.is_empty() || tail.chars().all(|c| c.is_whitespace())
                })
                .unwrap_or_else(|| panic!("marker `{}` missing from output", marker.label()));
            let marker_indent = leading_whitespace(lines[marker_idx]).to_string();
            let body = graft
                .block(marker)
                .expect("settle claims this marker")
                .trimmed_body();
            // Body lines land one row after the `begin_banner` emitted by
            // AUDIT 2026-04-19 H-11..H-14's idempotence refactor. R5/A2
            // (2026-05-04) appended a ` sha256:<short>` suffix; assert
            // on the prefix shape so the test isn't coupled to the live
            // sha256 of every fixture manifest.
            let expected_prefix =
                format!("{marker_indent}::  graft-inject:settle-graft:{}:begin", marker.label());
            assert!(
                lines[marker_idx + 1].starts_with(&expected_prefix),
                "marker `{}` begin banner missing; got: {}",
                marker.label(),
                lines[marker_idx + 1]
            );
            for (i, want) in body.lines().enumerate() {
                let got = lines[marker_idx + 2 + i];
                let expected = if want.is_empty() {
                    String::new()
                } else {
                    format!("{marker_indent}{want}")
                };
                assert_eq!(
                    got,
                    expected,
                    "marker `{}` line {i} byte mismatch",
                    marker.label()
                );
            }
        }
    }

    #[test]
    fn multi_graft_injection_composes_blocks() {
        // vesl + two synthetic grafts, all three contribute to every marker.
        // Each marker region must contain all three sentinels in priority order.
        let mut grafts = settle_only_grafts();
        grafts.push(synthetic_graft("alpha", 50));
        grafts.push(synthetic_graft("beta", 60));
        let (out, _) = inject(BARE_SCAFFOLD, &grafts).unwrap();

        // imports: all three import directives present
        assert!(out.contains("/+  *settle-graft"));
        assert!(out.contains("/+  *alpha"));
        assert!(out.contains("/+  *beta"));
        // state: all three field declarations
        assert!(out.contains("settle=settle-state"));
        assert!(out.contains("alpha=alpha-state"));
        assert!(out.contains("beta=beta-state"));
        // cause: all three cause-union members
        assert!(out.contains("settle-cause"));
        assert!(out.contains("alpha-cause"));
        assert!(out.contains("beta-cause"));
        // poke: all three first-arm tags
        assert!(out.contains("%settle-register"));
        assert!(out.contains("%alpha-do"));
        assert!(out.contains("%beta-do"));
        // peek: all three chain bindings
        assert!(out.contains("=/  settle-res  (settle-peek settle.state path)"));
        assert!(out.contains("=/  alpha-res  (alpha-peek state path)"));
        assert!(out.contains("=/  beta-res  (beta-peek state path)"));
    }

    #[test]
    fn peek_chain_composition() {
        // Three grafts → each contributes a 4-line banner-wrapped pair
        // (begin, =/, ?., end) for 12 lines, plus the terminal `~` = 13
        // lines total immediately after the marker, in priority order.
        let mut grafts = settle_only_grafts();
        grafts.push(synthetic_graft("alpha", 50));
        grafts.push(synthetic_graft("beta", 60));
        let (out, _) = inject(BARE_SCAFFOLD, &grafts).unwrap();
        let peek_lines: Vec<String> = out
            .lines()
            .skip_while(|l| !l.contains("nockup:peek"))
            .skip(1)
            .take(13)
            .map(|l| l.trim_start().to_string())
            .collect();
        assert_eq!(peek_lines.len(), 13, "expected 13 lines after peek marker");
        // R5/A2: begin banners now carry a ` sha256:<short>` suffix.
        // Match on the prefix to avoid coupling tests to live sha256
        // values of fixture manifests.
        assert!(peek_lines[0].starts_with("::  graft-inject:settle-graft:peek:begin"));
        assert_eq!(peek_lines[1], "=/  settle-res  (settle-peek settle.state path)");
        assert_eq!(peek_lines[2], "?.  =(~ settle-res)  settle-res");
        assert_eq!(peek_lines[3], "::  graft-inject:settle-graft:peek:end");
        assert!(peek_lines[4].starts_with("::  graft-inject:alpha:peek:begin"));
        assert_eq!(peek_lines[5], "=/  alpha-res  (alpha-peek state path)");
        assert_eq!(peek_lines[6], "?.  =(~ alpha-res)  alpha-res");
        assert_eq!(peek_lines[7], "::  graft-inject:alpha:peek:end");
        assert!(peek_lines[8].starts_with("::  graft-inject:beta:peek:begin"));
        assert_eq!(peek_lines[9], "=/  beta-res  (beta-peek state path)");
        assert_eq!(peek_lines[10], "?.  =(~ beta-res)  beta-res");
        assert_eq!(peek_lines[11], "::  graft-inject:beta:peek:end");
        assert_eq!(peek_lines[12], "~");
    }

    #[test]
    fn per_graft_idempotence_inject_settle_then_alpha() {
        // First inject settle alone; then re-inject with [settle, alpha].
        // settle region must not double-up (no duplicated sentinels), and
        // alpha must appear interleaved at every marker.
        let settle = settle_only_grafts();
        let (after_settle, _) = inject(BARE_SCAFFOLD, &settle).unwrap();

        let mut both = settle.clone();
        both.push(synthetic_graft("alpha", 50));
        let (after_both, report) = inject(&after_settle, &both).unwrap();

        // Use exact-trimmed-line matching to avoid spurious substring
        // hits inside the poke body (e.g., `new-settle=settle-state` contains
        // the `settle=settle-state` substring).
        let lines: Vec<&str> = after_both.lines().collect();
        let trimmed_eq_count = |needle: &str| -> usize {
            lines.iter().filter(|l| l.trim() == needle).count()
        };

        for needle in [
            "/+  *settle-graft",
            "/+  *vesl-merkle",
            "settle=settle-state",
            "settle-cause",
            "%settle-register",
            "=/  settle-res  (settle-peek settle.state path)",
        ] {
            assert_eq!(
                trimmed_eq_count(needle),
                1,
                "settle line `{needle}` must appear exactly once"
            );
        }
        for needle in [
            "/+  *alpha",
            "alpha=alpha-state",
            "alpha-cause",
            "%alpha-do",
            "=/  alpha-res  (alpha-peek state path)",
        ] {
            assert_eq!(
                trimmed_eq_count(needle),
                1,
                "alpha line `{needle}` must appear exactly once"
            );
        }
        // settle was wired on the first run, so all 5 of its markers
        // skip on the second; alpha is fresh and injects all 5.
        let settle_report = &report.grafts[0];
        let alpha_report = &report.grafts[1];
        assert_eq!(settle_report.name, "settle-graft");
        assert_eq!(settle_report.injected.len(), 0);
        assert_eq!(settle_report.skipped.len(), 5);
        assert_eq!(alpha_report.name, "alpha");
        assert_eq!(alpha_report.injected.len(), 5);
        assert_eq!(alpha_report.skipped.len(), 0);
    }

    #[test]
    fn peek_chain_idempotence_append_third_graft() {
        // Build vesl+alpha chain, then add beta. Beta's two lines must
        // land immediately before the terminal `~`, after the existing
        // vesl and alpha chain lines.
        let vesl_alpha: Vec<Graft> = {
            let mut v = settle_only_grafts();
            v.push(synthetic_graft("alpha", 50));
            v
        };
        let (after_va, _) = inject(BARE_SCAFFOLD, &vesl_alpha).unwrap();

        let mut all = vesl_alpha.clone();
        all.push(synthetic_graft("beta", 60));
        let (after_all, _) = inject(&after_va, &all).unwrap();

        // Beta lines exist exactly once in the output.
        assert_eq!(
            after_all
                .matches("=/  beta-res  (beta-peek state path)")
                .count(),
            1
        );

        // The peek region after the marker is now: vesl banner-wrapped pair,
        // alpha banner-wrapped pair, beta banner-wrapped pair, terminal `~`.
        // Each pair is 4 lines (begin, =/, ?., end); 3 pairs + `~` = 13 lines.
        // Beta's pair lands immediately before the terminal `~`.
        let peek_lines: Vec<String> = after_all
            .lines()
            .skip_while(|l| !l.contains("nockup:peek"))
            .skip(1)
            .take(13)
            .map(|l| l.trim_start().to_string())
            .collect();
        assert_eq!(peek_lines.len(), 13);
        assert!(peek_lines[8].starts_with("::  graft-inject:beta:peek:begin"));
        assert_eq!(peek_lines[9], "=/  beta-res  (beta-peek state path)");
        assert_eq!(peek_lines[10], "?.  =(~ beta-res)  beta-res");
        assert_eq!(peek_lines[11], "::  graft-inject:beta:peek:end");
        assert_eq!(peek_lines[12], "~");
    }

    #[test]
    fn peek_chain_n1_matches_legacy_replacement() {
        // For N=1 the chain (post-AUDIT 2026-04-19 banner refactor) is:
        //   ::  graft-inject:settle-graft:peek:begin
        //   =/  settle-res  (settle-peek settle.state path)
        //   ?.  =(~ settle-res)  settle-res
        //   ::  graft-inject:settle-graft:peek:end
        //   ~                                   <- terminal fallback
        //
        // The legacy `(settle-peek settle.state path)` expression lives inside
        // the chain's `=/` binding — same runtime semantics as the
        // pre-Phase-4 flat replacement.
        let grafts = settle_only_grafts();
        let (out, _) = inject(BARE_SCAFFOLD, &grafts).unwrap();
        let peek_lines: Vec<&str> = out
            .lines()
            .skip_while(|l| !l.contains("nockup:peek"))
            .skip(1)
            .take(5)
            .collect();
        assert_eq!(peek_lines.len(), 5, "peek region has fewer than 5 lines");
        assert!(
            peek_lines[0]
                .trim_start()
                .starts_with("::  graft-inject:settle-graft:peek:begin")
        );
        assert_eq!(
            peek_lines[1].trim_start(),
            "=/  settle-res  (settle-peek settle.state path)"
        );
        assert_eq!(peek_lines[2].trim_start(), "?.  =(~ settle-res)  settle-res");
        assert_eq!(
            peek_lines[3].trim_start(),
            "::  graft-inject:settle-graft:peek:end"
        );
        assert_eq!(peek_lines[4].trim_start(), "~");
    }

    // ---------- CLI tests ----------

    fn cli_with(lib_dir: PathBuf) -> Cli {
        Cli {
            command: None,
            path: None,
            grafts: Vec::new(),
            exclude: Vec::new(),
            lib_dir,
            list: false,
            json: false,
            dry_run: false,
            apply: false,
            no_migrate: false,
        }
    }

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


    // ---------- codegen kernel-cause-tags ----------

    /// `emit_kernel_cause_tags_rs` produces a sorted slice + macro
    /// scaffolding. Verify the slice contains the supplied tags in
    /// sorted order and that the assert_kernel_cause_tag! macro
    /// definition appears.
    #[test]
    fn codegen_kernel_cause_tags_emits_slice_and_macro() {
        let mut tags = std::collections::BTreeSet::new();
        tags.insert("settle-register".to_string());
        tags.insert("g-set".to_string());
        tags.insert("snapshot-root".to_string());
        let path = PathBuf::from("hoon/app/app.hoon");
        let src = emit_kernel_cause_tags_rs(&path, "deadbeef", &tags);
        assert!(src.contains("pub const KERNEL_CAUSE_TAGS: &[&str] = &["));
        // BTreeSet iteration order is sorted: g-set < settle-register < snapshot-root
        let g_pos = src.find("\"g-set\"").expect("g-set should be present");
        let s_pos = src
            .find("\"settle-register\"")
            .expect("settle-register should be present");
        let sn_pos = src
            .find("\"snapshot-root\"")
            .expect("snapshot-root should be present");
        assert!(g_pos < s_pos);
        assert!(s_pos < sn_pos);
        assert!(src.contains("macro_rules! assert_kernel_cause_tag"));
        assert!(src.contains("Source: hoon/app/app.hoon sha256:deadbeef"));
    }

    /// Build a temp lib dir with settle-graft.toml and an alpha synthetic
    /// manifest so multi-manifest selection logic can be tested without
    /// the real hoon/lib tree.
    fn tempdir_with_two_manifests(label: &str) -> PathBuf {
        let dir = tempdir_for_test(label);
        let settle_src = fs::read_to_string(settle_graft_manifest_path()).unwrap();
        fs::write(dir.join("settle-graft.toml"), settle_src).unwrap();
        fs::write(
            dir.join("alpha.toml"),
            r#"[graft]
name     = "alpha"
version  = "0.1.0"
priority = 50
after    = []

[graft.blocks.imports]
sentinel = "*alpha"
body     = "/+  *alpha"

[graft.blocks.state]
sentinel = "alpha=alpha-state"
body     = "alpha=alpha-state"

[graft.blocks.cause]
sentinel = "alpha-cause"
body     = "alpha-cause"

[graft.blocks.poke]
sentinel = "%alpha-do"
body     = """
  %alpha-do
[~ state]"""

[graft.blocks.peek]
sentinel = "alpha-peek"
body     = "(alpha-peek state path)"
"#,
        )
        .unwrap();
        dir
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

    /// Write a synthetic manifest with the given `name` into `dir` at
    /// `file_name`, so `discover_grafts` can exercise collision + name
    /// validation paths without touching the real hoon/lib tree.
    fn write_manifest(dir: &Path, file_name: &str, name: &str) {
        fs::write(
            dir.join(file_name),
            format!(
                r#"[graft]
name     = "{name}"
version  = "0.1.0"
priority = 50
after    = []

[graft.blocks.imports]
sentinel = "*{name}"
body     = "/+  *{name}"

[graft.blocks.poke]
sentinel = "%{name}-do"
body     = """
  %{name}-do
[~ state]"""
"#,
            ),
        )
        .unwrap();
    }

    /// Like `write_manifest` but adds a `[graft.types]` table with the
    /// caller-supplied effect/cause names. Used by the cross-graft type
    /// uniqueness tests.
    fn write_manifest_with_types(
        dir: &Path,
        file_name: &str,
        name: &str,
        effect: &str,
        cause: &str,
    ) {
        fs::write(
            dir.join(file_name),
            format!(
                r#"[graft]
name     = "{name}"
version  = "0.1.0"
priority = 50
after    = []

[graft.types]
effect = "{effect}"
cause  = "{cause}"

[graft.blocks.imports]
sentinel = "*{name}"
body     = "/+  *{name}"

[graft.blocks.poke]
sentinel = "%{name}-do"
body     = """
  %{name}-do
[~ state]"""
"#,
            ),
        )
        .unwrap();
    }

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

    /// H-12: graft A's injected body contains graft B's sentinel as a
    /// bare substring. Banner-comment idempotence must not mistake A's
    /// body for B being wired — B's begin banner is the only signal.
    #[test]
    fn cross_graft_sentinel_no_false_positive() {
        // `poison` carries `%contaminant-do` in its poke body but never
        // emits a `contaminant:poke:begin` banner. A subsequent run that
        // adds the real `contaminant` graft must still inject it.
        let poison = Graft {
            name: "poison".to_string(),
            version: "0.1.0".to_string(),
            priority: 10,
            after: vec![],
            blocks: GraftBlocks {
                imports: Some(Block {
                    sentinel: "*poison".to_string(),
                    body: "/+  *poison".to_string(),
                }),
                state: None,
                cause: None,
                poke_prelude: None,
                poke: Some(Block {
                    sentinel: "%poison-do".to_string(),
                    body: "  %poison-do\n::  references %contaminant-do elsewhere\n[~ state]".to_string(),
                }),
                poke_postlude: None,
                peek: None,
            },
            gates: None,
            types: None,
            sha256: String::new(),
        };
        let contaminant = synthetic_graft("contaminant", 20);

        let (after_poison, _) = inject(BARE_SCAFFOLD, std::slice::from_ref(&poison)).unwrap();
        // Pre-condition: poison's body literally contains the contaminant sentinel.
        assert!(after_poison.contains("%contaminant-do"));

        let (after_both, report) =
            inject(&after_poison, &[poison.clone(), contaminant.clone()]).unwrap();
        let contaminant_report = report
            .grafts
            .iter()
            .find(|g| g.name == "contaminant")
            .expect("contaminant present");
        assert!(
            contaminant_report.injected.contains(&Marker::Poke),
            "H-12: contaminant poke must inject despite %contaminant-do \
             appearing in poison's body"
        );
        assert!(after_both.contains("::  graft-inject:contaminant:poke:begin"));

        // Now a second re-run with both grafts: nothing should inject.
        let (after_third, report) =
            inject(&after_both, &[poison, contaminant]).unwrap();
        assert_eq!(after_third, after_both);
        for g in &report.grafts {
            assert!(g.injected.is_empty(), "re-run must not re-inject {}", g.name);
        }
    }

    /// H-13: peek-chain idempotence broke at 6+ grafts because the bare
    /// `~` lived past the 10-line scan window. Build 7 grafts, inject,
    /// re-inject, and assert byte-identical output plus exactly one bare
    /// `~` between the peek marker and its `==` closer (the pre-fix path
    /// produced two).
    #[test]
    fn peek_chain_seven_grafts_idempotent() {
        let grafts: Vec<Graft> = (0..7)
            .map(|i| synthetic_graft(&format!("g{i}"), 10 + i * 10))
            .collect();
        let (first, _) = inject(BARE_SCAFFOLD, &grafts).unwrap();
        let (second, report) = inject(&first, &grafts).unwrap();
        assert_eq!(first, second, "seven-graft inject must be idempotent");
        for g in &report.grafts {
            assert!(g.injected.is_empty(), "{} re-injected", g.name);
        }
        let lines: Vec<&str> = second.lines().collect();
        let peek_idx = lines
            .iter()
            .position(|l| l.contains("nockup:peek"))
            .expect("peek marker present");
        let close_idx = lines[peek_idx..]
            .iter()
            .position(|l| l.trim() == "==")
            .map(|o| peek_idx + o)
            .expect("peek block closer");
        let tilde_count = lines[peek_idx..close_idx]
            .iter()
            .filter(|l| l.trim() == "~")
            .count();
        assert_eq!(
            tilde_count, 1,
            "exactly one terminal ~ expected in peek block"
        );
        // Peek block is large enough to span all 7 banner-wrapped pairs
        // (4 lines each) plus the terminal tilde.
        assert!(
            close_idx - peek_idx >= 7 * 4,
            "peek block should fit 7 banner-wrapped pairs, got {} lines",
            close_idx - peek_idx
        );
    }

    /// H-14: poke-body with an inner bare `==` line (a shape Hoon kernels
    /// routinely produce from nested `?-`/`?+` tuple destructures) made
    /// the sentinel walk terminate before reaching the sentinel, causing
    /// every re-run to append the body again. Banner-comment idempotence
    /// is file-wide, so inner `==` is no longer a concern — this locks
    /// the fix in place.
    #[test]
    fn poke_body_inner_double_equals_idempotent() {
        let nested = Graft {
            name: "nested".to_string(),
            version: "0.1.0".to_string(),
            priority: 10,
            after: vec![],
            blocks: GraftBlocks {
                imports: None,
                state: None,
                cause: None,
                poke_prelude: None,
                poke: Some(Block {
                    sentinel: "%nested-do".to_string(),
                    body: "  %nested-do\n?-  +.state\n  [%foo ~]  [~ state]\n  [%bar ~]  [~ state]\n==\n[~ state]".to_string(),
                }),
                poke_postlude: None,
                peek: None,
            },
            gates: None,
            types: None,
            sha256: String::new(),
        };
        let (first, _) = inject(BARE_SCAFFOLD, std::slice::from_ref(&nested)).unwrap();
        assert!(first.lines().any(|l| l.trim() == "=="), "inner == present");
        let (second, report) = inject(&first, &[nested]).unwrap();
        assert_eq!(first, second, "inner == must not re-trigger inject");
        assert!(report.grafts[0].injected.is_empty());
    }

    /// RH1 step 1 (HARD-BUG-1): removing a graft from the injection set
    /// auto-prunes its banner-pair-bounded blocks. Pre-RH1 the tool was
    /// additive-only; orphan blocks then referenced types missing from the
    /// shrunk effect-union and hoonc failed silently. The new contract is:
    /// drop a graft from `--grafts`, re-run with `--apply`, and the orphan
    /// blocks are stripped automatically.
    ///
    /// Byte-identical round-trip across drop-then-readd is a Step 2 concern
    /// (HARD-FRICTION-2 — preserve position on fresh-inject after a partial
    /// drop). This test isolates the prune contract.
    #[test]
    fn removed_graft_auto_prunes_orphan_banners() {
        let a = synthetic_graft("alpha", 10);
        let b = synthetic_graft("beta", 20);
        let (after_both, _) = inject(BARE_SCAFFOLD, &[a.clone(), b.clone()]).unwrap();
        assert!(after_both.contains("::  graft-inject:beta:imports:begin"));
        let (after_alpha_only, report) = inject(&after_both, &[a]).unwrap();
        assert!(
            !after_alpha_only.contains("::  graft-inject:beta:"),
            "beta banner pairs must be pruned when beta drops from --grafts"
        );
        assert!(
            !after_alpha_only.contains("/+  *beta"),
            "beta imports must be pruned with the rest of its banner pair"
        );
        assert!(
            after_alpha_only.contains("::  graft-inject:alpha:imports:begin"),
            "alpha banners must remain — only beta dropped"
        );
        let pruned: Vec<&str> = report
            .pruned_grafts
            .iter()
            .map(|g| g.name.as_str())
            .collect();
        assert_eq!(pruned, vec!["beta"], "report surfaces beta as pruned");
        assert!(
            !report.pruned_grafts[0].pruned.is_empty(),
            "pruned markers list is non-empty"
        );
    }

    /// RH1 step 2 (HARD-FRICTION-2): manifest drift on a non-first graft
    /// must re-inject the block at its ORIGINAL line position, not at the
    /// marker line. Pre-RH1 the strip-then-reinject path placed the
    /// drifted graft's block at marker_idx+1, pushing every later graft
    /// down by one — so a non-semantic edit (e.g., a gate-selection swap
    /// in the manifest) changed `sha256(app.hoon)` even though the file
    /// was logically equivalent. After Step 2, drift re-injection at
    /// emit_block-class markers preserves position; the file is byte-
    /// identical when the drifted manifest is reverted.
    #[test]
    fn drift_reinject_preserves_block_position() {
        let alpha = synthetic_graft("alpha", 10);
        let mut beta = synthetic_graft("beta", 20);
        // Compute and store a stable sha256 so check_injection can detect
        // "drift" when we later mutate the manifest.
        beta.sha256 = sha256_hex(b"beta-v1");

        let (composed, _) = inject(BARE_SCAFFOLD, &[alpha.clone(), beta.clone()]).unwrap();

        // Confirm beta's poke block is BELOW alpha's in the original.
        let alpha_poke = composed
            .lines()
            .position(|l| l.contains("graft-inject:alpha:poke:begin"))
            .expect("alpha poke banner present");
        let beta_poke = composed
            .lines()
            .position(|l| l.contains("graft-inject:beta:poke:begin"))
            .expect("beta poke banner present");
        assert!(
            alpha_poke < beta_poke,
            "initial layout: alpha:poke must precede beta:poke"
        );

        // Simulate a beta manifest edit (sha256 changes; body unchanged).
        let mut beta_drifted = beta.clone();
        beta_drifted.sha256 = sha256_hex(b"beta-v2");

        let (after_drift, _) =
            inject(&composed, &[alpha.clone(), beta_drifted]).unwrap();
        let alpha_poke2 = after_drift
            .lines()
            .position(|l| l.contains("graft-inject:alpha:poke:begin"))
            .expect("alpha poke banner survives drift");
        let beta_poke2 = after_drift
            .lines()
            .position(|l| l.contains("graft-inject:beta:poke:begin"))
            .expect("beta poke banner re-emitted after drift");
        assert!(
            alpha_poke2 < beta_poke2,
            "drift re-injection must preserve order: alpha:poke still precedes beta:poke. \
             Pre-RH1 the drifted graft jumped to marker_idx+1, inverting the order."
        );

        // Revert beta to its original sha. The result is byte-identical
        // to the initial composition — drift round-trips at the byte level.
        let (after_revert, _) = inject(&after_drift, &[alpha, beta]).unwrap();
        assert_eq!(
            after_revert, composed,
            "drift-then-revert is byte-identical (Step 2 invariant)"
        );
    }

    /// RH2 HARD-BUG-2 regression guard: peek-marker drift re-injection
    /// must preserve relative order between graft peek blocks. Pre-fix
    /// (RH1 step 2) Peek was excluded from the position-preservation
    /// gate, so peek drift fell through to the batch fresh-inject path
    /// (`emit_peek_chain`) which inserts before the chain's terminal
    /// `~` — relocating the drifted block to the tail. Post-fix (RH2
    /// step 2) `canonicalize_marker_section` strips and re-emits all
    /// active grafts in canonical order regardless of marker type.
    ///
    /// Test shape: drift the FIRST graft of a 3-graft chain.
    /// Reproduces the post-mortem's settle-graft peek migration
    /// (line 101 → 113) at HARD-REV-SWAP-GATE.
    #[test]
    fn peek_drift_reinject_preserves_block_position() {
        let mut alpha = synthetic_graft("alpha", 10);
        alpha.sha256 = sha256_hex(b"alpha-v1");
        let beta = synthetic_graft("beta", 20);
        let gamma = synthetic_graft("gamma", 30);

        let (composed, _) =
            inject(BARE_SCAFFOLD, &[alpha.clone(), beta.clone(), gamma.clone()]).unwrap();

        let pos = |s: &str, g: &str| -> usize {
            s.lines()
                .position(|l| l.contains(&format!("graft-inject:{g}:peek:begin")))
                .unwrap_or_else(|| panic!("{g} peek banner missing"))
        };
        assert!(
            pos(&composed, "alpha") < pos(&composed, "beta"),
            "initial layout: alpha:peek precedes beta:peek"
        );
        assert!(
            pos(&composed, "beta") < pos(&composed, "gamma"),
            "initial layout: beta:peek precedes gamma:peek"
        );

        let mut alpha_drifted = alpha.clone();
        alpha_drifted.sha256 = sha256_hex(b"alpha-v2");

        let (after_drift, _) =
            inject(&composed, &[alpha_drifted, beta.clone(), gamma.clone()]).unwrap();

        assert!(
            pos(&after_drift, "alpha") < pos(&after_drift, "beta"),
            "drift re-injection must preserve order at the peek marker: \
             alpha:peek still precedes beta:peek. HARD-BUG-2 currently \
             relocates the drifted peek block to the chain tail."
        );
        assert!(
            pos(&after_drift, "beta") < pos(&after_drift, "gamma"),
            "non-drifted blocks (beta, gamma) keep relative order through drift"
        );

        let (after_revert, _) = inject(&after_drift, &[alpha, beta, gamma]).unwrap();
        assert_eq!(
            after_revert, composed,
            "peek drift-then-revert is byte-identical (HARD-BUG-2 invariant)"
        );
    }

    /// RH2 HARD-BUG-3: dropping a graft and re-adding it currently lands
    /// the re-injected block at marker_idx+1 (position 1 of each marker
    /// section), displacing any other graft blocks below the marker.
    /// After the canonical-re-emit refactor, the final layout is a pure
    /// function of the active graft set and drop+readd is byte-identical.
    #[test]
    fn drop_readd_preserves_position_byte_identical() {
        let alpha = synthetic_graft("alpha", 10);
        let beta = synthetic_graft("beta", 20);
        let gamma = synthetic_graft("gamma", 30);

        let (composed, _) =
            inject(BARE_SCAFFOLD, &[alpha.clone(), beta.clone(), gamma.clone()]).unwrap();

        let (after_drop, _) = inject(&composed, &[alpha.clone(), gamma.clone()]).unwrap();
        assert!(
            !after_drop.contains("graft-inject:beta:"),
            "beta banners pruned on drop (precondition for the readd test)"
        );

        let (after_readd, _) = inject(&after_drop, &[alpha, beta, gamma]).unwrap();
        assert_eq!(
            after_readd, composed,
            "drop+readd is byte-identical (HARD-BUG-3 invariant). \
             Pre-fix the re-added beta lands at marker_idx+1 in each \
             section instead of between alpha and gamma."
        );
    }

    /// RH2 HARD-BUG-3 cross-marker scenario: matches the post-mortem's
    /// HARD-REV-IDEMPOTENCE-CHAIN sequence with four grafts. The byte-
    /// identical assertion catches both the direct (re-added graft
    /// position) and the collateral (other grafts moving) symptoms in a
    /// single check.
    #[test]
    fn cross_marker_drop_readd_no_collateral_movement() {
        let a = synthetic_graft("aaa", 10);
        let b = synthetic_graft("bbb", 20);
        let c = synthetic_graft("ccc", 30);
        let d = synthetic_graft("ddd", 40);

        let (composed, _) =
            inject(BARE_SCAFFOLD, &[a.clone(), b.clone(), c.clone(), d.clone()]).unwrap();

        let (after_drop, _) =
            inject(&composed, &[a.clone(), b.clone(), c.clone()]).unwrap();

        let (after_readd, _) = inject(&after_drop, &[a, b, c, d]).unwrap();

        assert_eq!(
            after_readd, composed,
            "drop+readd cycle (4 grafts) is byte-identical. \
             Catches the HARD-BUG-3 collateral-movement symptom — \
             the post-mortem's `log-graft jumps to position 1 even \
             though only validate was re-added` bug."
        );
    }

    // ---------------------------------------------------------------
    // typed effect-union codegen
    // ---------------------------------------------------------------

    /// Synthetic graft with a `[graft.types]` declaration. Reuses
    /// `synthetic_graft` (which leaves `types: None`) and overrides.
    fn synthetic_graft_with_effect(name: &str, priority: i32) -> Graft {
        let mut g = synthetic_graft(name, priority);
        g.types = Some(GraftTypes {
            effect: Some(format!("{name}-effect")),
            cause: Some(format!("{name}-cause")),
        });
        g
    }

    /// Bare scaffold + a `nockup:effect-union` marker. Used as the
    /// codegen test fixture so the existing BARE_SCAFFOLD tests keep
    /// running unmodified.
    const SCAFFOLD_WITH_UNION_MARKER: &str = "\
::  test scaffold with codegen marker
::  nockup:effect-union
::
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
";

    /// Same as above plus a `nockup:domain-effect` marker and a
    /// developer-declared `+$ domain-effect` block.
    const SCAFFOLD_WITH_BOTH_MARKERS: &str = "\
::  test scaffold with both codegen markers
::
::  nockup:domain-effect
+$  domain-effect
  $%  [%user-thing ~]
  ==
::
::  nockup:effect-union
::
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
";

    #[test]
    fn codegen_skipped_without_marker() {
        let g = synthetic_graft_with_effect("alpha", 10);
        let (out, report) = inject(BARE_SCAFFOLD, &[g]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Skipped);
        assert!(report.codegen.variants.is_empty());
        assert!(!out.contains("graft-inject:effect-union:begin"));
    }

    #[test]
    fn codegen_inserts_with_one_graft() {
        let g = synthetic_graft_with_effect("alpha", 10);
        let (out, report) = inject(SCAFFOLD_WITH_UNION_MARKER, &[g]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Inserted);
        assert_eq!(report.codegen.variants, vec!["alpha-effect"]);
        assert!(out.contains("::  graft-inject:effect-union:begin"));
        assert!(out.contains("+$  effect"));
        assert!(out.contains("$%  alpha-effect"));
        assert!(out.contains("::  graft-inject:effect-union:end"));
    }

    #[test]
    fn codegen_inserts_with_n_grafts() {
        let grafts = vec![
            synthetic_graft_with_effect("alpha", 10),
            synthetic_graft_with_effect("beta", 20),
            synthetic_graft_with_effect("gamma", 30),
        ];
        let (out, report) = inject(SCAFFOLD_WITH_UNION_MARKER, &grafts).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Inserted);
        assert_eq!(
            report.codegen.variants,
            vec!["alpha-effect", "beta-effect", "gamma-effect"]
        );
        // Variant order in source matches the input slice (priority order).
        let begin = out.find("graft-inject:effect-union:begin").unwrap();
        let end = out.find("graft-inject:effect-union:end").unwrap();
        let block = &out[begin..end];
        let alpha = block.find("alpha-effect").unwrap();
        let beta = block.find("beta-effect").unwrap();
        let gamma = block.find("gamma-effect").unwrap();
        assert!(alpha < beta && beta < gamma, "variants in priority order");
    }

    #[test]
    fn codegen_includes_domain_effect_when_marker_present() {
        let g = synthetic_graft_with_effect("alpha", 10);
        let (out, report) = inject(SCAFFOLD_WITH_BOTH_MARKERS, &[g]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Inserted);
        assert_eq!(
            report.codegen.variants,
            vec!["alpha-effect", "domain-effect"]
        );
        assert!(out.contains("domain-effect"));
        // Developer's `+$ domain-effect $%([%user-thing ~] ==)` declaration
        // must survive the codegen pass untouched.
        assert!(out.contains("[%user-thing ~]"));
    }

    #[test]
    fn codegen_idempotent_unchanged_on_rerun() {
        let g = synthetic_graft_with_effect("alpha", 10);
        let (first, _) = inject(SCAFFOLD_WITH_UNION_MARKER, std::slice::from_ref(&g)).unwrap();
        let (second, report) = inject(&first, &[g]).unwrap();
        assert_eq!(first, second, "second run must be byte-identical");
        assert_eq!(report.codegen.status, CodegenStatus::Unchanged);
    }

    #[test]
    fn codegen_replace_grows_when_graft_added() {
        let alpha = synthetic_graft_with_effect("alpha", 10);
        let beta = synthetic_graft_with_effect("beta", 20);
        let (one, _) = inject(SCAFFOLD_WITH_UNION_MARKER, std::slice::from_ref(&alpha)).unwrap();
        let (two, report) = inject(&one, &[alpha, beta]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Replaced);
        assert_eq!(
            report.codegen.variants,
            vec!["alpha-effect", "beta-effect"]
        );
        assert!(two.contains("alpha-effect"));
        assert!(two.contains("beta-effect"));
    }

    #[test]
    fn codegen_replace_shrinks_when_graft_removed() {
        let alpha = synthetic_graft_with_effect("alpha", 10);
        let beta = synthetic_graft_with_effect("beta", 20);
        let (two, _) = inject(SCAFFOLD_WITH_UNION_MARKER, &[alpha.clone(), beta]).unwrap();
        assert!(two.contains("beta-effect"));
        let (one, report) = inject(&two, &[alpha]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Replaced);
        assert_eq!(report.codegen.variants, vec!["alpha-effect"]);
        // Codegen owns the union — the dropped variant must be gone.
        let begin = one.find("graft-inject:effect-union:begin").unwrap();
        let end = one.find("graft-inject:effect-union:end").unwrap();
        let block = &one[begin..end];
        assert!(!block.contains("beta-effect"), "beta-effect must be removed from union body");
    }

    #[test]
    fn codegen_empty_graft_set_emits_placeholder() {
        let (out, report) = inject(SCAFFOLD_WITH_UNION_MARKER, &[]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Inserted);
        assert_eq!(report.codegen.variants, vec!["[%effect-placeholder ~]"]);
        assert!(out.contains("[%effect-placeholder ~]"));
    }

    #[test]
    fn codegen_empty_graft_set_with_domain_effect() {
        let (out, report) = inject(SCAFFOLD_WITH_BOTH_MARKERS, &[]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Inserted);
        assert_eq!(report.codegen.variants, vec!["domain-effect"]);
        assert!(!out.contains("[%effect-placeholder ~]"));
    }

    #[test]
    fn codegen_orphan_end_banner_bails() {
        let src = "\
::  test
::
::  nockup:effect-union
::  graft-inject:effect-union:end
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
";
        let g = synthetic_graft_with_effect("alpha", 10);
        let result = inject(src, &[g]);
        assert!(result.is_err());
        let msg = format!("{:#}", result.unwrap_err());
        assert!(msg.contains("orphan"), "error must mention orphan: {msg}");
    }

    #[test]
    fn codegen_orphan_begin_banner_bails() {
        let src = "\
::  test
::
::  nockup:effect-union
::  graft-inject:effect-union:begin
+$  effect
  $%  alpha-effect
  ==
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
";
        let g = synthetic_graft_with_effect("alpha", 10);
        let result = inject(src, &[g]);
        assert!(result.is_err());
        let msg = format!("{:#}", result.unwrap_err());
        assert!(msg.contains("orphan"), "error must mention orphan: {msg}");
    }

    #[test]
    fn codegen_replaces_post_migration_bare_effect_line() {
        // Post-migration / pre-codegen state from commit 7: marker is
        // present and a bare `+$  effect  *` line sits immediately
        // beneath. Codegen must wrap-and-replace that single line.
        let src = "\
::  test
::
::  nockup:effect-union
+$  effect  *
::
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
";
        let g = synthetic_graft_with_effect("alpha", 10);
        let (out, report) = inject(src, &[g]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Inserted);
        assert!(out.contains("+$  effect\n  $%  alpha-effect\n  ==\n"));
        // The bare `+$  effect  *` line must be gone.
        assert!(!out.lines().any(|l| l.trim() == "+$  effect  *"));
    }

    // ---------------------------------------------------------------
    // weld-friction lint
    // ---------------------------------------------------------------

    /// Scaffold + a domain `%set` arm that binds narrowly. Used to
    /// exercise the weld-friction lint on developer code outside any
    /// graft-inject banner region.
    const SCAFFOLD_NARROW_BINDING: &str = "\
::  test scaffold with narrow effect bindings
::
::  nockup:domain-effect
+$  domain-effect
  $%  [%set-done ~]
  ==
::
::  nockup:effect-union
+$  effect  *
::
+$  cause
  $%  [%cause ~]
      [%set name=@t value=@]
      ::  nockup:cause
  ==
::
=/  [efx-c=(list counter-effect) new-counter=counter-state]
  (counter-poke counter.state [%counter-increment name.u.act])
=/  [efx-k=(list kv-effect) new-kv=kv-state]
  (kv-poke kv.state [%kv-set name.u.act value.u.act])
(weld efx-c efx-k)
--
";

    #[test]
    fn weld_lint_flags_narrow_bindings_in_domain_code() {
        let counter = synthetic_graft_with_effect("counter", 60);
        let kv = synthetic_graft_with_effect("kv", 50);
        let (_, report) = inject(SCAFFOLD_NARROW_BINDING, &[kv, counter]).unwrap();
        assert_eq!(
            report.weld_lint.findings.len(),
            2,
            "two narrow bindings should be flagged: {:#?}",
            report.weld_lint.findings,
        );
        let narrow_types: Vec<&str> = report
            .weld_lint
            .findings
            .iter()
            .map(|f| f.narrow_type.as_str())
            .collect();
        assert!(narrow_types.contains(&"counter-effect"));
        assert!(narrow_types.contains(&"kv-effect"));
    }

    #[test]
    fn weld_lint_skips_graft_injected_bodies() {
        // Graft poke bodies legitimately contain `(list <graft>-effect)`.
        // The lint must only fire on developer code, not on graft-injected
        // regions between :begin/:end banners. Re-injecting the same
        // kernel keeps banner regions intact and asserts the lint count
        // doesn't grow with each graft's body.
        let counter = synthetic_graft_with_effect("counter", 60);
        let kv = synthetic_graft_with_effect("kv", 50);
        let (out, _) = inject(SCAFFOLD_NARROW_BINDING, &[kv.clone(), counter.clone()]).unwrap();
        let (_, report) = inject(&out, &[kv, counter]).unwrap();
        // Still 2 — the graft poke bodies inside :begin/:end banners are
        // ignored, only the developer's domain bindings count.
        assert_eq!(report.weld_lint.findings.len(), 2);
    }

    #[test]
    fn weld_lint_silent_on_widened_bindings() {
        // Pattern B: bindings widen to `(list effect)`. No findings.
        let widened = SCAFFOLD_NARROW_BINDING
            .replace("(list counter-effect)", "(list effect)")
            .replace("(list kv-effect)", "(list effect)");
        let counter = synthetic_graft_with_effect("counter", 60);
        let kv = synthetic_graft_with_effect("kv", 50);
        let (_, report) = inject(&widened, &[kv, counter]).unwrap();
        assert!(
            report.weld_lint.findings.is_empty(),
            "Pattern B widening must not trip the lint: {:#?}",
            report.weld_lint.findings,
        );
    }

    #[test]
    fn weld_lint_silent_when_codegen_skipped() {
        // No nockup:effect-union marker → codegen Skipped → empty
        // variant list → lint short-circuits. Domain code is left
        // alone whatever it does; we don't have a typed union to
        // recommend widening toward.
        let g = synthetic_graft_with_effect("alpha", 10);
        let (_, report) = inject(BARE_SCAFFOLD, &[g]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Skipped);
        assert!(report.weld_lint.findings.is_empty());
    }

    // ---------------------------------------------------------------
    // migrate_legacy_effect
    // ---------------------------------------------------------------

    #[test]
    fn migration_rewrites_bare_effect_star() {
        let (out, report) = migrate_legacy_effect(BARE_SCAFFOLD);
        assert!(report.migrated);
        assert!(!report.skipped_custom);
        assert!(out.contains("::  nockup:domain-effect"));
        assert!(out.contains("+$  domain-effect"));
        assert!(out.contains("[%domain-placeholder ~]"));
        assert!(out.contains("::  nockup:effect-union"));
        assert!(out.contains("+$  effect  *"));
        // The original lone `+$  effect  *` is gone — replaced by the
        // marker block. Count: one `+$  effect  *` survives, but only as
        // the placeholder beneath nockup:effect-union.
        let bare_count = out.lines().filter(|l| l.trim() == "+$  effect  *").count();
        assert_eq!(bare_count, 1, "exactly one bare effect line after migration");
    }

    #[test]
    fn migration_idempotent_after_first_run() {
        let (once, _) = migrate_legacy_effect(BARE_SCAFFOLD);
        let (twice, report) = migrate_legacy_effect(&once);
        assert_eq!(once, twice, "second migration must be a no-op");
        assert!(!report.migrated);
        assert!(!report.skipped_custom);
    }

    #[test]
    fn migration_skips_custom_effect_type() {
        let custom = BARE_SCAFFOLD.replace("+$  effect  *", "+$  effect  (list @t)");
        let (out, report) = migrate_legacy_effect(&custom);
        assert!(!report.migrated);
        assert!(report.skipped_custom);
        assert_eq!(out, custom, "custom effect type must be left untouched");
    }

    #[test]
    fn migration_then_inject_then_codegen_end_to_end() {
        // The full --apply path: migration adds markers, inject wires
        // graft blocks, codegen synthesizes the typed union.
        let g = synthetic_graft_with_effect("alpha", 10);
        let (migrated, _) = migrate_legacy_effect(BARE_SCAFFOLD);
        let (out, report) = inject(&migrated, &[g]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Inserted);
        assert_eq!(
            report.codegen.variants,
            vec!["alpha-effect", "domain-effect"]
        );
        // Banner block is present and references the union variants.
        assert!(out.contains("::  graft-inject:effect-union:begin"));
        assert!(out.contains("$%  alpha-effect"));
        assert!(out.contains("domain-effect"));
        assert!(out.contains("[%domain-placeholder ~]"));
    }

    #[test]
    fn duplicate_effect_type_bails() {
        let dir = tempdir_for_test("duplicate_effect_type");
        write_manifest_with_types(&dir, "a.toml", "alpha", "shared-effect", "alpha-cause");
        write_manifest_with_types(&dir, "b.toml", "beta", "shared-effect", "beta-cause");
        let err = discover_grafts(&dir).expect_err("duplicate type must bail");
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate [graft.types].effect `shared-effect`"),
            "got: {msg}"
        );
        assert!(msg.contains("a.toml"), "missing path a in: {msg}");
        assert!(msg.contains("b.toml"), "missing path b in: {msg}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_cause_type_bails() {
        let dir = tempdir_for_test("duplicate_cause_type");
        write_manifest_with_types(&dir, "a.toml", "alpha", "alpha-effect", "shared-cause");
        write_manifest_with_types(&dir, "b.toml", "beta", "beta-effect", "shared-cause");
        let err = discover_grafts(&dir).expect_err("duplicate type must bail");
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate [graft.types].cause `shared-cause`"),
            "got: {msg}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn distinct_effect_types_ok() {
        // Sanity: different effect names across two manifests must NOT
        // bail. Guards against an over-zealous uniqueness check.
        let dir = tempdir_for_test("distinct_effect_types");
        write_manifest_with_types(&dir, "a.toml", "alpha", "alpha-effect", "alpha-cause");
        write_manifest_with_types(&dir, "b.toml", "beta", "beta-effect", "beta-cause");
        let grafts = discover_grafts(&dir).expect("distinct types must load");
        assert_eq!(grafts.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn codegen_leaves_custom_effect_type_alone() {
        // If the developer wrote `+$ effect (list @t)` (custom, not the
        // bare `*`), the codegen INSERTs after the marker without
        // touching the developer's line. The developer's definition
        // ends up colliding with the synthesized one — which is hoonc's
        // job to surface, not the codegen's. The point of this test is
        // to confirm we don't silently rewrite bespoke types.
        let src = "\
::  test
::
::  nockup:effect-union
+$  effect  (list @t)
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
";
        let g = synthetic_graft_with_effect("alpha", 10);
        let (out, _report) = inject(src, &[g]).unwrap();
        assert!(
            out.contains("+$  effect  (list @t)"),
            "custom effect type must NOT be rewritten by codegen"
        );
    }

    // ---------------------------------------------------------------
    // RM4 §1 v0.2: load-defaults overlay codegen
    // ---------------------------------------------------------------

    /// Bare scaffold + a `nockup:load-defaults` marker placed inside an
    /// `++load` arm body. The placeholder `old-state` line directly
    /// after the marker mirrors the production marker template; the
    /// codegen replaces it with a `=/  defaults  ^*(versioned-state)` +
    /// `%_  defaults  ...  ==` overlay block.
    const SCAFFOLD_WITH_LOAD_DEFAULTS_MARKER: &str = "\
::  test scaffold with load-defaults marker
::  nockup:load-defaults
old-state
::  nockup:effect-union
::
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
";

    #[test]
    fn load_defaults_skipped_without_marker() {
        // BARE_SCAFFOLD has no `nockup:load-defaults` marker — codegen
        // returns Skipped and the source is unchanged where the load
        // arm lives.
        let g = synthetic_graft("alpha", 10);
        let (out, report) = inject(BARE_SCAFFOLD, &[g]).unwrap();
        assert_eq!(report.load_defaults.status, CodegenStatus::Skipped);
        assert!(report.load_defaults.fields.is_empty());
        assert!(!out.contains("graft-inject:load-defaults:begin"));
    }

    #[test]
    fn load_defaults_inserts_overlay_for_one_graft() {
        let g = synthetic_graft("alpha", 10);
        let (out, report) = inject(SCAFFOLD_WITH_LOAD_DEFAULTS_MARKER, &[g]).unwrap();
        assert_eq!(report.load_defaults.status, CodegenStatus::Inserted);
        assert_eq!(report.load_defaults.fields, vec!["alpha"]);
        assert!(out.contains("::  graft-inject:load-defaults:begin"));
        assert!(out.contains("=/  defaults  ^*(versioned-state)"));
        assert!(out.contains("%_  defaults"));
        // The per-field overlay line wraps the field-access in
        // `(mole |.(;;(<type> <field>.old-state)))` so same-composition
        // resume preserves data and schema-extension resume falls back
        // to defaults exactly where axes shifted.
        assert!(out.contains("alpha  =/  a  (mole |.(;;(alpha-state alpha.old-state)))"));
        assert!(out.contains("?~(a ^*(alpha-state) u.a)"));
        assert!(out.contains("::  graft-inject:load-defaults:end"));
        // The `old-state` placeholder line must be gone — the codegen
        // owns that slot now.
        let begin = out.find("graft-inject:load-defaults:begin").unwrap();
        let end = out.find("graft-inject:load-defaults:end").unwrap();
        let block = &out[begin..end];
        assert!(
            !block.contains("\n    old-state\n") && !block.ends_with("old-state"),
            "raw `old-state` placeholder must be replaced by overlay\nblock:\n{block}"
        );
    }

    #[test]
    fn load_defaults_emits_fields_in_priority_order() {
        let grafts = vec![
            synthetic_graft("alpha", 10),
            synthetic_graft("beta", 20),
            synthetic_graft("gamma", 30),
        ];
        let (out, report) = inject(SCAFFOLD_WITH_LOAD_DEFAULTS_MARKER, &grafts).unwrap();
        assert_eq!(report.load_defaults.status, CodegenStatus::Inserted);
        assert_eq!(report.load_defaults.fields, vec!["alpha", "beta", "gamma"]);
        let begin = out.find("graft-inject:load-defaults:begin").unwrap();
        let end = out.find("graft-inject:load-defaults:end").unwrap();
        let block = &out[begin..end];
        let alpha = block.find("alpha  =/  a  (mole").unwrap();
        let beta = block.find("beta  =/  b  (mole").unwrap();
        let gamma = block.find("gamma  =/  g  (mole").unwrap();
        assert!(
            alpha < beta && beta < gamma,
            "fields out of priority order in:\n{block}"
        );
    }

    #[test]
    fn load_defaults_idempotent_unchanged_on_rerun() {
        let g = synthetic_graft("alpha", 10);
        let (first, _) =
            inject(SCAFFOLD_WITH_LOAD_DEFAULTS_MARKER, std::slice::from_ref(&g)).unwrap();
        let (second, report) = inject(&first, &[g]).unwrap();
        assert_eq!(first, second, "second run must be byte-identical");
        assert_eq!(report.load_defaults.status, CodegenStatus::Unchanged);
    }

    #[test]
    fn load_defaults_replace_grows_when_graft_added() {
        let alpha = synthetic_graft("alpha", 10);
        let beta = synthetic_graft("beta", 20);
        let (one, _) =
            inject(SCAFFOLD_WITH_LOAD_DEFAULTS_MARKER, std::slice::from_ref(&alpha)).unwrap();
        let (two, report) = inject(&one, &[alpha, beta]).unwrap();
        assert_eq!(report.load_defaults.status, CodegenStatus::Replaced);
        assert_eq!(report.load_defaults.fields, vec!["alpha", "beta"]);
        assert!(two.contains("alpha  =/  a  (mole"));
        assert!(two.contains("beta  =/  b  (mole"));
    }

    #[test]
    fn load_defaults_replace_shrinks_when_graft_removed() {
        let alpha = synthetic_graft("alpha", 10);
        let beta = synthetic_graft("beta", 20);
        let (two, _) =
            inject(SCAFFOLD_WITH_LOAD_DEFAULTS_MARKER, &[alpha.clone(), beta]).unwrap();
        assert!(two.contains("beta  =/  b  (mole"));
        let (one, report) = inject(&two, &[alpha]).unwrap();
        assert_eq!(report.load_defaults.status, CodegenStatus::Replaced);
        assert_eq!(report.load_defaults.fields, vec!["alpha"]);
        let begin = one.find("graft-inject:load-defaults:begin").unwrap();
        let end = one.find("graft-inject:load-defaults:end").unwrap();
        let block = &one[begin..end];
        assert!(
            !block.contains("beta  =/  b  (mole"),
            "removed graft's overlay line must be gone\nblock:\n{block}",
        );
    }

    #[test]
    fn load_defaults_empty_graft_set_emits_bunt() {
        // A composition with no stateful grafts (e.g. forge-only)
        // should still produce a valid `_state`-typed expression. The
        // codegen emits a bare `^*(versioned-state)` so the load arm
        // is the bunt of the kernel state shape.
        let (out, report) = inject(SCAFFOLD_WITH_LOAD_DEFAULTS_MARKER, &[]).unwrap();
        assert_eq!(report.load_defaults.status, CodegenStatus::Inserted);
        assert!(report.load_defaults.fields.is_empty());
        assert!(out.contains("^*(versioned-state)"));
        assert!(!out.contains("%_  defaults"));
    }

    #[test]
    fn load_defaults_skips_graft_without_state_block() {
        // A graft that doesn't declare a `[graft.blocks.state]` block
        // (forge-graft pattern: stateless) doesn't contribute a state
        // field to versioned-state, so it must NOT appear in the
        // overlay either.
        let with_state = synthetic_graft("alpha", 10);
        let mut without_state = synthetic_graft("forge", 50);
        without_state.blocks.state = None;
        let (out, report) =
            inject(SCAFFOLD_WITH_LOAD_DEFAULTS_MARKER, &[with_state, without_state]).unwrap();
        assert_eq!(report.load_defaults.fields, vec!["alpha"]);
        assert!(out.contains("alpha  =/  a  (mole"));
        assert!(
            !out.contains("forge  =/  f  (mole"),
            "stateless graft must not contribute a load-defaults overlay line\n{out}",
        );
    }

    #[test]
    fn load_defaults_orphan_end_banner_bails() {
        // An orphan end banner (no matching begin) is structural
        // corruption; the codegen must surface it via Result::Err
        // rather than silently emit a duplicate banner pair.
        let src = "\
::  test
::  nockup:load-defaults
::  graft-inject:load-defaults:end
old-state
::  nockup:effect-union
::
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
";
        let g = synthetic_graft("alpha", 10);
        let err = inject(src, &[g]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("orphan") && msg.contains("load-defaults"),
            "expected orphan-banner error, got: {msg}"
        );
    }
}
