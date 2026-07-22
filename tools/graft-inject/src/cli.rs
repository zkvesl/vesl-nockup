//! Clap-driven CLI surface: the `Cli` / `Command` parser, subcommand
//! dispatch, and per-subcommand drivers (`run_inject`, `run_rename_kernel`,
//! the lint / codegen pass-throughs).
//!
//! The shared `Cli` flag-set carries the
//! legacy-bare-invocation path; the `Command::*` variants are the
//! modern subcommand surface. `dispatch` reifies each subcommand into
//! the legacy shape and feeds it to `run_inject`, keeping the inject
//! pipeline a single code path.
//!
//! The `--list` JSON schema (`GraftSummary` / `GraftTypesSummary`) is
//! stable per the manifest doc — additive bumps only.
//!
//! Reporting helpers (`emit_list`, `print_report`, `print_codegen_line`)
//! live here because their output shape is tightly coupled to the CLI
//! flags (`--json`, `--apply`, etc.) that drive them.

use anyhow::{Context, Result, anyhow, bail};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::codegen::{
    CodegenReport, CodegenStatus, run_codegen_harness_methods, run_codegen_kernel_cause_tags,
};
use crate::doctor::{check_hand_edits, emit_human as emit_doctor_human, run_doctor};
use crate::inject::{InjectReport, enforce_markers_placeable, inject};
use crate::migration::{MigrationReport, migrate_legacy_effect, print_migration_line};
use crate::lint::{
    LintFinding, LintPolicy, LintSeverity, lint_bare_tilde_ambiguity, lint_collision_check,
    lint_internal_dupes, lint_transitive_imports, lint_unresolved_cause_references,
    print_lint_findings, run_lint, summarize_severity,
};
use crate::manifest::{Graft, atomic_write, check_schema_compat, discover_grafts};
use crate::marker::Marker;
use crate::update::run_update;
use crate::{DEFAULT_KERNEL_PATH, DEFAULT_LIB_DIR};
use crate::util::check_lib_dir_trust;

mod rename_kernel;
use rename_kernel::run_rename_kernel;

pub(crate) const ASCII_LOGO: &str = r#"
██╗   ██╗███████╗███████╗██╗
██║   ██║██╔════╝██╔════╝██║
██║   ██║█████╗  ███████╗██║
╚██╗ ██╔╝██╔══╝  ╚════██║██║
 ╚████╔╝ ███████╗███████║███████╗
  ╚═══╝  ╚══════╝╚══════╝╚══════╝
"#;

#[derive(Parser, Debug)]
#[command(
    name = "graft-inject",
    version,
    about = "Compose vesl-flavored grafts into a nockup app.hoon kernel",
    long_about = "Compose vesl-flavored grafts into a nockup app.hoon kernel.\n\
                  \n\
                  Subcommands:\n  \
                    inject     compose grafts into app.hoon (preview-by-default; --apply to write)\n  \
                    list       list discovered grafts under --lib-dir\n  \
                  \n\
                  Without a subcommand, falls back to the legacy bare invocation\n\
                  (`graft-inject <PATH> --grafts ...`). That form is deprecated; prefer\n\
                  `graft-inject inject <PATH>` so the operation is explicit. Run\n\
                  `graft-inject <subcommand> --help` for subcommand-specific options.",
    after_help = ASCII_LOGO,
)]
pub(crate) struct Cli {
    /// Top-level subcommand. When omitted, the legacy bare-invocation
    /// flags (`<PATH>`, `--grafts`, `--apply`, `--list`, …) are honored
    /// for back-compat — a one-line deprecation note prints to stderr.
    #[command(subcommand)]
    command: Option<Command>,

    /// Target file (omit when using --list).
    path: Option<PathBuf>,

    /// Comma-separated graft names, in injection order. When omitted,
    /// auto-discovers all *.toml manifests under --lib-dir.
    #[arg(long, value_delimiter = ',')]
    grafts: Vec<String>,

    /// Comma-separated graft names to subtract from the discovered set.
    /// Ignored when --grafts is given (use --grafts instead).
    #[arg(long, value_delimiter = ',')]
    exclude: Vec<String>,

    /// Manifest discovery root.
    #[arg(long, default_value = DEFAULT_LIB_DIR)]
    lib_dir: PathBuf,

    /// Allow a `--lib-dir` outside any project tree (no `nockapp.toml`
    /// ancestor). Without it, an out-of-tree lib-dir is refused — its
    /// graft manifests are spliced verbatim into compiled Hoon.
    #[arg(long, global = true)]
    accept_untrusted_libs: bool,

    /// Print discovered grafts and exit. Pair with --json for machine-readable.
    #[arg(long)]
    list: bool,

    /// JSON output mode (currently only meaningful with --list).
    #[arg(long)]
    json: bool,

    /// Deprecated alias of the default preview-only behavior. Kept for
    /// script compatibility.
    /// Prints a one-line deprecation note to stderr and otherwise does
    /// nothing beyond the default.
    #[arg(long)]
    dry_run: bool,

    /// Write the composed output to PATH. The
    /// default is preview-only — stdout gets the composed Hoon, stderr
    /// gets the per-manifest sha256 summary, disk is untouched. This
    /// flag is the explicit "yes, compose these manifests into kernel
    /// source" acknowledgement.
    #[arg(long)]
    apply: bool,

    /// Skip the auto-migration of legacy `+$  effect  *` to the
    /// marker-shape (`nockup:domain-effect` + `nockup:effect-union` +
    /// bare `+$ effect *`). Default behavior is to migrate
    /// transparently; `--no-migrate` is the opt-out for paranoid review.
    /// The codegen pass still skips kernels without the
    /// `nockup:effect-union` marker.
    #[arg(long = "no-migrate")]
    no_migrate: bool,

    /// Per-lint severity override in `NAME=SEVERITY` form
    /// (e.g. `--lint-override weld-friction=error`). Repeatable.
    /// CLI overrides win over the `[lint]` table in `nockapp.toml`,
    /// which wins over the per-lint default. Unknown lint names or
    /// invalid severities hard-error so a typo doesn't silently no-op.
    #[arg(long = "lint-override")]
    lint_override: Vec<String>,

    /// Re-inject through banner pairs whose body has been hand-edited.
    /// By default `inject --apply` refuses the write when a hand-edit
    /// is present so the user's customization is not silently
    /// overwritten — pass this flag to acknowledge the loss (e.g. when
    /// rolling back to canonical) and proceed.
    #[arg(long = "force-overwrite-hand-edits")]
    force_overwrite_hand_edits: bool,

    /// Raise the default log floor from INFO to WARN before spawning
    /// any subprocess (e.g. the `nockup package install` invoked by
    /// `update`). nockup-graft's own status lines are unaffected; this
    /// flag exists so verbose subprocess INFO doesn't drown the
    /// composer's output. RUST_LOG (if set) still wins.
    #[arg(short = 'q', long, global = true)]
    quiet: bool,
}

impl Cli {
    /// Whether the operator passed `--quiet` / `-q`. Exposed so
    /// `lib::run` can translate the flag into a `RUST_LOG=warn`
    /// default for any subprocess this binary spawns.
    pub(crate) fn is_quiet(&self) -> bool {
        self.quiet
    }
}

/// Subcommands. Each variant carries its own argument set so
/// `graft-inject <subcmd> --help` shows only the relevant flags. Bare
/// `graft-inject <PATH> [flags]` keeps working through the
/// `Cli::command == None` branch in `main`.
#[derive(Subcommand, Debug, Clone)]
pub(crate) enum Command {
    /// Compose grafts into app.hoon (preview-by-default; --apply to write).
    Inject {
        /// Target Hoon source file. Defaults to `hoon/app/app.hoon`
        /// (the template scaffold's canonical kernel location).
        #[arg(default_value = DEFAULT_KERNEL_PATH)]
        path: PathBuf,

        /// Comma-separated graft names, in injection order. When omitted,
        /// auto-discovers all *.toml manifests under --lib-dir.
        #[arg(long, value_delimiter = ',')]
        grafts: Vec<String>,

        /// Comma-separated graft names to subtract from the discovered set.
        #[arg(long, value_delimiter = ',')]
        exclude: Vec<String>,

        /// Manifest discovery root.
        #[arg(long, default_value = DEFAULT_LIB_DIR)]
        lib_dir: PathBuf,

        /// Write the composed output to PATH (default is preview-only).
        #[arg(long)]
        apply: bool,

        /// Skip the auto-migration of legacy `+$ effect *` to the marker
        /// shape. Default migrates transparently.
        #[arg(long = "no-migrate")]
        no_migrate: bool,

        /// Per-lint severity override (`NAME=SEVERITY`). Repeatable;
        /// CLI overrides win over the `[lint]` table in `nockapp.toml`.
        #[arg(long = "lint-override")]
        lint_override: Vec<String>,

        /// Re-inject through banner pairs whose body has been
        /// hand-edited. By default `--apply` refuses the write so the
        /// edit is not silently overwritten; pass this to proceed.
        #[arg(long = "force-overwrite-hand-edits")]
        force_overwrite_hand_edits: bool,
    },

    /// List discovered grafts under --lib-dir.
    List {
        /// Manifest discovery root.
        #[arg(long, default_value = DEFAULT_LIB_DIR)]
        lib_dir: PathBuf,

        /// Comma-separated graft names to subtract from the discovered set.
        #[arg(long, value_delimiter = ',')]
        exclude: Vec<String>,

        /// JSON output mode (machine-readable).
        #[arg(long)]
        json: bool,
    },

    /// Run pre-apply structural validations on app.hoon. Exits 1 on
    /// any HARD finding so CI can gate `--apply` on the lint passing.
    Lint {
        /// Target Hoon source file. Defaults to `hoon/app/app.hoon`
        /// (the template scaffold's canonical kernel location).
        #[arg(default_value = DEFAULT_KERNEL_PATH)]
        path: PathBuf,

        /// Manifest discovery root for collision-check across grafts.
        #[arg(long, default_value = DEFAULT_LIB_DIR)]
        lib_dir: PathBuf,

        /// JSON output mode (machine-readable).
        #[arg(long)]
        json: bool,

        /// Per-lint severity override (`NAME=SEVERITY`). Repeatable;
        /// CLI overrides win over the `[lint]` table in `nockapp.toml`.
        #[arg(long = "lint-override")]
        lint_override: Vec<String>,
    },

    /// Project-health check: schema-version handshake, Cargo `[patch]`
    /// consistency, hand-edited injected blocks, and a missing
    /// `nockup:load-defaults` marker. Exits nonzero on findings so CI
    /// can gate on it.
    Doctor {
        /// Target Hoon source file (the project's app.hoon). Defaults
        /// to `hoon/app/app.hoon` so a bare `nockup-graft doctor`
        /// inside a project Just Works.
        #[arg(default_value = DEFAULT_KERNEL_PATH)]
        path: PathBuf,

        /// Manifest discovery root.
        #[arg(long, default_value = DEFAULT_LIB_DIR)]
        lib_dir: PathBuf,

        /// Emit a machine-readable JSON report to stdout instead of the
        /// grouped human surface. Overrides `--format human`.
        #[arg(long)]
        json: bool,

        /// Text output format: `human` (grouped stderr, default) or
        /// `build-warnings` (one `doctor: <msg>` line per finding to
        /// stdout, always exit 0 — the scaffold build.rs forwards these
        /// as `cargo:warning=`).
        #[arg(long, value_enum, default_value = "human")]
        format: crate::doctor::DoctorFormat,

        /// Per-lint severity override (`NAME=SEVERITY`). Repeatable;
        /// folded into the resolved per-lint policy line the doctor
        /// surface emits.
        #[arg(long = "lint-override")]
        lint_override: Vec<String>,
    },

    /// Update the graft library and recompose the kernel: refresh
    /// `hoon/lib/` via `nockup package install`, preview the
    /// recomposition with the doctor health report, confirm, then
    /// `inject --apply`. Preview-by-default; `--yes` skips the prompt.
    Update {
        /// Target Hoon source file (the project's app.hoon).
        path: PathBuf,

        /// Manifest discovery root.
        #[arg(long, default_value = DEFAULT_LIB_DIR)]
        lib_dir: PathBuf,

        /// Skip the interactive confirmation prompt (for CI). The
        /// preview still prints; only the y/N gate is bypassed.
        #[arg(long)]
        yes: bool,
    },

    /// Emit Rust source from app.hoon — codegen target depends on the
    /// sub-subcommand. Currently ships `kernel-cause-tags`; future
    /// targets append here.
    Codegen {
        #[command(subcommand)]
        target: CodegenTarget,
    },

    /// Rename the project kernel from `hoon/app/<from>.hoon` to
    /// `hoon/app/<new-name>.hoon`. Updates `[project].kernel_name` in
    /// `nockapp.toml` and rewrites bash code blocks in `./README.md`
    /// if present. Preview-by-default; `--apply` writes.
    RenameKernel {
        /// New kernel base name (without `.hoon` suffix). Validated
        /// against `^[a-z][a-z0-9-]*$` (Hoon module name shape).
        new_name: String,

        /// Existing kernel base name to rename FROM. Defaults to the
        /// `[project].kernel_name` value in `./nockapp.toml` if set,
        /// else `"app"` — so re-renames don't require typing the
        /// previous name.
        #[arg(long)]
        from: Option<String>,

        /// Write the planned operations to disk. Default is
        /// preview-only (matches the `inject` subcommand convention).
        #[arg(long)]
        apply: bool,
    },

    /// Emit a shell-completion script to stdout. Source the output to
    /// get tab-completion for subcommands + flag names. The script
    /// names the binary `nockup-graft` (the published install name);
    /// run it through `sed 's/nockup-graft/graft-inject/g'` if you
    /// invoke the legacy alias.
    ///
    /// Bash:  `nockup-graft completions bash > ~/.local/share/bash-completion/completions/nockup-graft`
    /// Zsh:   `nockup-graft completions zsh  > "${fpath[1]}/_nockup-graft"`
    /// Fish:  `nockup-graft completions fish > ~/.config/fish/completions/nockup-graft.fish`
    Completions {
        /// Target shell (bash / zsh / fish / elvish / powershell).
        shell: Shell,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum CodegenTarget {
    /// Emit `pub const KERNEL_CAUSE_TAGS: &[&str]` from app.hoon's
    /// composed cause $%. Pairs with the `assert_kernel_cause_tag!`
    /// macro the same file emits, so driver-side
    /// `b"<tag>"` literals are checked at compile time against the
    /// kernel's accepted tags. Catches a kernel rename that leaves the
    /// driver pointing at a dead tag, and a driver tag with no kernel
    /// arm.
    KernelCauseTags {
        /// Target Hoon source file (app.hoon with the grafts already
        /// composed, or the canonical scaffold for codegen-only flows).
        path: PathBuf,

        /// Manifest discovery root. Cause tags are collected from
        /// every graft's `[graft.blocks.poke]` body in addition to
        /// the domain `nockup:cause` region.
        #[arg(long, default_value = DEFAULT_LIB_DIR)]
        lib_dir: PathBuf,

        /// Output Rust file path. Without `--out` the emitted source
        /// goes to stdout — useful for `cargo run -- codegen ... |
        /// rustfmt`.
        #[arg(long)]
        out: Option<PathBuf>,

        /// JSON output mode — emit a `{"kernel_cause_tags": [...]}`
        /// document to stdout instead of Rust source. Useful for
        /// non-Rust consumers and CI smoke checks.
        #[arg(long)]
        json: bool,
    },

    /// Emit typed `GraftTestHarness` methods + per-graft outcome enums
    /// from the `harness-bindings.toml` sidecar. The generated file
    /// gets committed to `test/vesl-test/src/generated_harness.rs`;
    /// re-run after every sidecar or per-graft poke-arm change.
    /// Cross-checks every `(graft, tag)` against the matching
    /// `*-graft.toml` poke body so a rename in either surface surfaces
    /// at codegen time rather than as a runtime empty effect list.
    HarnessMethods {
        /// Path to the sidecar TOML. Defaults to
        /// `hoon/lib/harness-bindings.toml` when omitted.
        #[arg(default_value = "hoon/lib/harness-bindings.toml")]
        bindings: PathBuf,

        /// Manifest discovery root for the cross-check.
        #[arg(long, default_value = DEFAULT_LIB_DIR)]
        lib_dir: PathBuf,

        /// Output Rust file path. Without `--out` the emitted source
        /// goes to stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

/// Schema item for `--list --json`. Stable: version bumps append
/// fields, never reshape existing ones. Documented
/// in vesl/docs/graft-manifest.md (`--list --json schema`).
#[derive(Debug, Serialize)]
pub(crate) struct GraftSummary<'a> {
    pub(crate) name: &'a str,
    pub(crate) version: &'a str,
    pub(crate) priority: i32,
    pub(crate) blocks: Vec<&'static str>,
    pub(crate) applicable: usize,
    pub(crate) deferred: bool,
    /// Hex sha256 of the manifest's raw TOML bytes. Lets supply-chain
    /// reviewers pin expected digests without re-reading the file.
    pub(crate) sha256: &'a str,
    /// Per-graft `[graft.types]` table contents, surfaced for tooling
    /// that wants to know which grafts contribute to the typed effect
    /// union. `null` when the manifest omits the table.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) types: Option<GraftTypesSummary<'a>>,
}

#[derive(Debug, Serialize)]
pub(crate) struct GraftTypesSummary<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) effect: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cause: Option<&'a str>,
}

impl<'a> GraftSummary<'a> {
    pub(crate) fn from_graft(g: &'a Graft) -> Self {
        let blocks: Vec<&'static str> = Marker::ALL
            .iter()
            .filter(|m| g.block(**m).is_some())
            .map(|m| m.label())
            .collect();
        let applicable = blocks.len();
        let types = g.types.as_ref().map(|t| GraftTypesSummary {
            effect: t.effect.as_deref(),
            cause: t.cause.as_deref(),
        });
        Self {
            name: &g.name,
            version: &g.version,
            priority: g.priority,
            blocks,
            applicable,
            deferred: false,
            sha256: &g.sha256,
            types,
        }
    }
}

/// Subcommand dispatch. Either runs an explicit subcommand (modern
/// surface) or falls through to the legacy bare-invocation flow
/// (`graft-inject <PATH> --apply --grafts ...`) — emitting a
/// deprecation note when the legacy path is taken so scripts know to
/// migrate.
///
/// Each subcommand variant is reified into the legacy `Cli` shape and
/// handed to `run()`. The shared dispatch keeps subcommand-specific
/// flags isolated in `Command::*` while reusing the inject pipeline
/// and the `select_grafts` / `emit_list` plumbing unchanged.
pub(crate) fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Command::Inject {
            path,
            grafts,
            exclude,
            lib_dir,
            apply,
            no_migrate,
            lint_override,
            force_overwrite_hand_edits,
        }) => run_inject(Cli {
            command: None,
            path: Some(path),
            grafts,
            exclude,
            lib_dir,
            accept_untrusted_libs: cli.accept_untrusted_libs,
            list: false,
            json: false,
            dry_run: false,
            apply,
            no_migrate,
            lint_override,
            force_overwrite_hand_edits,
            quiet: cli.quiet,
        }),
        Some(Command::List {
            lib_dir,
            exclude,
            json,
        }) => run_inject(Cli {
            command: None,
            path: None,
            grafts: Vec::new(),
            exclude,
            lib_dir,
            accept_untrusted_libs: cli.accept_untrusted_libs,
            list: true,
            json,
            dry_run: false,
            apply: false,
            no_migrate: false,
            lint_override: Vec::new(),
            force_overwrite_hand_edits: false,
            quiet: cli.quiet,
        }),
        Some(Command::Lint {
            path,
            lib_dir,
            json,
            lint_override,
        }) => run_lint(&path, &lib_dir, json, &lint_override),
        Some(Command::Doctor {
            path,
            lib_dir,
            json,
            format,
            lint_override,
        }) => run_doctor(&path, &lib_dir, json, format, &lint_override),
        Some(Command::Update {
            path,
            lib_dir,
            yes,
        }) => run_update(&path, &lib_dir, yes),
        Some(Command::Codegen { target }) => match target {
            CodegenTarget::KernelCauseTags {
                path,
                lib_dir,
                out,
                json,
            } => run_codegen_kernel_cause_tags(&path, &lib_dir, out.as_deref(), json),
            CodegenTarget::HarnessMethods {
                bindings,
                lib_dir,
                out,
            } => run_codegen_harness_methods(&bindings, &lib_dir, out.as_deref()),
        },
        Some(Command::RenameKernel {
            new_name,
            from,
            apply,
        }) => run_rename_kernel(&new_name, from.as_deref(), apply),
        Some(Command::Completions { shell }) => {
            // Stream the script to stdout. Bin name is hard-coded to
            // the published install name so a default invocation
            // produces a working script; sed-rename to `graft-inject`
            // covers the legacy-alias case.
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "nockup-graft", &mut std::io::stdout());
            Ok(())
        }
        None => {
            // Legacy bare-invocation back-compat. The user typed
            // `graft-inject <PATH> ...` or `graft-inject --list ...`
            // without naming a subcommand; emit a deprecation hint
            // unless this is a help-style invocation with nothing to do.
            if cli.list {
                eprintln!(
                    "graft-inject: --list is deprecated; use \
                     `graft-inject list` instead."
                );
            } else if cli.path.is_some() {
                eprintln!(
                    "graft-inject: bare-invocation is deprecated; use \
                     `graft-inject inject <PATH>` instead."
                );
            }
            run_inject(cli)
        }
    }
}

/// Locate the project root by walking up from `start` until a directory
/// containing `nockapp.toml` is found. Mirrors `has_nockapp_toml_ancestor`
/// but returns the path so callers can read/write files relative to it.
pub(crate) fn find_project_root(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start);
    while let Some(dir) = cur {
        if dir.join("nockapp.toml").is_file() {
            return Some(dir.to_path_buf());
        }
        cur = dir.parent();
    }
    None
}

pub(crate) fn run_inject(cli: Cli) -> Result<()> {
    let grafts = select_grafts(&cli)?;

    if cli.list {
        emit_list(&grafts, cli.json);
        return Ok(());
    }

    // Manifest-schema handshake: refuse to compose against a manifest
    // authored for a newer nockup-graft than this binary models. An
    // unmodelled schema would be mis-composed silently, so bail before
    // any bytes render — `--list` (handled above) stays non-erroring.
    if let Some(skew) = check_schema_compat(&grafts).first() {
        bail!(
            "manifest schema too new: graft `{}` targets schema_version {} \
             but this nockup-graft supports up to {}.\n  \
             Update the binary: cargo install --git \
             https://github.com/zkvesl/vesl-nockup --bin nockup-graft --force",
            skew.graft,
            skew.manifest_version,
            skew.binary_version,
        );
    }

    let path = cli.path.as_ref().ok_or_else(|| {
        anyhow!("missing target path (or use --list to enumerate discovered grafts)")
    })?;
    // Require the target to be a Hoon source
    // file. A mistyped argument (e.g. `graft-inject README.md`) would
    // otherwise inject Hoon into whatever happened to contain a marker
    // pattern — useful only for shooting feet.
    match path.extension().and_then(|e| e.to_str()) {
        Some("hoon") => {}
        Some(other) => bail!(
            "target {} has extension `.{}`; refusing to inject Hoon into a non-.hoon file",
            path.display(),
            other,
        ),
        None => bail!(
            "target {} has no file extension; refusing to inject Hoon into a non-.hoon file",
            path.display(),
        ),
    }
    let raw_source = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;

    // Optional auto-migration of legacy `+$ effect *` to the marker
    // shape. Runs before the inject pass so the codegen can take over
    // the rewritten line in the same `--apply` invocation.
    let (source, migration) = if cli.no_migrate {
        (raw_source, MigrationReport::skipped())
    } else {
        migrate_legacy_effect(&raw_source)
    };
    print_migration_line(&migration);

    // Resolve the per-lint policy once: walk up for nockapp.toml,
    // apply its `[lint]` table, then apply `--lint-override` flags on
    // top. CLI > config > per-variant default.
    let mut policy = LintPolicy::load_from_project(path)?;
    policy.apply_cli_overrides(&cli.lint_override)?;
    for w in policy.warnings() {
        eprintln!("graft-inject: {w}");
    }

    // Pre-inject structural lints. Each pass is independent of compose;
    // gating up front lets the printer surface a unified report before
    // any bytes change. `--apply` refuses the write on any
    // error-tier finding — composing the file is the step that turns
    // these silent-fail surfaces into corrupt output.
    let pre_lines: Vec<String> = source.lines().map(String::from).collect();
    let mut pre_findings: Vec<LintFinding> = Vec::new();
    pre_findings.extend(lint_bare_tilde_ambiguity(&pre_lines));
    pre_findings.extend(lint_collision_check(&grafts, &pre_lines));
    pre_findings.extend(lint_transitive_imports(path, &cli.lib_dir));
    pre_findings.extend(lint_unresolved_cause_references(&grafts, &pre_lines));
    gate_inject_lint_findings(&pre_findings, path, cli.apply, &policy)?;

    // Pre-inject hand-edit gate. Re-uses `doctor`'s check_hand_edits so
    // a banner-bounded body whose content drifted from its manifest is
    // detected before it gets silently overwritten. `--apply` is the
    // only step that does the overwriting, so preview runs surface the
    // findings without bailing. `--force-overwrite-hand-edits` is the
    // explicit "yes, roll the customization back to canonical" opt-in.
    let hand_edits = check_hand_edits(path, &source, &grafts);
    if !hand_edits.is_empty() {
        emit_doctor_human(path, &hand_edits);
        if cli.apply && !cli.force_overwrite_hand_edits {
            bail!(
                "refusing to write {}: {} hand-edited block(s) above would be \
                 overwritten. Move the customization out of the banner pair, \
                 or pass --force-overwrite-hand-edits to roll back to canonical.",
                path.display(),
                hand_edits.len(),
            );
        }
    }

    let (output, report) = inject(&source, &grafts)
        .with_context(|| format!("injecting into {}", path.display()))?;

    // Refuse a partial compose: a graft contributing a block for an
    // absent marker would have that block silently dropped.
    enforce_markers_placeable(&report, path)?;

    // Internal-dupe scan runs on the composed output — the lint reads
    // the literal cause-union and state-record shapes, which only
    // settle into their final form after inject runs.
    let post_lines: Vec<String> = output.lines().map(String::from).collect();
    let post_findings: Vec<LintFinding> = lint_internal_dupes(&post_lines);
    gate_inject_lint_findings(&post_findings, path, cli.apply, &policy)?;

    if cli.dry_run {
        eprintln!(
            "graft-inject: --dry-run is deprecated; preview is the default. \
             Pass --apply to write."
        );
    }

    // Preview by default, `--apply` to write. The
    // preview prints composed Hoon to stdout and a sha256 summary to
    // stderr so reviewers can see both the exact output and which
    // manifests produced it before any bytes hit disk.
    if cli.apply {
        if output != source {
            atomic_write(path, &output)
                .with_context(|| format!("writing {}", path.display()))?;
            eprintln!();
            eprintln!(
                "graft-inject: wrote {}. out.jam is now stale — recompile before",
                path.display(),
            );
            eprintln!("  `cargo build`, or the build links the previous kernel:");
            eprintln!(
                "    honk --new --output out.jam --prelude hoon/common/hoon.hoon {} hoon \
      && [ -s out.jam ] || (echo 'honk produced no out.jam' >&2; exit 1)",
                path.display(),
            );
        }
    } else {
        print!("{output}");
    }

    print_report(path, &report, &grafts, cli.apply, &policy);
    if report.markers_in_source.is_empty() {
        bail!(
            "no nockup markers found in {}; nothing to wire",
            path.display()
        );
    }
    Ok(())
}

/// Surface a set of structural lint findings on stderr and gate the
/// inject write on them. The header line + `print_lint_findings` are
/// always emitted; the bail only fires under `--apply` AND when at
/// least one finding is at [`LintSeverity::Error`] (preview mode and
/// warning-only findings never refuse the write). The error message
/// enumerates the unique error-tier kinds that tripped so the err
/// string is self-explanatory in CI logs without re-reading stderr.
fn gate_inject_lint_findings(
    findings: &[LintFinding],
    path: &Path,
    apply: bool,
    policy: &crate::lint::LintPolicy,
) -> Result<()> {
    if findings.is_empty() {
        return Ok(());
    }
    eprintln!("graft-inject: {}", summarize_severity(findings, policy));
    print_lint_findings(findings, path, policy);
    if !apply {
        return Ok(());
    }
    let error_kinds: Vec<&str> = {
        let mut k: Vec<&str> = findings
            .iter()
            .filter(|f| policy.effective(f) == LintSeverity::Error)
            .map(LintFinding::kind_label)
            .collect();
        k.sort();
        k.dedup();
        k
    };
    if error_kinds.is_empty() {
        // Warnings / notes only — surface but don't gate.
        return Ok(());
    }
    let error_count = findings
        .iter()
        .filter(|f| policy.effective(f) == LintSeverity::Error)
        .count();
    bail!(
        "refusing to write {}: resolve the {} error-level lint finding(s) above first ({})",
        path.display(),
        error_count,
        error_kinds.join(", "),
    );
}

/// Resolve the effective graft set per CLI flags. `--grafts` is explicit
/// (must name discovered grafts; unknown names hard-error). Otherwise
/// discover all manifests under `--lib-dir` and subtract `--exclude`.
pub(crate) fn select_grafts(cli: &Cli) -> Result<Vec<Graft>> {
    if !cli.lib_dir.is_dir() {
        bail!(
            "lib-dir {} does not exist or is not a directory",
            cli.lib_dir.display()
        );
    }
    check_lib_dir_trust(&cli.lib_dir, cli.accept_untrusted_libs)?;
    let mut discovered = discover_grafts(&cli.lib_dir)
        .with_context(|| format!("discovering grafts under {}", cli.lib_dir.display()))?;
    if discovered.is_empty() {
        bail!(
            "no grafts discovered under {}; expected at least one *.toml with a [graft] table",
            cli.lib_dir.display()
        );
    }

    if !cli.grafts.is_empty() {
        let known: HashSet<&str> = discovered.iter().map(|g| g.name.as_str()).collect();
        let mut selected: Vec<Graft> = Vec::new();
        for name in &cli.grafts {
            if !known.contains(name.as_str()) {
                bail!(
                    "unknown graft `{name}` (discovered: {})",
                    discovered
                        .iter()
                        .map(|g| g.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            // Keep CLI ordering for the explicit form.
            let g = discovered
                .iter()
                .find(|g| g.name == *name)
                .expect("checked above")
                .clone();
            selected.push(g);
        }
        return Ok(selected);
    }

    if !cli.exclude.is_empty() {
        let exclude: HashSet<&str> = cli.exclude.iter().map(String::as_str).collect();
        discovered.retain(|g| !exclude.contains(g.name.as_str()));
        if discovered.is_empty() {
            eprintln!("graft-inject: warning — all discovered grafts were excluded");
        }
    }
    Ok(discovered)
}

pub(crate) fn emit_list(grafts: &[Graft], json: bool) {
    if json {
        let summaries: Vec<GraftSummary> = grafts.iter().map(GraftSummary::from_graft).collect();
        let s = serde_json::to_string_pretty(&summaries)
            .expect("GraftSummary always serializes");
        println!("{s}");
        return;
    }
    if grafts.is_empty() {
        println!("(no grafts discovered)");
        return;
    }
    for g in grafts {
        let summary = GraftSummary::from_graft(g);
        println!(
            "  {:<16} {:<8} priority={:<3} ({})",
            summary.name,
            summary.version,
            summary.priority,
            summary.blocks.join(", ")
        );
    }
}

/// Print the per-graft injection report to stderr. stderr (not stdout)
/// so preview users can pipe the rendered file out cleanly. Includes the
/// per-manifest sha256 so supply-chain reviewers can confirm what's
/// about to be composed.
pub(crate) fn print_report(
    path: &Path,
    report: &InjectReport,
    grafts: &[Graft],
    applied: bool,
    policy: &crate::lint::LintPolicy,
) {
    eprintln!("graft-inject: {}", path.display());
    let sha_by_name: HashMap<&str, &str> = grafts
        .iter()
        .map(|g| (g.name.as_str(), g.sha256.as_str()))
        .collect();
    let mut had_output = false;
    for g in &report.grafts {
        if g.applicable.is_empty() {
            continue;
        }
        had_output = true;
        let injected_labels: Vec<&str> =
            g.injected.iter().map(|m| m.label()).collect();
        let skipped_labels: Vec<&str> =
            g.skipped.iter().map(|m| m.label()).collect();
        let sha = sha_by_name
            .get(g.name.as_str())
            .copied()
            .unwrap_or("(sha unavailable)");
        // First 12 hex chars are enough to eyeball; full digest goes in
        // --list --json for machine-readable audits.
        let short = &sha[..sha.len().min(12)];
        let mut summary = format!(
            "  {:<16} sha256:{short} injected {}/{}",
            g.name,
            g.injected.len(),
            g.applicable.len()
        );
        if !injected_labels.is_empty() {
            summary.push_str(&format!(" ({})", injected_labels.join(", ")));
        }
        if !skipped_labels.is_empty() {
            summary.push_str(&format!("; skipped {}", skipped_labels.join(", ")));
        }
        if !g.pruned.is_empty() {
            // A graft can both be in the active set AND have
            // had stale orphan markers (from a partial prior run). Surface
            // both states on the same line.
            let pruned_labels: Vec<&str> = g.pruned.iter().map(|m| m.label()).collect();
            summary.push_str(&format!("; pruned {}", pruned_labels.join(", ")));
        }
        eprintln!("{summary}");
    }
    // Orphan grafts (banner pairs present in source but graft
    // dropped from --grafts) carry no manifest, so they live on a separate
    // carrier. Surface them so the user sees the drop confirmed.
    for g in &report.pruned_grafts {
        had_output = true;
        let pruned_labels: Vec<&str> = g.pruned.iter().map(|m| m.label()).collect();
        eprintln!(
            "  {:<16} no-manifest    pruned {}/{} ({}) (orphan blocks from previous injection)",
            g.name,
            g.pruned.len(),
            g.applicable.len(),
            pruned_labels.join(", ")
        );
    }
    if !had_output {
        eprintln!("  (no grafts contributed)");
    }
    let present_labels: Vec<&str> = report
        .markers_in_source
        .iter()
        .map(|m| m.label())
        .collect();
    let missing_labels: Vec<&str> = report
        .markers_missing
        .iter()
        .map(|m| m.label())
        .collect();
    // Use `applicable` (not `injected`) so the count is stable across `--apply` reruns.
    let populated_labels: Vec<&str> = report
        .markers_in_source
        .iter()
        .filter(|m| report.grafts.iter().any(|g| g.applicable.contains(m)))
        .map(|m| m.label())
        .collect();
    eprintln!(
        "  markers in source: {} ({})",
        present_labels.len(),
        present_labels.join(", ")
    );
    eprintln!(
        "  markers populated: {} ({})",
        populated_labels.len(),
        populated_labels.join(", ")
    );
    if !missing_labels.is_empty() {
        eprintln!(
            "  warning — markers not found: {}",
            missing_labels.join(", ")
        );
    }
    print_codegen_line(&report.codegen);
    print_lint_findings(&report.weld_lint, path, policy);
    if !applied {
        eprintln!("  (preview only — pass --apply to write {})", path.display());
    }
}

/// One-line stderr surface for the typed effect-union codegen pass.
/// Skipped: silent on success-path silence (every kernel without the
/// marker would otherwise spam this line). Inserted/Replaced/Unchanged:
/// announce variant count + names so reviewers can confirm the union
/// matches the active graft set without re-reading the kernel.
fn print_codegen_line(report: &CodegenReport) {
    let label = match report.status {
        CodegenStatus::Skipped => {
            eprintln!(
                "  effect-union codegen: skipped (no nockup:effect-union marker; cast/weld friction remains)"
            );
            return;
        }
        CodegenStatus::Inserted => "inserted",
        CodegenStatus::Replaced => "replaced",
        CodegenStatus::Unchanged => "unchanged",
    };
    eprintln!(
        "  effect-union codegen: {label} ({} variant{}: {})",
        report.variants.len(),
        if report.variants.len() == 1 { "" } else { "s" },
        report.variants.join(", "),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use clap::Parser;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn cli_with(lib_dir: PathBuf) -> Cli {
        Cli {
            command: None,
            path: None,
            grafts: Vec::new(),
            exclude: Vec::new(),
            lib_dir,
            accept_untrusted_libs: true,
            list: false,
            json: false,
            dry_run: false,
            apply: false,
            no_migrate: false,
            lint_override: Vec::new(),
            force_overwrite_hand_edits: false,
            quiet: false,
        }
    }

    // ---------- CLI parse ----------

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

    /// `graft-inject inject` (no positional) resolves to the template
    /// scaffold's canonical kernel path so a bare invocation inside a
    /// project Just Works. Out-of-project, the path falls through to
    /// the same "file not found" diagnostic any explicit miss would
    /// produce — clap doesn't error here.
    #[test]
    fn cli_inject_defaults_path_to_scaffold_kernel() {
        let cli = Cli::try_parse_from(["graft-inject", "inject"])
            .expect("inject with no PATH must parse via default");
        match cli.command {
            Some(Command::Inject { path, .. }) => {
                assert_eq!(path, PathBuf::from("hoon/app/app.hoon"));
            }
            other => panic!("expected Command::Inject, got {other:?}"),
        }
    }

    /// `graft-inject lint` — same default-path contract as `inject`.
    #[test]
    fn cli_lint_defaults_path_to_scaffold_kernel() {
        let cli = Cli::try_parse_from(["graft-inject", "lint"])
            .expect("lint with no PATH must parse via default");
        match cli.command {
            Some(Command::Lint { path, .. }) => {
                assert_eq!(path, PathBuf::from("hoon/app/app.hoon"));
            }
            other => panic!("expected Command::Lint, got {other:?}"),
        }
    }

    /// `graft-inject doctor` — same default-path contract as `inject`.
    /// Closes the bare-invocation friction the sandbox-build DX eval
    /// flagged on doctor specifically.
    #[test]
    fn cli_doctor_defaults_path_to_scaffold_kernel() {
        let cli = Cli::try_parse_from(["graft-inject", "doctor"])
            .expect("doctor with no PATH must parse via default");
        match cli.command {
            Some(Command::Doctor { path, .. }) => {
                assert_eq!(path, PathBuf::from("hoon/app/app.hoon"));
            }
            other => panic!("expected Command::Doctor, got {other:?}"),
        }
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

    /// `inject --apply` on a kernel whose domain `?-` arm body ends in a
    /// bare `~` line must refuse to write — the peek-chain emitter would
    /// otherwise splice the chain into the poke body and corrupt the file.
    #[test]
    fn inject_apply_refuses_bare_tilde_ambiguity() {
        let dir = tempdir_with_two_manifests("bare_tilde_refuse");
        let kernel = dir.join("app.hoon");
        fs::write(
            &kernel,
            "?-  -.u.act\n    %ping\n  :_  state\n  ^-  (list effect)\n  ~\n==\n",
        )
        .unwrap();
        let before = fs::read_to_string(&kernel).unwrap();
        let mut cli = cli_with(dir.clone());
        cli.path = Some(kernel.clone());
        cli.apply = true;
        let err = run_inject(cli).expect_err("bare-tilde + --apply must refuse");
        assert!(
            err.to_string().contains("bare-tilde"),
            "error should name the bare-tilde ambiguity, got: {err}"
        );
        assert_eq!(
            fs::read_to_string(&kernel).unwrap(),
            before,
            "the file must be untouched after a refused --apply",
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// `inject --apply` refuses to write when the structural collision
    /// lint fires — two grafts declaring the same `%<tag>` poke arm
    /// would compose into a duplicate-headed cause union. The kernel
    /// file must be untouched after the refused write, and the error
    /// must surface the `LintFinding::Collision` variant via its kind
    /// label.
    #[test]
    fn inject_apply_refuses_collision() {
        let dir = tempdir_for_test("collision_refuse");
        // Two synthetic manifests that both declare `%shared-tag`.
        let alpha_toml = r#"[graft]
name     = "alpha-graft"
version  = "0.1.0"
priority = 50

[graft.blocks.poke]
body = """
::
  %shared-tag
[~ state]"""
"#;
        let beta_toml = r#"[graft]
name     = "beta-graft"
version  = "0.1.0"
priority = 60

[graft.blocks.poke]
body = """
::
  %shared-tag
[~ state]"""
"#;
        fs::write(dir.join("alpha-graft.toml"), alpha_toml).unwrap();
        fs::write(dir.join("beta-graft.toml"), beta_toml).unwrap();

        // Minimal kernel with the poke marker so enforce_markers_placeable
        // doesn't preempt the collision gate.
        let kernel = dir.join("app.hoon");
        fs::write(&kernel, "?-  -.u.act\n  ::  nockup:poke\n  [~ state]\n==\n").unwrap();
        let before = fs::read_to_string(&kernel).unwrap();

        let mut cli = cli_with(dir.clone());
        cli.path = Some(kernel.clone());
        cli.apply = true;
        let err = run_inject(cli).expect_err("collision + --apply must refuse");
        assert!(
            err.to_string().contains("collision"),
            "error should name the collision kind, got: {err}"
        );
        assert_eq!(
            fs::read_to_string(&kernel).unwrap(),
            before,
            "the file must be untouched after a refused --apply",
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// `inject --apply` refuses to write when the kernel's `+$ cause`
    /// union cites a sub-cause-type no manifest in the active set
    /// declares. Today this kind of orphan reference reaches hoonc as
    /// `find . <name>-cause`; the structural gate surfaces it with the
    /// referenced type name + file path before composing.
    #[test]
    fn inject_apply_refuses_unresolved_cause_reference() {
        let dir = tempdir_for_test("unresolved_cause_refuse");
        // Synthetic manifest that doesn't declare `[graft.types].cause`.
        let toml = r#"[graft]
name     = "lone-graft"
version  = "0.1.0"
priority = 50

[graft.blocks.poke]
body = """
::
  %lone-do
[~ state]"""
"#;
        fs::write(dir.join("lone-graft.toml"), toml).unwrap();

        // Kernel cites `phantom-cause` from its `+$ cause` union — no
        // graft declares `[graft.types].cause = "phantom-cause"`, so the
        // reference is orphan.
        let kernel = dir.join("app.hoon");
        let source = "+$  cause\n  $%  [%cause ~]\n      phantom-cause\n      ::  nockup:cause\n  ==\n?-  -.u.act\n  ::  nockup:poke\n  [~ state]\n==\n";
        fs::write(&kernel, source).unwrap();
        let before = fs::read_to_string(&kernel).unwrap();

        let mut cli = cli_with(dir.clone());
        cli.path = Some(kernel.clone());
        cli.apply = true;
        let err = run_inject(cli).expect_err("unresolved cause-reference + --apply must refuse");
        assert!(
            err.to_string().contains("unresolved-cause-reference"),
            "error should name the unresolved-cause-reference kind, got: {err}"
        );
        assert_eq!(
            fs::read_to_string(&kernel).unwrap(),
            before,
            "the file must be untouched after a refused --apply",
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A project with `[lint] transitive-imports = "warn"` in
    /// `nockapp.toml` demotes the transitive-imports lint below the
    /// `--apply` gate. The finding still surfaces (preview prints + the
    /// summary line counts it as a warning), but the write proceeds.
    #[test]
    fn inject_apply_policy_demotes_to_warn() {
        let dir = tempdir_for_test("policy_demote");
        // Project markers: nockapp.toml at the root so the policy
        // loader picks up the `[lint]` table.
        fs::write(
            dir.join("nockapp.toml"),
            "[project]\nkernel_name = \"app\"\n\n[lint]\ntransitive-imports = \"warn\"\n",
        )
        .unwrap();
        // Minimal kernel with an unsatisfied `/+ lib` import (no
        // lib.hoon written) — would normally trip the structural gate.
        // Add one nockup marker so `run_inject` doesn't bail on
        // "no nockup markers found" before the gate fires.
        let kernel = dir.join("app.hoon");
        fs::write(&kernel, "/+  lib\n::  nockup:imports\n").unwrap();

        // A synthetic graft so select_grafts doesn't bail on an empty
        // lib_dir. The graft contributes no blocks the kernel marker
        // would need to place.
        fs::write(
            dir.join("noop-graft.toml"),
            r#"[graft]
name     = "noop-graft"
version  = "0.1.0"
priority = 50

[graft.blocks]
"#,
        )
        .unwrap();

        let mut cli = cli_with(dir.clone());
        cli.path = Some(kernel.clone());
        cli.grafts = vec!["noop-graft".to_string()];
        cli.apply = true;
        // `--apply` succeeds because the only finding is a warning
        // under the demoting policy.
        run_inject(cli).expect("warn-only finding must not gate --apply");
        let _ = fs::remove_dir_all(&dir);
    }

    /// `inject` refuses when an active graft contributes a block for a
    /// marker absent from the file — the block would be silently dropped.
    #[test]
    fn inject_refuses_when_a_graft_block_has_no_marker() {
        let dir = tempdir_with_two_manifests("missing_marker");
        let kernel = dir.join("app.hoon");
        // Only the imports marker is present; settle-graft also needs
        // state / cause / poke / peek markers.
        fs::write(&kernel, "::  nockup:imports\n").unwrap();
        let mut cli = cli_with(dir.clone());
        cli.path = Some(kernel.clone());
        cli.grafts = vec!["settle-graft".to_string()];
        let err = run_inject(cli).expect_err("a graft block with no marker must refuse");
        assert!(
            err.to_string().contains("could not be placed"),
            "error should explain the unplaceable block, got: {err}"
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
        // The default is preview-only. Without
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
        // --apply is the explicit write-enabler.
        let dir = tempdir_with_two_manifests("apply_writes");
        // Stub the `/+ lib` target so the transitive-imports lint
        // doesn't fire on the scaffold's illustrative library import.
        // The `/= * /common/wrapper` line is stripped from the scaffold
        // because the resolver would look for it under lib_dir.parent(),
        // which in this flat tempdir layout lives outside the test root.
        fs::write(dir.join("lib.hoon"), "").unwrap();
        let kernel_source = BARE_SCAFFOLD.replace("/=  *  /common/wrapper\n", "");
        let target = dir.join("app.hoon");
        fs::write(&target, &kernel_source).unwrap();

        let mut cli = cli_with(dir.clone());
        cli.path = Some(target.clone());
        cli.grafts = vec!["settle-graft".to_string()];
        cli.apply = true;
        run_inject(cli).unwrap();

        let after = fs::read_to_string(&target).unwrap();
        assert_ne!(after, kernel_source, "--apply must modify the file");
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
        // `sha256` is additive per the
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
        assert_eq!(first["version"], "0.2.0");
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
}
