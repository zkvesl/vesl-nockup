//! Pre/post-inject lint suite: weld-friction, bare-tilde ambiguity,
//! collision check, transitive imports, internal dupes,
//! unresolved-cause references.
//!
//! Every lint produces the same type — [`LintFinding`], with one
//! variant per lint. Consumers (`run_lint`, `run_inject`, the inject
//! report) route through a single pattern-match instead of branching on
//! five wrapper structs. Each lint function returns
//! `Vec<LintFinding>`; the unified printer ([`print::print_lint_findings`])
//! groups by [`LintFinding::kind_label`] and emits the per-lint
//! remediation hint blocks verbatim.
//!
//! Codegen consumes a couple of helpers here (`CauseUnionMember`,
//! `extract_cause_union_members`, `extract_graft_cause_tags`) because
//! its cause-tag set composition is the same shape as the lint's
//! cross-reference. There's no other coupling.
//!
//! Module layout:
//! - [`extract`] — shared graft / domain extractors + the
//!   [`CauseUnionMember`] type.
//! - [`weld_friction`], [`bare_tilde`], [`collision`],
//!   [`transitive_imports`], [`internal_dupes`], [`unresolved_cause`]
//!   — one file per lint pass; each owns its lint function plus the
//!   JSON projection record (when one applies) and the kind-specific
//!   discriminator enum (collision / internal-dupe).
//! - [`print`] — unified stderr printer + per-kind remediation hints.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::manifest::discover_grafts;

mod bare_tilde;
mod collision;
mod extract;
mod internal_dupes;
mod print;
mod transitive_imports;
mod unresolved_cause;
mod weld_friction;

pub(crate) use bare_tilde::lint_bare_tilde_ambiguity;
pub(crate) use collision::{CollisionKind, lint_collision_check};
pub(crate) use extract::{
    CauseUnionMember, extract_cause_union_members, extract_graft_cause_tags,
};
pub(crate) use internal_dupes::{InternalDupeKind, lint_internal_dupes};
pub(crate) use print::print_lint_findings;
pub(crate) use transitive_imports::lint_transitive_imports;
pub(crate) use unresolved_cause::lint_unresolved_cause_references;
pub(crate) use weld_friction::lint_weld_friction;

use bare_tilde::BareTildeRecord;
use collision::CollisionRecord;
use internal_dupes::InternalDupeRecord;
use transitive_imports::TransitiveImportRecord;
use unresolved_cause::UnresolvedCauseReferenceRecord;

// ---------------------------------------------------------------
// Unified finding type
// ---------------------------------------------------------------

/// One lint finding. Variants absorb the fields of the per-lint shapes
/// the wrapper structs used to carry; consumers pattern-match on the
/// variant and read the inner fields directly. The sub-discriminator
/// enums [`CollisionKind`] and [`InternalDupeKind`] stay as nested
/// fields so the JSON projection keeps its existing key shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LintFinding {
    /// Narrow effect binding in domain code — `(list <graft>-effect)`
    /// will nest-fail at any cross-graft `weld`. Advisory: surfaces
    /// during compose but does not gate the write.
    WeldFriction {
        /// 1-indexed line number of the narrow binding.
        line: usize,
        /// Trimmed line text — short enough to copy-paste into a search.
        text: String,
        /// The narrow type referenced, e.g., `counter-effect`.
        narrow_type: String,
    },
    /// Domain `?-` arm body ends with a bare `~` line; the composer's
    /// chain rebuilder may mistake it for the peek terminator and
    /// splice the peek chain into the poke body.
    BareTildeAmbiguity {
        /// 1-indexed line number of the bare `~`.
        line: usize,
        /// Domain arm tag (e.g. "ping") whose body ends in the bare `~`.
        arm: String,
    },
    /// Two grafts (or a graft + the domain) declare the same cause
    /// tag or state field — composes into a duplicate-headed union /
    /// record.
    Collision {
        kind: CollisionKind,
        /// The colliding name (`enqueue-job`, `entries`, ...).
        name: String,
        /// Owners that declared the name. `(domain)` represents the
        /// app.hoon domain code; everything else is a graft name.
        owners: Vec<String>,
    },
    /// A `.hoon` file imports a name whose target does not exist on
    /// disk under the resolved root — hoonc would later silently fail
    /// when it eager-parses `hoon/common/`.
    TransitiveImport {
        /// `.hoon` file that owns the unsatisfied import.
        source: PathBuf,
        /// Rune ("/+", "/=", "/-", "/#").
        rune: String,
        /// Import name (or `/=` bind name).
        name: String,
        /// Expected resolution path that doesn't exist on disk.
        target: PathBuf,
        /// Chain of files traversed to reach `source`. Empty when
        /// `source` is a top-level seed (the input root or a
        /// hoon/common/ entry).
        reachable_from: Vec<PathBuf>,
    },
    /// Literal duplicate variant head inside the composed `+$ cause`
    /// union, or duplicate field name inside `+$ versioned-state`.
    /// Catches the post-injection graft+graft dupe that the manifest-
    /// side collision lint can miss.
    InternalDupe {
        kind: InternalDupeKind,
        /// Duplicate name (`enqueue-job`, `entries`, ...).
        name: String,
        /// 1-indexed line numbers of every occurrence (sorted).
        lines: Vec<usize>,
    },
    /// The kernel's `+$ cause $%(...)` cites a sub-cause-type
    /// (e.g. `settle-cause`) that no graft's `[graft.types].cause`
    /// declares in the active set. Today the cause-tag codegen
    /// silently drops the contribution and hoonc surfaces the
    /// failure as `find . <name>-cause`.
    UnresolvedCauseReference {
        /// 1-indexed line of the reference inside the kernel's
        /// `+$ cause` union.
        line: usize,
        /// The cause-type name the union references.
        name: String,
    },
}

impl LintFinding {
    /// Stable kind label used by the unified printer's per-finding line
    /// prefix and the JSON schema's per-kind key. Identifier-style; the
    /// labels match the existing JSON schema keys.
    pub(crate) fn kind_label(&self) -> &'static str {
        match self {
            LintFinding::WeldFriction { .. } => "weld-friction",
            LintFinding::BareTildeAmbiguity { .. } => "bare-tilde-ambiguity",
            LintFinding::Collision { .. } => "collision",
            LintFinding::TransitiveImport { .. } => "transitive-imports",
            LintFinding::InternalDupe { .. } => "internal-dupes",
            LintFinding::UnresolvedCauseReference { .. } => "unresolved-cause-reference",
        }
    }

    /// 1-indexed source line for findings anchored on a single line.
    /// `Collision` (manifest-side, no source line), `TransitiveImport`
    /// (resolution failure spans files), and `InternalDupe` (multi-
    /// line) carry no single line number and return `None`.
    #[allow(dead_code)]
    pub(crate) fn line(&self) -> Option<usize> {
        match self {
            LintFinding::WeldFriction { line, .. }
            | LintFinding::BareTildeAmbiguity { line, .. }
            | LintFinding::UnresolvedCauseReference { line, .. } => Some(*line),
            LintFinding::Collision { .. }
            | LintFinding::TransitiveImport { .. }
            | LintFinding::InternalDupe { .. } => None,
        }
    }

    /// Default severity tier per variant. The printer routes the word
    /// (`error: ...`, `warning: ...`, `note: ...`) and the inject /
    /// `lint` drivers gate on the presence of any
    /// [`LintSeverity::Error`]. Defaults match the pre-Phase-3 gate
    /// behavior: `weld-friction` was advisory-only, every other lint
    /// gated the write or exit code.
    pub(crate) fn severity(&self) -> LintSeverity {
        match self {
            LintFinding::WeldFriction { .. } => LintSeverity::Warn,
            LintFinding::BareTildeAmbiguity { .. }
            | LintFinding::Collision { .. }
            | LintFinding::TransitiveImport { .. }
            | LintFinding::InternalDupe { .. }
            | LintFinding::UnresolvedCauseReference { .. } => LintSeverity::Error,
        }
    }
}

/// Severity tier per lint finding. The printer prefixes each line with
/// the matching word (`error`, `warning`, `note`) and the inject /
/// `lint` drivers gate the write / exit-code on the presence of any
/// [`LintSeverity::Error`]. Warnings and notes surface but never gate,
/// giving the policy machinery a principled middle between the
/// pre-Phase-3 binary outcomes (advisory or hard-bail).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LintSeverity {
    Error,
    Warn,
    /// Reserved for policy overrides that demote a lint below `Warn`.
    /// No lint defaults to `Note` today — the variant exists so
    /// `[lint] <name> = "note"` is a valid config setting.
    #[allow(dead_code)]
    Note,
}

impl LintSeverity {
    /// Lower-case word the printer emits before the kind label
    /// (`error: <kind>: ...`). Matches the
    /// existing rustc / gcc convention so terminal scrapers that watch
    /// for `error:` / `warning:` markers pick the right lines.
    pub(crate) fn word(self) -> &'static str {
        match self {
            LintSeverity::Error => "error",
            LintSeverity::Warn => "warning",
            LintSeverity::Note => "note",
        }
    }

    /// Parse a config-table or CLI value (`"error"`, `"warn"`, `"note"`).
    /// Hard-errors on anything else so a typo (`"warning"`,
    /// `"warnning"`) doesn't silently degrade to the default.
    pub(crate) fn parse(s: &str) -> Result<Self> {
        match s {
            "error" => Ok(LintSeverity::Error),
            "warn" => Ok(LintSeverity::Warn),
            "note" => Ok(LintSeverity::Note),
            other => bail!(
                "unknown lint severity `{other}` — must be one of `error`, `warn`, `note`"
            ),
        }
    }
}

/// Project-scoped policy that promotes / demotes per-lint severity.
///
/// Resolution order: CLI override (`--lint-override`) wins, then the
/// `[lint]` table from the nearest `nockapp.toml`, then the per-variant
/// default in [`LintFinding::severity`]. Unknown lint names at either
/// surface hard-error so a typo (`transitive-importss`) doesn't
/// silently no-op.
#[derive(Debug, Clone, Default)]
pub(crate) struct LintPolicy {
    overrides: HashMap<&'static str, LintSeverity>,
    /// Non-fatal config warnings to surface to the operator (missing
    /// or malformed `[lint]` table that we recovered from). The
    /// caller decides where to surface — `run_inject` prints them to
    /// stderr after policy load.
    warnings: Vec<String>,
}

impl LintPolicy {
    /// Build a policy with no overrides — every lint runs at its
    /// per-variant default severity. Used when no `nockapp.toml`
    /// ancestor exists and no CLI overrides were passed.
    pub(crate) fn empty() -> Self {
        Self::default()
    }

    /// Walk upward from `kernel_path`'s parent looking for a
    /// `nockapp.toml`; when found, read its `[lint]` table and apply
    /// each entry as an override. Missing file falls back to an empty
    /// policy with no warnings. Malformed file (parse error,
    /// non-table `[lint]`) falls back to defaults with a recorded
    /// warning. Unknown lint names or invalid severities in a
    /// well-formed `[lint]` table hard-error — that's the surface that
    /// catches typos.
    pub(crate) fn load_from_project(kernel_path: &Path) -> Result<Self> {
        let start = kernel_path.parent().unwrap_or(kernel_path);
        let Some(project_root) = walk_up_for_nockapp_toml(start) else {
            return Ok(Self::empty());
        };
        let toml_path = project_root.join("nockapp.toml");
        let raw = match fs::read_to_string(&toml_path) {
            Ok(s) => s,
            Err(_) => return Ok(Self::empty()),
        };
        let value: toml::Value = match toml::from_str(&raw) {
            Ok(v) => v,
            Err(err) => {
                let mut policy = Self::empty();
                policy.warnings.push(format!(
                    "nockapp.toml at {} could not be parsed ({err}); falling back to lint defaults",
                    toml_path.display(),
                ));
                return Ok(policy);
            }
        };
        let Some(lint_section) = value.get("lint") else {
            return Ok(Self::empty());
        };
        let Some(table) = lint_section.as_table() else {
            let mut policy = Self::empty();
            policy.warnings.push(format!(
                "nockapp.toml at {}: [lint] is not a table; falling back to lint defaults",
                toml_path.display(),
            ));
            return Ok(policy);
        };

        let mut overrides: HashMap<&'static str, LintSeverity> = HashMap::new();
        for (key, val) in table {
            let kind = canonical_kind(key).ok_or_else(|| {
                anyhow::anyhow!(
                    "nockapp.toml at {}: unknown lint name `{key}` in [lint] table. \
                     Valid names: {}",
                    toml_path.display(),
                    KIND_ORDER.join(", "),
                )
            })?;
            let sev_str = val.as_str().ok_or_else(|| {
                anyhow::anyhow!(
                    "nockapp.toml at {}: [lint] `{key}` must be a string (`error`/`warn`/`note`)",
                    toml_path.display(),
                )
            })?;
            let severity = LintSeverity::parse(sev_str).with_context(|| {
                format!(
                    "nockapp.toml at {}: [lint] `{key}` value",
                    toml_path.display(),
                )
            })?;
            overrides.insert(kind, severity);
        }
        Ok(Self {
            overrides,
            warnings: Vec::new(),
        })
    }

    /// Apply CLI overrides — each entry parses as `NAME=SEVERITY`.
    /// CLI overrides win over the config file's `[lint]` table.
    /// Unknown names or invalid severities hard-error so a typo
    /// doesn't silently no-op.
    pub(crate) fn apply_cli_overrides<S: AsRef<str>>(
        &mut self,
        args: &[S],
    ) -> Result<()> {
        for arg in args {
            let raw = arg.as_ref();
            let Some((name, sev_str)) = raw.split_once('=') else {
                bail!(
                    "--lint-override `{raw}` must be `NAME=SEVERITY` \
                     (e.g. `--lint-override weld-friction=error`)"
                );
            };
            let kind = canonical_kind(name).ok_or_else(|| {
                anyhow::anyhow!(
                    "--lint-override `{raw}`: unknown lint name `{name}`. \
                     Valid names: {}",
                    KIND_ORDER.join(", "),
                )
            })?;
            let severity = LintSeverity::parse(sev_str)
                .with_context(|| format!("--lint-override `{raw}`"))?;
            self.overrides.insert(kind, severity);
        }
        Ok(())
    }

    /// Resolve the effective severity for `finding`: the override
    /// when one is set, otherwise the per-variant default.
    pub(crate) fn effective(&self, finding: &LintFinding) -> LintSeverity {
        self.overrides
            .get(finding.kind_label())
            .copied()
            .unwrap_or_else(|| finding.severity())
    }

    /// Resolve the effective severity for `kind` against `default`.
    /// Used by the doctor surface to list per-lint policy without a
    /// concrete finding in hand.
    pub(crate) fn effective_for_default(
        &self,
        kind: &str,
        default: LintSeverity,
    ) -> LintSeverity {
        self.overrides.get(kind).copied().unwrap_or(default)
    }

    /// Borrow the recorded config-load warnings (malformed
    /// nockapp.toml, [lint] not a table). Caller decides where to
    /// surface — `run_inject` and `run_lint` print each to stderr
    /// after policy load.
    pub(crate) fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

/// Canonical order of lint kinds used by the printer, the doctor
/// surface, and the policy-loader's error messages. Adding a new lint
/// kind: append it here, add a [`LintFinding`] variant, and add a
/// dispatch arm in [`default_severity_table`].
pub(super) const KIND_ORDER: &[&str] = &[
    "weld-friction",
    "bare-tilde-ambiguity",
    "collision",
    "transitive-imports",
    "internal-dupes",
    "unresolved-cause-reference",
];

/// Match a key (from config or CLI) against the canonical kind labels.
/// Returns the `&'static str` so the policy map can use it as a key.
fn canonical_kind(name: &str) -> Option<&'static str> {
    KIND_ORDER.iter().copied().find(|k| *k == name)
}

/// Walk upward from `start` for the nearest directory carrying a
/// `nockapp.toml`. Returns that directory; `None` when the walk
/// reaches the filesystem root without finding one.
fn walk_up_for_nockapp_toml(start: &Path) -> Option<PathBuf> {
    let canonical = start.canonicalize().ok();
    let mut cur: Option<&Path> = canonical.as_deref().or(Some(start));
    while let Some(dir) = cur {
        if dir.join("nockapp.toml").is_file() {
            return Some(dir.to_path_buf());
        }
        cur = dir.parent();
    }
    None
}

// ---------------------------------------------------------------
// JSON projection (`run_lint --json`)
// ---------------------------------------------------------------

/// Per-kind JSON projection — keys + record shape match the historic
/// `LintReport` schema for the four pre-existing lints
/// (`bare_tilde_ambiguity`, `collision`, `transitive_imports`,
/// `internal_dupes`). New keys are additive only: a future caller
/// pinned to the legacy schema sees its keys unchanged. Weld-friction
/// is not part of the lint subcommand JSON (it ships through the
/// inject report's stderr).
#[derive(Serialize, Default)]
pub(crate) struct LintReport<'a> {
    bare_tilde_ambiguity: Vec<BareTildeRecord<'a>>,
    collision: Vec<CollisionRecord<'a>>,
    transitive_imports: Vec<TransitiveImportRecord<'a>>,
    internal_dupes: Vec<InternalDupeRecord<'a>>,
    unresolved_cause_references: Vec<UnresolvedCauseReferenceRecord<'a>>,
}

impl<'a> LintReport<'a> {
    pub(crate) fn from_findings(findings: &'a [LintFinding], policy: &LintPolicy) -> Self {
        let mut report = Self::default();
        for f in findings {
            let severity = policy.effective(f);
            match f {
                // Weld-friction is not part of the lint subcommand JSON
                // schema — it's reported through the inject path's
                // stderr, not the standalone lint driver.
                LintFinding::WeldFriction { .. } => {}
                LintFinding::BareTildeAmbiguity { line, arm } => {
                    report.bare_tilde_ambiguity.push(BareTildeRecord {
                        severity,
                        line: *line,
                        arm,
                    });
                }
                LintFinding::Collision { kind, name, owners } => {
                    report.collision.push(CollisionRecord {
                        severity,
                        kind: *kind,
                        name,
                        owners,
                    });
                }
                LintFinding::TransitiveImport {
                    source,
                    rune,
                    name,
                    target,
                    reachable_from,
                } => {
                    report.transitive_imports.push(TransitiveImportRecord {
                        severity,
                        source,
                        rune,
                        name,
                        target,
                        reachable_from,
                    });
                }
                LintFinding::InternalDupe { kind, name, lines } => {
                    report.internal_dupes.push(InternalDupeRecord {
                        severity,
                        kind: *kind,
                        name,
                        lines,
                    });
                }
                LintFinding::UnresolvedCauseReference { line, name } => {
                    report
                        .unresolved_cause_references
                        .push(UnresolvedCauseReferenceRecord {
                            severity,
                            line: *line,
                            name,
                        });
                }
            }
        }
        report
    }
}

// ---------------------------------------------------------------
// Lint CLI dispatch (`graft-inject lint ...`)
// ---------------------------------------------------------------

/// Driver for the `graft-inject lint` subcommand. Loads the kernel,
/// runs every structural lint pass, and surfaces findings either as
/// pretty stderr lines (default) or as a stable JSON report (`--json`).
/// Returns `Err` when at least one finding fires so the parent
/// dispatch can map that to a non-zero exit code (callers that just
/// want the report should call the individual lint functions directly,
/// not this driver).
///
/// `lib_dir` doubles as the manifest discovery root — when it doesn't
/// exist the collision-check is skipped (the other lints stay useful
/// on their own). Findings emit to stderr in the human-readable form,
/// or to stdout as JSON when `--json` is set.
pub(crate) fn run_lint(
    path: &Path,
    lib_dir: &Path,
    json: bool,
    lint_overrides: &[String],
) -> Result<()> {
    let mut policy = LintPolicy::load_from_project(path)?;
    policy.apply_cli_overrides(lint_overrides)?;
    for w in policy.warnings() {
        eprintln!("graft-inject: {w}");
    }

    let findings = collect_lint_findings(path, lib_dir)?;

    if json {
        // Stable schema: { "bare_tilde_ambiguity": [...], "collision": [...],
        // "transitive_imports": [...], "internal_dupes": [...] }. Future
        // lint families append top-level keys without reshaping
        // existing ones; each record gains an additive "severity" field
        // (resolved against the active policy).
        let report = LintReport::from_findings(&findings, &policy);
        let s = serde_json::to_string_pretty(&report)
            .expect("LintReport always serializes");
        println!("{s}");
    } else {
        eprintln!("graft-inject lint: {}", summarize_severity(&findings, &policy));
        print_lint_findings(&findings, path, &policy);
    }

    let errors = findings
        .iter()
        .filter(|f| policy.effective(f) == LintSeverity::Error)
        .count();
    if errors > 0 {
        bail!("graft-inject lint: {errors} error finding(s) above");
    }
    Ok(())
}

/// Discover-and-collect entry point shared by `run_lint` and
/// `doctor::run_doctor`. Validates the kernel path, reads source,
/// runs every lint pass, and returns the raw findings — leaving
/// policy resolution, printing, and exit-code mapping to the caller.
///
/// Pure in the policy sense: a downstream pass can apply its own
/// per-lint severity table without re-collecting findings. The
/// caller owns whether warnings exit nonzero.
pub(crate) fn collect_lint_findings(
    path: &Path,
    lib_dir: &Path,
) -> Result<Vec<LintFinding>> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("hoon") => {}
        Some(other) => bail!(
            "target {} has extension `.{}`; lint only runs on Hoon source files",
            path.display(),
            other,
        ),
        None => bail!(
            "target {} has no file extension; lint only runs on Hoon source files",
            path.display(),
        ),
    }
    let source = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let lines: Vec<String> = source.lines().map(String::from).collect();

    let mut findings: Vec<LintFinding> = Vec::new();
    findings.extend(lint_bare_tilde_ambiguity(&lines));

    // Collision check + unresolved-cause-reference need the discovered
    // graft set so they can cross-reference manifests. When --lib-dir
    // doesn't exist we skip both rather than hard-error; the other
    // lints stay useful on their own (e.g. on a kernel outside its
    // project tree).
    if lib_dir.is_dir() {
        let grafts = discover_grafts(lib_dir)
            .with_context(|| format!("discovering grafts under {}", lib_dir.display()))?;
        findings.extend(lint_collision_check(&grafts, &lines));
        findings.extend(lint_unresolved_cause_references(&grafts, &lines));
    }

    // Transitive import walk. Runs unconditionally — the silent-fail
    // fires when hoonc eager-parses hoon/common/, and the lint needs
    // to mirror that scope to be useful.
    findings.extend(lint_transitive_imports(path, lib_dir));

    // Internal-dupe lint: literal duplicate cause-tag heads or
    // state-field names inside the composed unions. Catches both
    // hand-written domain dupes and post-injection graft dupes that
    // collision_check (manifest-side) misses.
    findings.extend(lint_internal_dupes(&lines));

    Ok(findings)
}

/// Build a stable per-kind table of (default, effective) severities for
/// the doctor command's policy surface. The kinds appear in
/// `KIND_ORDER`, defaults come from a freshly-constructed example
/// finding per variant, and the effective column folds in `policy`.
pub(crate) fn resolved_policy_table(
    policy: &LintPolicy,
) -> BTreeMap<&'static str, (LintSeverity, LintSeverity)> {
    let defaults = default_severity_table();
    let mut out: BTreeMap<&'static str, (LintSeverity, LintSeverity)> = BTreeMap::new();
    for kind in KIND_ORDER {
        let default = *defaults.get(kind).expect("KIND_ORDER covered");
        let effective = policy.effective_for_default(kind, default);
        out.insert(*kind, (default, effective));
    }
    out
}

/// Canonical (kind → default severity) table for the doctor surface
/// and tests. Mirrors the per-variant [`LintFinding::severity`]
/// defaults; kept in one place so a future tier change touches a
/// single line.
fn default_severity_table() -> HashMap<&'static str, LintSeverity> {
    let mut t = HashMap::new();
    t.insert("weld-friction", LintSeverity::Warn);
    t.insert("bare-tilde-ambiguity", LintSeverity::Error);
    t.insert("collision", LintSeverity::Error);
    t.insert("transitive-imports", LintSeverity::Error);
    t.insert("internal-dupes", LintSeverity::Error);
    t.insert("unresolved-cause-reference", LintSeverity::Error);
    t
}

/// One-line summary breaking findings out by severity, e.g.
/// `3 error(s), 2 warning(s)`. Empty-severity buckets are dropped so
/// the line stays terse when only one tier fires.
pub(crate) fn summarize_severity(findings: &[LintFinding], policy: &LintPolicy) -> String {
    let mut errors = 0usize;
    let mut warnings = 0usize;
    let mut notes = 0usize;
    for f in findings {
        match policy.effective(f) {
            LintSeverity::Error => errors += 1,
            LintSeverity::Warn => warnings += 1,
            LintSeverity::Note => notes += 1,
        }
    }
    let mut parts: Vec<String> = Vec::new();
    if errors > 0 {
        parts.push(format!("{errors} error(s)"));
    }
    if warnings > 0 {
        parts.push(format!("{warnings} warning(s)"));
    }
    if notes > 0 {
        parts.push(format!("{notes} note(s)"));
    }
    if parts.is_empty() {
        "0 finding(s)".to_string()
    } else {
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- unified finding shape ----------

    /// `kind_label` returns the same identifier-style label the printer
    /// emits and the JSON schema keys use. Catches a typo'd label
    /// before it desynchronizes printer output from JSON keys.
    #[test]
    fn lint_finding_kind_labels_are_stable() {
        let weld = LintFinding::WeldFriction {
            line: 1,
            text: "x".into(),
            narrow_type: "kv-effect".into(),
        };
        let bare = LintFinding::BareTildeAmbiguity {
            line: 1,
            arm: "ping".into(),
        };
        let coll = LintFinding::Collision {
            kind: CollisionKind::CauseTag,
            name: "x".into(),
            owners: vec![],
        };
        let trans = LintFinding::TransitiveImport {
            source: PathBuf::new(),
            rune: "/+".into(),
            name: "x".into(),
            target: PathBuf::new(),
            reachable_from: vec![],
        };
        let dupe = LintFinding::InternalDupe {
            kind: InternalDupeKind::CauseTag,
            name: "x".into(),
            lines: vec![],
        };
        assert_eq!(weld.kind_label(), "weld-friction");
        assert_eq!(bare.kind_label(), "bare-tilde-ambiguity");
        assert_eq!(coll.kind_label(), "collision");
        assert_eq!(trans.kind_label(), "transitive-imports");
        assert_eq!(dupe.kind_label(), "internal-dupes");
    }

    /// `line()` returns Some only for findings anchored on a single
    /// source line. Multi-line / cross-file variants return None.
    #[test]
    fn lint_finding_line_anchors_only_single_line_variants() {
        assert_eq!(
            LintFinding::WeldFriction {
                line: 12,
                text: "".into(),
                narrow_type: "".into(),
            }
            .line(),
            Some(12)
        );
        assert_eq!(
            LintFinding::BareTildeAmbiguity {
                line: 5,
                arm: "ping".into(),
            }
            .line(),
            Some(5)
        );
        assert_eq!(
            LintFinding::Collision {
                kind: CollisionKind::CauseTag,
                name: "".into(),
                owners: vec![],
            }
            .line(),
            None
        );
        assert_eq!(
            LintFinding::TransitiveImport {
                source: PathBuf::new(),
                rune: "".into(),
                name: "".into(),
                target: PathBuf::new(),
                reachable_from: vec![],
            }
            .line(),
            None
        );
        assert_eq!(
            LintFinding::InternalDupe {
                kind: InternalDupeKind::CauseTag,
                name: "".into(),
                lines: vec![],
            }
            .line(),
            None
        );
    }

    /// JSON projection keeps the historic schema keys
    /// (`bare_tilde_ambiguity`, `collision`, `transitive_imports`,
    /// `internal_dupes`) and per-finding field shape — even on an
    /// empty findings input, all four keys appear with empty arrays.
    #[test]
    fn lint_report_json_schema_preserves_keys() {
        let findings: Vec<LintFinding> = vec![];
        let policy = LintPolicy::empty();
        let report = LintReport::from_findings(&findings, &policy);
        let s = serde_json::to_string(&report).unwrap();
        assert!(s.contains("\"bare_tilde_ambiguity\":[]"));
        assert!(s.contains("\"collision\":[]"));
        assert!(s.contains("\"transitive_imports\":[]"));
        assert!(s.contains("\"internal_dupes\":[]"));
        // Weld-friction is NOT a top-level run_lint JSON key (matches
        // pre-Phase-1 schema).
        assert!(!s.contains("\"weld_friction\""));
    }

    /// Round-trip a Collision finding through the JSON projection and
    /// confirm the record shape matches the pre-Phase-1 layout —
    /// `{kind: "cause_tag" | "state_field", name, owners}` — plus the
    /// Phase-3 additive `severity` field.
    #[test]
    fn lint_report_collision_serializes_with_legacy_shape() {
        let findings = vec![LintFinding::Collision {
            kind: CollisionKind::CauseTag,
            name: "enqueue-job".into(),
            owners: vec!["queue-graft".into(), "pipeline-graft".into()],
        }];
        let policy = LintPolicy::empty();
        let report = LintReport::from_findings(&findings, &policy);
        let s = serde_json::to_string(&report).unwrap();
        assert!(s.contains("\"kind\":\"cause_tag\""));
        assert!(s.contains("\"name\":\"enqueue-job\""));
        assert!(s.contains("\"queue-graft\""));
        assert!(s.contains("\"pipeline-graft\""));
        // Severity field is additive — Collision defaults to Error.
        assert!(s.contains("\"severity\":\"error\""));
    }

    // ---------- severity tiering ----------

    /// Default severity per variant matches the Phase-3 specification:
    /// `weld-friction` is the only `Warn`; every other lint defaults
    /// to `Error` so its gate behavior matches pre-Phase-3.
    #[test]
    fn lint_finding_severity_defaults_match_spec() {
        let weld = LintFinding::WeldFriction {
            line: 1,
            text: "".into(),
            narrow_type: "x".into(),
        };
        let bare = LintFinding::BareTildeAmbiguity {
            line: 1,
            arm: "x".into(),
        };
        let coll = LintFinding::Collision {
            kind: CollisionKind::CauseTag,
            name: "x".into(),
            owners: vec![],
        };
        let trans = LintFinding::TransitiveImport {
            source: PathBuf::new(),
            rune: "/+".into(),
            name: "x".into(),
            target: PathBuf::new(),
            reachable_from: vec![],
        };
        let dupe = LintFinding::InternalDupe {
            kind: InternalDupeKind::CauseTag,
            name: "x".into(),
            lines: vec![],
        };
        let unres = LintFinding::UnresolvedCauseReference {
            line: 1,
            name: "x".into(),
        };
        assert_eq!(weld.severity(), LintSeverity::Warn);
        assert_eq!(bare.severity(), LintSeverity::Error);
        assert_eq!(coll.severity(), LintSeverity::Error);
        assert_eq!(trans.severity(), LintSeverity::Error);
        assert_eq!(dupe.severity(), LintSeverity::Error);
        assert_eq!(unres.severity(), LintSeverity::Error);
    }

    /// `summarize_severity` breaks the count out by tier, drops empty
    /// buckets, and falls back to the `0 finding(s)` form when the
    /// input is empty.
    #[test]
    fn summarize_severity_groups_by_tier() {
        let policy = LintPolicy::empty();
        let empty: Vec<LintFinding> = vec![];
        assert_eq!(summarize_severity(&empty, &policy), "0 finding(s)");

        let mixed = vec![
            LintFinding::BareTildeAmbiguity {
                line: 1,
                arm: "x".into(),
            },
            LintFinding::Collision {
                kind: CollisionKind::CauseTag,
                name: "x".into(),
                owners: vec![],
            },
            LintFinding::WeldFriction {
                line: 1,
                text: "".into(),
                narrow_type: "x".into(),
            },
        ];
        assert_eq!(
            summarize_severity(&mixed, &policy),
            "2 error(s), 1 warning(s)"
        );

        let warn_only = vec![LintFinding::WeldFriction {
            line: 1,
            text: "".into(),
            narrow_type: "x".into(),
        }];
        assert_eq!(summarize_severity(&warn_only, &policy), "1 warning(s)");
    }

    // ---------- LintPolicy ----------

    /// Empty policy = per-variant defaults. Effective severity equals
    /// the variant default for every finding.
    #[test]
    fn lint_policy_empty_falls_back_to_defaults() {
        let policy = LintPolicy::empty();
        let weld = LintFinding::WeldFriction {
            line: 1,
            text: "".into(),
            narrow_type: "x".into(),
        };
        let coll = LintFinding::Collision {
            kind: CollisionKind::CauseTag,
            name: "x".into(),
            owners: vec![],
        };
        assert_eq!(policy.effective(&weld), LintSeverity::Warn);
        assert_eq!(policy.effective(&coll), LintSeverity::Error);
    }

    /// `--lint-override` parses `NAME=SEVERITY`, validates the name
    /// against `KIND_ORDER`, and overrides the per-variant default.
    #[test]
    fn lint_policy_cli_overrides_apply() {
        let mut policy = LintPolicy::empty();
        policy
            .apply_cli_overrides(&[
                "weld-friction=error".to_string(),
                "transitive-imports=warn".to_string(),
            ])
            .unwrap();
        let weld = LintFinding::WeldFriction {
            line: 1,
            text: "".into(),
            narrow_type: "x".into(),
        };
        let trans = LintFinding::TransitiveImport {
            source: PathBuf::new(),
            rune: "/+".into(),
            name: "x".into(),
            target: PathBuf::new(),
            reachable_from: vec![],
        };
        assert_eq!(policy.effective(&weld), LintSeverity::Error);
        assert_eq!(policy.effective(&trans), LintSeverity::Warn);
    }

    /// A typo'd lint name in `--lint-override` hard-errors so the
    /// override doesn't silently no-op.
    #[test]
    fn lint_policy_cli_override_typo_errors() {
        let mut policy = LintPolicy::empty();
        let err = policy
            .apply_cli_overrides(&["transitive-importss=warn".to_string()])
            .unwrap_err();
        assert!(
            err.to_string().contains("unknown lint name"),
            "expected unknown-lint-name error, got: {err}"
        );
    }

    /// An override with an invalid severity hard-errors with the
    /// allowed set named.
    #[test]
    fn lint_policy_cli_override_bad_severity_errors() {
        let mut policy = LintPolicy::empty();
        let err = policy
            .apply_cli_overrides(&["weld-friction=warning".to_string()])
            .unwrap_err();
        // The wrapper (`--lint-override ...`) is the top of the chain;
        // the underlying "unknown lint severity" lives in the source.
        // Use the alt format to walk the chain so both surfaces appear.
        let full = format!("{err:#}");
        assert!(
            full.contains("unknown lint severity"),
            "expected unknown-severity error in chain, got: {full}"
        );
    }

    /// `load_from_project` walks up from the kernel path until it
    /// finds a `nockapp.toml` and applies its `[lint]` table. Missing
    /// nockapp.toml falls back to an empty policy with no warnings.
    #[test]
    fn lint_policy_loads_from_nockapp_toml() {
        let dir = std::env::temp_dir().join(format!(
            "graft-inject-test-lint-policy-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("nockapp.toml"),
            "[lint]\nweld-friction = \"error\"\ntransitive-imports = \"warn\"\n",
        )
        .unwrap();
        let app = dir.join("hoon").join("app").join("app.hoon");
        fs::create_dir_all(app.parent().unwrap()).unwrap();
        fs::write(&app, "").unwrap();

        let policy = LintPolicy::load_from_project(&app).expect("load");
        let weld = LintFinding::WeldFriction {
            line: 1,
            text: "".into(),
            narrow_type: "x".into(),
        };
        let trans = LintFinding::TransitiveImport {
            source: PathBuf::new(),
            rune: "/+".into(),
            name: "x".into(),
            target: PathBuf::new(),
            reachable_from: vec![],
        };
        assert_eq!(policy.effective(&weld), LintSeverity::Error);
        assert_eq!(policy.effective(&trans), LintSeverity::Warn);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A typo in `nockapp.toml`'s `[lint]` table hard-errors at
    /// policy load, naming the offending key and the valid set.
    #[test]
    fn lint_policy_load_typo_errors() {
        let dir = std::env::temp_dir().join(format!(
            "graft-inject-test-lint-policy-typo-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("nockapp.toml"),
            "[lint]\ntransitive-importss = \"warn\"\n",
        )
        .unwrap();
        let app = dir.join("app.hoon");
        fs::write(&app, "").unwrap();

        let err = LintPolicy::load_from_project(&app).unwrap_err();
        assert!(
            err.to_string().contains("unknown lint name"),
            "expected unknown-lint-name error, got: {err}"
        );
        assert!(
            err.to_string().contains("transitive-importss"),
            "error should name the typo, got: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// CLI override wins over the config-file override (CLI > config
    /// > default).
    #[test]
    fn lint_policy_cli_wins_over_config() {
        let dir = std::env::temp_dir().join(format!(
            "graft-inject-test-lint-policy-prec-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("nockapp.toml"),
            "[lint]\nweld-friction = \"error\"\n",
        )
        .unwrap();
        let app = dir.join("app.hoon");
        fs::write(&app, "").unwrap();

        let mut policy = LintPolicy::load_from_project(&app).expect("load");
        // Config says weld=error; CLI override demotes it to warn.
        policy
            .apply_cli_overrides(&["weld-friction=warn".to_string()])
            .unwrap();
        let weld = LintFinding::WeldFriction {
            line: 1,
            text: "".into(),
            narrow_type: "x".into(),
        };
        assert_eq!(policy.effective(&weld), LintSeverity::Warn);
        let _ = fs::remove_dir_all(&dir);
    }
}
