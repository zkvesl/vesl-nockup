//! Pre/post-inject lint suite: weld-friction, bare-tilde ambiguity,
//! collision check, transitive imports, internal dupes.
//!
//! Every lint produces the same type — [`LintFinding`], with one
//! variant per lint. Consumers (`run_lint`, `run_inject`, the inject
//! report) route through a single pattern-match instead of branching on
//! five wrapper structs. Each lint function returns
//! `Vec<LintFinding>`; the unified printer ([`print_lint_findings`])
//! groups by [`LintFinding::kind_label`] and emits the per-lint
//! remediation hint blocks verbatim.
//!
//! Codegen consumes a couple of helpers here (`CauseUnionMember`,
//! `extract_cause_union_members`, `extract_graft_cause_tags`) because
//! its cause-tag set composition is the same shape as the lint's
//! cross-reference. There's no other coupling.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::manifest::{Graft, discover_grafts};
use crate::marker::Marker;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CollisionKind {
    CauseTag,
    StateField,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InternalDupeKind {
    CauseTag,
    StateField,
}

// ---------------------------------------------------------------
// Weld-friction lint
// ---------------------------------------------------------------

/// Walk `lines` and flag any developer-code line that contains a
/// narrow effect binding like `(list <graft>-effect)`. Skips lines
/// inside `graft-inject:<...>:begin / :end` banner regions (those are
/// graft-injected bodies, not user code; the narrow types are correct
/// there). Skips entirely when codegen status is Skipped or the variant
/// list is empty — there's no typed union to widen toward.
///
/// A real composition confirmed that the typed effect union does NOT
/// auto-fix the cross-graft `weld` friction when the developer's
/// domain arm binds narrowly:
///
/// ```text
/// =/  [efx-c=(list counter-effect) new-counter=counter-state]   :: NARROW
///   (counter-poke counter.state ...)
/// (weld efx-c efx-k)                                            :: nest-fail
/// ```
///
/// The fix is Pattern B: widen each binding to `(list effect)`. The
/// lint scans developer code (outside `graft-inject:<X>:begin/:end`
/// banner regions) for narrow bindings and surfaces a finding pointing
/// at the zkvesl-docs §"Composing two graft arms in one domain cause"
/// anchor so the developer has a searchable handle.
pub(crate) fn lint_weld_friction(lines: &[String], variants: &[String]) -> Vec<LintFinding> {
    let effect_variants: HashSet<&str> = variants
        .iter()
        .filter(|v| v.ends_with("-effect") && v.as_str() != "domain-effect")
        .map(String::as_str)
        .collect();

    if effect_variants.is_empty() {
        return Vec::new();
    }

    let mut findings: Vec<LintFinding> = Vec::new();
    let mut in_banner = false;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        // Banner detection: any `graft-inject:<X>:<Y>:begin/:end` line
        // toggles the in_banner state. Codegen banner pairs
        // (`graft-inject:effect-union:...`) are also skipped — those
        // bodies are synthesized, not user-written.
        if trimmed.starts_with("::") && trimmed.contains("graft-inject:") {
            // Begin banners may carry a ` sha256:<hex>` suffix;
            // match on the `:begin` token regardless of suffix. End
            // banners are still suffix-free.
            if trimmed.contains(":begin ") || trimmed.ends_with(":begin") {
                in_banner = true;
                continue;
            }
            if trimmed.ends_with(":end") {
                in_banner = false;
                continue;
            }
        }
        if in_banner {
            continue;
        }

        for variant in &effect_variants {
            let needle = format!("(list {variant})");
            if line.contains(&needle) {
                findings.push(LintFinding::WeldFriction {
                    line: i + 1,
                    text: trimmed.to_string(),
                    narrow_type: (*variant).to_string(),
                });
                break; // one finding per line is enough
            }
        }
    }
    findings
}

// ---------------------------------------------------------------
// Bare-tilde ambiguity lint
// ---------------------------------------------------------------

/// Pre-apply lint: bare-`~` ambiguity inside domain `?-` switch arms.
///
/// The bug this guards against: `find_last_bare_tilde` walks from
/// the `nockup:peek` marker until the next `==` capturing the last
/// `~`-only line as the peek-chain terminator. The next `==` is
/// typically the `?-  -.u.act` close in the poke arm, so any bare-`~`
/// line inside a domain arm body (e.g. `%ping :_ state ^- (list effect) ~`)
/// becomes the new "terminator" and graft-inject inserts the peek
/// chain into the poke body — corrupting the file.
///
/// The canonical re-emit fixed the placement bugs it targeted, but
/// `emit_peek_chain` still anchors against `find_last_bare_tilde`.
/// Until that anchor changes, the safest surface is a pre-apply lint
/// that warns when the user's domain arms create the structural
/// ambiguity.
///
/// The lint walks lines inside the `nockup:poke` region but outside
/// any `graft-inject:*:begin/:end` banner (graft-injected arms are
/// graft-inject's own output and aren't user-editable). When a
/// domain arm body's final line is exactly `~`, the line is flagged
/// and the developer is pointed at the workaround:
/// `\`(list effect)\`~` or `^- (list effect) ~` on a single line.
pub(crate) fn lint_bare_tilde_ambiguity(lines: &[String]) -> Vec<LintFinding> {
    // Anchor on the `?-  -.u.act` switch header. graft-inject's
    // `find_last_bare_tilde` would scan the same range from the
    // peek marker forward, so any domain arm body inside this
    // switch that ends with bare `~` is the friction shape this lint
    // targets. The `nockup:poke` marker by itself isn't
    // enough — domain arms live BEFORE the marker (between the
    // switch open and the marker), so a forward-only scan from
    // the marker would miss them.
    let Some(switch_idx) = lines.iter().position(|l| {
        let t = l.trim();
        t.starts_with("?-") && t.contains("-.u.act")
    }) else {
        return Vec::new();
    };

    let mut findings: Vec<LintFinding> = Vec::new();
    let mut in_banner = false;
    // Track the most recent domain `%<tag>` arm header so each finding
    // can name its parent arm. Domain arms are leading `%<tag>` lines
    // that are NOT inside a graft-inject banner.
    let mut current_arm: Option<String> = None;
    for (i, line) in lines.iter().enumerate().skip(switch_idx + 1) {
        let trimmed = line.trim();
        if trimmed == "==" {
            break;
        }
        // Banner state machine — copies the lint_weld_friction shape so
        // graft-injected arm bodies are skipped.
        if trimmed.starts_with("::") && trimmed.contains("graft-inject:") {
            if trimmed.contains(":begin ") || trimmed.ends_with(":begin") {
                in_banner = true;
                continue;
            }
            if trimmed.ends_with(":end") {
                in_banner = false;
                continue;
            }
        }
        if in_banner {
            continue;
        }
        // Skip the `nockup:poke` placeholder — it's a comment marker,
        // not a domain arm. Comments in general (`::  ...`) reset
        // nothing; they're transparent to the arm-tracking logic.
        if trimmed.starts_with("::") {
            continue;
        }
        // Track the most recent domain arm header. A domain arm header
        // is a line whose first token starts with `%` followed by a
        // tag character. We only need the tag for the finding message,
        // so a quick prefix match is enough — full Hoon parsing isn't
        // required.
        if let Some(rest) = trimmed.strip_prefix('%') {
            if rest
                .chars()
                .next()
                .map(|c| c.is_ascii_alphabetic() || c == '-')
                .unwrap_or(false)
            {
                let tag: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                    .collect();
                if !tag.is_empty() {
                    current_arm = Some(tag);
                }
            }
        }
        if trimmed == "~" {
            if let Some(arm) = current_arm.take() {
                findings.push(LintFinding::BareTildeAmbiguity {
                    line: i + 1,
                    arm,
                });
                // After flagging once per arm, reset so multi-line arm
                // bodies don't repeat-flag (the bug fires on the LAST
                // line; one finding per arm is enough).
            }
        }
    }
    findings
}

// ---------------------------------------------------------------
// Collision-check lint
// ---------------------------------------------------------------

/// Pre-apply lint: cross-graft and graft-vs-domain name collisions.
///
/// Two kinds of collision can arise in cumulative-domain mode:
/// - Cause-tag collisions: two grafts (or a graft and the domain)
///   declare the same `%<tag>` poke arm. The composed `?-` switch
///   has duplicate `%<tag>` arms; hoonc's exhaustiveness check
///   fires `mint-lost` or accepts whichever arm wins lexically.
/// - State-field collisions: two grafts (or a graft and the domain)
///   declare the same field name in the state record. The composed
///   `+$ versioned-state` has duplicate field names; hoonc fires a
///   nest-fail.
///
/// The lint reads each graft's `[graft.blocks.poke]` body (cause
/// tags appear as leading `%<tag>` arm headers) and `[graft.blocks.state]`
/// body (field names appear before `=`). It also parses the domain's
/// `nockup:cause` and `nockup:state` regions in app.hoon. Any name
/// declared by more than one source becomes a finding.
pub(crate) fn lint_collision_check(
    grafts: &[Graft],
    domain_lines: &[String],
) -> Vec<LintFinding> {
    use std::collections::BTreeMap;
    let mut cause_owners: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut state_owners: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for g in grafts {
        for tag in extract_graft_cause_tags(g) {
            cause_owners.entry(tag).or_default().push(g.name.clone());
        }
        for field in extract_graft_state_fields(g) {
            state_owners.entry(field).or_default().push(g.name.clone());
        }
    }
    for tag in extract_domain_cause_tags(domain_lines) {
        cause_owners
            .entry(tag)
            .or_default()
            .push("(domain)".to_string());
    }
    for field in extract_domain_state_fields(domain_lines) {
        state_owners
            .entry(field)
            .or_default()
            .push("(domain)".to_string());
    }

    let mut findings: Vec<LintFinding> = Vec::new();
    for (tag, owners) in cause_owners {
        if owners.len() > 1 {
            findings.push(LintFinding::Collision {
                kind: CollisionKind::CauseTag,
                name: tag,
                owners,
            });
        }
    }
    for (field, owners) in state_owners {
        if owners.len() > 1 {
            findings.push(LintFinding::Collision {
                kind: CollisionKind::StateField,
                name: field,
                owners,
            });
        }
    }
    findings
}

/// Extract `%<tag>` arm headers from a graft's poke block body.
/// graft poke bodies follow a uniform shape: each arm starts with
/// `%<tag>` on its own line (modulo leading whitespace), preceded by
/// `::` separators between arms. Walk the lines and collect the tags.
pub(crate) fn extract_graft_cause_tags(g: &Graft) -> Vec<String> {
    let mut tags = Vec::new();
    for marker in [Marker::Poke, Marker::PokePrelude, Marker::PokePostlude] {
        let Some(body) = g.block(marker) else {
            continue;
        };
        for line in body.body.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix('%') {
                let tag: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                    .collect();
                if !tag.is_empty() {
                    // Skip embedded `%foo` references inside expressions
                    // (e.g., `[%queue-push ...]` inside a `=/`). Real arm
                    // headers are bare on a line; embedded references are
                    // inside `[]` or `()` or have leading punctuation.
                    if !line.contains('[') && !line.contains('(') {
                        tags.push(tag);
                    }
                }
            }
        }
    }
    tags
}

/// Extract field names from a graft's state block body. The shape is
/// `<field>=<type>` (most grafts) or a `$:` record with multiple
/// `<field>=<type>` lines. Tokens before `=` (modulo leading
/// whitespace) are field names.
fn extract_graft_state_fields(g: &Graft) -> Vec<String> {
    let Some(body) = g.block(Marker::State) else {
        return Vec::new();
    };
    let mut fields = Vec::new();
    for line in body.body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("::")
            || trimmed.starts_with("$:")
            || trimmed == "=="
        {
            continue;
        }
        if let Some(eq) = trimmed.find('=') {
            let name: String = trimmed[..eq]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect();
            if !name.is_empty() {
                fields.push(name);
            }
        }
    }
    fields
}

/// Walk `domain_lines` (the entire app.hoon source as line vec) and
/// extract domain cause tags — `[%<tag> ...]` lines that sit between
/// the `+$ cause $%(...)` opening and the `::  nockup:cause` marker
/// (or the closing `==` if no marker is present).
pub(crate) fn extract_domain_cause_tags(lines: &[String]) -> Vec<String> {
    let mut tags = Vec::new();
    let Some(open_idx) = lines.iter().position(|l| {
        let t = l.trim();
        t.starts_with("+$") && t.contains("cause")
    }) else {
        return tags;
    };
    let mut started = false;
    let mut in_banner = false;
    for line in &lines[open_idx..] {
        let trimmed = line.trim();
        if !started {
            if let Some(after) = trimmed.find("$%") {
                started = true;
                // `$%` may be followed by a variant on the same line
                // (e.g. `$%  [%cause ~]`). Probe for `[%<tag>` after
                // the `$%` token before continuing.
                let rest = &trimmed[after + 2..];
                push_bracket_tag(rest, &mut tags);
            }
            continue;
        }
        if trimmed.starts_with("::  nockup:cause") || trimmed == "==" {
            break;
        }
        if trimmed.starts_with("::") && trimmed.contains("graft-inject:") {
            if trimmed.contains(":begin ") || trimmed.ends_with(":begin") {
                in_banner = true;
                continue;
            }
            if trimmed.ends_with(":end") {
                in_banner = false;
                continue;
            }
        }
        if in_banner {
            continue;
        }
        push_bracket_tag(trimmed, &mut tags);
    }
    tags
}

/// Extract a `[%<tag> ...]` leading tag from a string and append to
/// `tags`. No-op when the input doesn't start with `[%`.
fn push_bracket_tag(s: &str, tags: &mut Vec<String>) {
    let trimmed = s.trim_start();
    if let Some(rest) = trimmed.strip_prefix("[%") {
        let tag: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        if !tag.is_empty() {
            tags.push(tag);
        }
    }
}

/// Walk `lines` and extract domain state field names — `<name>=<type>`
/// lines between `+$ versioned-state $:(...)` (or similar) and the
/// `::  nockup:state` marker.
fn extract_domain_state_fields(lines: &[String]) -> Vec<String> {
    let mut fields = Vec::new();
    let Some(open_idx) = lines.iter().position(|l| {
        let t = l.trim();
        t.starts_with("+$") && (t.contains("state") || t.contains("versioned-state"))
    }) else {
        return fields;
    };
    let mut started = false;
    let mut in_banner = false;
    for line in &lines[open_idx..] {
        let trimmed = line.trim();
        if !started {
            if trimmed.contains("$:") {
                started = true;
            }
            continue;
        }
        if trimmed.starts_with("::  nockup:state") || trimmed == "==" {
            break;
        }
        if trimmed.starts_with("::") && trimmed.contains("graft-inject:") {
            if trimmed.contains(":begin ") || trimmed.ends_with(":begin") {
                in_banner = true;
                continue;
            }
            if trimmed.ends_with(":end") {
                in_banner = false;
                continue;
            }
        }
        if in_banner {
            continue;
        }
        if trimmed.starts_with("::") || trimmed.is_empty() {
            continue;
        }
        if let Some(eq) = trimmed.find('=') {
            let name: String = trimmed[..eq]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect();
            if !name.is_empty() {
                fields.push(name);
            }
        }
    }
    fields
}

// ---------------------------------------------------------------
// Transitive-imports lint
// ---------------------------------------------------------------

/// One import edge extracted from a .hoon prologue.
#[derive(Debug, Clone)]
struct ImportSpec {
    rune: &'static str,
    name: String,
    /// `/=` only: the path argument (e.g. `/common/wrapper`). Empty
    /// for the other runes.
    path_arg: String,
}

/// Pre-apply lint: walk every `.hoon` file reachable from the input
/// path via `/+`, `/=`, `/-`, `/#` imports, AND eagerly scan every
/// `.hoon` under `<hoon-root>/common/`. Report unsatisfied edges as
/// findings.
///
/// Reproduces a real friction (`hoon/common/nock-prover.hoon → /#
/// softed-constraints` after a slimmed copy): even though an app.hoon
/// doesn't reach nock-prover transitively, hoonc parses hoon/common/
/// eagerly and silent-fails on the missing `/dat/` target. This lint
/// surfaces the same edge before hoonc runs so the developer sees a
/// clear "missing file at PATH" rather than hoonc's "no panic!" lie.
///
/// Resolution rules:
/// - `/+ <name>`         → `<lib-dir>/<name>.hoon`
/// - `/+ *<name>`        → `<lib-dir>/<name>.hoon` (public-import form)
/// - `/= <bind> /<path>` → `<hoon-root>/<path>.hoon`
/// - `/-  <name>`        → `<hoon-root>/sur/<name>.hoon`
/// - `/# <name>`         → `<hoon-root>/dat/<name>.hoon`
pub(crate) fn lint_transitive_imports(root_path: &Path, lib_dir: &Path) -> Vec<LintFinding> {
    use std::collections::VecDeque;

    let hoon_root = lib_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let common_dir = hoon_root.join("common");

    // Canonicalize for dedup. If canonicalize fails (e.g. the file
    // doesn't exist), fall back to the raw path — the resolver below
    // is the place that flags absence, not the dedup step.
    let canon = |p: &Path| -> PathBuf {
        p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
    };

    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut queue: VecDeque<(PathBuf, Vec<PathBuf>)> = VecDeque::new();
    queue.push_back((canon(root_path), Vec::new()));

    // Eagerly seed every .hoon under hoon/common/. Manual recursion via
    // fs::read_dir keeps us off walkdir.
    if common_dir.is_dir() {
        let mut stack = vec![common_dir.clone()];
        while let Some(dir) = stack.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().and_then(|e| e.to_str()) == Some("hoon") {
                    queue.push_back((canon(&p), Vec::new()));
                }
            }
        }
    }

    let mut findings: Vec<LintFinding> = Vec::new();
    while let Some((current, parents)) = queue.pop_front() {
        if !visited.insert(current.clone()) {
            continue;
        }
        let content = match fs::read_to_string(&current) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let lines: Vec<String> = content.lines().map(String::from).collect();
        for spec in parse_imports(&lines) {
            let target = resolve_import(&spec, &hoon_root, lib_dir);
            if target.exists() {
                let mut next_parents = parents.clone();
                next_parents.push(current.clone());
                queue.push_back((canon(&target), next_parents));
            } else {
                let mut chain = parents.clone();
                chain.push(current.clone());
                findings.push(LintFinding::TransitiveImport {
                    source: current.clone(),
                    rune: spec.rune.to_string(),
                    name: spec.name.clone(),
                    target,
                    reachable_from: chain,
                });
            }
        }
    }

    findings
}

/// Parse the leading import block of a .hoon file. Stops at the first
/// non-rune non-comment non-empty line — Hoon prologues conventionally
/// run all imports before the first runic body.
fn parse_imports(lines: &[String]) -> Vec<ImportSpec> {
    let mut out = Vec::new();
    for line in lines {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with("::") {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("/+") {
            for name in split_import_names(rest) {
                out.push(ImportSpec {
                    rune: "/+",
                    name,
                    path_arg: String::new(),
                });
            }
        } else if let Some(rest) = trimmed.strip_prefix("/=") {
            // `/= <bind> /<path>`. Extract the leading slash-path; bind
            // name is the first whitespace-separated token.
            let fields: Vec<&str> = rest.split_whitespace().collect();
            if let Some(p) = fields.iter().find(|f| f.starts_with('/')) {
                out.push(ImportSpec {
                    rune: "/=",
                    name: fields.first().map(|s| s.to_string()).unwrap_or_default(),
                    path_arg: p.to_string(),
                });
            }
        } else if let Some(rest) = trimmed.strip_prefix("/-") {
            for name in split_import_names(rest) {
                out.push(ImportSpec {
                    rune: "/-",
                    name,
                    path_arg: String::new(),
                });
            }
        } else if let Some(rest) = trimmed.strip_prefix("/#") {
            for name in split_import_names(rest) {
                out.push(ImportSpec {
                    rune: "/#",
                    name,
                    path_arg: String::new(),
                });
            }
        } else {
            break;
        }
    }
    out
}

/// Split a `/+` or `/-` argument into individual import names.
/// Tolerates leading `*` (public import) and comma-separated lists.
fn split_import_names(rest: &str) -> Vec<String> {
    rest.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_start_matches('*').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Resolve an import spec to a candidate file path under hoon-root.
fn resolve_import(spec: &ImportSpec, hoon_root: &Path, lib_dir: &Path) -> PathBuf {
    match spec.rune {
        "/+" => lib_dir.join(format!("{}.hoon", spec.name)),
        "/=" => {
            let p = spec.path_arg.trim_start_matches('/');
            hoon_root.join(format!("{}.hoon", p))
        }
        "/-" => hoon_root.join("sur").join(format!("{}.hoon", spec.name)),
        "/#" => hoon_root.join("dat").join(format!("{}.hoon", spec.name)),
        _ => PathBuf::new(),
    }
}

// ---------------------------------------------------------------
// Internal-dupes lint
// ---------------------------------------------------------------

/// Member of a literal `+$ cause` definition. Distinguishes inline
/// `[%<tag> ...]` variants from sub-union type references like
/// `settle-cause` or `intent-cause` — the codegen pass needs both
/// (literals → tag direct; references → look up the named graft's
/// manifest), the lint pass cares only about literals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CauseUnionMember {
    /// `[%<tag> ...]` form — an inline variant whose head is `tag`.
    Literal { tag: String, line: usize },
    /// Sub-union reference — a bare type name like `settle-cause`,
    /// `intent-cause` etc. that resolves to another `+$` definition
    /// (typically the one a graft contributes via its imports).
    Reference { name: String, line: usize },
}

/// Pre-apply lint: literal duplicate variant heads inside the
/// `+$ cause $%(...)` union, OR literal duplicate field names inside
/// the `+$ versioned-state $:(...)` record.
///
/// Distinguishes from `lint_collision_check` (which scans manifests
/// cross-referenced against domain): this pass scans the
/// already-composed app.hoon's literal unions for self-collisions.
/// Catches the case where the developer hand-writes two domain causes
/// with the same head, AND the case where two grafts each contribute
/// the same head after injection (collision_check would miss the
/// latter when the manifests declared distinct cause names but the
/// underlying `[%<tag> ...]` ended up identical).
///
/// Reports literal-match duplicates only. Near-miss disambiguation
/// (`%enqueue-job-f` vs `%enqueue-job-i`) is intentionally not
/// flagged — adds parser complexity without matching empirical demand.
pub(crate) fn lint_internal_dupes(lines: &[String]) -> Vec<LintFinding> {
    use std::collections::BTreeMap;

    let mut findings: Vec<LintFinding> = Vec::new();

    let mut cause_lines: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (tag, line) in extract_all_cause_variants(lines) {
        cause_lines.entry(tag).or_default().push(line);
    }
    for (tag, line_nums) in cause_lines {
        if line_nums.len() > 1 {
            findings.push(LintFinding::InternalDupe {
                kind: InternalDupeKind::CauseTag,
                name: tag,
                lines: line_nums,
            });
        }
    }

    let mut state_lines: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (name, line) in extract_all_state_fields(lines) {
        state_lines.entry(name).or_default().push(line);
    }
    for (name, line_nums) in state_lines {
        if line_nums.len() > 1 {
            findings.push(LintFinding::InternalDupe {
                kind: InternalDupeKind::StateField,
                name,
                lines: line_nums,
            });
        }
    }

    findings
}

// ---------------------------------------------------------------
// Unresolved cause-reference lint
// ---------------------------------------------------------------

/// Pre-apply lint: the kernel's `+$ cause $%(...)` cites a
/// sub-cause-type (e.g. `settle-cause`) that no graft's
/// `[graft.types].cause` declares in the active set.
///
/// `run_codegen_kernel_cause_tags` falls through silently when a
/// reference doesn't resolve — its comment described this as
/// "caught earlier" by `inject`, but `inject` operates on banner
/// markers, not on the `+$ cause` body. Without this lint, the
/// orphan reference reaches hoonc, which surfaces it as
/// `find . <name>-cause` — a message that doesn't name the kernel
/// source line or the graft set that should have declared the type.
///
/// The lint scans `extract_cause_union_members(lines)` for
/// `CauseUnionMember::Reference` entries and cross-checks each
/// against the set of declared `[graft.types].cause` names. The
/// placeholder `[%cause ~]` literal (which the template ships) is
/// already filtered out by the Reference / Literal split.
pub(crate) fn lint_unresolved_cause_references(
    grafts: &[Graft],
    lines: &[String],
) -> Vec<LintFinding> {
    let declared: HashSet<&str> = grafts
        .iter()
        .filter_map(|g| g.types.as_ref().and_then(|t| t.cause.as_deref()))
        .collect();
    // Banner-bounded reference entries are part of a graft's own
    // cause block — they're either declared (active graft, no lint
    // needed) or about to be orphan-pruned by `inject` (inactive
    // graft, false-positive flag if the lint fired). Skip those line
    // ranges so the lint only flags references the developer added
    // outside any graft-inject banner.
    let banner_lines = banner_line_set(lines);
    let mut findings: Vec<LintFinding> = Vec::new();
    for member in extract_cause_union_members(lines) {
        let CauseUnionMember::Reference { name, line } = member else {
            continue;
        };
        if banner_lines.contains(&line) {
            continue;
        }
        if !declared.contains(name.as_str()) {
            findings.push(LintFinding::UnresolvedCauseReference { line, name });
        }
    }
    findings
}

/// Build the set of 1-indexed line numbers that fall inside a
/// `::  graft-inject:<...>:begin / :end` banner pair. The `begin` and
/// `end` lines themselves are included so a reference that
/// accidentally lands on a banner line is also skipped.
fn banner_line_set(lines: &[String]) -> HashSet<usize> {
    let mut out: HashSet<usize> = HashSet::new();
    let mut in_banner = false;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let is_marker = trimmed.starts_with("::") && trimmed.contains("graft-inject:");
        if is_marker {
            if trimmed.contains(":begin ") || trimmed.ends_with(":begin") {
                in_banner = true;
                out.insert(i + 1);
                continue;
            }
            if trimmed.ends_with(":end") {
                out.insert(i + 1);
                in_banner = false;
                continue;
            }
        }
        if in_banner {
            out.insert(i + 1);
        }
    }
    out
}

/// Walk from `+$ cause $%(...)` open to its closing `==`, emitting
/// `(tag, 1-indexed line)` for every `[%<tag> ...]` variant. Banner
/// content IS included — internal-collision lint cares about literal
/// duplicates regardless of whether they came from domain or graft
/// injection.
fn extract_all_cause_variants(lines: &[String]) -> Vec<(String, usize)> {
    extract_cause_union_members(lines)
        .into_iter()
        .filter_map(|m| match m {
            CauseUnionMember::Literal { tag, line } => Some((tag, line)),
            CauseUnionMember::Reference { .. } => None,
        })
        .collect()
}

/// Parse the `+$ cause` definition in `lines`. Three shapes accepted:
///   1. `+$ cause $%(...)` — explicit union; emit one member per
///      variant.
///   2. `+$ cause <type-name>` — single-line alias; emit one
///      Reference for the alias target.
///   3. `+$ cause` then `$%(...)` on a later line — same as shape 1
///      but split across lines.
pub(crate) fn extract_cause_union_members(lines: &[String]) -> Vec<CauseUnionMember> {
    let mut out = Vec::new();
    let Some(open_idx) = lines.iter().position(|l| {
        let t = l.trim();
        t.starts_with("+$") && t.contains("cause")
    }) else {
        return out;
    };

    // Detect shape 2 (`+$ cause <type-name>` alias) by inspecting the
    // tokens after `cause` on the open line.
    let cause_line = lines[open_idx].trim();
    let after_cause: Vec<&str> = cause_line
        .split_whitespace()
        .skip_while(|t| *t != "cause")
        .skip(1)
        .collect();
    if let Some(first) = after_cause.first() {
        if !first.starts_with("$%") && !first.starts_with("[%") && !first.is_empty() {
            let name: String = first
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect();
            if !name.is_empty() {
                out.push(CauseUnionMember::Reference {
                    name,
                    line: open_idx + 1,
                });
                return out;
            }
        }
    }

    // Shape 1 / 3: scan for `$%`, then collect members until `==`.
    let mut started = false;
    for (i, line) in lines.iter().enumerate().skip(open_idx) {
        let trimmed = line.trim();
        if !started {
            if let Some(after) = trimmed.find("$%") {
                started = true;
                let rest = &trimmed[after + 2..];
                push_cause_member(rest, i + 1, &mut out);
            }
            continue;
        }
        if trimmed == "==" {
            break;
        }
        if trimmed.starts_with("::") {
            continue;
        }
        push_cause_member(trimmed, i + 1, &mut out);
    }
    out
}

/// Append a `CauseUnionMember` parsed from `s`. `[%<tag>` becomes a
/// Literal; bare identifiers become a Reference. Empty strings are
/// no-ops.
fn push_cause_member(s: &str, line: usize, out: &mut Vec<CauseUnionMember>) {
    let t = s.trim();
    if t.is_empty() {
        return;
    }
    if let Some(tag) = bracket_tag(t) {
        out.push(CauseUnionMember::Literal { tag, line });
        return;
    }
    let name: String = t
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    if !name.is_empty() {
        out.push(CauseUnionMember::Reference { name, line });
    }
}

/// Walk from `+$ versioned-state $:(...)` open to close, emit
/// `(field, 1-indexed line)` for every `<name>=<type>` line.
fn extract_all_state_fields(lines: &[String]) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    let Some(open_idx) = lines.iter().position(|l| {
        let t = l.trim();
        t.starts_with("+$") && (t.contains("state") || t.contains("versioned-state"))
    }) else {
        return out;
    };
    let mut started = false;
    for (i, line) in lines.iter().enumerate().skip(open_idx) {
        let trimmed = line.trim();
        if !started {
            if trimmed.contains("$:") {
                started = true;
            }
            continue;
        }
        if trimmed == "==" {
            break;
        }
        if trimmed.starts_with("::") || trimmed.is_empty() {
            continue;
        }
        if let Some(eq) = trimmed.find('=') {
            let name: String = trimmed[..eq]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect();
            if !name.is_empty() {
                out.push((name, i + 1));
            }
        }
    }
    out
}

/// Read `[%<tag>` prefix and return the tag. None when the input
/// doesn't start with `[%` or the tag is empty. Sibling of
/// `push_bracket_tag` — that one mutates an output Vec, this one
/// returns by value.
fn bracket_tag(s: &str) -> Option<String> {
    let trimmed = s.trim_start();
    let rest = trimmed.strip_prefix("[%")?;
    let tag: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    if tag.is_empty() { None } else { Some(tag) }
}

// ---------------------------------------------------------------
// Unified printer
// ---------------------------------------------------------------

/// One stderr line for a single finding, prefixed with
/// `  {severity}: {kind}: `. The severity word follows rustc / gcc
/// convention so terminal scrapers picking up `error:` / `warning:`
/// markers route correctly; the kind prefix lets `grep '<kind>:'` count
/// findings by kind without scraping the body. `path` provides context
/// for findings that don't embed a source path of their own; `policy`
/// resolves per-lint overrides (CLI + nockapp.toml) over the variant
/// default.
pub(crate) fn print_lint_finding(f: &LintFinding, path: &Path, policy: &LintPolicy) {
    let kind = f.kind_label();
    let sev = policy.effective(f).word();
    match f {
        LintFinding::WeldFriction { line, text, .. } => {
            eprintln!("  {sev}: {kind}: line {line}: {text}");
        }
        LintFinding::BareTildeAmbiguity { line, arm } => {
            eprintln!(
                "  {sev}: {kind}: {}:{line} — domain arm `%{arm}` body ends with bare `~` line",
                path.display(),
            );
        }
        LintFinding::Collision {
            kind: ck,
            name,
            owners,
        } => {
            let ck_str = match ck {
                CollisionKind::CauseTag => "cause-tag",
                CollisionKind::StateField => "state-field",
            };
            eprintln!(
                "  {sev}: {kind}: {ck_str} `{name}` declared by: {}",
                owners.join(", "),
            );
        }
        LintFinding::TransitiveImport {
            source,
            rune,
            name,
            target,
            reachable_from,
        } => {
            eprintln!(
                "  {sev}: {kind}: {}: {rune} {name} → {} (NOT FOUND)",
                source.display(),
                target.display(),
            );
            for parent in reachable_from {
                eprintln!("      reachable from: {}", parent.display());
            }
        }
        LintFinding::InternalDupe {
            kind: dk,
            name,
            lines,
        } => {
            let dk_str = match dk {
                InternalDupeKind::CauseTag => "cause-tag",
                InternalDupeKind::StateField => "state-field",
            };
            let line_list: Vec<String> = lines.iter().map(usize::to_string).collect();
            eprintln!(
                "  {sev}: {kind}: duplicate {dk_str} `{name}` at lines {}",
                line_list.join(", "),
            );
        }
        LintFinding::UnresolvedCauseReference { line, name } => {
            eprintln!(
                "  {sev}: {kind}: {}:{line} — `+$ cause` references `{name}`, but no graft's [graft.types].cause declares that type",
                path.display(),
            );
        }
    }
}

/// Group `findings` by [`LintFinding::kind_label`] in canonical order
/// (weld-friction → bare-tilde-ambiguity → collision →
/// transitive-imports → internal-dupes), print each finding via
/// [`print_lint_finding`], then emit the per-lint remediation hint
/// once per non-empty group. The hint strings have been tuned through
/// the dogfood rounds and cross-link to zkvesl-docs — they are kept
/// here verbatim.
pub(crate) fn print_lint_findings(
    findings: &[LintFinding],
    path: &Path,
    policy: &LintPolicy,
) {
    if findings.is_empty() {
        return;
    }
    for kind in KIND_ORDER {
        let group: Vec<&LintFinding> = findings
            .iter()
            .filter(|f| f.kind_label() == *kind)
            .collect();
        if group.is_empty() {
            continue;
        }
        for f in &group {
            print_lint_finding(f, path, policy);
        }
        print_remediation_hint(kind);
    }
}

const KIND_ORDER: &[&str] = &[
    "weld-friction",
    "bare-tilde-ambiguity",
    "collision",
    "transitive-imports",
    "internal-dupes",
    "unresolved-cause-reference",
];

/// Emit the per-lint remediation hint block after a group of findings
/// of that kind. The text is the same dogfood-tuned copy the prior
/// per-kind printers shipped — only the dispatch is unified.
fn print_remediation_hint(kind: &str) {
    match kind {
        "weld-friction" => {
            eprintln!(
                "    cross-graft `(weld a b)` over these bindings will nest-fail. \
                 widen each to `(list effect)` so the typed union absorbs each graft's effect."
            );
            eprintln!(
                "    see zkvesl-docs §\"Composing two graft arms in one domain cause\" \
                 (/guides/grafting#composing-two-graft-arms-in-one-domain-cause)"
            );
        }
        "bare-tilde-ambiguity" => {
            eprintln!(
                "    graft-inject's chain-rebuilder may mistake this for the peek-chain"
            );
            eprintln!("    terminator. Refactor to one of:");
            eprintln!("      `(list effect)`~");
            eprintln!("      ^- (list effect) ~");
        }
        "collision" => {
            eprintln!(
                "    duplicate names compose into one cause $% / state record."
            );
            eprintln!(
                "    Disambiguate via manifest rename, profile-letter suffix, or"
            );
            eprintln!("    domain shadowing.");
        }
        "transitive-imports" => {
            eprintln!(
                "    hoonc eager-parses hoon/common/ regardless of import-graph"
            );
            eprintln!(
                "    reachability; unsatisfied edges leave hoonc exit 0 with no"
            );
            eprintln!(
                "    out.jam (the \"no panic!\" silent-fail). Either add the missing"
            );
            eprintln!(
                "    target file or strip the offending file from hoon/common/."
            );
        }
        "internal-dupes" => {
            eprintln!(
                "    literal duplicates in the composed +$ cause $%(...) or"
            );
            eprintln!(
                "    +$ versioned-state $:(...) — hoonc accepts whichever wins"
            );
            eprintln!(
                "    lexically (mint-lost) or fires nest-fail on duplicate fields."
            );
            eprintln!(
                "    Rename, merge into a tagged sum, or distinguish by argument shape."
            );
        }
        "unresolved-cause-reference" => {
            eprintln!(
                "    the cause-tag codegen drops the contribution silently and"
            );
            eprintln!(
                "    hoonc later surfaces it as `find . <name>-cause`. Either"
            );
            eprintln!(
                "    add the missing manifest to --lib-dir (and ensure its"
            );
            eprintln!(
                "    [graft.types].cause matches the referenced name), or remove"
            );
            eprintln!(
                "    the reference from the kernel's `+$ cause` union."
            );
        }
        _ => {}
    }
}

// ---------------------------------------------------------------
// JSON projection (run_lint --json)
// ---------------------------------------------------------------

#[derive(Serialize)]
struct BareTildeRecord<'a> {
    severity: LintSeverity,
    line: usize,
    arm: &'a str,
}

#[derive(Serialize)]
struct CollisionRecord<'a> {
    severity: LintSeverity,
    kind: CollisionKind,
    name: &'a str,
    owners: &'a [String],
}

#[derive(Serialize)]
struct TransitiveImportRecord<'a> {
    severity: LintSeverity,
    source: &'a Path,
    rune: &'a str,
    name: &'a str,
    target: &'a Path,
    reachable_from: &'a [PathBuf],
}

#[derive(Serialize)]
struct InternalDupeRecord<'a> {
    severity: LintSeverity,
    kind: InternalDupeKind,
    name: &'a str,
    lines: &'a [usize],
}

#[derive(Serialize)]
struct UnresolvedCauseReferenceRecord<'a> {
    severity: LintSeverity,
    line: usize,
    name: &'a str,
}

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
    use crate::manifest::{Block, GraftBlocks, GraftTypes};

    /// Helper: assert exactly one finding and unwrap its
    /// `BareTildeAmbiguity` variant, panicking with full state on
    /// mismatch. The pattern-match style is the new shape Phase 1
    /// introduced; the helper keeps the test bodies focused.
    fn expect_bare_tilde(findings: &[LintFinding]) -> (usize, &str) {
        assert_eq!(findings.len(), 1, "expected 1 finding, got {findings:#?}");
        match &findings[0] {
            LintFinding::BareTildeAmbiguity { line, arm } => (*line, arm.as_str()),
            other => panic!("expected BareTildeAmbiguity, got {other:?}"),
        }
    }

    // ---------- bare-tilde lint ----------

    /// A domain `%ping` arm whose body
    /// is `^- (list effect)` then a bare `~` line should trip the
    /// lint. The `find_last_bare_tilde` scan would otherwise pick
    /// this `~` up as the peek-chain terminator.
    #[test]
    fn bare_tilde_lint_flags_ping_arm() {
        let fixture = r#"?-    -.u.act
    %ping
  :_  state
  ^-  (list effect)
  ~
    %quiet
  [~ state]
    ::  nockup:poke
=="#;
        let lines: Vec<String> = fixture.lines().map(String::from).collect();
        let findings = lint_bare_tilde_ambiguity(&lines);
        let (line, arm) = expect_bare_tilde(&findings);
        assert_eq!(arm, "ping");
        // Line 5 is the `~` (1-indexed; line 1 is the `?-` switch).
        assert_eq!(line, 5);
    }

    /// Workaround form (`(list effect)~` on one line) is safe — no
    /// bare `~` line, no finding.
    #[test]
    fn bare_tilde_lint_clears_one_line_workaround() {
        let fixture = r#"?-    -.u.act
    %ping
  :_  state
  `(list effect)`~
    %quiet
  [~ state]
=="#;
        let lines: Vec<String> = fixture.lines().map(String::from).collect();
        let findings = lint_bare_tilde_ambiguity(&lines);
        assert!(
            findings.is_empty(),
            "workaround form should not flag, got {findings:#?}"
        );
    }

    /// Graft-injected arms use bare `~` legitimately (it's their
    /// chain terminator). The lint must skip lines inside
    /// `graft-inject:<X>:begin/:end` banner pairs.
    #[test]
    fn bare_tilde_lint_skips_graft_injected_arms() {
        let fixture = r#"?-    -.u.act
::  graft-inject:settle-graft:poke:begin sha256:deadbeef
    %settle-do
  :_  state
  ~
::  graft-inject:settle-graft:poke:end
    %ping
  :_  state
  `(list effect)`~
=="#;
        let lines: Vec<String> = fixture.lines().map(String::from).collect();
        let findings = lint_bare_tilde_ambiguity(&lines);
        assert!(
            findings.is_empty(),
            "graft-injected bodies must be skipped, got {findings:#?}"
        );
    }

    /// Without a `?-  -.u.act` switch, the lint is a no-op.
    #[test]
    fn bare_tilde_lint_no_switch_no_findings() {
        let fixture = "++  peek\n  ~\n--";
        let lines: Vec<String> = fixture.lines().map(String::from).collect();
        let findings = lint_bare_tilde_ambiguity(&lines);
        assert!(findings.is_empty());
    }

    // ---------- collision-check lint ----------

    /// Build a synthetic graft with named cause tags and state fields
    /// for collision-check tests. The block bodies follow the canonical
    /// shape: state body is `<field>=<type>`, poke body has bare
    /// `%<tag>` arm headers separated by `::`.
    fn synthetic_collision_graft(
        name: &str,
        cause_tags: &[&str],
        state_fields: &[&str],
    ) -> Graft {
        let mut poke_body = String::new();
        for tag in cause_tags {
            poke_body.push_str("::\n  %");
            poke_body.push_str(tag);
            poke_body.push_str("\n[~ state]\n");
        }
        let state_body = state_fields
            .iter()
            .map(|f| format!("{f}=@"))
            .collect::<Vec<_>>()
            .join("\n");
        Graft {
            name: name.to_string(),
            version: "0.1.0".to_string(),
            priority: 50,
            after: vec![],
            blocks: GraftBlocks {
                imports: None,
                state: if state_fields.is_empty() {
                    None
                } else {
                    Some(Block { body: state_body })
                },
                cause: None,
                poke_prelude: None,
                poke: Some(Block { body: poke_body }),
                poke_postlude: None,
                peek: None,
            },
            types: None,
            gates: None,
            schema_version: None,
            sha256: "0".repeat(64),
        }
    }

    /// Helper: collect every Collision finding into (kind, name, owners)
    /// triples for set-style assertions.
    fn collisions(findings: &[LintFinding]) -> Vec<(CollisionKind, &str, &[String])> {
        findings
            .iter()
            .filter_map(|f| match f {
                LintFinding::Collision { kind, name, owners } => {
                    Some((*kind, name.as_str(), owners.as_slice()))
                }
                _ => None,
            })
            .collect()
    }

    /// queue-graft and pipeline-graft both
    /// declare `%enqueue-job`. Cross-graft cause-tag collision should
    /// fire one finding naming both grafts as owners.
    #[test]
    fn collision_lint_flags_cross_graft_cause_tag() {
        let queue = synthetic_collision_graft(
            "queue-graft",
            &["enqueue-job", "drain-jobs"],
            &["queue"],
        );
        let pipeline = synthetic_collision_graft(
            "pipeline-graft",
            &["enqueue-job", "ack-job"],
            &["pipeline"],
        );
        let findings = lint_collision_check(&[queue, pipeline], &[]);
        let cs = collisions(&findings);
        assert_eq!(cs.len(), 1);
        let (kind, name, owners) = cs[0];
        assert_eq!(kind, CollisionKind::CauseTag);
        assert_eq!(name, "enqueue-job");
        assert!(owners.contains(&"queue-graft".to_string()));
        assert!(owners.contains(&"pipeline-graft".to_string()));
    }

    /// Domain declares `entries` field and a
    /// graft also exposes `entries`. The lint should fire one finding
    /// with one owner being `(domain)`.
    #[test]
    fn collision_lint_flags_domain_vs_graft_state() {
        let audit = synthetic_collision_graft("audit-graft", &["log-entry"], &["entries"]);
        let domain = vec![
            "+$  versioned-state".to_string(),
            "  $:  %v1".to_string(),
            "      entries=(list @t)".to_string(),
            "      ::  nockup:state".to_string(),
            "  ==".to_string(),
        ];
        let findings = lint_collision_check(&[audit], &domain);
        let cs = collisions(&findings);
        assert_eq!(cs.len(), 1);
        let (kind, name, owners) = cs[0];
        assert_eq!(kind, CollisionKind::StateField);
        assert_eq!(name, "entries");
        assert!(owners.contains(&"(domain)".to_string()));
        assert!(owners.contains(&"audit-graft".to_string()));
    }

    /// Two grafts with disjoint tag sets and disjoint field sets
    /// must produce zero findings. Sanity check that the lint isn't
    /// over-flagging.
    #[test]
    fn collision_lint_clears_disjoint_grafts() {
        let queue = synthetic_collision_graft("queue-graft", &["queue-push"], &["queue"]);
        let counter =
            synthetic_collision_graft("counter-graft", &["counter-inc"], &["counter"]);
        let findings = lint_collision_check(&[queue, counter], &[]);
        assert!(
            findings.is_empty(),
            "disjoint grafts must not collide, got {findings:#?}"
        );
    }

    /// `extract_domain_cause_tags` skips the placeholder `[%cause ~]`
    /// variant when the codegen builds its tag set — the placeholder
    /// is a syntactic anchor, not a real cause.
    #[test]
    fn codegen_skips_placeholder_cause() {
        // The codegen filter lives in run_codegen_kernel_cause_tags;
        // simulate the filtering here so the test runs without I/O.
        let domain_lines: Vec<String> = "+$  cause\n  $%  [%cause ~]\n      [%real-tag @t]\n      ::  nockup:cause\n  =="
            .lines()
            .map(String::from)
            .collect();
        let raw: Vec<String> = extract_domain_cause_tags(&domain_lines);
        assert!(raw.contains(&"cause".to_string()));
        let filtered: Vec<&String> = raw.iter().filter(|t| t.as_str() != "cause").collect();
        assert_eq!(filtered, vec![&"real-tag".to_string()]);
    }

    /// Domain cause-tag colliding with a graft cause-tag fires a
    /// CauseTag finding with `(domain)` listed alongside the graft.
    #[test]
    fn collision_lint_flags_domain_vs_graft_cause() {
        let queue = synthetic_collision_graft("queue-graft", &["queue-push"], &["queue"]);
        let domain = vec![
            "+$  cause".to_string(),
            "  $%  [%queue-push payload=@]".to_string(),
            "      ::  nockup:cause".to_string(),
            "  ==".to_string(),
        ];
        let findings = lint_collision_check(&[queue], &domain);
        let cs = collisions(&findings);
        assert!(
            cs.iter().any(|(kind, name, owners)| *kind == CollisionKind::CauseTag
                && *name == "queue-push"
                && owners.contains(&"(domain)".to_string())
                && owners.contains(&"queue-graft".to_string())),
            "expected domain-vs-graft cause-tag finding, got {findings:#?}"
        );
    }

    // ---------- unresolved cause-reference lint ----------

    /// Helper: build a graft with `[graft.types].cause = <name>` so the
    /// lint can resolve a reference against it. The blocks are kept
    /// minimal — only the type declaration matters for this lint.
    fn synthetic_graft_with_cause_type(name: &str, cause_type: &str) -> Graft {
        Graft {
            name: name.to_string(),
            version: "0.1.0".to_string(),
            priority: 50,
            after: vec![],
            blocks: GraftBlocks {
                imports: None,
                state: None,
                cause: None,
                poke_prelude: None,
                poke: None,
                poke_postlude: None,
                peek: None,
            },
            types: Some(GraftTypes {
                effect: None,
                cause: Some(cause_type.to_string()),
            }),
            gates: None,
            schema_version: None,
            sha256: "0".repeat(64),
        }
    }

    /// `+$ cause` cites `settle-cause` and no discovered graft declares
    /// `[graft.types].cause = "settle-cause"` — fire one finding naming
    /// the unresolved type.
    #[test]
    fn unresolved_cause_reference_flags_missing_type() {
        let domain: Vec<String> = "+$  cause\n  $%  [%cause ~]\n      settle-cause\n      ::  nockup:cause\n  =="
            .lines()
            .map(String::from)
            .collect();
        let findings = lint_unresolved_cause_references(&[], &domain);
        assert_eq!(findings.len(), 1, "expected 1 finding, got {findings:#?}");
        match &findings[0] {
            LintFinding::UnresolvedCauseReference { name, .. } => {
                assert_eq!(name, "settle-cause");
            }
            other => panic!("expected UnresolvedCauseReference, got {other:?}"),
        }
    }

    /// When the active set declares the referenced type, no finding
    /// fires. Sanity check that the lint isn't over-flagging.
    #[test]
    fn unresolved_cause_reference_clears_when_declared() {
        let domain: Vec<String> = "+$  cause\n  $%  [%cause ~]\n      settle-cause\n      ::  nockup:cause\n  =="
            .lines()
            .map(String::from)
            .collect();
        let settle = synthetic_graft_with_cause_type("settle-graft", "settle-cause");
        let findings = lint_unresolved_cause_references(&[settle], &domain);
        assert!(
            findings.is_empty(),
            "declared cause-type must not trigger the lint, got {findings:#?}"
        );
    }

    /// Inline `[%<tag> ...]` literals are not references — the lint
    /// only flags bare type-name members of the union. Pure-literal
    /// unions must produce zero findings.
    #[test]
    fn unresolved_cause_reference_ignores_literal_members() {
        let domain: Vec<String> = "+$  cause\n  $%  [%cause ~]\n      [%submit-artifact id=@]\n      ::  nockup:cause\n  =="
            .lines()
            .map(String::from)
            .collect();
        let findings = lint_unresolved_cause_references(&[], &domain);
        assert!(findings.is_empty());
    }

    /// References inside a `graft-inject:<X>:cause:begin/:end` banner
    /// belong to a graft's own block. They're either declared by an
    /// active graft (resolved) or about to be orphan-pruned by the
    /// next inject pass (transient state). Either way, flagging a
    /// banner-bounded reference is a false positive — the lint must
    /// only fire on developer-added references outside any banner.
    #[test]
    fn unresolved_cause_reference_skips_banner_bounded() {
        let domain: Vec<String> = "+$  cause\n  $%  [%cause ~]\n      ::  graft-inject:validate-graft:cause:begin sha256:deadbeef\n      validate-cause\n      ::  graft-inject:validate-graft:cause:end\n      ::  nockup:cause\n  =="
            .lines()
            .map(String::from)
            .collect();
        let findings = lint_unresolved_cause_references(&[], &domain);
        assert!(
            findings.is_empty(),
            "banner-bounded references must be skipped, got {findings:#?}"
        );
    }

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
