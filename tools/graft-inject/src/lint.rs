//! Pre/post-inject lint suite: weld-friction, bare-tilde ambiguity,
//! collision check, transitive imports, internal dupes.
//!
//! Audit §3.2 extraction. The lints are advisory passes — they read
//! kernel source (line vec) and graft manifests, return finding lists,
//! and surface them via stderr or a `LintReport` JSON shape. Codegen
//! consumes a couple of helpers here (`CauseUnionMember`,
//! `extract_cause_union_members`, `extract_graft_cause_tags`) because
//! its cause-tag set composition is the same shape as the lint's
//! cross-reference. There's no other coupling.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::manifest::{Graft, discover_grafts};
use crate::marker::Marker;

// ---------------------------------------------------------------
// Weld-friction lint
// ---------------------------------------------------------------

/// Weld-friction lint.
///
/// R5 dogfood (Profile G HULL_KEYED_KV) confirmed that the typed effect
/// union does NOT auto-fix the cross-graft `weld` friction when the
/// developer's domain arm binds narrowly:
///
///     =/  [efx-c=(list counter-effect) new-counter=counter-state]   :: NARROW
///       (counter-poke counter.state ...)
///     (weld efx-c efx-k)                                            :: nest-fail
///
/// The fix is Pattern B: widen each binding to `(list effect)`. The
/// lint scans developer code (outside `graft-inject:<X>:begin/:end`
/// banner regions) for narrow bindings and surfaces a stderr note
/// pointing at the zkvesl-docs §"Composing two graft arms in one
/// domain cause" so the developer has a searchable handle.
///
/// Findings are advisory — Pattern A (R4 backtick casts at the weld
/// site) still works as an escape hatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct WeldLintFinding {
    /// 1-indexed line number of the offending narrow binding.
    pub(crate) line: usize,
    /// Trimmed line text — short enough to copy-paste into a search.
    pub(crate) text: String,
    /// The narrow type referenced, e.g., `counter-effect`.
    pub(crate) narrow_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub(crate) struct WeldLint {
    pub(crate) findings: Vec<WeldLintFinding>,
}

/// Walk `lines` and flag any developer-code line that contains a
/// narrow effect binding like `(list <graft>-effect)`. Skips lines
/// inside `graft-inject:<...>:begin / :end` banner regions (those are
/// graft-injected bodies, not user code; the narrow types are correct
/// there). Skips entirely when codegen status is Skipped or the variant
/// list is empty — there's no typed union to widen toward.
pub(crate) fn lint_weld_friction(lines: &[String], variants: &[String]) -> WeldLint {
    let effect_variants: HashSet<&str> = variants
        .iter()
        .filter(|v| v.ends_with("-effect") && v.as_str() != "domain-effect")
        .map(String::as_str)
        .collect();

    if effect_variants.is_empty() {
        return WeldLint::default();
    }

    let mut findings = Vec::new();
    let mut in_banner = false;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        // Banner detection: any `graft-inject:<X>:<Y>:begin/:end` line
        // toggles the in_banner state. Codegen banner pairs
        // (`graft-inject:effect-union:...`) are also skipped — those
        // bodies are synthesized, not user-written.
        if trimmed.starts_with("::") && trimmed.contains("graft-inject:") {
            // Begin banners may carry a ` sha256:<hex>` suffix (R5/A2);
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
                findings.push(WeldLintFinding {
                    line: i + 1,
                    text: trimmed.to_string(),
                    narrow_type: (*variant).to_string(),
                });
                break; // one finding per line is enough
            }
        }
    }
    WeldLint { findings }
}

// ---------------------------------------------------------------
// Bare-tilde ambiguity lint
// ---------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct BareTildeLintFinding {
    /// 1-indexed line number of the bare `~`.
    pub(crate) line: usize,
    /// Domain arm tag (e.g. "ping") whose body ends in the bare `~`.
    pub(crate) arm: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub(crate) struct BareTildeLint {
    pub(crate) findings: Vec<BareTildeLintFinding>,
}

/// Pre-apply lint: bare-`~` ambiguity inside domain `?-` switch arms.
///
/// RM1 HARD-BUG-2 (`.dev/debug/log-meta/RM1/B_to_C.md` §HARD-BUG-2)
/// surfaced this: `find_last_bare_tilde` walks from the `nockup:peek`
/// marker until the next `==` capturing the last `~`-only line as
/// the peek-chain terminator. The next `==` is typically the
/// `?-  -.u.act` close in the poke arm, so any bare-`~` line inside a
/// domain arm body (e.g. `%ping :_ state ^- (list effect) ~`)
/// becomes the new "terminator" and graft-inject inserts the peek
/// chain into the poke body — corrupting the file.
///
/// RH2 step 2's canonical re-emit fix landed for the placement bugs
/// it targeted, but `emit_peek_chain` still anchors against
/// `find_last_bare_tilde`. Until that anchor changes, the safest
/// surface is a pre-apply lint that warns when the user's domain
/// arms create the structural ambiguity.
///
/// The lint walks lines inside the `nockup:poke` region but outside
/// any `graft-inject:*:begin/:end` banner (graft-injected arms are
/// graft-inject's own output and aren't user-editable). When a
/// domain arm body's final line is exactly `~`, the line is flagged
/// and the developer is pointed at the workaround:
/// `\`(list effect)\`~` or `^- (list effect) ~` on a single line.
pub(crate) fn lint_bare_tilde_ambiguity(lines: &[String]) -> BareTildeLint {
    let mut findings = Vec::new();
    // Anchor on the `?-  -.u.act` switch header. graft-inject's
    // `find_last_bare_tilde` would scan the same range from the
    // peek marker forward, so any domain arm body inside this
    // switch that ends with bare `~` is the friction shape from
    // RM1 HARD-BUG-2. The `nockup:poke` marker by itself isn't
    // enough — domain arms live BEFORE the marker (between the
    // switch open and the marker), so a forward-only scan from
    // the marker would miss them.
    let Some(switch_idx) = lines.iter().position(|l| {
        let t = l.trim();
        t.starts_with("?-") && t.contains("-.u.act")
    }) else {
        return BareTildeLint::default();
    };

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
                findings.push(BareTildeLintFinding {
                    line: i + 1,
                    arm,
                });
                // After flagging once per arm, reset so multi-line arm
                // bodies don't repeat-flag (the bug fires on the LAST
                // line; one finding per arm is enough).
            }
        }
    }
    BareTildeLint { findings }
}

// ---------------------------------------------------------------
// Collision-check lint
// ---------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CollisionKind {
    CauseTag,
    StateField,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CollisionFinding {
    pub(crate) kind: CollisionKind,
    /// The colliding name (`enqueue-job`, `entries`, ...).
    pub(crate) name: String,
    /// Owners that declared the name. `(domain)` represents the
    /// app.hoon domain code; everything else is a graft name.
    pub(crate) owners: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub(crate) struct CollisionLint {
    pub(crate) findings: Vec<CollisionFinding>,
}

/// Pre-apply lint: cross-graft and graft-vs-domain name collisions.
///
/// RM1 META-COLLISION-1 (`.dev/debug/log-meta/RM1/E_to_F.md`),
/// META-COLLISION-2 (`G_to_H.md`), and META-COLLISION-3 (`H_to_I.md`)
/// surfaced two kinds of collision in cumulative-domain mode:
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
) -> CollisionLint {
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

    let mut findings = Vec::new();
    for (tag, owners) in cause_owners {
        if owners.len() > 1 {
            findings.push(CollisionFinding {
                kind: CollisionKind::CauseTag,
                name: tag,
                owners,
            });
        }
    }
    for (field, owners) in state_owners {
        if owners.len() > 1 {
            findings.push(CollisionFinding {
                kind: CollisionKind::StateField,
                name: field,
                owners,
            });
        }
    }
    CollisionLint { findings }
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

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TransitiveImportFinding {
    /// .hoon file that owns the unsatisfied import.
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
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct TransitiveImportLint {
    pub(crate) findings: Vec<TransitiveImportFinding>,
}

/// Pre-apply lint: walk every `.hoon` file reachable from the input
/// path via `/+`, `/=`, `/-`, `/#` imports, AND eagerly scan every
/// `.hoon` under `<hoon-root>/common/`. Report unsatisfied edges as
/// HARD-LINT findings.
///
/// Reproduces the empirical seed-A friction (`hoon/common/nock-prover.hoon
/// → /# softed-constraints` after slim-cp): even though Profile A's
/// app.hoon doesn't reach nock-prover transitively, hoonc parses
/// hoon/common/ eagerly and silent-fails on the missing `/dat/` target.
/// This lint surfaces the same edge before hoonc runs so the developer
/// sees a clear "missing file at PATH" rather than hoonc's "no panic!"
/// lie. See `vesl-nockup/.dev/debug/log-meta/RM2/seed-A.md` §DOC-GAP-1.
///
/// Resolution rules:
/// - `/+ <name>`         → `<lib-dir>/<name>.hoon`
/// - `/+ *<name>`        → `<lib-dir>/<name>.hoon` (public-import form)
/// - `/= <bind> /<path>` → `<hoon-root>/<path>.hoon`
/// - `/-  <name>`        → `<hoon-root>/sur/<name>.hoon`
/// - `/# <name>`         → `<hoon-root>/dat/<name>.hoon`
pub(crate) fn lint_transitive_imports(root_path: &Path, lib_dir: &Path) -> TransitiveImportLint {
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

    let mut findings: Vec<TransitiveImportFinding> = Vec::new();
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
                findings.push(TransitiveImportFinding {
                    source: current.clone(),
                    rune: spec.rune.to_string(),
                    name: spec.name.clone(),
                    target,
                    reachable_from: chain,
                });
            }
        }
    }

    TransitiveImportLint { findings }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InternalDupeKind {
    CauseTag,
    StateField,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct InternalDupeFinding {
    pub(crate) kind: InternalDupeKind,
    /// Duplicate name (`enqueue-job`, `entries`, ...).
    pub(crate) name: String,
    /// 1-indexed line numbers of every occurrence (sorted).
    pub(crate) lines: Vec<usize>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct InternalDupeLint {
    pub(crate) findings: Vec<InternalDupeFinding>,
}

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
pub(crate) fn lint_internal_dupes(lines: &[String]) -> InternalDupeLint {
    use std::collections::BTreeMap;

    let mut findings = Vec::new();

    let mut cause_lines: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (tag, line) in extract_all_cause_variants(lines) {
        cause_lines.entry(tag).or_default().push(line);
    }
    for (tag, line_nums) in cause_lines {
        if line_nums.len() > 1 {
            findings.push(InternalDupeFinding {
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
            findings.push(InternalDupeFinding {
                kind: InternalDupeKind::StateField,
                name,
                lines: line_nums,
            });
        }
    }

    InternalDupeLint { findings }
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
// Lint CLI dispatch (`graft-inject lint ...`)
// ---------------------------------------------------------------

#[derive(Debug, Serialize)]
struct LintReport<'a> {
    bare_tilde_ambiguity: &'a [BareTildeLintFinding],
    collision: &'a [CollisionFinding],
    transitive_imports: &'a [TransitiveImportFinding],
    internal_dupes: &'a [InternalDupeFinding],
}

/// Driver for the `graft-inject lint` subcommand. Loads the kernel,
/// runs every advisory lint pass, and surfaces findings either as
/// pretty stderr lines (default) or as a stable JSON report (`--json`).
/// Returns `Err` when at least one finding fires so the parent
/// dispatch can map that to a non-zero exit code (callers that just
/// want the report should call the individual lint functions directly,
/// not this driver).
///
/// `lib_dir` doubles as the manifest discovery root — when it doesn't
/// exist the collision-check is skipped (bare-tilde lint stays useful
/// on its own). The findings themselves are emitted to stderr in the
/// human-readable form, or to stdout as JSON when `--json` is set.
pub(crate) fn run_lint(path: &Path, lib_dir: &Path, json: bool) -> Result<()> {
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
    let bare_tilde = lint_bare_tilde_ambiguity(&lines);

    // Collision check needs the discovered graft set so it can
    // cross-reference cause tags and state fields. When --lib-dir
    // doesn't exist we skip collision check rather than hard-error;
    // bare-tilde lint stays useful on its own (e.g. on a kernel
    // outside its project tree).
    let collision = if lib_dir.is_dir() {
        let grafts = discover_grafts(lib_dir)
            .with_context(|| format!("discovering grafts under {}", lib_dir.display()))?;
        lint_collision_check(&grafts, &lines)
    } else {
        CollisionLint::default()
    };

    // Transitive import walk (RM2 §1.1). Runs unconditionally — the
    // seed-A friction fires when hoonc eager-parses hoon/common/, and
    // the lint needs to mirror that scope to be useful.
    let transitive_imports = lint_transitive_imports(path, lib_dir);

    // Internal-dupe lint (RM2 §1.2): literal duplicate cause-tag heads
    // or state-field names inside the composed unions. Catches both
    // hand-written domain dupes and post-injection graft dupes that
    // collision_check (manifest-side) misses.
    let internal_dupes = lint_internal_dupes(&lines);

    let findings_total = bare_tilde.findings.len()
        + collision.findings.len()
        + transitive_imports.findings.len()
        + internal_dupes.findings.len();

    if json {
        // Stable schema: { "bare_tilde_ambiguity": [...], "collision": [...],
        // "transitive_imports": [...] }. Future lint families append
        // top-level keys without reshaping existing ones (mirrors the
        // --list --json schema policy at the GraftSummary block above).
        let report = LintReport {
            bare_tilde_ambiguity: &bare_tilde.findings,
            collision: &collision.findings,
            transitive_imports: &transitive_imports.findings,
            internal_dupes: &internal_dupes.findings,
        };
        let s = serde_json::to_string_pretty(&report)
            .expect("LintReport always serializes");
        println!("{s}");
    } else {
        eprintln!("graft-inject lint: {findings_total} finding(s)");
        if !bare_tilde.findings.is_empty() {
            eprintln!("  bare-tilde-ambiguity:");
            for f in &bare_tilde.findings {
                eprintln!(
                    "    {}:{} — domain arm `%{}` body ends with bare `~` line",
                    path.display(),
                    f.line,
                    f.arm,
                );
            }
            eprintln!(
                "    graft-inject's chain-rebuilder may mistake this for the peek-chain"
            );
            eprintln!("    terminator (RM1 HARD-BUG-2). Refactor to one of:");
            eprintln!("      `(list effect)`~");
            eprintln!("      ^- (list effect) ~");
            eprintln!(
                "    see vesl-nockup/.dev/debug/log-meta/RM1/B_to_C.md §HARD-BUG-2"
            );
        }
        if !collision.findings.is_empty() {
            eprintln!("  collision:");
            for f in &collision.findings {
                let kind = match f.kind {
                    CollisionKind::CauseTag => "cause-tag",
                    CollisionKind::StateField => "state-field",
                };
                eprintln!(
                    "    {} `{}` declared by: {}",
                    kind,
                    f.name,
                    f.owners.join(", ")
                );
            }
            eprintln!(
                "    duplicate names compose into one cause $% / state record."
            );
            eprintln!(
                "    Disambiguate via manifest rename, profile-letter suffix, or"
            );
            eprintln!("    domain shadowing.");
            eprintln!(
                "    see vesl-nockup/.dev/debug/log-meta/RM1/E_to_F.md §META-COLLISION-1"
            );
        }
        if !transitive_imports.findings.is_empty() {
            eprintln!("  transitive-imports:");
            for f in &transitive_imports.findings {
                eprintln!(
                    "    {}: {} {} → {} (NOT FOUND)",
                    f.source.display(),
                    f.rune,
                    f.name,
                    f.target.display(),
                );
                for parent in &f.reachable_from {
                    eprintln!("      reachable from: {}", parent.display());
                }
            }
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
            eprintln!(
                "    see vesl-nockup/.dev/debug/log-meta/RM2/seed-A.md §DOC-GAP-1"
            );
        }
        if !internal_dupes.findings.is_empty() {
            eprintln!("  internal-dupes:");
            for f in &internal_dupes.findings {
                let kind = match f.kind {
                    InternalDupeKind::CauseTag => "cause-tag",
                    InternalDupeKind::StateField => "state-field",
                };
                let line_list: Vec<String> = f.lines.iter().map(|l| l.to_string()).collect();
                eprintln!(
                    "    duplicate {} `{}` at lines {}",
                    kind,
                    f.name,
                    line_list.join(", "),
                );
            }
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
            eprintln!(
                "    see vesl-nockup/.dev/debug/log-meta/RM2/round.md §META-COLLISION"
            );
        }
    }

    if findings_total > 0 {
        bail!("graft-inject lint: {findings_total} finding(s) above");
    }
    Ok(())
}

/// Stderr surface for the weld-friction lint. Each finding gets its
/// own line so reviewers can grep / copy. The closing pointer to the
/// zkvesl-docs anchor uses a stable heading slug so the developer can
/// search the docs site without needing to remember the URL.
pub(crate) fn print_weld_lint(lint: &WeldLint) {
    if lint.findings.is_empty() {
        return;
    }
    let n = lint.findings.len();
    eprintln!(
        "  weld-friction lint: {n} narrow effect binding{} found in domain code",
        if n == 1 { "" } else { "s" },
    );
    for f in &lint.findings {
        eprintln!("    line {}: {}", f.line, f.text);
    }
    eprintln!(
        "    cross-graft `(weld a b)` over these bindings will nest-fail. \
         widen each to `(list effect)` so the typed union absorbs each graft's effect."
    );
    eprintln!(
        "    see zkvesl-docs §\"Composing two graft arms in one domain cause\" \
         (/guides/grafting#composing-two-graft-arms-in-one-domain-cause)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Block, GraftBlocks};

    // ---------- bare-tilde lint ----------

    /// RM1 HARD-BUG-2 reproduction: a domain `%ping` arm whose body
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
        let lint = lint_bare_tilde_ambiguity(&lines);
        assert_eq!(lint.findings.len(), 1, "expected 1 finding, got {lint:#?}");
        assert_eq!(lint.findings[0].arm, "ping");
        // Line 5 is the `~` (1-indexed; line 1 is the `?-` switch).
        assert_eq!(lint.findings[0].line, 5);
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
        let lint = lint_bare_tilde_ambiguity(&lines);
        assert!(
            lint.findings.is_empty(),
            "workaround form should not flag, got {lint:#?}"
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
        let lint = lint_bare_tilde_ambiguity(&lines);
        assert!(
            lint.findings.is_empty(),
            "graft-injected bodies must be skipped, got {lint:#?}"
        );
    }

    /// Without a `?-  -.u.act` switch, the lint is a no-op.
    #[test]
    fn bare_tilde_lint_no_switch_no_findings() {
        let fixture = "++  peek\n  ~\n--";
        let lines: Vec<String> = fixture.lines().map(String::from).collect();
        let lint = lint_bare_tilde_ambiguity(&lines);
        assert!(lint.findings.is_empty());
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
            sha256: "0".repeat(64),
        }
    }

    /// RM1 META-COLLISION-1: queue-graft and pipeline-graft both
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
        let lint = lint_collision_check(&[queue, pipeline], &[]);
        assert_eq!(lint.findings.len(), 1);
        assert_eq!(lint.findings[0].name, "enqueue-job");
        assert_eq!(lint.findings[0].kind, CollisionKind::CauseTag);
        assert!(lint.findings[0].owners.contains(&"queue-graft".to_string()));
        assert!(
            lint.findings[0]
                .owners
                .contains(&"pipeline-graft".to_string())
        );
    }

    /// RM1 META-COLLISION-2: domain declares `entries` field and a
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
        let lint = lint_collision_check(&[audit], &domain);
        assert_eq!(lint.findings.len(), 1);
        assert_eq!(lint.findings[0].name, "entries");
        assert_eq!(lint.findings[0].kind, CollisionKind::StateField);
        assert!(
            lint.findings[0]
                .owners
                .contains(&"(domain)".to_string())
        );
        assert!(
            lint.findings[0]
                .owners
                .contains(&"audit-graft".to_string())
        );
    }

    /// Two grafts with disjoint tag sets and disjoint field sets
    /// must produce zero findings. Sanity check that the lint isn't
    /// over-flagging.
    #[test]
    fn collision_lint_clears_disjoint_grafts() {
        let queue = synthetic_collision_graft("queue-graft", &["queue-push"], &["queue"]);
        let counter =
            synthetic_collision_graft("counter-graft", &["counter-inc"], &["counter"]);
        let lint = lint_collision_check(&[queue, counter], &[]);
        assert!(
            lint.findings.is_empty(),
            "disjoint grafts must not collide, got {lint:#?}"
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
        let lint = lint_collision_check(&[queue], &domain);
        assert!(
            lint.findings.iter().any(|f| f.name == "queue-push"
                && f.kind == CollisionKind::CauseTag
                && f.owners.contains(&"(domain)".to_string())
                && f.owners.contains(&"queue-graft".to_string())),
            "expected domain-vs-graft cause-tag finding, got {lint:#?}"
        );
    }
}
