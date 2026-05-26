//! Unified printer for lint findings. Groups by [`super::KIND_ORDER`]
//! and emits per-lint remediation hints once per non-empty group.

use std::path::Path;

use super::collision::CollisionKind;
use super::internal_dupes::InternalDupeKind;
use super::{KIND_ORDER, LintFinding, LintPolicy};

/// One stderr line for a single finding, prefixed with
/// `  {severity}: {kind}: `. The severity word follows rustc / gcc
/// convention so terminal scrapers picking up `error:` / `warning:`
/// markers route correctly; the kind prefix lets `grep '<kind>:'` count
/// findings by kind without scraping the body. `path` provides context
/// for findings that don't embed a source path of their own; `policy`
/// resolves per-lint overrides (CLI + nockapp.toml) over the variant
/// default.
fn print_lint_finding(f: &LintFinding, path: &Path, policy: &LintPolicy) {
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
