//! Internal-dupes lint: literal duplicate variant heads inside the
//! composed `+$ cause $%(...)` union or duplicate field names inside
//! `+$ versioned-state $:(...)`.

use std::collections::BTreeMap;

use serde::Serialize;

use super::extract::{CauseUnionMember, extract_cause_union_members};
use super::{LintFinding, LintSeverity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InternalDupeKind {
    CauseTag,
    StateField,
}

/// JSON projection record for `internal_dupes` findings.
#[derive(Serialize)]
pub(super) struct InternalDupeRecord<'a> {
    pub(super) severity: LintSeverity,
    pub(super) kind: InternalDupeKind,
    pub(super) name: &'a str,
    pub(super) lines: &'a [usize],
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

