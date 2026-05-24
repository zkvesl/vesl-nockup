//! Shared extractors used by more than one lint, plus the
//! [`CauseUnionMember`] type that codegen consumes for cause-tag
//! composition.
//!
//! The functions here parse the composed app.hoon source — its
//! `+$ cause` union, its `+$ versioned-state` record, and each
//! discovered graft's `[graft.blocks.poke]` / `[graft.blocks.state]`
//! bodies. Lints route through these helpers so the parsing surface
//! stays consistent across collision, unresolved-cause, and
//! internal-dupes passes.

use crate::manifest::Graft;
use crate::marker::Marker;

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
pub(super) fn extract_graft_state_fields(g: &Graft) -> Vec<String> {
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
pub(super) fn extract_domain_cause_tags(lines: &[String]) -> Vec<String> {
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
pub(super) fn extract_domain_state_fields(lines: &[String]) -> Vec<String> {
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
