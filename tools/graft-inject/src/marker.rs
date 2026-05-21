//! Marker enum, banner formatters, and marker-line scanning helpers.
//!
//! The 10 markers are the splice points graft-inject reads from app.hoon
//! and writes wrapped output back to. Banner formatting (`begin_banner`,
//! `end_banner`, sha256-suffixed and codegen variants) lives here because
//! every banner callsite also handles a Marker, and keeping them together
//! means inject/codegen/lint/cli all import this one module rather than
//! re-deriving the banner shape per module.
//!
//! Audit §3.2 extraction: items moved verbatim from the pre-split
//! lib.rs (formerly main.rs) at the line ranges noted in the maintenance
//! plan.

use anyhow::Result;

use crate::MARKER_PREFIX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Marker {
    Imports,
    State,
    Cause,
    /// Spliced before the poke `?-` switch — guards (`?:` short-circuits)
    /// and pre-state captures (`=/  pre-X`).
    PokePrelude,
    Poke,
    /// Spliced after the `?-` switch — `out` rebinds that transform the
    /// switch's `[(list effect) _state]` result.
    PokePostlude,
    Peek,
    /// Anchor for the developer's `+$ domain-effect $%(...)` declaration.
    /// Marker only — grafts do not contribute a block here. The codegen
    /// pass reads its presence to decide whether to splat `domain-effect`
    /// into the union.
    DomainEffect,
    /// REPLACE-IF-PRESENT codegen target for the typed effect union
    /// `+$ effect $%(<graft-effects> domain-effect ==)`.
    /// Marker only — grafts do not contribute a block here. The
    /// codegen pass synthesizes the union body from each graft's
    /// `[graft.types].effect` plus `domain-effect` if DomainEffect is
    /// present.
    EffectUnion,
    /// RM4 §1 HARD-BUG-2 v0.2: REPLACE-IF-PRESENT codegen target inside
    /// the marker template's `++load` arm. graft-inject populates this
    /// marker with a `%=  old-state ... ==` overlay block — one line per
    /// composed graft, mapping each graft's state field to its
    /// `++new-state` default. The overlay is sound regardless of the
    /// resumed snapshot's noun shape: `%=` writes at axes computed from
    /// `old-state`'s declared type (the kernel's current
    /// `versioned-state`), so a smaller-shape snapshot resuming into a
    /// larger kernel gets defaults at the new axes without panicking
    /// when later pokes access them. Operators who need data
    /// preservation under a schema change re-poke after resume.
    LoadDefaults,
}

impl Marker {
    pub(crate) const ALL: [Marker; 10] = [
        Marker::Imports,
        Marker::State,
        Marker::Cause,
        Marker::PokePrelude,
        Marker::Poke,
        Marker::PokePostlude,
        Marker::Peek,
        Marker::DomainEffect,
        Marker::EffectUnion,
        Marker::LoadDefaults,
    ];

    #[cfg(test)]
    fn parse(name: &str) -> Option<Self> {
        match name {
            "imports" => Some(Self::Imports),
            "state" => Some(Self::State),
            "cause" => Some(Self::Cause),
            "poke-prelude" => Some(Self::PokePrelude),
            "poke" => Some(Self::Poke),
            "poke-postlude" => Some(Self::PokePostlude),
            "peek" => Some(Self::Peek),
            "domain-effect" => Some(Self::DomainEffect),
            "effect-union" => Some(Self::EffectUnion),
            "load-defaults" => Some(Self::LoadDefaults),
            _ => None,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Imports => "imports",
            Self::State => "state",
            Self::Cause => "cause",
            Self::PokePrelude => "poke-prelude",
            Self::Poke => "poke",
            Self::PokePostlude => "poke-postlude",
            Self::Peek => "peek",
            Self::DomainEffect => "domain-effect",
            Self::EffectUnion => "effect-union",
            Self::LoadDefaults => "load-defaults",
        }
    }
}

pub(crate) fn codegen_begin_banner(marker: Marker) -> String {
    format!("::  graft-inject:{}:begin", marker.label())
}

pub(crate) fn codegen_end_banner(marker: Marker) -> String {
    format!("::  graft-inject:{}:end", marker.label())
}

/// Prefix form of the begin banner — used for line-prefix matching when
/// scanning the source for existing injections. Banners emitted into the
/// composed file always carry a ` sha256:<short>` suffix (see
/// `begin_banner_with_sha`); this prefix matches both the new and the
/// pre-A2 legacy format and lets the idempotence check distinguish them.
pub(crate) fn begin_banner(name: &str, marker: Marker) -> String {
    format!("::  graft-inject:{}:{}:begin", name, marker.label())
}

/// Full begin-banner form emitted into the composed file. The 12-char
/// sha256 prefix lets a re-run detect manifest drift: if the user edits
/// `<graft>.toml` (e.g. swaps a `[graft.gates]` selection or bumps a
/// version), the sha256 changes, the embedded prefix doesn't match, and
/// the inject pass strips the stale banner pair and re-emits with the
/// new one. Pre-A2 banners (no sha256 suffix) are detected by the same
/// scan and force-reinjected once on first run after the upgrade.
pub(crate) fn begin_banner_with_sha(name: &str, marker: Marker, sha256_short: &str) -> String {
    format!(
        "::  graft-inject:{}:{}:begin sha256:{}",
        name,
        marker.label(),
        sha256_short
    )
}

pub(crate) fn end_banner(name: &str, marker: Marker) -> String {
    format!("::  graft-inject:{}:{}:end", name, marker.label())
}

pub(crate) fn find_marker(lines: &[String], marker: Marker) -> Result<Option<usize>> {
    let needle = format!("{}{}", MARKER_PREFIX, marker.label());
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        // Two-space law: the marker comment must be `::  nockup:<name>`.
        // We accept trailing whitespace and require exact prefix match.
        if trimmed.starts_with(&needle) {
            // Ensure the character right after the marker name is either
            // end-of-line or whitespace — guards against `nockup:pokemon`
            // swallowing a poke match.
            let tail = &trimmed[needle.len()..];
            if tail.is_empty() || tail.chars().all(|c| c.is_whitespace()) {
                return Ok(Some(i));
            }
        }
    }
    Ok(None)
}

pub(crate) fn leading_whitespace(s: &str) -> &str {
    let end = s
        .char_indices()
        .find(|(_, c)| !c.is_whitespace())
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    &s[..end]
}

/// Locate a graft's `:begin`/`:end` banner pair for `marker`. Returns
/// the inclusive `(begin_idx, end_idx)` line indices, or `None` when the
/// pair isn't present. The begin match is a prefix (`begin_banner`), so
/// it catches both the sha256-suffixed and the legacy banner forms.
/// Read-only — `strip_banner_pair` is the mutating wrapper, and
/// `doctor`'s hand-edit check uses this to slice a live block out.
pub(crate) fn find_banner_pair(
    lines: &[String],
    graft_name: &str,
    marker: Marker,
) -> Option<(usize, usize)> {
    let begin_prefix = begin_banner(graft_name, marker);
    let end_str = end_banner(graft_name, marker);
    let begin_idx = lines
        .iter()
        .position(|l| l.trim().starts_with(&begin_prefix))?;
    let end_idx = lines
        .iter()
        .enumerate()
        .skip(begin_idx + 1)
        .find(|(_, l)| l.trim() == end_str)
        .map(|(i, _)| i)?;
    Some((begin_idx, end_idx))
}

/// Extract the `sha256:<hex>` token from a begin-banner line. `None` for
/// a legacy (pre-A2) banner that carries no suffix.
pub(crate) fn banner_sha256(line: &str) -> Option<&str> {
    line.split(" sha256:")
        .nth(1)
        .map(|tail| tail.split_whitespace().next().unwrap_or(""))
        .filter(|s| !s.is_empty())
}

pub(crate) fn strip_banner_pair(
    lines: &mut Vec<String>,
    graft_name: &str,
    marker: Marker,
) -> Option<usize> {
    let (begin_idx, end_idx) = find_banner_pair(lines, graft_name, marker)?;
    lines.drain(begin_idx..=end_idx);
    Some(begin_idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_parse_covers_all() {
        for name in [
            "imports",
            "state",
            "cause",
            "poke-prelude",
            "poke",
            "poke-postlude",
            "peek",
            "domain-effect",
            "effect-union",
        ] {
            assert!(Marker::parse(name).is_some(), "expected Some for {name}");
        }
        assert!(Marker::parse("load").is_none());
        assert!(Marker::parse("arms").is_none());
        assert!(Marker::parse("nonsense").is_none());
    }
}
