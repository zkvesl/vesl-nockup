//! Weld-friction lint: narrow effect bindings (`(list <graft>-effect)`)
//! in domain code that will nest-fail at any cross-graft `weld`.
//!
//! Advisory-only by default — surfaces during compose but does not gate
//! the write. Reports no JSON record on the `lint --json` projection;
//! findings reach developers through the inject path's stderr instead.

use std::collections::HashSet;

use super::LintFinding;

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
