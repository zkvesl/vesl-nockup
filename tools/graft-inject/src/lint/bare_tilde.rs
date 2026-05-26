//! Bare-tilde ambiguity lint: a `~` line in a domain `?-` switch arm
//! that the composer's chain rebuilder may misread as the peek-chain
//! terminator.

use serde::Serialize;

use super::{LintFinding, LintSeverity};

/// JSON projection record for `bare_tilde_ambiguity` findings.
#[derive(Serialize)]
pub(super) struct BareTildeRecord<'a> {
    pub(super) severity: LintSeverity,
    pub(super) line: usize,
    pub(super) arm: &'a str,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: assert exactly one finding and unwrap its
    /// `BareTildeAmbiguity` variant, panicking with full state on
    /// mismatch.
    fn expect_bare_tilde(findings: &[LintFinding]) -> (usize, &str) {
        assert_eq!(findings.len(), 1, "expected 1 finding, got {findings:#?}");
        match &findings[0] {
            LintFinding::BareTildeAmbiguity { line, arm } => (*line, arm.as_str()),
            other => panic!("expected BareTildeAmbiguity, got {other:?}"),
        }
    }

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
==
"#;
        let lines: Vec<String> = fixture.lines().map(String::from).collect();
        let findings = lint_bare_tilde_ambiguity(&lines);
        let (line, arm) = expect_bare_tilde(&findings);
        assert_eq!(line, 5);
        assert_eq!(arm, "ping");
    }

    /// The one-line workaround `^- (list effect) ~` should clear the
    /// lint — the bare `~` no longer sits on its own line.
    #[test]
    fn bare_tilde_lint_clears_one_line_workaround() {
        let fixture = r#"?-    -.u.act
    %ping
  :_  state
  ^-  (list effect)  ~
==
"#;
        let lines: Vec<String> = fixture.lines().map(String::from).collect();
        let findings = lint_bare_tilde_ambiguity(&lines);
        assert!(
            findings.is_empty(),
            "expected no findings, got {findings:#?}"
        );
    }

    /// Arms inside `graft-inject:<x>:begin/:end` banners are synthesized
    /// graft bodies — not user code. The bare `~` line inside such a
    /// region should not be flagged.
    #[test]
    fn bare_tilde_lint_skips_graft_injected_arms() {
        let fixture = r#"?-    -.u.act
::  graft-inject:counter:poke:begin
    %inc
  :_  state
  ^-  (list counter-effect)
  ~
::  graft-inject:counter:poke:end
==
"#;
        let lines: Vec<String> = fixture.lines().map(String::from).collect();
        let findings = lint_bare_tilde_ambiguity(&lines);
        assert!(
            findings.is_empty(),
            "expected no findings, got {findings:#?}"
        );
    }

    /// No `?-  -.u.act` switch in the file → no findings.
    #[test]
    fn bare_tilde_lint_no_switch_no_findings() {
        let fixture = "just some unrelated text\n~\n";
        let lines: Vec<String> = fixture.lines().map(String::from).collect();
        assert!(lint_bare_tilde_ambiguity(&lines).is_empty());
    }
}
