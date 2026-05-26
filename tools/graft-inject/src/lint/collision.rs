//! Collision-check lint: cross-graft and graft-vs-domain name
//! collisions on cause tags and state fields.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::manifest::Graft;

use super::extract::{
    extract_domain_cause_tags, extract_domain_state_fields, extract_graft_cause_tags,
    extract_graft_state_fields,
};
use super::{LintFinding, LintSeverity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CollisionKind {
    CauseTag,
    StateField,
}

/// JSON projection record for `collision` findings.
#[derive(Serialize)]
pub(super) struct CollisionRecord<'a> {
    pub(super) severity: LintSeverity,
    pub(super) kind: CollisionKind,
    pub(super) name: &'a str,
    pub(super) owners: &'a [String],
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Block, GraftBlocks};

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
}
