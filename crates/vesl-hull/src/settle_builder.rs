//! SettlePayloadBuilder — gate-aware `/settle` payload assembly (R6 §3).
//!
//! Stock `settle_handler` used to hardcode
//! `vesl_core::build_settle_note_poke(.., &leaf_bytes)`, a flat-atom
//! payload that only the default hash gate can accept. Any non-default
//! gate (`manifest-verify`, `schnorr`, `set-membership-verify`, …) clean-
//! denies the payload and the hull surfaces an opaque 409.
//!
//! This trait decouples the `/settle` HTTP handler from the kernel's
//! verify-gate selection. [`crate::api::AppState`] holds an
//! `Arc<dyn SettlePayloadBuilder>`; the binary picks the impl at boot
//! based on [`crate::ManifestSummary::gate`], and the handler dispatches
//! through the trait so adding a new gate is a single impl, not a hull
//! rewrite.
//!
//! Ships with two impls:
//! - [`DefaultHashPayloadBuilder`] — preserves the pre-R6 behavior. Body
//!   shape `{"data": "<hex>"}` or `{}` (re-mints from `field[0]`).
//! - [`ManifestVerifyPayloadBuilder`] — covers the R6 M / R findings.
//!   Body shape `{"fields": [{"name": "...", "value": "..."}, ...]}`;
//!   the impl re-derives proofs from the hull's committed tree.

use std::sync::Arc;

use nock_noun_rs::NounSlab;
use nockchain_tip5_rs::{MerkleTree, Tip5Hash};
use serde_json::Value;

use crate::api::Field;
use crate::verify::field_to_leaf_bytes;

/// Build a `%settle-note` poke for the active verify gate.
///
/// Implementations decode `body` themselves (the JSON shape varies per
/// gate) and assemble the kernel poke. Common envelope fields
/// (`note_id`, `hull`) are pulled by the handler before this is called
/// and exposed via [`SettleContext`].
pub trait SettlePayloadBuilder: Send + Sync {
    /// Build the `%settle-note` poke noun slab for this gate.
    ///
    /// Return `Err(BadRequest)` for caller-side body problems (400) or
    /// `Err(InternalError)` for impl bugs (500). The handler maps these
    /// to typed HTTP statuses.
    fn build_settle_poke(
        &self,
        ctx: &SettleContext<'_>,
        body: &Value,
    ) -> Result<NounSlab, SettleBuilderError>;

    /// Human-readable gate name. Used in startup logs and `/status`
    /// drift diagnostics. Defaults to a placeholder; impls SHOULD
    /// override.
    fn gate_name(&self) -> &'static str {
        "unknown"
    }
}

/// Per-request context — everything an impl might need beyond the raw
/// body. Borrows from [`crate::api::AppState`].
pub struct SettleContext<'a> {
    pub note_id: u64,
    pub hull_id: u64,
    pub root: &'a Tip5Hash,
    /// Committed Merkle tree. Always `Some` when the handler dispatches;
    /// kept as `Option` for future impls that might not require one.
    pub tree: Option<&'a MerkleTree>,
    /// Committed fields, in the order `/commit` mounted them. Indexed
    /// by impls that need per-field proofs.
    pub fields: &'a [Field],
}

/// Errors an impl raises while assembling a poke. The handler maps the
/// variant to an HTTP status — `BadRequest` → 400, `InternalError` → 500.
#[derive(Debug)]
pub enum SettleBuilderError {
    BadRequest(String),
    InternalError(String),
}

impl std::fmt::Display for SettleBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadRequest(s) | Self::InternalError(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for SettleBuilderError {}

// ---------------------------------------------------------------------------
// DefaultHashPayloadBuilder — pre-R6 behavior preserved.
// ---------------------------------------------------------------------------

/// Default single-leaf hash gate. Body shape:
/// - `{}` → re-mints the leaf from `field[0]` via `field_to_leaf_bytes`.
/// - `{"data": "<hex>"}` → caller supplies the leaf as a hex atom.
#[derive(Default, Clone, Copy)]
pub struct DefaultHashPayloadBuilder;

impl SettlePayloadBuilder for DefaultHashPayloadBuilder {
    fn gate_name(&self) -> &'static str {
        "default-hash"
    }

    fn build_settle_poke(
        &self,
        ctx: &SettleContext<'_>,
        body: &Value,
    ) -> Result<NounSlab, SettleBuilderError> {
        let leaf_bytes = match body.get("data").and_then(Value::as_str) {
            Some(hex_str) => hex::decode(hex_str).map_err(|e| {
                SettleBuilderError::BadRequest(format!("invalid hex in `data`: {e}"))
            })?,
            None => ctx.fields.first().map(field_to_leaf_bytes).ok_or_else(|| {
                SettleBuilderError::BadRequest(
                    "no committed fields; POST /commit first".into(),
                )
            })?,
        };
        Ok(vesl_core::build_settle_note_poke(
            ctx.note_id,
            ctx.hull_id,
            ctx.root,
            &leaf_bytes,
        ))
    }
}

// ---------------------------------------------------------------------------
// ManifestVerifyPayloadBuilder — multi-leaf manifest-verify gate.
// ---------------------------------------------------------------------------

/// Manifest-verify gate. Body shape:
/// `{"fields": [{"name": "email", "value": "alice@..."}, ...]}`.
///
/// Each named field must match a `Field` committed via `/commit`
/// (`key == name`, `value == value`). The impl re-derives the leaf bytes
/// via [`field_to_leaf_bytes`] and pulls the per-field proof from the
/// committed tree. Closes the M / R findings — stock `/settle` now
/// succeeds against a manifest-verify kernel without a custom route.
#[derive(Default, Clone, Copy)]
pub struct ManifestVerifyPayloadBuilder;

impl SettlePayloadBuilder for ManifestVerifyPayloadBuilder {
    fn gate_name(&self) -> &'static str {
        "manifest-verify"
    }

    fn build_settle_poke(
        &self,
        ctx: &SettleContext<'_>,
        body: &Value,
    ) -> Result<NounSlab, SettleBuilderError> {
        let tree = ctx.tree.ok_or_else(|| {
            SettleBuilderError::BadRequest(
                "manifest-verify /settle requires a committed tree".into(),
            )
        })?;
        let fields_spec = body
            .get("fields")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                SettleBuilderError::BadRequest(
                    "manifest-verify /settle requires `fields: [{name, value}, ...]`".into(),
                )
            })?;
        if fields_spec.is_empty() {
            return Err(SettleBuilderError::BadRequest(
                "`fields` array must not be empty".into(),
            ));
        }

        let mut field_pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(fields_spec.len());
        let mut proofs: Vec<Vec<nockchain_tip5_rs::ProofNode>> =
            Vec::with_capacity(fields_spec.len());

        for (i, spec) in fields_spec.iter().enumerate() {
            let name = spec
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    SettleBuilderError::BadRequest(format!(
                        "fields[{i}] missing `name` string"
                    ))
                })?;
            let value = spec
                .get("value")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    SettleBuilderError::BadRequest(format!(
                        "fields[{i}] missing `value` string"
                    ))
                })?;
            let idx = ctx
                .fields
                .iter()
                .position(|f| f.key == name && f.value == value)
                .ok_or_else(|| {
                    SettleBuilderError::BadRequest(format!(
                        "fields[{i}] {{name='{name}', value='{value}'}} not in committed set"
                    ))
                })?;
            let leaf = field_to_leaf_bytes(&Field {
                key: name.to_string(),
                value: value.to_string(),
            });
            field_pairs.push((name.as_bytes().to_vec(), leaf));
            // AUDIT 2026-05-21 L-21: MerkleTree::proof is fallible.
            proofs.push(tree.proof(idx).map_err(|e| {
                SettleBuilderError::BadRequest(format!("fields[{i}] merkle proof: {e}"))
            })?);
        }

        let borrowed: Vec<(&[u8], &[u8])> = field_pairs
            .iter()
            .map(|(n, v)| (n.as_slice(), v.as_slice()))
            .collect();

        Ok(vesl_core::build_settle_note_manifest_poke(
            ctx.note_id,
            ctx.hull_id,
            ctx.root,
            &borrowed,
            &proofs,
        ))
    }
}

// ---------------------------------------------------------------------------
// Gate-name -> builder dispatch
// ---------------------------------------------------------------------------

/// Pick a payload builder from a gate name (e.g.
/// [`ManifestSummary::gate`](crate::ManifestSummary)). Falls back to
/// [`DefaultHashPayloadBuilder`] for any gate without a current impl,
/// and logs a warning to stderr so operators see the gap.
///
/// Adding a new gate impl is a one-line match arm here plus the impl
/// itself — no other call sites need to change.
pub fn payload_builder_for_gate(gate: &str) -> Arc<dyn SettlePayloadBuilder> {
    match gate {
        "default-hash" => Arc::new(DefaultHashPayloadBuilder),
        "manifest-verify" => Arc::new(ManifestVerifyPayloadBuilder),
        other => {
            tracing::warn!(
                target: "vesl_hull::settle_builder",
                "gate `{other}` has no SettlePayloadBuilder impl yet; \
                 falling back to default-hash. Stock /settle will dead-deny \
                 on this gate — write a custom route or add a SettlePayloadBuilder impl."
            );
            Arc::new(DefaultHashPayloadBuilder)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use vesl_core::Mint;

    fn dummy_tree(leaves: &[&[u8]]) -> (MerkleTree, Tip5Hash) {
        let mut mint = Mint::new();
        let root = mint.commit(leaves);
        let tree = MerkleTree::build(leaves).expect("dummy_tree leaves are non-empty");
        (tree, root)
    }

    #[test]
    fn default_hash_re_mints_from_fields_when_no_data() {
        let fields = vec![Field {
            key: "k".into(),
            value: "v".into(),
        }];
        let leaf = field_to_leaf_bytes(&fields[0]);
        let (tree, root) = dummy_tree(&[leaf.as_slice()]);
        let ctx = SettleContext {
            note_id: 1,
            hull_id: 1,
            root: &root,
            tree: Some(&tree),
            fields: &fields,
        };
        let builder = DefaultHashPayloadBuilder;
        let body = serde_json::json!({});
        builder
            .build_settle_poke(&ctx, &body)
            .expect("default-hash with empty body re-mints from field[0]");
    }

    #[test]
    fn default_hash_rejects_invalid_hex() {
        let zero_root: Tip5Hash = [0u64; 5];
        let ctx = SettleContext {
            note_id: 1,
            hull_id: 1,
            root: &zero_root,
            tree: None,
            fields: &[],
        };
        let body = serde_json::json!({"data": "zzz"});
        let err = DefaultHashPayloadBuilder
            .build_settle_poke(&ctx, &body)
            .unwrap_err();
        match err {
            SettleBuilderError::BadRequest(s) => assert!(s.contains("invalid hex")),
            _ => panic!("expected BadRequest, got {err:?}"),
        }
    }

    #[test]
    fn manifest_verify_requires_fields_array() {
        let (tree, root) = dummy_tree(&[b"a:1"]);
        let ctx = SettleContext {
            note_id: 1,
            hull_id: 1,
            root: &root,
            tree: Some(&tree),
            fields: &[Field { key: "a".into(), value: "1".into() }],
        };
        let body = serde_json::json!({});
        let err = ManifestVerifyPayloadBuilder
            .build_settle_poke(&ctx, &body)
            .unwrap_err();
        match err {
            SettleBuilderError::BadRequest(s) => assert!(s.contains("fields")),
            _ => panic!("expected BadRequest, got {err:?}"),
        }
    }

    #[test]
    fn manifest_verify_rejects_unknown_field() {
        let fields = vec![Field { key: "a".into(), value: "1".into() }];
        let leaf = field_to_leaf_bytes(&fields[0]);
        let (tree, root) = dummy_tree(&[leaf.as_slice()]);
        let ctx = SettleContext {
            note_id: 1,
            hull_id: 1,
            root: &root,
            tree: Some(&tree),
            fields: &fields,
        };
        let body = serde_json::json!({
            "fields": [{"name": "ghost", "value": "missing"}]
        });
        let err = ManifestVerifyPayloadBuilder
            .build_settle_poke(&ctx, &body)
            .unwrap_err();
        match err {
            SettleBuilderError::BadRequest(s) => assert!(s.contains("not in committed set")),
            _ => panic!("expected BadRequest, got {err:?}"),
        }
    }

    #[test]
    fn manifest_verify_builds_for_committed_fields() {
        let fields = vec![
            Field { key: "email".into(), value: "alice@example.com".into() },
            Field { key: "role".into(), value: "admin".into() },
        ];
        let leaves: Vec<Vec<u8>> = fields.iter().map(field_to_leaf_bytes).collect();
        let leaf_refs: Vec<&[u8]> = leaves.iter().map(|v| v.as_slice()).collect();
        let (tree, root) = dummy_tree(&leaf_refs);
        let ctx = SettleContext {
            note_id: 1,
            hull_id: 1,
            root: &root,
            tree: Some(&tree),
            fields: &fields,
        };
        let body = serde_json::json!({
            "fields": [
                {"name": "email", "value": "alice@example.com"},
                {"name": "role",  "value": "admin"}
            ]
        });
        ManifestVerifyPayloadBuilder
            .build_settle_poke(&ctx, &body)
            .expect("matching fields produce a valid poke");
    }

    #[test]
    fn dispatch_falls_back_to_default_hash() {
        // The dispatcher returns *some* impl for unknown gates without
        // panicking — the warning goes to stderr.
        let b = payload_builder_for_gate("schnorr");
        assert_eq!(b.gate_name(), "default-hash");
    }

    #[test]
    fn dispatch_picks_manifest_verify_by_name() {
        let b = payload_builder_for_gate("manifest-verify");
        assert_eq!(b.gate_name(), "manifest-verify");
    }
}
