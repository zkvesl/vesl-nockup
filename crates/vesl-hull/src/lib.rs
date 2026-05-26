//! vesl-hull — HTTP API over a Nock kernel.
//!
//! Factored from vesl-core/hull as a vesl-nockup-native lib. The
//! template at `templates/vesl/` boots a kernel from `out.jam` and
//! hands the [`NockApp`](nockapp::NockApp) to [`serve`] (or composes a
//! custom router via [`router`]).
//!
//! Public surface is intentionally narrow at the crate root. Less-common
//! items (request/response types, wallet config sub-structs, signing
//! re-exports) live in their parent modules — reach them via
//! `vesl_hull::api::*`, `vesl_hull::config::*`, `vesl_hull::signing::*`.
//! Widening to the crate root only happens when a concrete user need
//! appears.

pub mod api;
pub mod config;
pub mod manifest_summary;
pub mod settle_builder;
pub mod signing;
pub mod verify;

pub use api::{
    serve, serve_with_extra_routes, router, router_with_extra, router_with_extra_inner,
    AppState, SharedState, Field,
    check_auth_config_with_bind, load_note_counter,
};
pub use manifest_summary::{ManifestSummary, ManifestSummaryError};
pub use settle_builder::{
    payload_builder_for_gate, DefaultHashPayloadBuilder, ManifestVerifyPayloadBuilder,
    SettleBuilderError, SettleContext, SettlePayloadBuilder,
};
pub use config::{
    HullConfig, HullRbacToml, RbacConfig, SettlementCliOverrides, SettlementConfig,
    SettlementMode, SettlementToml, load_config, resolve_with_demo_key_checked,
};
pub use signing::{demo_signing_key, is_demo_key, DEMO_KEY_PKH_BASE58};
pub use verify::{FieldVerifier, FieldWithProof, field_to_leaf_bytes};
