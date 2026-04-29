//! Parity between vesl-signing's vendored math substrate and `nockchain-math`
//! upstream.
//!
//! ## Status (v0.1.0): test framework only, no live regen.
//!
//! Per the architectural decision 2026-04-29 (math-substrate vendoring):
//! vesl-signing carries its own copy of `Belt`, `F6lt`, `CheetahPoint`, and
//! Tip5. Drift detection is the cost. The intended workflow:
//!
//! 1. A dev-only example `regen_parity_vectors.rs` consumes
//!    `nockchain-math` (path-dep to the local nockchain checkout) and
//!    generates `tests/fixtures/parity_vectors_<sha>.json` containing
//!    100+ random (scalar, point) and (input, output) pairs.
//! 2. The fixture is committed into vesl-identity. Filename includes the
//!    nockchain SHA it was generated against.
//! 3. This test reads the fixture and runs vesl-signing's vendored math
//!    against each pair, asserting byte-equality.
//!
//! The regen pipeline is deferred to v0.2.0 because (a) `nockchain-math`
//! requires nightly Rust (`#![feature(cold_path)]`) which contaminates
//! vesl-identity's stable-pinned toolchain unless the regen example is
//! built out-of-tree, and (b) the existing inline tests in
//! `crate::math::cheetah::tests` and `crate::math::tip5::tests` already
//! exercise the algorithms against known reference values from
//! nockchain-math's own test suite — drift would surface there first.
//!
//! v0.1.0 ships the test file as a placeholder so future work has a clear
//! landing spot. Tracked in `vesl-identity/CHANGELOG.md` Pending section.

#[test]
fn parity_pipeline_documented() {
    // No-op assertion: this test file exists primarily as scaffolding
    // for the v0.2.0 parity regen workflow. See module doc above.
    //
    // When the workflow lands, replace this with:
    //
    //   let fixture = std::fs::read_to_string(
    //       "tests/fixtures/parity_vectors.json"
    //   ).expect("regenerate via `cargo run --example regen_parity_vectors`");
    //   let vectors: ParityVectors = serde_json::from_str(&fixture).unwrap();
    //   for v in vectors.belt_ops { /* run vendored math, assert equality */ }
    //   for v in vectors.cheetah_ops { /* … */ }
    //   for v in vectors.tip5_ops { /* … */ }
}
