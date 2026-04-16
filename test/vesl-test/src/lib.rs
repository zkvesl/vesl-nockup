//! vesl-test — harness + standard suite for grafted NockApp kernels.
//!
//! Boots a kernel from an `out.jam`, constructs vesl-register / verify /
//! settle pokes, runs a lifecycle test, and asserts the effect tags.
//! Reuses the poke shapes from vesl-core and nock-noun-rs — no kernel
//! knowledge required from the caller.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use nock_noun_rs::{jam_to_bytes, make_atom_in, make_tag_in, new_stack};
use nockapp::NockApp;
use nockapp::kernel::boot;
use nockapp::noun::slab::NounSlab;
use nockapp::wire::{SystemWire, Wire};
use nockvm::noun::{D, T};
use vesl_core::{Tip5Hash, tip5_to_atom_le_bytes};

// -- public test vectors ----------------------------------------------------

pub const TEST_HULL_A: u64 = 1;
pub const TEST_HULL_B: u64 = 2;
pub const TEST_PAYLOAD: &[u8] = b"vesl-test fixture payload";

// -- harness ---------------------------------------------------------------

pub struct GraftTestHarness {
    app: NockApp,
}

impl GraftTestHarness {
    /// Boot a NockApp from a compiled out.jam.
    pub async fn boot<P: AsRef<Path>>(jam_path: P) -> Result<Self> {
        let jam_path = jam_path.as_ref();
        let cli = boot::default_boot_cli(false);
        boot::init_default_tracing(&cli);
        let kernel = fs::read(jam_path)
            .with_context(|| format!("reading kernel jam at {}", jam_path.display()))?;
        let app: NockApp =
            boot::setup(&kernel, cli, &[], "vesl-test", None)
                .await
                .map_err(|e| anyhow::anyhow!("boot setup failed: {e}"))?;
        Ok(Self { app })
    }

    /// Send `[%vesl-register hull root]`. Returns the effect tag list.
    pub async fn register(&mut self, hull: u64, root: &Tip5Hash) -> Result<Vec<String>> {
        let slab = build_register_poke(hull, root);
        self.poke_slab(slab).await
    }

    /// Send `[%vesl-verify payload]` where payload is pre-jammed graft bytes.
    pub async fn verify(&mut self, payload: &[u8]) -> Result<Vec<String>> {
        let slab = build_payload_poke("vesl-verify", payload);
        self.poke_slab(slab).await
    }

    /// Send `[%vesl-settle payload]` where payload is pre-jammed graft bytes.
    pub async fn settle(&mut self, payload: &[u8]) -> Result<Vec<String>> {
        let slab = build_payload_poke("vesl-settle", payload);
        self.poke_slab(slab).await
    }

    /// Raw escape hatch — send an arbitrary NounSlab as a system poke.
    pub async fn poke_slab(&mut self, slab: NounSlab) -> Result<Vec<String>> {
        let effects = self
            .app
            .poke(SystemWire.to_wire(), slab)
            .await
            .map_err(|e| anyhow::anyhow!("poke failed: {e}"))?;
        Ok(effect_tags(&effects))
    }

    /// Run the standard lifecycle suite. Returns a report with pass/fail
    /// per test. Does not panic on failure — the caller decides.
    pub async fn run_standard_suite(&mut self) -> SuiteReport {
        let mut report = SuiteReport::new();

        // Build a single-leaf Merkle tree so the default hash gate passes.
        let mut mint = vesl_core::Mint::new();
        let root = mint.commit(&[TEST_PAYLOAD]);

        // 1. register A
        report.record(
            "register",
            self.register(TEST_HULL_A, &root).await,
            &["vesl-registered"],
        );

        // 2. duplicate register → error
        report.record(
            "duplicate-register",
            self.register(TEST_HULL_A, &root).await,
            &["vesl-error"],
        );

        // 3. verify (valid payload)
        let payload = jam_graft_payload(1, TEST_HULL_A, &root, TEST_PAYLOAD);
        report.record(
            "verify",
            self.verify(&payload).await,
            &["vesl-verified"],
        );

        // 4. register B, settle
        report.record(
            "register-b",
            self.register(TEST_HULL_B, &root).await,
            &["vesl-registered"],
        );
        let settle_payload = jam_graft_payload(42, TEST_HULL_B, &root, TEST_PAYLOAD);
        report.record(
            "settle",
            self.settle(&settle_payload).await,
            &["vesl-settled"],
        );

        // 5. replay settle (same note-id)
        report.record(
            "replay-settle",
            self.settle(&settle_payload).await,
            &["vesl-error"],
        );

        // 6. unregistered hull
        let bogus = jam_graft_payload(99, 99_999, &root, TEST_PAYLOAD);
        report.record(
            "unregistered-hull",
            self.settle(&bogus).await,
            &["vesl-error"],
        );

        // 7. root mismatch
        let mut other_mint = vesl_core::Mint::new();
        let other_root = other_mint.commit(&[b"different-payload".as_ref()]);
        let mismatched = jam_graft_payload(100, TEST_HULL_A, &other_root, TEST_PAYLOAD);
        report.record(
            "root-mismatch",
            self.settle(&mismatched).await,
            &["vesl-error"],
        );

        report
    }
}

// -- poke builders ----------------------------------------------------------

/// Build a `[%vesl-register hull root]` poke.
pub fn build_register_poke(hull: u64, root: &Tip5Hash) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "vesl-register");
    let root_bytes = tip5_to_atom_le_bytes(root);
    let root_atom = make_atom_in(&mut slab, &root_bytes);
    let poke = T(&mut slab, &[tag, D(hull), root_atom]);
    slab.set_root(poke);
    slab
}

/// Build a `[%vesl-<verb> payload]` poke where payload is a pre-jammed atom.
pub fn build_payload_poke(verb: &str, payload: &[u8]) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, verb);
    let jammed = make_atom_in(&mut slab, payload);
    let poke = T(&mut slab, &[tag, jammed]);
    slab.set_root(poke);
    slab
}

/// Build a graft-payload noun and jam it.
///
/// Shape: `[note=[id hull root [%pending ~]] data expected-root]`
pub fn jam_graft_payload(note_id: u64, hull: u64, root: &Tip5Hash, data: &[u8]) -> Vec<u8> {
    let mut slab: NounSlab = NounSlab::new();
    let rb = tip5_to_atom_le_bytes(root);

    let note_root = make_atom_in(&mut slab, &rb);
    let pending_tag = make_tag_in(&mut slab, "pending");
    let state = T(&mut slab, &[pending_tag, D(0)]);
    let note = T(&mut slab, &[D(note_id), D(hull), note_root, state]);

    let data_atom = make_atom_in(&mut slab, data);
    let exp_root = make_atom_in(&mut slab, &rb);
    let payload_noun = T(&mut slab, &[note, data_atom, exp_root]);

    let mut stack = new_stack();
    jam_to_bytes(&mut stack, payload_noun)
}

// -- effect parsing --------------------------------------------------------

/// Extract the head-atom tag from each effect as a string.
fn effect_tags(effects: &[NounSlab]) -> Vec<String> {
    let mut out = Vec::new();
    for effect in effects {
        let noun = unsafe { effect.root() };
        if let Ok(cell) = noun.as_cell() {
            if let Ok(tag) = cell.head().as_atom() {
                let bytes = tag.as_ne_bytes();
                let s = std::str::from_utf8(bytes)
                    .unwrap_or("?")
                    .trim_end_matches('\0')
                    .to_string();
                out.push(s);
            }
        }
    }
    out
}

// -- suite report ----------------------------------------------------------

#[derive(Debug, Default)]
pub struct SuiteReport {
    pub passed: Vec<String>,
    pub failed: Vec<(String, String)>,
}

impl SuiteReport {
    pub fn new() -> Self {
        Self::default()
    }

    fn record(
        &mut self,
        name: &str,
        result: Result<Vec<String>>,
        expected_contains: &[&str],
    ) {
        match result {
            Err(e) => {
                self.failed.push((name.to_string(), format!("poke error: {e:#}")));
            }
            Ok(tags) => {
                let mut hit = false;
                for needle in expected_contains {
                    if tags.iter().any(|t| t == *needle) {
                        hit = true;
                        break;
                    }
                }
                if hit {
                    self.passed.push(name.to_string());
                } else {
                    self.failed.push((
                        name.to_string(),
                        format!("expected one of {expected_contains:?}, got {tags:?}"),
                    ));
                }
            }
        }
    }

    pub fn is_success(&self) -> bool {
        self.failed.is_empty()
    }

    pub fn summary(&self) -> String {
        format!(
            "vesl-test: {} passed, {} failed",
            self.passed.len(),
            self.failed.len()
        )
    }
}
