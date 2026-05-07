//! vesl-test — harness + standard suite for grafted NockApp kernels.
//!
//! Boots a kernel from an `out.jam`, constructs settle-register / verify /
//! note pokes, runs a lifecycle test, and asserts the effect tags.
//! Reuses the poke shapes from vesl-core and nock-noun-rs — no kernel
//! knowledge required from the caller.
//!
//! Phase 12A renamed the primitive from `vesl-graft` to `settle-graft`;
//! the method names below track the new naming (`register` /  `verify`
//! /  `note`). The `settle` method remains as a deprecated alias so
//! existing tests outside this repo keep compiling for one release.

use std::fs;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

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
        init_capture_tracing(&cli);
        let kernel = fs::read(jam_path)
            .with_context(|| format!("reading kernel jam at {}", jam_path.display()))?;
        let app: NockApp =
            boot::setup(&kernel, cli, &[], "vesl-test", None)
                .await
                .map_err(|e| anyhow::anyhow!("boot setup failed: {e}"))?;
        Ok(Self { app })
    }

    /// Send `[%settle-register hull root]`. Returns the effect tag list.
    pub async fn register(&mut self, hull: u64, root: &Tip5Hash) -> Result<Vec<String>> {
        let slab = build_register_poke(hull, root);
        self.poke_slab(slab).await
    }

    /// Send `[%settle-verify payload]` where payload is pre-jammed graft bytes.
    pub async fn verify(&mut self, payload: &[u8]) -> Result<Vec<String>> {
        let slab = build_payload_poke("settle-verify", payload);
        self.poke_slab(slab).await
    }

    /// Send `[%settle-note payload]` where payload is pre-jammed graft bytes.
    pub async fn note(&mut self, payload: &[u8]) -> Result<Vec<String>> {
        let slab = build_payload_poke("settle-note", payload);
        self.poke_slab(slab).await
    }

    /// Deprecated alias for [`GraftTestHarness::note`]. The `%vesl-settle`
    /// cause tag became `%settle-note` in Phase 12A.
    #[deprecated(since = "0.2.0", note = "renamed in Phase 12A; use note()")]
    pub async fn settle(&mut self, payload: &[u8]) -> Result<Vec<String>> {
        self.note(payload).await
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

    /// Like [`poke_slab`] but also returns any slog warnings emitted
    /// during the call (e.g. `invalid cause` from the wrapper's
    /// `(soft cause)` short-circuit). Use when a test needs to assert
    /// on the kernel's diagnostics, not just on the effect tags.
    ///
    /// Capture is process-global: the kernel emits slogs from whichever
    /// tokio worker thread runs the poke, so a thread-local buffer
    /// would miss them. The global buffer is drained at the start of
    /// every call. Concurrent `poke_slab_report` calls from the same
    /// process interleave their slogs into a single window — fine for
    /// the typical one-test-at-a-time integration setup, but tests that
    /// run multiple harnesses in parallel within the same process should
    /// fall back to `poke_slab` and parse stderr themselves.
    pub async fn poke_slab_report(&mut self, slab: NounSlab) -> Result<PokeReport> {
        clear_capture();
        let effects = self
            .app
            .poke(SystemWire.to_wire(), slab)
            .await
            .map_err(|e| anyhow::anyhow!("poke failed: {e}"))?;
        Ok(PokeReport {
            effect_tags: effect_tags(&effects),
            slog_warnings: drain_capture(),
        })
    }

    /// Peek a path through the kernel's `++peek` arm. Wraps
    /// `NockApp::peek_handle` semantics: `Ok(None)` for a recognized
    /// path with no value (`[~ ~]` in Hoon), `Ok(Some(slab))` when a
    /// value is present, `Err` when the kernel returned bare `~`
    /// (unrecognized path).
    pub async fn peek_handle(&mut self, path: NounSlab) -> Result<Option<NounSlab>> {
        self.app
            .peek_handle(path)
            .await
            .map_err(|e| anyhow::anyhow!("peek failed: {e}"))
    }

    /// Peek and return the raw `(unit (unit *))` result from the
    /// kernel — no unwrapping. Use this when the peek returns a
    /// nested unit (settle-graft's `%settle-root` convention — `` `` ``
    /// around a `(unit @)` — produces `[~ [~ [~ value]]]` / `[~ [~ ~]]`).
    pub async fn peek_raw(&mut self, path: NounSlab) -> Result<NounSlab> {
        self.app
            .peek(path)
            .await
            .map_err(|e| anyhow::anyhow!("peek failed: {e}"))
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
            &["settle-registered"],
        );

        // 2. duplicate register → error
        report.record(
            "duplicate-register",
            self.register(TEST_HULL_A, &root).await,
            &["settle-error"],
        );

        // 3. verify (valid payload)
        let payload = jam_graft_payload(1, TEST_HULL_A, &root, TEST_PAYLOAD);
        report.record(
            "verify",
            self.verify(&payload).await,
            &["settle-verified"],
        );

        // 4. register B, settle
        report.record(
            "register-b",
            self.register(TEST_HULL_B, &root).await,
            &["settle-registered"],
        );
        let settle_payload = jam_graft_payload(42, TEST_HULL_B, &root, TEST_PAYLOAD);
        report.record(
            "note",
            self.note(&settle_payload).await,
            &["settle-noted"],
        );

        // 5. replay settle (same note-id)
        report.record(
            "replay-note",
            self.note(&settle_payload).await,
            &["settle-error"],
        );

        // 6. unregistered hull
        let bogus = jam_graft_payload(99, 99_999, &root, TEST_PAYLOAD);
        report.record(
            "unregistered-hull",
            self.note(&bogus).await,
            &["settle-error"],
        );

        // 7. root mismatch
        let mut other_mint = vesl_core::Mint::new();
        let other_root = other_mint.commit(&[b"different-payload".as_ref()]);
        let mismatched = jam_graft_payload(100, TEST_HULL_A, &other_root, TEST_PAYLOAD);
        report.record(
            "root-mismatch",
            self.note(&mismatched).await,
            &["settle-error"],
        );

        report
    }
}

// -- poke builders ----------------------------------------------------------

/// Build a `[%settle-register hull root]` poke.
pub fn build_register_poke(hull: u64, root: &Tip5Hash) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "settle-register");
    let root_bytes = tip5_to_atom_le_bytes(root);
    let root_atom = make_atom_in(&mut slab, &root_bytes);
    let poke = T(&mut slab, &[tag, D(hull), root_atom]);
    slab.set_root(poke);
    slab
}

/// Build a `[%settle-<verb> payload]` poke where payload is a pre-jammed atom.
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
        if let Ok(cell) = noun.as_cell()
            && let Ok(tag) = cell.head().as_atom() {
                let bytes = tag.as_ne_bytes();
                let s = std::str::from_utf8(bytes)
                    .unwrap_or("?")
                    .trim_end_matches('\0')
                    .to_string();
                out.push(s);
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

// -- poke report ------------------------------------------------------------

/// Outcome of a single poke. `effect_tags` is the same `Vec<String>`
/// that [`GraftTestHarness::poke_slab`] returns; `slog_warnings`
/// captures any `target: "slogger"` tracing events emitted by the
/// kernel during the call.
#[derive(Debug, Clone, Default)]
pub struct PokeReport {
    pub effect_tags: Vec<String>,
    pub slog_warnings: Vec<SlogWarning>,
}

/// Structured slog observation. `InvalidCause` is parsed out of the
/// wrapper's `~> %slog.[1 (crip "invalid cause {<noun>}")]` shape;
/// other slogs land in `Other` verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlogWarning {
    /// The kernel's `(soft cause)` rejected the poke's cause cell.
    /// `noun` is the printed noun body (decimal-with-dots tag atoms
    /// per Hoon's default formatter); use [`decode_cause_tag`] to
    /// extract the leading tag if needed.
    InvalidCause { noun: String },
    /// Anything else slogged through `target: "slogger"`.
    Other(String),
}

impl PokeReport {
    /// Convenience: did the kernel reject any cause-tag during this poke?
    pub fn rejected_cause(&self) -> bool {
        self.slog_warnings
            .iter()
            .any(|w| matches!(w, SlogWarning::InvalidCause { .. }))
    }
}

/// Decode the leading tag of an `invalid cause` noun shown as
/// dotted-decimal. `"499.918.253.415 138.296..."` → `Some("g-set")`.
/// Hoon's `<...>` formatter prints atoms as little-endian decimal with
/// dot separators every three digits; this reverses that for the head
/// atom only. Returns None when the noun doesn't fit the expected
/// `[head_atom rest...]` shape.
pub fn decode_cause_tag(noun: &str) -> Option<String> {
    let inner = noun.trim().trim_start_matches('[').trim_end_matches(']');
    let head = inner.split_whitespace().next()?;
    let digits: String = head.chars().filter(|c| c.is_ascii_digit()).collect();
    let mut value: u64 = digits.parse().ok()?;
    if value == 0 {
        return None;
    }
    let mut bytes = Vec::new();
    while value > 0 {
        bytes.push((value & 0xff) as u8);
        value >>= 8;
    }
    String::from_utf8(bytes).ok()
}

// -- process-global capture ------------------------------------------------

static CAPTURE: Mutex<Vec<SlogWarning>> = Mutex::new(Vec::new());

fn clear_capture() {
    if let Ok(mut buf) = CAPTURE.lock() {
        buf.clear();
    }
}

fn drain_capture() -> Vec<SlogWarning> {
    CAPTURE
        .lock()
        .map(|mut buf| std::mem::take(&mut *buf))
        .unwrap_or_default()
}

fn push_capture(w: SlogWarning) {
    if let Ok(mut buf) = CAPTURE.lock() {
        buf.push(w);
    }
}

// -- tracing init + capture layer ------------------------------------------

static TRACING_INIT: OnceLock<()> = OnceLock::new();

/// Initialize tracing once per process: fmt layer (default human-
/// readable output) + EnvFilter (RUST_LOG, default "info") + a custom
/// layer that scoops `target: "slogger"` events into the per-thread
/// capture buffer. Subsequent calls are a no-op so multiple harnesses
/// in the same test process don't double-init.
fn init_capture_tracing(_cli: &boot::Cli) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{EnvFilter, fmt};
    TRACING_INIT.get_or_init(|| {
        let filter = EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
        );
        let _ = tracing_subscriber::registry()
            .with(fmt::layer())
            .with(filter)
            .with(SlogCaptureLayer)
            .try_init();
    });
}

struct SlogCaptureLayer;

impl<S> tracing_subscriber::Layer<S> for SlogCaptureLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() != "slogger" {
            return;
        }
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let Some(msg) = visitor.message else { return };
        let warning = if let Some(noun) = msg.strip_prefix("invalid cause ") {
            SlogWarning::InvalidCause {
                noun: noun.trim().to_string(),
            }
        } else {
            SlogWarning::Other(msg)
        };
        push_capture(warning);
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
}

impl tracing::field::Visit for MessageVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        }
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" && self.message.is_none() {
            self.message = Some(format!("{value:?}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_cause_tag_recovers_g_set() {
        // Hoon prints `[%g-set ...]` as `[499918253415 ...]`, formatted
        // with dotted thousands. The first atom decodes back to "g-set".
        let noun = "[499.918.253.415 138.296.650.232.540.498.593.146.226 1]";
        assert_eq!(decode_cause_tag(noun).as_deref(), Some("g-set"));
    }

    #[test]
    fn decode_cause_tag_rejects_zero_atom() {
        assert_eq!(decode_cause_tag("[0 1]"), None);
    }

    #[test]
    fn decode_cause_tag_handles_short_tag() {
        // `%foo` → 0x6f6f66 → 7.303.014 in the dotted format.
        let noun = "[7.303.014 ~]";
        assert_eq!(decode_cause_tag(noun).as_deref(), Some("foo"));
    }
}
