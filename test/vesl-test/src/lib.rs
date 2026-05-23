//! vesl-test — harness + standard suite for grafted NockApp kernels.
//!
//! Boots a kernel from an `out.jam`, constructs settle-register / verify /
//! note pokes, runs a lifecycle test, and asserts the effect tags.
//! Reuses the poke shapes from vesl-core and nock-noun-rs — no kernel
//! knowledge required from the caller.
//!
//! The primitive was renamed from `vesl-graft` to `settle-graft`;
//! the method names below track the new naming (`register` /  `verify`
//! /  `note`). The `settle` method remains as a deprecated alias so
//! existing tests outside this repo keep compiling for one release.

pub mod watch;

use std::fs;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use nockapp::NockApp;
use nockapp::kernel::boot;
use nockapp::noun::slab::NounSlab;
use nockapp::wire::{SystemWire, Wire};
use vesl_core::{
    classify_effects, build_graft_single_leaf_payload_jammed, build_settle_poke_jammed,
    build_settle_register_poke, PokeCrashError, PokeOutcome, Tip5Hash,
};

// -- public test vectors ----------------------------------------------------

pub const TEST_HULL_A: u64 = 1;
pub const TEST_HULL_B: u64 = 2;
pub const TEST_PAYLOAD: &[u8] = b"vesl-test fixture payload";

// -- harness ---------------------------------------------------------------

pub struct GraftTestHarness {
    app: NockApp,
    // Held for the lifetime of the harness so the kernel's data files
    // (event log, pma snapshots) survive until the harness drops. The
    // TempDir's Drop wipes the directory, isolating each test run.
    _data_dir: tempfile::TempDir,
}

impl GraftTestHarness {
    /// Borrow the underlying `NockApp`. Used by `vesl-checkpoint`
    /// snapshot/resume tests that need to pass the live app to
    /// `snapshot()` without going through a harness method.
    pub fn app(&self) -> &NockApp {
        &self.app
    }

    /// Boot a NockApp from a compiled out.jam.
    ///
    /// Each harness instance gets its own scratch data directory so
    /// parallel tests don't share an event log. Without this, the
    /// kernel's default data dir resolves to `./.data.vesl-test/`
    /// (cwd-rooted) and successive boots replay prior tests' events —
    /// hull-id collisions on `%settle-register` are the visible
    /// symptom.
    pub async fn boot<P: AsRef<Path>>(jam_path: P) -> Result<Self> {
        let jam_path = jam_path.as_ref();
        let data_dir = tempfile::Builder::new()
            .prefix("vesl-test-data-")
            .tempdir()
            .context("create tempdir for vesl-test harness data")?;
        let mut cli = boot::default_boot_cli(false);
        cli.data_dir = Some(data_dir.path().to_path_buf());
        init_capture_tracing(&cli);
        let kernel = fs::read(jam_path)
            .with_context(|| format!("reading kernel jam at {}", jam_path.display()))?;
        let app: NockApp =
            boot::setup(&kernel, cli, &[], "vesl-test", None)
                .await
                .map_err(|e| anyhow::anyhow!("boot setup failed: {e}"))?;
        Ok(Self {
            app,
            _data_dir: data_dir,
        })
    }

    /// Send `[%settle-register hull root]`. Returns the typed
    /// [`PokeOutcome`]; call `.effect_head_tags()` for the tag list.
    pub async fn register(&mut self, hull: u64, root: &Tip5Hash) -> Result<PokeOutcome> {
        let slab = build_settle_register_poke(hull, root);
        self.poke_slab(slab).await
    }

    /// Send `[%settle-verify payload]` where payload is pre-jammed graft bytes.
    pub async fn verify(&mut self, payload: &[u8]) -> Result<PokeOutcome> {
        let slab = build_settle_poke_jammed("settle-verify", payload);
        self.poke_slab(slab).await
    }

    /// Send `[%settle-note payload]` where payload is pre-jammed graft bytes.
    pub async fn note(&mut self, payload: &[u8]) -> Result<PokeOutcome> {
        let slab = build_settle_poke_jammed("settle-note", payload);
        self.poke_slab(slab).await
    }

    /// Deprecated alias for [`GraftTestHarness::note`]. The `%vesl-settle`
    /// cause tag became `%settle-note`.
    #[deprecated(since = "0.2.0", note = "renamed; use note()")]
    pub async fn settle(&mut self, payload: &[u8]) -> Result<PokeOutcome> {
        self.note(payload).await
    }

    /// Raw escape hatch — send an arbitrary NounSlab as a system poke.
    /// Returns a typed [`PokeOutcome`] classifying the kernel's reply.
    /// A `NockAppError` from `app.poke` becomes
    /// [`PokeCrashError::KernelPoke`] under [`PokeOutcome::Crashed`] —
    /// tests can match on it instead of catching the error at the
    /// `Result` layer.
    pub async fn poke_slab(&mut self, slab: NounSlab) -> Result<PokeOutcome> {
        let outcome = match self.app.poke(SystemWire.to_wire(), slab).await {
            Ok(effects) => classify_effects(effects),
            Err(e) => PokeOutcome::Crashed {
                error: PokeCrashError::KernelPoke(e),
            },
        };
        Ok(outcome)
    }

    /// Like [`poke_slab`] but also returns any slog warnings emitted
    /// during the call (e.g. `invalid cause` from the wrapper's
    /// `(soft cause)` short-circuit). Use when a test needs to assert
    /// on the kernel's diagnostics, not just on the typed outcome.
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
        let outcome = self.poke_slab(slab).await?;
        Ok(PokeReport {
            outcome,
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

        // 2. duplicate register → typed rejection (audit M-01: hull is
        //    one-shot; settle-graft emits %settle-register-rejected with
        //    the existing root rather than a generic %settle-error).
        report.record(
            "duplicate-register",
            self.register(TEST_HULL_A, &root).await,
            &["settle-register-rejected"],
        );

        // 3. verify (valid payload)
        let payload = build_graft_single_leaf_payload_jammed(1, TEST_HULL_A, &root, TEST_PAYLOAD);
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
        let settle_payload = build_graft_single_leaf_payload_jammed(42, TEST_HULL_B, &root, TEST_PAYLOAD);
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
        let bogus = build_graft_single_leaf_payload_jammed(99, 99_999, &root, TEST_PAYLOAD);
        report.record(
            "unregistered-hull",
            self.note(&bogus).await,
            &["settle-error"],
        );

        // 7. root mismatch
        let mut other_mint = vesl_core::Mint::new();
        let other_root = other_mint.commit(&[b"different-payload".as_ref()]);
        let mismatched = build_graft_single_leaf_payload_jammed(100, TEST_HULL_A, &other_root, TEST_PAYLOAD);
        report.record(
            "root-mismatch",
            self.note(&mismatched).await,
            &["settle-error"],
        );

        report
    }
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
        result: Result<PokeOutcome>,
        expected_contains: &[&str],
    ) {
        match result {
            Err(e) => {
                self.failed.push((name.to_string(), format!("poke error: {e:#}")));
            }
            Ok(outcome) => {
                let tags = outcome.effect_head_tags();
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

/// Outcome of a single poke alongside any slog warnings emitted during
/// the call. `outcome` is the typed [`PokeOutcome`] that
/// [`GraftTestHarness::poke_slab`] returns; `slog_warnings` captures
/// `target: "slogger"` tracing events from the kernel. For tests that
/// only need the effect tag list, call `report.outcome.effect_head_tags()`.
#[derive(Debug)]
pub struct PokeReport {
    pub outcome: PokeOutcome,
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

/// Decode the leading tag of an `invalid cause` noun. Handles two
/// canonical slog shapes:
///
/// 1. **Cord-decoded** (the current `templates/app.hoon` shape):
///    `"[%g-set ...] (full: [499.918.253.415 ...])"` → `Some("g-set")`.
///    The `?@` ladder in the kernel's `?~ act` slog renders the head
///    atom as `@tas` when it fits, and falls back to `%unknown` for
///    cell-headed or non-tas shapes — in which case the original noun
///    follows after `(full: ...)` and we try the dotted-decimal path
///    against that.
///
/// 2. **Raw dotted-decimal** (pre-cord-decoder kernels, or `%unknown`
///    fallback): `"[499.918.253.415 138.296...]"` → `Some("g-set")`.
///    Hoon's `<...>` formatter prints atoms as little-endian decimal
///    with dot separators every three digits; this reverses that for
///    the head atom only.
///
/// Returns None when neither shape matches or the head atom is zero.
pub fn decode_cause_tag(noun: &str) -> Option<String> {
    let trimmed = noun.trim();

    if let Some(after_bracket) = trimmed.strip_prefix("[%") {
        let tag_end = after_bracket
            .find(|c: char| c.is_whitespace() || c == ']')
            .unwrap_or(after_bracket.len());
        let tag = &after_bracket[..tag_end];
        if !tag.is_empty() && tag != "unknown" {
            return Some(tag.to_string());
        }
        if let Some(full_start) = trimmed.find("(full: ") {
            let full_str = &trimmed[full_start + "(full: ".len()..];
            return decode_dotted_decimal_head(full_str);
        }
        return None;
    }

    decode_dotted_decimal_head(trimmed)
}

fn decode_dotted_decimal_head(noun: &str) -> Option<String> {
    let inner = noun
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(')')
        .trim_end_matches(']');
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

/// Reset the process-global slog buffer. Called at the start of every
/// `poke_slab_report` so each report's slogs don't accumulate from
/// previous calls. Exposed publicly so the `watch` bin can frame
/// per-event slog windows the same way.
pub fn clear_capture() {
    if let Ok(mut buf) = CAPTURE.lock() {
        buf.clear();
    }
}

/// Drain and return every `SlogWarning` captured since the last
/// [`clear_capture`]. Public so the `watch` bin can interleave slogs
/// with effect-broadcast events without duplicating the capture stack.
pub fn drain_capture() -> Vec<SlogWarning> {
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
/// in the same test process don't double-init. Public so the `watch`
/// bin can install the same capture stack from outside the harness.
pub fn init_capture_tracing(_cli: &boot::Cli) {
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

    #[test]
    fn decode_cause_tag_handles_cord_decoded_head() {
        // The cord-decoder ladder renders @tas heads as %<tag>
        // inline, with the full noun after `(full: ...)`.
        let noun = "[%g-mint ...] (full: [128.017.563.987.303 0])";
        assert_eq!(decode_cause_tag(noun).as_deref(), Some("g-mint"));
    }

    #[test]
    fn decode_cause_tag_falls_back_on_unknown_head() {
        // %unknown means the cord-decoder couldn't fit the head as @tas
        // (cell head, garbage atom, etc.). Fall back to dotted-decimal
        // decode of the (full: ...) portion.
        let noun = "[%unknown ...] (full: [499.918.253.415 1])";
        assert_eq!(decode_cause_tag(noun).as_deref(), Some("g-set"));
    }

    #[test]
    fn decode_cause_tag_unknown_with_zero_head_returns_none() {
        let noun = "[%unknown ...] (full: [0 1])";
        assert_eq!(decode_cause_tag(noun), None);
    }
}
