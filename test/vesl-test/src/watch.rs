//! `watch` — REPL-style live-trace tool. Boots a kernel from `out.jam`,
//! runs `app.run()` in the background, subscribes to its
//! `effect_broadcast`, and prints one structured row per kernel event
//! while reading poke/peek commands from stdin. Closes the
//! EFFECT-OBSERVATION friction class flagged in
//! `vesl-nockup/.dev/debug/log-meta/RM4/round.md` §"Tool gap analysis".
//!
//! The bin (`src/bin/watch.rs`) is a thin clap wrapper over
//! [`run_with_jam`]; the integration test in `tests/watch_smoke.rs`
//! drives [`drive`] directly with in-process readers and writers so the
//! render loop can be tested without subprocess overhead.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use nockapp::NockApp;
use nockapp::NockAppError;
use nockapp::driver::{NockAppHandle, PokeResult};
use nockapp::kernel::boot;
use nockapp::noun::slab::NounSlab;
use nockapp::wire::{SystemWire, Wire};
use nock_noun_rs::{cue_from_bytes, jam_to_bytes, make_tag_in, new_stack};
use nockvm::noun::{D, T};
use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::broadcast;
use tokio::time::Instant;
use vesl_core::{
    build_hull_peek_path, build_keyed_peek_path, build_keyless_peek_path,
    effect_head_tags,
};

use crate::{SlogWarning, clear_capture, drain_capture, init_capture_tracing};

// =============================================================================
// public surface
// =============================================================================

/// Per-event drain window (ms). After a poke acks, drain the broadcast
/// for at most this many ms before rendering. RM4 §6 acceptance #2
/// bounds the visible-event latency at 100 ms.
pub const DEFAULT_EFFECT_WINDOW_MS: u64 = 100;

/// Watch configuration. Fields are public so the bin (clap-driven)
/// and the smoke test (programmatic) can both populate it.
#[derive(Debug, Clone)]
pub struct WatchOpts {
    /// Compiled kernel jam path — used in heartbeat output and
    /// preserved through `kernel-died` rendering.
    pub jam: PathBuf,
    /// Emit one JSON object per line instead of the human table.
    pub json: bool,
    /// Optional cause/effect-tag filter; `None` lets every event through.
    pub filter: Option<Filter>,
    /// Per-event drain window for the broadcast tap. See
    /// [`DEFAULT_EFFECT_WINDOW_MS`].
    pub effect_window: Duration,
}

impl Default for WatchOpts {
    fn default() -> Self {
        Self {
            jam: PathBuf::new(),
            json: false,
            filter: None,
            effect_window: Duration::from_millis(DEFAULT_EFFECT_WINDOW_MS),
        }
    }
}

/// Either-or filter: `cause` is matched against the head-tag of the
/// poke this command issued (we know it from the stdin grammar);
/// `effect` is matched against any head-tag in the effect list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    Cause(String),
    Effect(String),
}

/// Parse `cause=<tag>` / `effect=<tag>` strings as accepted by the
/// `--filter` flag. Returns `Ok(None)` for empty/None.
pub fn parse_filter(s: Option<&str>) -> Result<Option<Filter>> {
    let Some(s) = s else { return Ok(None); };
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    if let Some(v) = s.strip_prefix("cause=") {
        Ok(Some(Filter::Cause(v.trim().to_string())))
    } else if let Some(v) = s.strip_prefix("effect=") {
        Ok(Some(Filter::Effect(v.trim().to_string())))
    } else {
        bail!("--filter must be `cause=<tag>` or `effect=<tag>` (got `{s}`)")
    }
}

/// One stdin command. The grammar is line-delimited:
///
///   `poke-tag <tag>`               — tag-only poke `[%<tag> ~]`
///   `poke-jam <hex>`               — pre-jammed cause noun (hex bytes)
///   `peek-tag <tag>`               — keyless peek path `[%<tag> ~]`
///   `peek-hull <tag> <decimal>`    — hull-keyed peek `[%<tag> hull ~]`
///   `peek-key  <tag> <string>`     — cord-keyed peek `[%<tag> %key ~]`
///   `state`                        — heartbeat (event count, jam path)
///   `quit` | `exit`                — clean shutdown
///   `# anything`                   — comment
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    PokeTag {
        tag: String,
    },
    PokeJam {
        bytes: Vec<u8>,
        cause_tag: Option<String>,
    },
    PeekTag {
        tag: String,
    },
    PeekHull {
        tag: String,
        hull: u64,
    },
    PeekKey {
        tag: String,
        key: String,
    },
}

impl Command {
    /// Cause-tag this command will produce in the rendered row.
    /// `poke-jam` callers may pre-declare a tag in the trailing
    /// `# tag=<name>` comment; without it, the rendered cause is the
    /// command verb (`poke-jam`).
    pub fn cause_tag(&self) -> &str {
        match self {
            Command::PokeTag { tag } => tag,
            Command::PokeJam { cause_tag, .. } => {
                cause_tag.as_deref().unwrap_or("poke-jam")
            }
            Command::PeekTag { tag } => tag,
            Command::PeekHull { tag, .. } => tag,
            Command::PeekKey { tag, .. } => tag,
        }
    }
}

/// Parse one stdin line. Comments and blank lines should be filtered
/// before calling this — the parser bails on empty input.
pub fn parse_command(line: &str) -> Result<Command> {
    let line = line.trim();
    if line.is_empty() {
        bail!("empty line");
    }
    let mut parts = line.split_whitespace();
    let verb = parts.next().expect("non-empty after trim");
    match verb {
        "poke-tag" => {
            let tag = parts
                .next()
                .ok_or_else(|| anyhow!("poke-tag: missing <tag>"))?
                .to_string();
            if parts.next().is_some() {
                bail!("poke-tag: trailing args (got `{line}`)");
            }
            Ok(Command::PokeTag { tag })
        }
        "poke-jam" => {
            let hex = parts
                .next()
                .ok_or_else(|| anyhow!("poke-jam: missing <hex>"))?;
            let bytes = decode_hex(hex)
                .with_context(|| format!("poke-jam: hex decode `{hex}`"))?;
            // Optional `# tag=<name>` annotation at end of line.
            let rest: Vec<&str> = parts.collect();
            let cause_tag = rest
                .iter()
                .find_map(|s| s.strip_prefix("tag=").map(str::to_string))
                .or_else(|| rest.iter().find_map(|s| s.strip_prefix("#tag=").map(str::to_string)));
            Ok(Command::PokeJam { bytes, cause_tag })
        }
        "peek-tag" => {
            let tag = parts
                .next()
                .ok_or_else(|| anyhow!("peek-tag: missing <tag>"))?
                .to_string();
            Ok(Command::PeekTag { tag })
        }
        "peek-hull" => {
            let tag = parts
                .next()
                .ok_or_else(|| anyhow!("peek-hull: missing <tag>"))?
                .to_string();
            let hull = parts
                .next()
                .ok_or_else(|| anyhow!("peek-hull: missing <hull>"))?
                .parse::<u64>()
                .with_context(|| "peek-hull: <hull> must be a decimal u64")?;
            Ok(Command::PeekHull { tag, hull })
        }
        "peek-key" => {
            let tag = parts
                .next()
                .ok_or_else(|| anyhow!("peek-key: missing <tag>"))?
                .to_string();
            let key = parts
                .next()
                .ok_or_else(|| anyhow!("peek-key: missing <key>"))?
                .to_string();
            Ok(Command::PeekKey { tag, key })
        }
        other => bail!("unknown command `{other}` (line: `{line}`)"),
    }
}

/// Boot a kernel from `opts.jam`, get a handle, spawn the run loop,
/// and run [`drive`] against stdin/stdout. The bin's `main` calls this.
pub async fn run_with_jam(opts: WatchOpts) -> Result<()> {
    let mut boot_cli = boot::default_boot_cli(false);
    boot_cli.state_jam = None; // CLI-level state-jam handling is out of scope
                               // for v1 — boot::setup loads from `data_dir` if
                               // set, and the bin's `--state-jam` flag would
                               // overwrite this when we wire it through.
    init_capture_tracing(&boot_cli);

    let kernel = std::fs::read(&opts.jam)
        .with_context(|| format!("reading kernel jam at {}", opts.jam.display()))?;
    let mut app: NockApp =
        boot::setup(&kernel, boot_cli, &[], "vesl-test-watch", None)
            .await
            .map_err(|e| anyhow!("boot setup failed: {e}"))?;

    let handle = app.get_handle();
    let effect_rx = handle.effect_sender.subscribe();
    let run_join = tokio::spawn(async move { app.run().await });

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let reader = tokio::io::BufReader::new(stdin);

    drive(opts, handle, run_join, effect_rx, reader, stdout).await
}

/// The render REPL. Runs until stdin closes, the user types `quit`/
/// `exit`, or the spawned `app.run()` task terminates (clean exit OR
/// panic — both produce a `kernel-died` row before returning).
///
/// `R`/`W` are generic so the smoke test can substitute a `&[u8]`
/// reader and a `Vec<u8>` writer without spawning a subprocess.
pub async fn drive<R, W>(
    opts: WatchOpts,
    handle: NockAppHandle,
    run_join: tokio::task::JoinHandle<Result<(), NockAppError>>,
    mut effect_rx: broadcast::Receiver<NounSlab>,
    mut reader: R,
    mut writer: W,
) -> Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    write_heartbeat(&opts, &mut writer).await?;

    let mut event_num: u64 = 0;
    let mut line_buf = String::new();
    let mut run_join = run_join;

    loop {
        line_buf.clear();
        tokio::select! {
            biased;
            res = &mut run_join => {
                let reason = match res {
                    Ok(Ok(())) => "kernel exited cleanly".to_string(),
                    Ok(Err(e)) => format!("kernel error: {e:?}"),
                    Err(je) => format!("kernel task panicked: {je}"),
                };
                write_kernel_died(&opts, &mut writer, &reason, event_num).await?;
                return Ok(());
            }
            n = reader.read_line(&mut line_buf) => {
                let n = n.context("stdin read")?;
                if n == 0 {
                    // EOF — graceful shutdown
                    break;
                }
                let line = line_buf.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if line == "quit" || line == "exit" {
                    break;
                }
                if line == "state" {
                    write_state(&opts, &mut writer, event_num).await?;
                    continue;
                }
                event_num += 1;
                let cmd = match parse_command(line) {
                    Ok(c) => c,
                    Err(e) => {
                        write_error(
                            &opts,
                            &mut writer,
                            event_num,
                            &format!("parse: {e:#}"),
                        ).await?;
                        continue;
                    }
                };
                handle_command(
                    &opts,
                    &handle,
                    &mut effect_rx,
                    &mut writer,
                    event_num,
                    cmd,
                ).await?;
            }
        }
    }
    Ok(())
}

// =============================================================================
// command dispatch
// =============================================================================

async fn handle_command<W>(
    opts: &WatchOpts,
    handle: &NockAppHandle,
    effect_rx: &mut broadcast::Receiver<NounSlab>,
    writer: &mut W,
    event_num: u64,
    cmd: Command,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let cause_tag = cmd.cause_tag().to_string();

    if !opts.filter.as_ref().is_none_or(|f| match f {
        Filter::Cause(t) => *t == cause_tag,
        // effect filter can't pre-empt — we only know effect tags after the poke
        Filter::Effect(_) => true,
    }) {
        return Ok(());
    }

    match cmd {
        Command::PokeTag { tag } => {
            let slab = build_tag_only_poke(&tag);
            run_poke(opts, handle, effect_rx, writer, event_num, &cause_tag, slab).await
        }
        Command::PokeJam { bytes, .. } => {
            let slab = cue_jammed(&bytes)
                .with_context(|| format!("poke-jam: cue {} bytes", bytes.len()))?;
            run_poke(opts, handle, effect_rx, writer, event_num, &cause_tag, slab).await
        }
        Command::PeekTag { tag } => {
            let path = build_keyless_peek_path(&tag);
            run_peek(opts, handle, writer, event_num, &cause_tag, path).await
        }
        Command::PeekHull { tag, hull } => {
            let path = build_hull_peek_path(&tag, hull);
            run_peek(opts, handle, writer, event_num, &cause_tag, path).await
        }
        Command::PeekKey { tag, key } => {
            let path = build_keyed_peek_path(&tag, &key);
            run_peek(opts, handle, writer, event_num, &cause_tag, path).await
        }
    }
}

async fn run_poke<W>(
    opts: &WatchOpts,
    handle: &NockAppHandle,
    effect_rx: &mut broadcast::Receiver<NounSlab>,
    writer: &mut W,
    event_num: u64,
    cause_tag: &str,
    slab: NounSlab,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    // Frame the slog window: clear before submitting, drain after.
    clear_capture();

    let wire = SystemWire.to_wire();
    let poke_outcome = handle.poke(wire, slab).await;

    let (ack, poke_err) = match poke_outcome {
        Ok(PokeResult::Ack) => ("ack".to_string(), None),
        Ok(PokeResult::Nack) => ("nack".to_string(), None),
        Err(e) => ("error".to_string(), Some(format!("{e:?}"))),
    };

    // Drain the broadcast for the configured window (default 100ms).
    // The kernel's `handle_poke` spawns a task that fires
    // `effect_broadcast.send(...)` per effect AFTER the poke acks, so a
    // bounded post-ack drain is the right signal-to-noise tradeoff.
    let effects = drain_effects(effect_rx, opts.effect_window).await;
    let effect_tags = effect_head_tags(&effects);
    let slogs = drain_capture();

    if let Some(Filter::Effect(needle)) = &opts.filter {
        if !effect_tags.iter().any(|t| t == needle) {
            return Ok(());
        }
    }

    write_event(
        opts,
        writer,
        event_num,
        cause_tag,
        Some(&ack),
        poke_err.as_deref(),
        &effect_tags,
        &slogs,
        None,
    )
    .await
}

async fn run_peek<W>(
    opts: &WatchOpts,
    handle: &NockAppHandle,
    writer: &mut W,
    event_num: u64,
    cause_tag: &str,
    path: NounSlab,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    clear_capture();
    let outcome = handle.peek(path).await;
    let (ack, peek_err, repr) = match outcome {
        Ok(Some(_)) => ("present".to_string(), None, Some("present".to_string())),
        Ok(None) => ("absent".to_string(), None, Some("absent".to_string())),
        Err(e) => ("error".to_string(), Some(format!("{e:?}")), None),
    };
    let slogs = drain_capture();

    write_event(
        opts,
        writer,
        event_num,
        cause_tag,
        Some(&ack),
        peek_err.as_deref(),
        &[],
        &slogs,
        repr.as_deref(),
    )
    .await
}

async fn drain_effects(
    effect_rx: &mut broadcast::Receiver<NounSlab>,
    window: Duration,
) -> Vec<NounSlab> {
    let deadline = Instant::now() + window;
    let mut effects = Vec::new();
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;
        match tokio::time::timeout(remaining, effect_rx.recv()).await {
            Ok(Ok(slab)) => effects.push(slab),
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => {
                // dropped events — keep draining what we can
                continue;
            }
            Ok(Err(broadcast::error::RecvError::Closed)) => break,
            Err(_) => break, // window expired
        }
    }
    effects
}

// =============================================================================
// poke builders
// =============================================================================

fn build_tag_only_poke(tag: &str) -> NounSlab {
    let mut slab = NounSlab::new();
    let head = make_tag_in(&mut slab, tag);
    let cause = T(&mut slab, &[head, D(0)]);
    slab.set_root(cause);
    slab
}

fn cue_jammed(bytes: &[u8]) -> Result<NounSlab> {
    let mut stack = new_stack();
    let noun = cue_from_bytes(&mut stack, bytes)
        .ok_or_else(|| anyhow!("cue failed: not a valid jammed noun"))?;
    let mut slab = NounSlab::new();
    let copied = slab.copy_into(noun);
    slab.set_root(copied);
    Ok(slab)
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        bail!("odd-length hex string ({} chars)", s.len());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let pair = &s[i..i + 2];
        out.push(u8::from_str_radix(pair, 16).with_context(|| format!("bad hex pair `{pair}`"))?);
    }
    Ok(out)
}

/// Re-jam an existing slab to wire bytes (caller-friendly companion to
/// the `poke-jam` command — round-trips a pre-built slab through the
/// decoder so tests can assemble pokes with the lib's existing helpers
/// and feed them into watch via stdin).
pub fn jam_slab(slab: &NounSlab) -> Vec<u8> {
    let mut stack = new_stack();
    let root = unsafe { *slab.root() };
    jam_to_bytes(&mut stack, root)
}

/// Hex-encode bytes for the `poke-jam` stdin command. Pairs with
/// [`jam_slab`].
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// =============================================================================
// rendering
// =============================================================================

async fn write_heartbeat<W>(opts: &WatchOpts, writer: &mut W) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let line = if opts.json {
        let v = json!({
            "kind": "heartbeat",
            "jam": opts.jam.display().to_string(),
            "filter": filter_repr(&opts.filter),
        });
        format!("{v}\n")
    } else {
        format!(
            "watch: subscribed to {} (filter: {})\n",
            opts.jam.display(),
            filter_repr_human(&opts.filter),
        )
    };
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

async fn write_state<W>(opts: &WatchOpts, writer: &mut W, event_num: u64) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let line = if opts.json {
        let v = json!({ "kind": "state", "event_num": event_num });
        format!("{v}\n")
    } else {
        format!("[#{event_num}] state: {} commands processed\n", event_num)
    };
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn write_event<W>(
    opts: &WatchOpts,
    writer: &mut W,
    event_num: u64,
    cause_tag: &str,
    ack: Option<&str>,
    err: Option<&str>,
    effect_tags: &[String],
    slogs: &[SlogWarning],
    peek_repr: Option<&str>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let line = if opts.json {
        let slogs_json: Vec<Value> = slogs.iter().map(slog_to_json).collect();
        let v = json!({
            "event_num": event_num,
            "wall_clock": now_secs(),
            "cause_tag": cause_tag,
            "ack": ack,
            "err": err,
            "effect_tags": effect_tags,
            "slogs": slogs_json,
            "peek": peek_repr,
        });
        format!("{v}\n")
    } else {
        let mut s = format!("[#{event_num}] cause={cause_tag}");
        if let Some(a) = ack {
            s.push_str(&format!(" ack={a}"));
        }
        if let Some(e) = err {
            s.push_str(&format!(" err={e}"));
        }
        if !effect_tags.is_empty() {
            s.push_str(&format!(" effects=[{}]", effect_tags.join(", ")));
        } else {
            s.push_str(" effects=[]");
        }
        if !slogs.is_empty() {
            let printed: Vec<String> = slogs.iter().map(slog_to_human).collect();
            s.push_str(&format!(" slogs=[{}]", printed.join("; ")));
        }
        if let Some(p) = peek_repr {
            s.push_str(&format!(" peek={p}"));
        }
        s.push('\n');
        s
    };
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

async fn write_error<W>(
    opts: &WatchOpts,
    writer: &mut W,
    event_num: u64,
    msg: &str,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let line = if opts.json {
        let v = json!({ "event_num": event_num, "kind": "error", "message": msg });
        format!("{v}\n")
    } else {
        format!("[#{event_num}] error: {msg}\n")
    };
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

async fn write_kernel_died<W>(
    opts: &WatchOpts,
    writer: &mut W,
    reason: &str,
    event_num: u64,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let line = if opts.json {
        let v = json!({
            "event_num": event_num,
            "kind": "kernel-died",
            "reason": reason,
        });
        format!("{v}\n")
    } else {
        format!("[#{event_num}] kernel-died: {reason}\n")
    };
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

fn filter_repr(f: &Option<Filter>) -> Value {
    match f {
        None => Value::Null,
        Some(Filter::Cause(t)) => json!({ "cause": t }),
        Some(Filter::Effect(t)) => json!({ "effect": t }),
    }
}

fn filter_repr_human(f: &Option<Filter>) -> String {
    match f {
        None => "none".to_string(),
        Some(Filter::Cause(t)) => format!("cause={t}"),
        Some(Filter::Effect(t)) => format!("effect={t}"),
    }
}

fn slog_to_human(w: &SlogWarning) -> String {
    match w {
        SlogWarning::InvalidCause { noun } => format!("invalid-cause {noun}"),
        SlogWarning::Other(s) => s.clone(),
    }
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn slog_to_json(w: &SlogWarning) -> Value {
    match w {
        SlogWarning::InvalidCause { noun } => {
            json!({ "kind": "invalid-cause", "noun": noun })
        }
        SlogWarning::Other(s) => json!({ "kind": "other", "message": s }),
    }
}

// =============================================================================
// tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_command_poke_tag() {
        let cmd = parse_command("poke-tag clear").unwrap();
        assert_eq!(cmd, Command::PokeTag { tag: "clear".into() });
    }

    #[test]
    fn parse_command_poke_jam_with_tag_annotation() {
        let cmd = parse_command("poke-jam deadbeef tag=settle-register").unwrap();
        match cmd {
            Command::PokeJam { bytes, cause_tag } => {
                assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
                assert_eq!(cause_tag.as_deref(), Some("settle-register"));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn parse_command_peek_hull() {
        let cmd = parse_command("peek-hull settle-registered 1").unwrap();
        assert_eq!(
            cmd,
            Command::PeekHull {
                tag: "settle-registered".into(),
                hull: 1
            }
        );
    }

    #[test]
    fn parse_command_rejects_unknown_verb() {
        let err = parse_command("dance now").unwrap_err();
        assert!(format!("{err:#}").contains("unknown command"));
    }

    #[test]
    fn parse_filter_recognizes_cause() {
        let f = parse_filter(Some("cause=settle-error")).unwrap();
        assert_eq!(f, Some(Filter::Cause("settle-error".into())));
    }

    #[test]
    fn parse_filter_recognizes_effect() {
        let f = parse_filter(Some("effect=settle-registered")).unwrap();
        assert_eq!(f, Some(Filter::Effect("settle-registered".into())));
    }

    #[test]
    fn parse_filter_rejects_garbage() {
        assert!(parse_filter(Some("bare-tag")).is_err());
    }

    #[test]
    fn decode_hex_round_trips() {
        let bytes = vec![0x01, 0x02, 0xff, 0x00, 0x80];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "0102ff0080");
        assert_eq!(decode_hex(&hex).unwrap(), bytes);
    }

    #[test]
    fn decode_hex_strips_0x_prefix() {
        assert_eq!(decode_hex("0xdeadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn decode_hex_rejects_odd_length() {
        assert!(decode_hex("abc").is_err());
    }
}
