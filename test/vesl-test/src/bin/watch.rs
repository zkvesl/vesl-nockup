//! `vesl-test watch` (RM4 §"Tool gap analysis" deferred — Tool 4) —
//! REPL-style live-trace tool. Boots a kernel from `out.jam`, runs
//! `app.run()` in the background, subscribes to its
//! `effect_broadcast`, and prints one structured row per kernel event
//! while reading poke/peek commands from stdin.
//!
//! All real logic lives in [`vesl_test::watch`]; the bin is a clap
//! shim so the same code paths can be tested in-process from
//! `tests/watch_smoke.rs` without subprocess overhead.
//!
//! Examples:
//!   cargo run -p vesl-test --bin watch -- out.jam
//!   echo 'poke-tag clear' | cargo run -p vesl-test --bin watch -- out.jam --json
//!   cargo run -p vesl-test --bin watch -- out.jam --filter cause=settle-register

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use vesl_test::watch::{self, DEFAULT_EFFECT_WINDOW_MS, WatchOpts};

#[derive(Parser, Debug)]
#[command(
    name = "watch",
    about = "REPL-style live-trace tool: subscribe to a NockApp kernel's effect broadcast and render events as they arrive."
)]
struct Cli {
    /// Compiled `out.jam` to boot.
    jam: PathBuf,
    /// `cause=<tag>` keeps only events whose cause matches; `effect=<tag>`
    /// keeps only events whose effect-list contains `<tag>`. Without a
    /// filter, every event is emitted.
    #[arg(long)]
    filter: Option<String>,
    /// Emit one JSON object per line instead of the human table.
    #[arg(long)]
    json: bool,
    /// Per-event drain window (ms) for the broadcast tap. After a poke
    /// acks, drain effects for this many ms before rendering. Default
    /// 100 ms (RM4 §6 acceptance #2 latency bound).
    #[arg(long, default_value_t = DEFAULT_EFFECT_WINDOW_MS)]
    effect_window_ms: u64,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("watch: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let opts = WatchOpts {
        jam: cli.jam,
        json: cli.json,
        filter: watch::parse_filter(cli.filter.as_deref())?,
        effect_window: Duration::from_millis(cli.effect_window_ms),
    };
    watch::run_with_jam(opts).await
}
