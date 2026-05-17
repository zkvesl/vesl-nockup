use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use nockapp::kernel::boot;
use nockapp::noun::slab::NounSlab;
use nockapp::wire::{SystemWire, Wire};
use nockapp::NockApp;
use tokio::sync::Mutex;
use vesl_core::{
    build_settle_note_poke, build_settle_register_poke, Mint, Tip5Hash,
};

#[derive(Parser)]
#[command(name = "{{project_name}}", about = "{{description}}")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    #[command(flatten)]
    boot: boot::Cli,
}

#[derive(Subcommand)]
enum Cmd {
    /// Register a Merkle root and settle a note (default if no subcommand).
    Demo,
    /// Boot the kernel and serve the hull HTTP API on the configured port.
    Serve {
        #[arg(long, default_value = "3000")]
        port: u16,
        #[arg(long, default_value = "127.0.0.1")]
        bind_addr: String,
        #[arg(long)]
        no_auth: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    boot::init_default_tracing(&cli.boot);
    let kernel = fs::read("out.jam")?;
    let app: NockApp = boot::setup(&kernel, cli.boot, &[], "{{project_name}}", None).await?;

    match cli.cmd.unwrap_or(Cmd::Demo) {
        Cmd::Demo => run_demo(app).await,
        Cmd::Serve { port, bind_addr, no_auth } => {
            vesl_hull::check_auth_config_with_bind(no_auth, &bind_addr)
                .map_err(|e| -> Box<dyn Error> { e.into() })?;
            let state = build_app_state(app)?;
            vesl_hull::serve(state, port, &bind_addr).await
        }
    }
}

async fn run_demo(mut app: NockApp) -> Result<(), Box<dyn Error>> {
    // 1. Commit data to a Merkle tree.
    //    Default hash-gate verifies single-leaf commits only; see the
    //    vesl-nockup README "Customizing" section for multi-leaf /
    //    signed / STARK gates.
    let items: [&[u8]; 1] = [b"first"];
    let mut mint = Mint::new();
    let root: Tip5Hash = mint.commit(&items);

    // 2. Register the root under hull_id = 1
    poke(&mut app, build_settle_register_poke(1, &root)).await?;

    // 3. Settle a note committing to `first` (note_id = 1, hull = 1)
    poke(&mut app, build_settle_note_poke(1, 1, &root, items[0])).await?;

    Ok(())
}

fn build_app_state(app: NockApp) -> Result<vesl_hull::SharedState, Box<dyn Error>> {
    let settlement = vesl_hull::resolve_with_demo_key_checked(
        &vesl_hull::SettlementCliOverrides::default(),
        &vesl_hull::HullConfig::default(),
    )
    .map_err(|e| -> Box<dyn Error> { e.into() })?;
    let output_dir = PathBuf::from(".");
    let note_counter = vesl_hull::load_note_counter(Path::new(&output_dir));
    Ok(Arc::new(Mutex::new(vesl_hull::AppState {
        app,
        fields: Vec::new(),
        tree: None,
        hull_id: 1,
        note_counter,
        settlement,
        output_dir,
    })))
}

async fn poke(app: &mut NockApp, slab: NounSlab) -> Result<(), Box<dyn Error>> {
    let effects = app.poke(SystemWire.to_wire(), slab).await?;
    if effects.is_empty() {
        return Err("kernel returned no effects (likely duplicate hull \
                    registration or replay; see settle kernel slog)"
            .into());
    }
    for tag in vesl_core::effect_head_tags(&effects) {
        println!("  effect: %{tag}");
    }
    Ok(())
}
