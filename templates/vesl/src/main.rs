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
struct Args {
    /// Raise the default log floor from INFO to WARN. Suppresses
    /// nockapp boot / PMA INFO chatter so the actual app output is
    /// readable. RUST_LOG (if set) still wins — `--quiet` only
    /// shifts the default.
    #[arg(short = 'q', long, global = true)]
    quiet: bool,

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
    let args = Args::parse();
    // Translate --quiet into a RUST_LOG default before nockapp reads
    // it. RUST_LOG (if explicitly set) still wins.
    if args.quiet && std::env::var_os("RUST_LOG").is_none() {
        // SAFETY: single-threaded at this point (no tokio tasks spawned yet).
        unsafe { std::env::set_var("RUST_LOG", "warn") };
    }
    boot::init_default_tracing(&args.boot);
    let kernel = load_kernel()?;
    let app: NockApp = boot::setup(&kernel, args.boot, &[], "{{project_name}}", None).await?;

    match args.cmd.unwrap_or(Cmd::Demo) {
        Cmd::Demo => run_demo(app).await,
        Cmd::Serve { port, bind_addr, no_auth } => {
            vesl_hull::check_auth_config_with_bind(no_auth, &bind_addr)
                .map_err(|e| -> Box<dyn Error> { e.into() })?;
            let state = build_app_state(app)?;
            vesl_hull::serve(state, port, &bind_addr).await
        }
    }
}

/// Read `out.jam` and verify its integrity before boot.
///
/// When `VESL_KERNEL_SHA256` is set, the kernel's sha256 must match it or
/// boot is refused; when unset, boot proceeds with a warning. This keeps
/// the edit-Hoon / recompile / rerun loop fast while letting a production
/// deploy pin the kernel hash.
fn load_kernel() -> Result<Vec<u8>, Box<dyn Error>> {
    use sha2::{Digest, Sha256};

    let kernel =
        fs::read("out.jam").map_err(|e| format!("Failed to read out.jam: {e}"))?;
    // hoonc can exit 0 while producing no kernel: a structural error in the
    // Hoon surfaces as a "no panic!" line and an empty `out.jam`, not a
    // non-zero exit. Reject the empty artifact here so a silently-failed
    // compile cannot boot a garbage kernel.
    if kernel.is_empty() {
        return Err("out.jam is empty — hoonc exited 0 but produced no kernel. \
                    Recompile and check hoonc's output for the structural \
                    error (look for a [DIAG] / mote line); compile.sh makes \
                    that failure loud."
            .into());
    }
    match std::env::var("VESL_KERNEL_SHA256") {
        Ok(expected) => {
            let expected = expected.trim();
            let actual: String = Sha256::digest(&kernel)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            if actual != expected {
                return Err(format!(
                    "out.jam sha256 mismatch: expected {expected}, got {actual} \
                     — refusing to boot"
                )
                .into());
            }
        }
        Err(_) => eprintln!(
            "warning: out.jam integrity unverified — \
             set VESL_KERNEL_SHA256 to pin the kernel hash"
        ),
    }
    Ok(kernel)
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
    // Snapshot the manifest dir once at boot so /status can surface the
    // active gate, the composed grafts, and per-graft sha256s.
    // Missing dir is non-fatal: the hull falls back to a default-hash
    // empty summary if run outside a graft project scaffold.
    let manifest = vesl_hull::ManifestSummary::from_manifest_dir(Path::new("hoon/lib"))
        .unwrap_or_else(|e| {
            eprintln!("WARNING: failed to scan hoon/lib for graft manifests: {e}");
            vesl_hull::ManifestSummary::empty()
        });
    // Pick the SettlePayloadBuilder impl from the active gate.
    // Stock /settle dispatches through this so manifest-verify (or any
    // future catalog gate with a SettlePayloadBuilder impl) succeeds
    // without a custom route. Unknown gates warn and fall back to
    // default-hash.
    let settle_builder = vesl_hull::payload_builder_for_gate(&manifest.gate);
    Ok(Arc::new(Mutex::new(vesl_hull::AppState {
        app,
        fields: Vec::new(),
        tree: None,
        hull_id: 1,
        note_counter,
        settlement,
        output_dir,
        manifest,
        settle_builder,
        rbac: vesl_hull::RbacConfig::default(),
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
