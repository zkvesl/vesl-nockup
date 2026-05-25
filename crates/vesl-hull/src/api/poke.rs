//! Timed wrapper around `NockApp::poke` that classifies the result into
//! the typed [`PokeOutcome`] every handler matches on.

use nockapp::wire::{SystemWire, Wire};
use nockapp::NockApp;

use vesl_core::{classify_effects, NounSlab, PokeCrashError, PokeOutcome};

/// Poke the kernel with a 30s timeout, classifying the result into a
/// typed [`PokeOutcome`]. `log_prefix` names the poke for stderr logging
/// (e.g. "register", "settle") on the crash paths.
///
/// Callers match the returned outcome to dispatch on success / rejection /
/// crash without scraping stderr or string-matching effect tags blindly.
/// `classify_effects` (in `vesl-core`) routes a non-empty effect list by
/// the head tag of its first effect; the wrapper here adds the
/// timeout, `NockAppError`, and empty-list cases that the classifier
/// cannot see from `effects` alone.
pub(super) async fn poke_kernel_with_timeout(
    app: &mut NockApp,
    poke: NounSlab,
    log_prefix: &str,
) -> PokeOutcome {
    match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        app.poke(SystemWire.to_wire(), poke),
    )
    .await
    {
        Err(_) => {
            tracing::warn!(target: "vesl_hull::poke", "kernel {log_prefix} poke timed out");
            PokeOutcome::Crashed {
                error: PokeCrashError::Timeout,
            }
        }
        Ok(Err(e)) => {
            tracing::error!(target: "vesl_hull::poke", "kernel {log_prefix} poke failed: {e}");
            PokeOutcome::Crashed {
                error: PokeCrashError::KernelPoke(e),
            }
        }
        Ok(Ok(effects)) => classify_effects(effects),
    }
}
