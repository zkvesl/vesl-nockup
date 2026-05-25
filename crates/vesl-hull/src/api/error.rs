//! Crash → HTTP mapping shared by every handler, plus the typed decoder
//! for `%settle-register-rejected` existing-root payloads (L-09).

use axum::http::StatusCode;
use axum::Json;

use nockvm::noun::NounAllocator;

use vesl_core::{NounSlab, PokeCrashError};

use super::types::ErrorBody;

/// Map a [`PokeCrashError`] to the handler's HTTP error tuple. Shared by
/// the handlers because the crash mapping is identical across pokes —
/// timeout → 504, `NockAppError` → 500, protocol violation (kernel emitted
/// an unparsable effect) → 502.
pub(super) fn crash_to_error(err: PokeCrashError) -> (StatusCode, Json<ErrorBody>) {
    match err {
        PokeCrashError::Timeout => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(ErrorBody {
                error: "kernel operation timed out".into(),
            }),
        ),
        PokeCrashError::KernelPoke(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "internal error".into(),
            }),
        ),
        PokeCrashError::UnexpectedTag { tag, .. } => (
            StatusCode::BAD_GATEWAY,
            Json(ErrorBody {
                error: format!("kernel emitted unparsable effect (head tag: {tag:?})"),
            }),
        ),
    }
}

/// Decode the `existing-root` atom from a `[%settle-register-rejected
/// hull=@ existing-root=@]` effect (audit L-09). Returns lowercase hex of
/// the atom's LE bytes — the same byte representation `tip5_to_atom_le_bytes`
/// produced at register time. Returns `None` if the effect's tail isn't a
/// cell with an atom on the right; callers fall back to a generic body
/// hint in that case.
pub(super) fn decode_register_rejected_existing_root(effect: &NounSlab) -> Option<String> {
    // SAFETY: the slab outlives this call.
    let root_noun = unsafe { *effect.root() };
    let space = effect.noun_space();
    let outer = root_noun.in_space(&space).as_cell().ok()?;
    let inner = outer.tail().as_cell().ok()?;
    let existing_atom = inner.tail().as_atom().ok()?;
    let bytes = existing_atom.as_ne_bytes();
    let trimmed_len = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    if trimmed_len == 0 {
        return Some(String::from("00"));
    }
    Some(hex::encode(&bytes[..trimmed_len]))
}
