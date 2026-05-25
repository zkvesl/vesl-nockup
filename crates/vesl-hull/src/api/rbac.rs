//! RBAC pre-check: peek `[%rbac-has-perm pubkey perm ~]` against the
//! composed rbac-graft before invoking the kernel poke, so denials never
//! reach the kernel slog.

use axum::http::{HeaderMap, StatusCode};
use axum::Json;

use nock_noun_rs::{make_atom_in, make_tag_in};
use nockapp::NockApp;
use nockvm::noun::{D, T};

use vesl_core::{peek_loobean, NounSlab, PokeCrashError, PokeOutcome, RejectionReason};

use super::error::crash_to_error;
use super::types::ErrorBody;

/// Request header carrying the acting pubkey for RBAC peeks. Caller-set
/// hex (with or without a `0x` prefix); the hull decodes to bytes before
/// building the peek atom. Independent of the API-key middleware — the
/// key authenticates the request, the pubkey identifies the principal.
pub(super) const PUBKEY_HEADER: &str = "x-hull-pubkey";

/// Perm name gating POST /commit.
pub(super) const COMMIT_PERM: &str = "commit";

/// Perm name gating POST /settle.
pub(super) const SETTLE_PERM: &str = "settle";

/// Build the `[%rbac-has-perm pubkey=@ perm=@t ~]` peek path slab.
///
/// `pubkey_hex` may carry an optional `0x` prefix; bytes are decoded
/// and packed as the atom payload (the rbac-graft compares atom equality
/// against whatever was passed to `%rbac-grant`). Returns `None` when
/// the hex string is malformed — caller should surface as HTTP 400.
fn build_rbac_has_perm_peek_path(pubkey_hex: &str, perm: &str) -> Option<NounSlab> {
    let stripped = pubkey_hex.trim_start_matches("0x").trim_start_matches("0X");
    let pubkey_bytes = hex::decode(stripped).ok()?;
    let mut slab: NounSlab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "rbac-has-perm");
    let pk_atom = make_atom_in(&mut slab, &pubkey_bytes);
    let perm_atom = make_tag_in(&mut slab, perm);
    let path = T(&mut slab, &[tag, pk_atom, perm_atom, D(0)]);
    slab.set_root(path);
    Some(slab)
}

/// Check whether `pubkey_hex` holds `perm` against the kernel's rbac-graft.
///
/// Returns:
/// - `PokeOutcome::Accepted { effects: vec![] }` when the peek returns
///   `%.y`. The empty effects field signals "no kernel-emitted effects to
///   consume" — the peek doesn't produce effects, only a verdict.
/// - `PokeOutcome::Rejected { reason: RejectionReason::RbacDenied { .. } }`
///   when the peek returns `%.n` or `[~ ~]` (path bound, no value).
/// - `PokeOutcome::Crashed { error: PokeCrashError::KernelPoke(..) }` on
///   a peek-level failure (e.g. rbac-graft not composed in the kernel —
///   nockapp's `peek_handle` surfaces this as `NockAppError::PeekFailed`).
/// - `PokeOutcome::Crashed { error: PokeCrashError::UnexpectedTag { .. } }`
///   when the peek returns a non-loobean atom — protocol drift from
///   rbac-graft's expected `(unit (unit ?))` contract.
pub(super) async fn check_rbac_perm(
    app: &mut NockApp,
    pubkey_hex: &str,
    perm: &str,
) -> Result<PokeOutcome, (StatusCode, Json<ErrorBody>)> {
    let Some(path) = build_rbac_has_perm_peek_path(pubkey_hex, perm) else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: format!("invalid {PUBKEY_HEADER} header: not hex"),
            }),
        ));
    };
    let outcome = match app.peek_handle(path).await {
        Ok(Some(slab)) => match peek_loobean(&slab) {
            Some(true) => PokeOutcome::Accepted {
                effects: Vec::new(),
            },
            Some(false) => PokeOutcome::Rejected {
                reason: RejectionReason::RbacDenied {
                    pubkey: pubkey_hex.to_string(),
                    perm: perm.to_string(),
                },
            },
            None => PokeOutcome::Crashed {
                error: PokeCrashError::UnexpectedTag {
                    tag: format!("rbac-has-perm: non-loobean result for pubkey {pubkey_hex}"),
                    raw_effects: Vec::new(),
                },
            },
        },
        Ok(None) => PokeOutcome::Rejected {
            reason: RejectionReason::RbacDenied {
                pubkey: pubkey_hex.to_string(),
                perm: perm.to_string(),
            },
        },
        Err(e) => PokeOutcome::Crashed {
            error: PokeCrashError::KernelPoke(e),
        },
    };
    Ok(outcome)
}

/// Read the `X-Hull-Pubkey` header. Missing or non-UTF-8 → HTTP 400 with
/// a header-name hint so callers know what to add. Returns the raw header
/// value (caller passes it to `build_rbac_has_perm_peek_path`, which
/// validates hex shape).
pub(super) fn extract_pubkey_header(
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<ErrorBody>)> {
    let value = headers.get(PUBKEY_HEADER).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: format!(
                    "missing {PUBKEY_HEADER} header; RBAC is enabled and this endpoint \
                     requires a pubkey to identify the acting principal"
                ),
            }),
        )
    })?;
    value
        .to_str()
        .map(|s| s.to_string())
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: format!("invalid {PUBKEY_HEADER} header: not UTF-8"),
                }),
            )
        })
}

/// Map an RBAC pre-check [`PokeOutcome`] to the handler's error tuple.
/// Identical mapping for both endpoints — denial → 403, crash → via
/// [`crash_to_error`]. Accepted falls through (caller proceeds to poke
/// the kernel); the function returns `Ok(())` in that case.
pub(super) fn handle_rbac_outcome(
    outcome: PokeOutcome,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    match outcome {
        PokeOutcome::Accepted { .. } => Ok(()),
        PokeOutcome::Rejected {
            reason: RejectionReason::RbacDenied { pubkey, perm },
        } => Err((
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: format!("pubkey {pubkey} lacks perm {perm}"),
            }),
        )),
        PokeOutcome::Rejected { reason } => {
            // check_rbac_perm only constructs Accepted / RbacDenied / Crashed.
            // A different Rejected variant would be a logic bug here.
            unreachable!("check_rbac_perm produced unexpected rejection: {reason:?}")
        }
        PokeOutcome::Crashed { error } => Err(crash_to_error(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HullRbacToml, RbacConfig};
    use axum::http::HeaderValue;
    use nockvm::noun::NounAllocator;

    #[test]
    fn rbac_peek_path_accepts_hex_with_and_without_prefix() {
        let bare = build_rbac_has_perm_peek_path("deadbeef", "commit");
        let prefixed = build_rbac_has_perm_peek_path("0xdeadbeef", "commit");
        let upper = build_rbac_has_perm_peek_path("0XDEADBEEF", "commit");
        assert!(bare.is_some());
        assert!(prefixed.is_some());
        assert!(upper.is_some());
    }

    #[test]
    fn rbac_peek_path_rejects_non_hex() {
        assert!(build_rbac_has_perm_peek_path("nothex", "commit").is_none());
        assert!(build_rbac_has_perm_peek_path("0xZZ", "commit").is_none());
        // odd-length hex is also rejected (hex::decode requires pairs).
        assert!(build_rbac_has_perm_peek_path("abc", "commit").is_none());
    }

    #[test]
    fn rbac_peek_path_first_element_is_rbac_has_perm_tag() {
        let slab = build_rbac_has_perm_peek_path("deadbeef", "commit").expect("valid hex");
        // Reach into the slab to confirm the head tag — the rest of the
        // shape (4 elements ending in ~) is enforced by the rbac-graft
        // peek arm; we only sanity-check the entry point here.
        let space = slab.noun_space();
        let root = unsafe { *slab.root() };
        let outer = root.in_space(&space).as_cell().expect("outer cell");
        let tag_atom = outer.head().as_atom().expect("head is atom");
        let bytes = tag_atom.as_ne_bytes();
        let trimmed_len = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        assert_eq!(&bytes[..trimmed_len], b"rbac-has-perm");
    }

    #[test]
    fn extract_pubkey_header_succeeds_when_set() {
        let mut headers = HeaderMap::new();
        headers.insert(PUBKEY_HEADER, HeaderValue::from_static("0xabc"));
        match extract_pubkey_header(&headers) {
            Ok(pk) => assert_eq!(pk, "0xabc"),
            Err(_) => panic!("header was set; extraction must succeed"),
        }
    }

    #[test]
    fn extract_pubkey_header_400s_when_missing() {
        let headers = HeaderMap::new();
        match extract_pubkey_header(&headers) {
            Ok(_) => panic!("no header set; extraction must fail"),
            Err((status, _)) => assert_eq!(status, StatusCode::BAD_REQUEST),
        }
    }

    #[test]
    fn handle_rbac_outcome_accepted_falls_through() {
        let outcome = PokeOutcome::Accepted {
            effects: Vec::new(),
        };
        assert!(handle_rbac_outcome(outcome).is_ok());
    }

    #[test]
    fn handle_rbac_outcome_rbac_denied_yields_403() {
        let outcome = PokeOutcome::Rejected {
            reason: RejectionReason::RbacDenied {
                pubkey: "0xabc".into(),
                perm: "commit".into(),
            },
        };
        match handle_rbac_outcome(outcome) {
            Ok(()) => panic!("RbacDenied must produce an error"),
            Err((status, body)) => {
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert!(body.0.error.contains("0xabc"));
                assert!(body.0.error.contains("commit"));
            }
        }
    }

    #[test]
    fn handle_rbac_outcome_crashed_routes_via_crash_to_error() {
        let outcome = PokeOutcome::Crashed {
            error: PokeCrashError::Timeout,
        };
        match handle_rbac_outcome(outcome) {
            Ok(()) => panic!("Crashed must produce an error"),
            Err((status, _)) => assert_eq!(status, StatusCode::GATEWAY_TIMEOUT),
        }
    }

    #[test]
    fn rbac_config_defaults_to_disabled() {
        assert!(!RbacConfig::default().enabled);
        assert!(!RbacConfig::from_toml(None).enabled);
        assert!(!RbacConfig::from_toml(Some(&HullRbacToml { enabled: None })).enabled);
        assert!(
            RbacConfig::from_toml(Some(&HullRbacToml { enabled: Some(true) })).enabled
        );
    }
}
