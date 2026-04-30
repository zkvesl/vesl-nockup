//! Replay-cache trait plus an in-memory TTL implementation used by the
//! SIWN middleware and the §6.6 authorization-nonce check in the
//! facilitator's `verify_envelope`.
//!
//! Persistence is deliberately out of scope here — the in-memory
//! cache is acceptable because facilitator state is not yet durable;
//! ADR-0010 (deferred) tracks the persistence question.
//!
//! ## Domain-prefixed keys
//!
//! Two consumers share the same trait — SIWN authentication nonces and
//! Authorization replay nonces. Both nonce surfaces are independently
//! generated, but a single shared cache must not collide them; an attacker
//! crafting a SIWN nonce equal to an Authorization nonce should not be able
//! to suppress legitimate traffic on the other channel. Callers MUST
//! prefix their nonces with a [`domains`] constant via [`prefixed`] before
//! passing them to [`ReplayCache::seen`].

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Trait for a bounded-lifetime nonce cache. Implementations MUST return
/// `true` iff the nonce has already been observed within `ttl`; a fresh
/// nonce MUST be recorded so the next call in-window returns `true`.
pub trait ReplayCache: Send + Sync {
    fn seen(&self, nonce: &[u8], ttl: Duration) -> bool;
}

/// Domain tags every caller MUST prepend to its nonce via [`prefixed`]
/// so the SIWN and Authorization nonce surfaces share a cache without
/// colliding.
pub mod domains {
    /// Prefix for SIWN authentication nonces (per `11-extensions.md §11.2`).
    pub const SIWN: &str = "siwn";
    /// Prefix for `Authorization.nonce` replay tracking (per
    /// `06-facilitator.md §6.6`).
    pub const AUTHORIZATION: &str = "x402-auth";
}

/// Concatenate a domain tag and a raw nonce into a single cache key.
///
/// Format: `<domain>:<nonce-bytes>`. The colon separator is a literal byte
/// that no domain string contains, so two distinct domains can never
/// produce the same key for any nonce input.
pub fn prefixed(domain: &str, nonce: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + 1 + nonce.len());
    out.extend_from_slice(domain.as_bytes());
    out.push(b':');
    out.extend_from_slice(nonce);
    out
}

/// HashMap-backed cache. Not persistent across restarts.
#[derive(Default)]
pub struct InMemoryReplayCache {
    inner: Mutex<HashMap<Vec<u8>, Instant>>,
}

impl InMemoryReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop any entries whose `inserted + ttl < now`. Called on every
    /// `seen()` so the cache never grows unboundedly.
    fn sweep(&self, now: Instant, ttl: Duration) {
        let mut guard = self.inner.lock().expect("replay cache poisoned");
        guard.retain(|_, inserted| now.duration_since(*inserted) <= ttl);
    }
}

impl ReplayCache for InMemoryReplayCache {
    fn seen(&self, nonce: &[u8], ttl: Duration) -> bool {
        let now = Instant::now();
        self.sweep(now, ttl);
        let mut guard = self.inner.lock().expect("replay cache poisoned");
        match guard.get(nonce) {
            Some(inserted) if now.duration_since(*inserted) <= ttl => true,
            _ => {
                guard.insert(nonce.to_vec(), now);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_then_replay() {
        let cache = InMemoryReplayCache::new();
        assert!(!cache.seen(b"abc", Duration::from_secs(60)));
        assert!(cache.seen(b"abc", Duration::from_secs(60)));
        assert!(!cache.seen(b"def", Duration::from_secs(60)));
    }

    #[test]
    fn expires_after_ttl() {
        let cache = InMemoryReplayCache::new();
        assert!(!cache.seen(b"n", Duration::from_millis(10)));
        std::thread::sleep(Duration::from_millis(25));
        assert!(!cache.seen(b"n", Duration::from_millis(10)));
    }

    #[test]
    fn prefixed_isolates_domains() {
        let cache = InMemoryReplayCache::new();
        let ttl = Duration::from_secs(60);
        let raw = b"shared-nonce";
        // The same raw nonce under two distinct domains MUST NOT collide.
        assert!(!cache.seen(&prefixed(domains::SIWN, raw), ttl));
        assert!(!cache.seen(&prefixed(domains::AUTHORIZATION, raw), ttl));
        // Replays within a domain are still detected.
        assert!(cache.seen(&prefixed(domains::SIWN, raw), ttl));
        assert!(cache.seen(&prefixed(domains::AUTHORIZATION, raw), ttl));
    }

    #[test]
    fn prefixed_format_is_domain_colon_nonce() {
        assert_eq!(prefixed("a", b"b"), b"a:b");
        assert_eq!(prefixed(domains::SIWN, b"x"), b"siwn:x");
        assert_eq!(prefixed(domains::AUTHORIZATION, b""), b"x402-auth:");
    }
}
