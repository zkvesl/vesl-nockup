//! Settlement mode configuration — hull layer.
//!
//! Re-exports generic config from vesl-core and adds:
//! - HullConfig (domain-specific toml fields)
//! - load_config() for reading hull.toml / vesl.toml
//! - resolve_with_demo_key_checked() convenience wrapper

use std::path::Path;

use serde::Deserialize;

pub use vesl_core::config::{
    SettlementCliOverrides, SettlementConfig, SettlementMode, SettlementToml, WalletConfig,
    WalletRoleConfig, WalletRoleToml, WalletToml,
};

use crate::signing;

// ---------------------------------------------------------------------------
// HullConfig — toml fields for the generic hull
// ---------------------------------------------------------------------------

/// Deserializable config from `vesl.toml`.
#[derive(Debug, Default, Deserialize)]
pub struct HullConfig {
    pub nock_home: Option<String>,
    pub api_port: Option<u16>,
    pub settlement_mode: Option<String>,
    pub chain_endpoint: Option<String>,
    pub tx_fee: Option<u64>,
    pub coinbase_timelock_min: Option<u64>,
    pub accept_timeout_secs: Option<u64>,
    /// Wallet configuration block. Set this in `vesl.toml` to drive the
    /// per-role config-toggle pattern: `[wallet]` for shared options
    /// (seed_phrase, coin_type, account), `[wallet.intent]` and
    /// `[wallet.payment]` for per-role role/index overrides.
    pub wallet: Option<HullWalletToml>,
    /// Optional RBAC configuration. Set `[rbac] enabled = true` to gate
    /// `/commit` and `/settle` behind an `[%rbac-has-perm pubkey perm ~]`
    /// peek against the composed rbac-graft. Default: disabled.
    pub rbac: Option<HullRbacToml>,
}

/// `[rbac]` TOML block. Today only an enable flag; future entries (custom
/// perm names per endpoint, default-allow override) can land here without
/// reshaping the schema.
#[derive(Debug, Default, Deserialize)]
pub struct HullRbacToml {
    pub enabled: Option<bool>,
}

/// Resolved RBAC configuration consumed by the hull's request path. Built
/// from [`HullRbacToml`] at boot; defaults to disabled when no `[rbac]`
/// block is present (preserving existing test + downstream-consumer
/// behaviour).
#[derive(Debug, Default, Clone, Copy)]
pub struct RbacConfig {
    pub enabled: bool,
}

impl RbacConfig {
    /// Resolve from the TOML block. Absent block → disabled; present block
    /// with no `enabled` field → disabled (explicit opt-in only).
    pub fn from_toml(toml: Option<&HullRbacToml>) -> Self {
        Self {
            enabled: toml.and_then(|t| t.enabled).unwrap_or(false),
        }
    }
}

/// Hull-side mirror of `vesl_core::config::WalletToml`. Held separately
/// so HullConfig can derive `Deserialize` without forcing serde into
/// vesl-core; the conversion to the generic `WalletToml` is mechanical.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct HullWalletToml {
    pub seed_phrase: Option<String>,
    pub coin_type: Option<u32>,
    pub account: Option<u32>,
    pub intent: Option<HullWalletRoleToml>,
    pub payment: Option<HullWalletRoleToml>,
}

#[derive(Debug, Default, Clone, Copy, Deserialize)]
pub struct HullWalletRoleToml {
    pub role: Option<u32>,
    pub index: Option<u32>,
}

impl From<&HullWalletRoleToml> for WalletRoleToml {
    fn from(v: &HullWalletRoleToml) -> Self {
        Self { role: v.role, index: v.index }
    }
}

impl From<&HullWalletToml> for WalletToml {
    fn from(v: &HullWalletToml) -> Self {
        Self {
            seed_phrase: v.seed_phrase.clone(),
            coin_type: v.coin_type,
            account: v.account,
            intent: v.intent.as_ref().map(WalletRoleToml::from),
            payment: v.payment.as_ref().map(WalletRoleToml::from),
        }
    }
}

impl From<&HullConfig> for SettlementToml {
    fn from(v: &HullConfig) -> Self {
        Self {
            settlement_mode: v.settlement_mode.clone(),
            chain_endpoint: v.chain_endpoint.clone(),
            tx_fee: v.tx_fee,
            coinbase_timelock_min: v.coinbase_timelock_min,
            accept_timeout_secs: v.accept_timeout_secs,
            wallet: v.wallet.as_ref().map(WalletToml::from),
        }
    }
}

/// Load config from a TOML file. Returns defaults if the file doesn't exist.
pub fn load_config(path: &Path) -> HullConfig {
    match std::fs::read_to_string(path) {
        Ok(contents) => match toml::from_str(&contents) {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::warn!(
                    target: "vesl_hull::config",
                    "failed to parse {}: {e} -- using default config",
                    path.display()
                );
                HullConfig::default()
            }
        },
        Err(_) => HullConfig::default(),
    }
}

// ---------------------------------------------------------------------------
// Convenience: resolve with demo key for fakenet
// ---------------------------------------------------------------------------

/// Resolve settlement config with hull defaults (demo key for fakenet).
/// Surfaces misconfiguration as a typed error for main.rs (L-14).
pub fn resolve_with_demo_key_checked(
    overrides: &SettlementCliOverrides,
    toml: &HullConfig,
) -> Result<SettlementConfig, String> {
    let settlement_toml = SettlementToml::from(toml);
    let config = SettlementConfig::resolve_checked(
        overrides,
        &settlement_toml,
        Some(signing::demo_signing_key()),
    )?;
    // AUDIT 2026-05-19 H-15: the demo key is publicly known — a
    // fakenet-only convenience. Refuse it on the dumbnet chain path so a
    // fakenet config copied to dumbnet cannot sign real transactions
    // with it. (resolve_dumbnet derives from the wallet today; this is
    // the defense-in-depth gate the exported `is_demo_key` was built for.)
    if config.mode == SettlementMode::Dumbnet
        && let Some(sk) = config.signing_key
        && signing::is_demo_key(&sk)
    {
        return Err(
            "refusing to settle on dumbnet with the public demo signing \
             key — configure a real wallet seed phrase in [wallet]"
                .to_string(),
        );
    }
    Ok(config)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_local() {
        let toml = HullConfig::default();
        let cfg = resolve_with_demo_key_checked(&SettlementCliOverrides::default(), &toml).unwrap();
        assert_eq!(cfg.mode, SettlementMode::Local);
        assert!(cfg.chain_endpoint.is_none());
        assert!(cfg.signing_key.is_none());
        assert!(!cfg.auto_submit);
    }

    #[test]
    fn chain_endpoint_infers_fakenet() {
        let toml = HullConfig::default();
        let cfg = resolve_with_demo_key_checked(
            &SettlementCliOverrides {
                chain_endpoint: Some("http://localhost:9090".into()),
                ..Default::default()
            },
            &toml,
        ).unwrap();
        assert_eq!(cfg.mode, SettlementMode::Fakenet);
        assert!(cfg.signing_key.is_some());
        assert!(cfg.auto_submit);
    }

    #[test]
    fn explicit_local_ignores_chain_endpoint() {
        let toml = HullConfig::default();
        let cfg = resolve_with_demo_key_checked(
            &SettlementCliOverrides {
                mode: Some(SettlementMode::Local),
                chain_endpoint: Some("http://localhost:9090".into()),
                submit: true,
                ..Default::default()
            },
            &toml,
        ).unwrap();
        assert_eq!(cfg.mode, SettlementMode::Local);
        assert!(cfg.chain_endpoint.is_none());
        assert!(!cfg.auto_submit);
    }

    #[test]
    fn fakenet_defaults() {
        let toml = HullConfig::default();
        let cfg = resolve_with_demo_key_checked(
            &SettlementCliOverrides { mode: Some(SettlementMode::Fakenet), ..Default::default() },
            &toml,
        ).unwrap();
        assert_eq!(cfg.chain_endpoint.as_deref(), Some("http://localhost:9090"));
        assert_eq!(cfg.tx_fee, 256);
        assert_eq!(cfg.coinbase_timelock_min, 1);
        assert_eq!(cfg.accept_timeout_secs, 300);
        assert!(cfg.signing_key.is_some());
    }

    #[test]
    fn cli_overrides_toml() {
        let toml = HullConfig {
            tx_fee: Some(5000),
            ..Default::default()
        };
        let cfg = resolve_with_demo_key_checked(
            &SettlementCliOverrides {
                mode: Some(SettlementMode::Fakenet),
                chain_endpoint: Some("http://cli:9090".into()),
                tx_fee: Some(7000),
                ..Default::default()
            },
            &toml,
        ).unwrap();
        assert_eq!(cfg.tx_fee, 7000);
        assert_eq!(cfg.chain_endpoint.as_deref(), Some("http://cli:9090"));
    }

    #[test]
    fn settlement_mode_display_roundtrip() {
        for mode in [SettlementMode::Local, SettlementMode::Fakenet, SettlementMode::Dumbnet] {
            let s = mode.to_string();
            let parsed: SettlementMode = s.parse().unwrap();
            assert_eq!(mode, parsed);
        }
    }

    #[test]
    fn hull_wallet_block_round_trips_through_settlement_toml() {
        // Verifies the `HullWalletToml -> WalletToml` From impl plumbs
        // every nested field through.
        let toml = HullConfig {
            wallet: Some(HullWalletToml {
                seed_phrase: Some("seed".into()),
                coin_type: Some(123),
                account: Some(7),
                intent: Some(HullWalletRoleToml { role: Some(0), index: Some(2) }),
                payment: Some(HullWalletRoleToml { role: Some(4), index: Some(5) }),
            }),
            ..Default::default()
        };
        let st = SettlementToml::from(&toml);
        let w = st.wallet.expect("wallet block should plumb through");
        assert_eq!(w.seed_phrase.as_deref(), Some("seed"));
        assert_eq!(w.coin_type, Some(123));
        assert_eq!(w.account, Some(7));
        assert_eq!(w.intent.unwrap().role, Some(0));
        assert_eq!(w.intent.unwrap().index, Some(2));
        assert_eq!(w.payment.unwrap().role, Some(4));
        assert_eq!(w.payment.unwrap().index, Some(5));
    }
}
