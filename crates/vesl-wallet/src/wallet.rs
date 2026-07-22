//! Public wallet API.

use bip39::Mnemonic;
use ibig::UBig;
use vesl_signing::domain::{domain_separators, tip5_with_domain};
use vesl_signing::prelude::Belt;
use vesl_signing::schnorr::{schnorr_sign, CheetahPoint, SchnorrPrivateKey};
use vesl_wallet_spec::{
    DerivationPath, BIP44_PURPOSE, ROLE_INTENT, ROLE_RECEIVING, ROLE_SESSION, ROLE_X402,
};

use crate::error::WalletError;
use crate::hd::{ckd_hardened, ckd_non_hardened, master_from_seed, serialize_point, ExtKey};

/// A derived key + the path it was derived at.
///
/// The chain code is intentionally *not* exposed: the BIP-32 chain code
/// is sensitive material (combined with the parent extended public key
/// it lets a holder enumerate all non-hardened siblings), and Hull
/// authors never need it for the in-process flows the wallet supports.
#[derive(Clone)]
pub struct DerivedKey {
    /// The Schnorr private key at [`Self::path`].
    pub private_key: SchnorrPrivateKey,
    /// The path the key was derived at.
    pub path: DerivationPath,
}

/// High-level Hull-author wallet.
///
/// Wraps a BIP-39 master seed + a Cheetah-BIP32-over-Tip5 derivation
/// tree and exposes per-role convenience signers driven by the constants
/// in [`vesl_wallet_spec`].
///
/// ```ignore
/// # use vesl_signing::prelude::Belt;
/// # use vesl_wallet::{VeslWallet, VESL_COIN_TYPE_PLACEHOLDER};
/// let wallet = VeslWallet::from_seed_phrase(
///     "abandon abandon abandon abandon abandon abandon abandon abandon \
///      abandon abandon abandon about",
///     "",
///     VESL_COIN_TYPE_PLACEHOLDER,
/// )?;
/// let msg = [Belt(1), Belt(2), Belt(3), Belt(4), Belt(5)];
/// let (chal, sig) = wallet.sign_intent(0, &msg)?;
/// # Ok::<(), vesl_wallet::WalletError>(())
/// ```
pub struct VeslWallet {
    master: ExtKey,
    coin_type: u32,
}

impl VeslWallet {
    /// Build a wallet from a BIP-39 mnemonic + optional passphrase. The
    /// passphrase corresponds to BIP-39's "25th word" extension; pass an
    /// empty string for no passphrase.
    ///
    /// **Audit 2026-05-25 L-32 — caller-owned secret residue.** The 64-byte
    /// BIP-39 seed derived inside this function is zeroized on drop (via
    /// the M-13 fix), and `bip39`'s `zeroize` feature scrubs internal
    /// `Mnemonic` state. **But the caller's `phrase` and `passphrase`
    /// strings are owned by the caller and survive in their original
    /// buffers after this function returns** — `Mnemonic::parse` reads
    /// the bytes; it does not mutate or wipe them. Process-memory dumps
    /// (core file, debugger ptrace, /proc/&lt;pid&gt;/mem leak) recover the
    /// mnemonic verbatim from the caller's storage even after the
    /// wallet's own seed has been wiped.
    ///
    /// Callers handling secret mnemonics MUST keep `phrase` (and
    /// `passphrase`, if non-empty) in a `zeroize::Zeroizing<String>`
    /// buffer — or equivalent — that wipes on drop. This API does not
    /// take ownership of those strings, and changing it to require
    /// `Zeroizing<String>` would be an API-breaking change deferred
    /// to a future major version. Until then, the wipe discipline lives
    /// on the caller side.
    pub fn from_seed_phrase(
        phrase: &str,
        passphrase: &str,
        coin_type: u32,
    ) -> Result<Self, WalletError> {
        let mnemonic =
            Mnemonic::parse(phrase).map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
        // AUDIT 2026-05-20 M-13: wipe the 64-byte BIP-39 seed once the
        // master key is derived — it is the root secret every key
        // descends from, so it must not linger in freed memory.
        let seed = zeroize::Zeroizing::new(mnemonic.to_seed_normalized(passphrase));
        Self::from_seed(&seed, coin_type)
    }

    /// Build a wallet from a 64-byte BIP-39 seed directly. Useful for
    /// tests with canonical BIP-39 vectors and for callers that pin the
    /// seed bytes elsewhere (e.g. a hardware import).
    pub fn from_seed(seed: &[u8; 64], coin_type: u32) -> Result<Self, WalletError> {
        let master = master_from_seed(seed)?;
        Ok(Self { master, coin_type })
    }

    /// The coin_type the wallet was constructed with.
    pub fn coin_type(&self) -> u32 {
        self.coin_type
    }

    /// Derive at the full BIP-44 path `m / 44' / coin_type' / account' /
    /// role / index`. The path's `coin_type` MUST match the wallet's
    /// configured `coin_type`; mismatches return
    /// [`WalletError::NonBip44Purpose`] (rather than silently deriving
    /// at a different coin_type, which would be a key-confusion hazard).
    pub fn derive(&self, path: DerivationPath) -> Result<DerivedKey, WalletError> {
        if path.coin_type != self.coin_type {
            return Err(WalletError::NonBip44Purpose(path.coin_type));
        }
        let l1 = ckd_hardened(&self.master, BIP44_PURPOSE)?;
        let l2 = ckd_hardened(&l1, path.coin_type)?;
        let l3 = ckd_hardened(&l2, path.account)?;
        let l4 = ckd_non_hardened(&l3, path.role)?;
        let l5 = ckd_non_hardened(&l4, path.index)?;
        Ok(DerivedKey {
            private_key: l5.private_key()?,
            path,
        })
    }

    /// Schnorr-sign a 5-Belt message with the key at
    /// `m/44'/coin'/account'/ROLE_INTENT/0`.
    ///
    /// **Audit 2026-05-25 H-26 — placeholder status.** Upstream intent
    /// scripting has not landed yet: there is no verifier on the other
    /// side to negotiate a canonical binding against, so this function is
    /// a raw passthrough — it signs the 5-Belt input verbatim and does
    /// **not** apply the [`VESL_INTENT`] domain separator internally.
    /// The role-0 key slot is reserved; callers that need strict
    /// cross-protocol separation today MUST hash their payload under
    /// [`VESL_INTENT`] themselves (e.g. via
    /// `vesl_signing::domain::hash_canonical`) before calling
    /// `sign_intent`, or use a role whose binding is already wired
    /// (`ROLE_X402` for x402 payments, etc.). The
    /// `sign_intent_round_trip_via_schnorr` test in
    /// `tests/round_trip.rs` shows the caller-side pre-hashing
    /// convention this API expects today.
    ///
    /// When upstream intent scripting ships, this function will gain an
    /// internal `tip5_with_domain(VESL_INTENT, ...)` step and accept the
    /// raw payload bytes rather than the pre-hashed 5-Belt digest. The
    /// signature shape will become spec-binding at that point — until
    /// then, treat `sign_intent` as a thin role-0 Schnorr accessor.
    ///
    /// [`VESL_INTENT`]: vesl_signing::domain::domain_separators::VESL_INTENT
    pub fn sign_intent(
        &self,
        account: u32,
        message: &[Belt; 5],
    ) -> Result<(UBig, UBig), WalletError> {
        let signer = self.intent_signer(account, 0)?;
        schnorr_sign(&signer, message).map_err(WalletError::Signing)
    }

    /// Public key at `m/44'/coin'/account'/ROLE_RECEIVING/0`. Hull
    /// authors that need a noun-aware Nockchain "address" (pkh) can
    /// hash this through `vesl-core::pubkey_hash`; the wallet stays
    /// chain-agnostic and self-contained.
    pub fn receiving_pubkey(&self, account: u32) -> Result<CheetahPoint, WalletError> {
        let path = DerivationPath::new(self.coin_type, account, ROLE_RECEIVING, 0);
        Ok(self.derive(path)?.private_key.public_key()?)
    }

    /// An opaque 5-Belt fingerprint of the receiving pubkey. Useful as
    /// an address-shaped value when interacting with non-Nockchain
    /// systems that accept an arbitrary digest (the wallet stays
    /// chain-agnostic). Distinct from any Nockchain pkh.
    pub fn receiving_fingerprint(&self, account: u32) -> Result<[Belt; 5], WalletError> {
        let pk = self.receiving_pubkey(account)?;
        let mut input = Vec::with_capacity(ADDRESS_SUBDOMAIN.len() + 97);
        input.extend_from_slice(ADDRESS_SUBDOMAIN);
        input.extend_from_slice(&serialize_point(&pk));
        Ok(tip5_with_domain(domain_separators::VESL_HD, &input))
    }

    /// Derived key at `m/44'/coin'/account'/ROLE_SESSION/index`. Used
    /// for short-lived session keys that share the intent-signing
    /// separator.
    pub fn derive_session(&self, account: u32, index: u32) -> Result<DerivedKey, WalletError> {
        self.derive(DerivationPath::new(
            self.coin_type, account, ROLE_SESSION, index,
        ))
    }

    /// Schnorr private key at `m/44'/coin'/account'/ROLE_INTENT/index`.
    /// The "intent app" signer in the TOML config-toggle pattern.
    pub fn intent_signer(
        &self,
        account: u32,
        index: u32,
    ) -> Result<SchnorrPrivateKey, WalletError> {
        let path = DerivationPath::new(self.coin_type, account, ROLE_INTENT, index);
        Ok(self.derive(path)?.private_key)
    }

    /// Schnorr private key at `m/44'/coin'/account'/ROLE_X402/index`.
    /// The "payment app" signer in the TOML config-toggle pattern.
    pub fn payment_signer(
        &self,
        account: u32,
        index: u32,
    ) -> Result<SchnorrPrivateKey, WalletError> {
        let path = DerivationPath::new(self.coin_type, account, ROLE_X402, index);
        Ok(self.derive(path)?.private_key)
    }
}

const ADDRESS_SUBDOMAIN: &[u8] = b"vesl-hd:address\x00";
