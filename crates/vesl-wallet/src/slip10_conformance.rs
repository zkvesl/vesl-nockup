//! The frozen cross-implementation KAT for SLIP-10 derivation.
//!
//! ## Why this file exists
//!
//! Before it, every test of `hd.rs` was **relational** — determinism,
//! "distinct inputs give distinct keys", "this role differs from that
//! one". Not one pinned an actual key value. That is exactly the shape in
//! which a wrong adoption of a standard is invisible: a construction that
//! is SLIP-10-*shaped* but disagrees with upstream on any detail passes
//! every relational test while deriving the wrong keys.
//!
//! ⚠️ **What "wrong" means here, precisely.** Not *invalid*. The chain
//! never validates how a key was derived: a lock is a `%pkh`, a hash of a
//! public key, and `slip10.hoon` is imported by the wallet app and its
//! tests alone — by nothing on any consensus path. A non-conforming
//! derivation still yields a perfectly good Cheetah keypair that signs
//! and spends normally, which is why nothing on a test network would ever
//! have complained. What breaks is **interoperability and recovery**: the
//! same seed phrase in `nockchain-wallet`, in iris, or in a future
//! hardware wallet produces a DIFFERENT key. So a refund sent to
//! `Authorization.from` lands where its owner cannot reach it, and an
//! operator importing their phrase into the reference wallet finds an
//! empty account. That is the failure this file exists to prevent, and it
//! is invisible to every other test in the crate.
//!
//! ## What "conformance" means here
//!
//! Not "agrees with a third-party wallet". The vectors in
//! [`reference_wallet`] are the output of **`nockchain-wallet` itself**,
//! reached through `iris-rs/crates/iris-crypto/src/slip10.rs:121-162`,
//! which freezes that CLI's `keygen` / `derive-child` output. So a green
//! run here says: *this crate derives the same keys the chain's own
//! reference wallet derives from the same seed phrase.*
//!
//! ## Why it is a unit test and not `tests/`
//!
//! The reference vectors pin the master key and DEPTH-1 children. The
//! public API only ever walks the full five-level BIP-44 path, so an
//! integration test structurally cannot express them.
//! [`role_path`] does use the public API, and asserts the two agree.
//!
//! ## Regenerating
//!
//! `python3 tools/slip10_vectors.py` re-derives everything except the
//! non-hardened branch straight from `nockchain/hoon/common/slip10.hoon`
//! and self-tests against the same reference vectors. Run it if upstream
//! ever moves: it will say which vector changed, in seconds, instead of
//! leaving a wall of unexplainable constants behind.

use ibig::UBig;
use vesl_signing::schnorr::SchnorrPrivateKey;
use vesl_wallet_spec::{
    DerivationPath, ROLE_ENCRYPTION, ROLE_INTENT, ROLE_RECEIVING, ROLE_SESSION, ROLE_VOID,
    ROLE_WITHDRAWAL, ROLE_X402,
};

use crate::hd::{ckd_hardened, ckd_non_hardened, master_from_seed, ser_a_pt, ExtKey};
use crate::wallet::VeslWallet;
use crate::VESL_COIN_TYPE_PLACEHOLDER;

/// The mnemonic `nockchain-wallet keygen` produced for the reference
/// vectors (iris `slip10.rs:128`).
const REFERENCE_MNEMONIC: &str = "clutch inmate mango seek attract credit illegal popular term \
     loyal fiber output trumpet lucky garbage merge menu certain dynamic aim trip fantasy master \
     unveil";

/// The mnemonic this crate's own tests use (`tests/round_trip.rs:15`).
const CANONICAL_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon about";

fn seed(mnemonic: &str) -> [u8; 64] {
    let parsed = bip39::Mnemonic::parse(mnemonic).expect("test mnemonic parses");
    parsed.to_seed_normalized("")
}

fn master(mnemonic: &str) -> ExtKey {
    master_from_seed(&seed(mnemonic)).expect("master derives")
}

fn b58(s: &str) -> Vec<u8> {
    bs58::decode(s)
        .into_vec()
        .expect("base58 test vector decodes")
}

fn assert_scalar(label: &str, got: &UBig, want_b58: &str) {
    let mut want = [0u8; 32];
    let raw = b58(want_b58);
    want[32 - raw.len()..].copy_from_slice(&raw);
    assert_eq!(
        got.to_be_bytes().as_slice(),
        // to_be_bytes() is minimal-width, so compare on the same footing.
        &want[32 - got.to_be_bytes().len()..],
        "{label}: scalar does not match the reference wallet"
    );
    assert_eq!(
        UBig::from_be_bytes(&want),
        *got,
        "{label}: scalar does not match the reference wallet"
    );
}

fn assert_chain_code(label: &str, got: &[u8; 32], want_b58: &str) {
    assert_eq!(
        got.as_slice(),
        b58(want_b58).as_slice(),
        "{label}: chain code does not match the reference wallet"
    );
}

mod reference_wallet {
    //! Ground truth: `nockchain-wallet keygen`, `derive-child 0`,
    //! `derive-child --hardened 0`.

    use super::*;

    /// `nockchain-wallet keygen`.
    #[test]
    fn master_key_matches_the_reference_wallet() {
        let m = master(REFERENCE_MNEMONIC);
        assert_scalar(
            "master", &m.scalar, "3MoHxVXWAr9qny12Sw8ZZtrgEBFcZegQQVkwYyePb9LZ",
        );
        assert_chain_code(
            "master", &m.chain_code, "3NhBRdy7vRw8vKQ5RnR3CNcD43WDn5Ky7mhhotqUcaiR",
        );
    }

    /// `nockchain-wallet derive-child 0` — the NON-HARDENED branch.
    ///
    /// ⚑ This is the only vector that pins [`ser_a_pt`], and therefore the
    /// only thing anywhere that pins the Cheetah limb order our point
    /// serialization assumes. If `x`/`y` were swapped, the limbs reversed,
    /// or the leading `0x01` dropped, this is where it shows.
    #[test]
    fn non_hardened_child_matches_the_reference_wallet() {
        let child = ckd_non_hardened(&master(REFERENCE_MNEMONIC), 0).expect("child derives");
        assert_scalar(
            "non-hardened child 0", &child.scalar, "6AifHLAuT1MxnFsoCwjKNFaBze91DXFDV1rRLefkzPEK",
        );
        assert_chain_code(
            "non-hardened child 0", &child.chain_code,
            "8NL75o1uwMpGFcLRrnFt9adTyExwK9MP6RL8h2jAKEVD",
        );
    }

    /// `nockchain-wallet derive-child --hardened 0`.
    ///
    /// ⚑ · MEASURED: this vector's first HMAC yields `left >= G_ORDER`, so
    /// reaching it REQUIRES one pass through the invalid-key retry
    /// (`slip10.hoon:176`). That branch fires on ~52 % of all derivation
    /// steps, so it is the common case rather than a corner — and this
    /// test is what proves our retry agrees with upstream's, including the
    /// two details easiest to get wrong: the HMAC is keyed on the PARENT
    /// chain code, and the index it hashes is the FULL hardened index.
    #[test]
    fn hardened_child_matches_the_reference_wallet_through_the_retry_branch() {
        let child = ckd_hardened(&master(REFERENCE_MNEMONIC), 0).expect("child derives");
        assert_scalar(
            "hardened child 0", &child.scalar, "CpMAmcgN1V6Majtx2HC7ULLXD9psA3Gg3nMye3JpKpH",
        );
        assert_chain_code(
            "hardened child 0", &child.chain_code, "8x7zh5LQA7tsFQQ3qsPfYGgFzQkoizGhLqLK7iKTGj3R",
        );
    }

    /// The domain separator is the one operand a silent typo would break
    /// without breaking anything structural. Changing one byte must move
    /// the master key — asserted by deriving under a mutated separator and
    /// requiring a different answer.
    #[test]
    fn the_domain_separator_is_load_bearing() {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        let s = seed(REFERENCE_MNEMONIC);
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(b"Nockchain seeD").unwrap();
        mac.update(&s);
        let mutated: [u8; 64] = mac.finalize().into_bytes().into();
        assert_ne!(
            UBig::from_be_bytes(&mutated[..32]),
            master(REFERENCE_MNEMONIC).scalar,
            "a one-byte change to `Nockchain seed` must change the master key"
        );
    }
}

mod role_path {
    //! Regression pins for `m/44'/coin'/account'/role/index`, the walk
    //! `VeslWallet::derive` performs (`wallet.rs:112-116`).
    //!
    //! ⚑ These are OUR values, not upstream's — upstream publishes no
    //! vector at this path. Their standing is different from
    //! [`super::reference_wallet`]'s and is stated rather than blurred:
    //! conformance is proven there; these detect unintended drift here.
    //! The master and the three HARDENED levels below were independently
    //! reproduced by `tools/slip10_vectors.py`, a transcription of
    //! `slip10.hoon` that shares no code with this crate.

    use super::*;

    /// `(scalar, chain_code)` at `m/44'/coin'/account'`, cross-checked
    /// against the Python oracle.
    const HARDENED_PREFIX: [(&str, &str); 4] = [
        (
            "54d89f8a505e75c1b1ecdb0ca7be19524e68370ed0c21eb2d0fb5a3dfad6553b",
            "6616d5b4b53a6e3932d04eee8dbb042819da1d056d490e15ca6cae30ed39b25e",
        ),
        (
            "0a126405a93c53073e2446dadc6f834165b49f475c0193f6abff0a0f45a2cdfd",
            "adbda7143ff63feb2247cff0927c9a07545f138720cfb7f7e8c92cf66d84ae70",
        ),
        (
            "41068c2dbe3661f4b1b2bf673a19794ede88d9902169b0179abdf2b813101466",
            "9506729ec78ee7a168e68181f6a74929280a225f43766b6837293b84953214dc",
        ),
        (
            "6c23627b9001f927fe0baef5af0b268a58fda13f4d9de65c8cb590122643df20",
            "b0d4dff75df7bde2f208d5f8a36faa1e4e304e70e9c02d6df219138d78ba4632",
        ),
    ];

    /// The scalar at `m/44'/coin'/0'/ROLE/0` for each of the seven roles.
    ///
    /// ⛔⛔ **WHAT THIS TABLE IS, AND WHAT IT IS NOT — stated because the
    /// module header's *"agrees with the chain's own reference wallet"* is
    /// true of the MASTER and the DEPTH-1 children and is NOT true of these.**
    /// The role step is NON-HARDENED (`ckd_non_hardened` below), and the
    /// regeneration oracle `tools/slip10_vectors.py` deliberately does not
    /// implement that branch — it needs Cheetah point arithmetic, which the
    /// script says in its own scope note it will not re-transcribe. So every
    /// entry here was produced by THIS crate and is a **regression pin**: it
    /// freezes the walk against future change, and it is not an independent
    /// cross-check. Ground truth for the non-hardened branch is the reference
    /// wallet's own frozen depth-1 vector, asserted separately.
    ///
    /// ⚑ `ROLE_VOID` was added 2026-09-03 (x402 `U2`) and `ROLE_WITHDRAWAL`
    /// 2026-09-08 (x402 row 24); both are pinned to exactly that standard — no
    /// weaker than the roles beside them, and no stronger.
    ///
    /// ⛔ **THE LENGTH ANNOTATION IS THE GUARD.** Adding a role constant
    /// without adding a row here is a compile error, which is the only reason
    /// this table has never silently fallen behind the spec crate the way
    /// `tests/round_trip.rs`'s hand-written `5` did.
    const ROLE_SCALARS: [(u32, &str); 7] = [
        (
            ROLE_INTENT, "4db1adda8328b429df27572da7407f0f8feeb65c0c7d1f81df46fa8f74735c5b",
        ),
        (
            ROLE_RECEIVING, "18c785e1a59a801facc613cd94f8085c598fdbe3df4bf90605f1217396cc382f",
        ),
        (
            ROLE_ENCRYPTION, "30a119c98cb572c17297d5ec302ea228fa8467bca4c4712c1be58458a9179234",
        ),
        (
            ROLE_SESSION, "2ca93b30d1d843132820cee8c8c7ea53fb11109f97fc0de03959923ba4e7cdb9",
        ),
        (
            ROLE_X402, "685c44c433a5246cfd707bad021f09fa7c36a90b9301d949fc769e6433a9d326",
        ),
        (
            ROLE_VOID, "68d592b10de5939f4ad0311fe00c675c2caa43f4a8be0ccd48d02362382be52d",
        ),
        (
            ROLE_WITHDRAWAL, "0984e5f8b3dd5c7a6213614fe2a7675964817342b850256a0c475211df1666dc",
        ),
    ];

    fn hex_to_ubig(s: &str) -> UBig {
        UBig::from_str_radix(s, 16).expect("hex vector parses")
    }

    #[test]
    fn hardened_prefix_is_frozen() {
        let mut key = master(CANONICAL_MNEMONIC);
        let steps = [None, Some(44u32), Some(VESL_COIN_TYPE_PLACEHOLDER), Some(0u32)];
        for (i, step) in steps.iter().enumerate() {
            if let Some(index) = step {
                key = ckd_hardened(&key, *index).expect("hardened step derives");
            }
            let (scalar, chain) = HARDENED_PREFIX[i];
            assert_eq!(key.scalar, hex_to_ubig(scalar), "level {i} scalar");
            assert_eq!(hex(&key.chain_code), chain, "level {i} chain code");
        }
    }

    #[test]
    fn every_role_key_is_frozen() {
        let mut key = master(CANONICAL_MNEMONIC);
        for index in [44u32, VESL_COIN_TYPE_PLACEHOLDER, 0] {
            key = ckd_hardened(&key, index).expect("hardened step derives");
        }
        for (role, want) in ROLE_SCALARS {
            let l4 = ckd_non_hardened(&key, role).expect("role step derives");
            let l5 = ckd_non_hardened(&l4, 0).expect("index step derives");
            assert_eq!(l5.scalar, hex_to_ubig(want), "role {role}");
        }
    }

    /// The public walk must reach the same keys as the internal one — so a
    /// future change to `VeslWallet::derive`'s path shape goes red here,
    /// not silently in production.
    #[test]
    fn the_public_api_walks_to_the_same_keys() {
        let wallet =
            VeslWallet::from_seed_phrase(CANONICAL_MNEMONIC, "", VESL_COIN_TYPE_PLACEHOLDER)
                .expect("wallet builds");
        for (role, want) in ROLE_SCALARS {
            let derived = wallet
                .derive(DerivationPath::new(VESL_COIN_TYPE_PLACEHOLDER, 0, role, 0))
                .expect("public derive succeeds");
            let expected =
                SchnorrPrivateKey::new(hex_to_ubig(want)).expect("frozen scalar is a valid key");
            assert_eq!(
                derived.private_key.to_t8(),
                expected.to_t8(),
                "public API disagrees with the frozen vector at role {role}"
            );
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}

/// `ser_a_pt`'s shape, asserted where it is claimed. The reference
/// non-hardened vector is the behavioural proof; these are the cheap
/// structural checks that say which part broke.
#[test]
fn ser_a_pt_has_upstreams_shape() {
    let pk = master(REFERENCE_MNEMONIC)
        .private_key()
        .expect("master is a valid key")
        .public_key()
        .expect("public key derives");
    let encoded = ser_a_pt(&pk);
    assert_eq!(encoded.len(), 97, "ser-a-pt is 97 bytes (slip10.hoon:155)");
    assert_eq!(encoded[0], 0x01, "the leading `rep` block is 1");
}
