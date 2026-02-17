//! # BIP39 Mnemonic Identity Module
//!
//! Client-side identity generation and recovery using BIP39 mnemonics.
//! The mnemonic and private key NEVER leave the device — they are never sent to any relay.
//!
//! ## Flow
//! 1. Generate a 24-word mnemonic → derive Ed25519 keypair (new identity)
//! 2. Recover from mnemonic words → deterministically derive the same keypair
//! 3. Create encrypted sync bundles (keyed from mnemonic) for multi-device restore

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{bail, Context, Result};
use bip39::Mnemonic;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

/// Domain separation tag for keypair derivation.
const KEYPAIR_HKDF_INFO: &[u8] = b"accord-identity-ed25519-v1";

/// Domain separation tag for sync-bundle encryption key.
const SYNC_HKDF_INFO: &[u8] = b"accord-sync-bundle-aes256-v1";

/// AES-256-GCM nonce length.
const NONCE_LEN: usize = 12;

// ── Public types ────────────────────────────────────────────────────────────

/// Ed25519 keypair wrapper (client-side only — never serialised to the relay).
pub struct IdentityKeypair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

/// Data that can be encrypted into a sync bundle for multi-device restore.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncData {
    /// Node/server membership URLs or IDs.
    pub node_memberships: Vec<String>,
    /// Per-node display names (parallel to `node_memberships`).
    pub display_names: Vec<String>,
    /// Opaque JSON-encoded user settings.
    pub settings: String,
}

/// Encrypted blob that can be stored on the relay (safe — key never leaves client).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBundle {
    /// AES-256-GCM nonce (12 bytes).
    pub nonce: Vec<u8>,
    /// AES-256-GCM ciphertext + tag.
    pub ciphertext: Vec<u8>,
}

// ── Core API ────────────────────────────────────────────────────────────────

/// Generate a new 24-word BIP39 mnemonic and derive an Ed25519 identity keypair.
pub fn generate_mnemonic() -> (Mnemonic, IdentityKeypair) {
    let mut entropy = [0u8; 32]; // 256 bits → 24 words
    rand::thread_rng().fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy).expect("valid 256-bit entropy");
    entropy.zeroize();

    let keypair = derive_keypair(&mnemonic);
    (mnemonic, keypair)
}

/// Recover an Ed25519 identity keypair from existing mnemonic words.
pub fn recover_from_mnemonic(words: &str) -> Result<(Mnemonic, IdentityKeypair)> {
    let mnemonic: Mnemonic = words
        .parse()
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("invalid BIP39 mnemonic")?;
    let keypair = derive_keypair(&mnemonic);
    Ok((mnemonic, keypair))
}

/// Encrypt user data into a sync bundle using a key derived from the mnemonic.
///
/// The bundle can be stored on a relay — it is AES-256-GCM encrypted and the
/// key is derived purely from the mnemonic (which never touches the relay).
pub fn create_sync_bundle(
    mnemonic: &Mnemonic,
    node_memberships: Vec<String>,
    display_names: Vec<String>,
    settings: String,
) -> Result<EncryptedBundle> {
    let data = SyncData {
        node_memberships,
        display_names,
        settings,
    };
    let plaintext = bincode::serialize(&data).context("serialize sync data")?;
    let key = derive_sync_key(mnemonic);

    let cipher = Aes256Gcm::new_from_slice(&key).expect("valid 256-bit key");

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    Ok(EncryptedBundle {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Decrypt a sync bundle on a new device using the mnemonic.
pub fn restore_sync_bundle(mnemonic: &Mnemonic, bundle: &EncryptedBundle) -> Result<SyncData> {
    let key = derive_sync_key(mnemonic);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("valid 256-bit key");

    if bundle.nonce.len() != NONCE_LEN {
        bail!("invalid nonce length: expected {NONCE_LEN}, got {}", bundle.nonce.len());
    }
    let nonce = Nonce::from_slice(&bundle.nonce);

    let plaintext = cipher
        .decrypt(nonce, bundle.ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong mnemonic or corrupted bundle"))?;

    bincode::deserialize(&plaintext).context("deserialize sync data")
}

// ── Internal helpers ────────────────────────────────────────────────────────

/// Deterministically derive an Ed25519 signing key from a mnemonic via HKDF-SHA256.
fn derive_keypair(mnemonic: &Mnemonic) -> IdentityKeypair {
    let seed = mnemonic.to_entropy();
    let hk = Hkdf::<Sha256>::new(None, &seed);

    let mut okm = [0u8; 32];
    hk.expand(KEYPAIR_HKDF_INFO, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");

    let signing_key = SigningKey::from_bytes(&okm);
    okm.zeroize();

    let verifying_key = signing_key.verifying_key();
    IdentityKeypair {
        signing_key,
        verifying_key,
    }
}

/// Derive a 256-bit AES key for sync-bundle encryption from a mnemonic.
fn derive_sync_key(mnemonic: &Mnemonic) -> [u8; 32] {
    let seed = mnemonic.to_entropy();
    let hk = Hkdf::<Sha256>::new(None, &seed);

    let mut key = [0u8; 32];
    hk.expand(SYNC_HKDF_INFO, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_24_words() {
        let (mnemonic, _kp) = generate_mnemonic();
        assert_eq!(mnemonic.word_count(), 24);
    }

    #[test]
    fn recovery_yields_same_keypair() {
        let (mnemonic, kp1) = generate_mnemonic();
        let words = mnemonic.to_string();
        let (_m2, kp2) = recover_from_mnemonic(&words).unwrap();
        assert_eq!(
            kp1.signing_key.to_bytes(),
            kp2.signing_key.to_bytes(),
            "same mnemonic must produce identical signing key"
        );
        assert_eq!(
            kp1.verifying_key.to_bytes(),
            kp2.verifying_key.to_bytes(),
            "same mnemonic must produce identical verifying key"
        );
    }

    #[test]
    fn different_mnemonics_yield_different_keys() {
        let (_m1, kp1) = generate_mnemonic();
        let (_m2, kp2) = generate_mnemonic();
        assert_ne!(kp1.signing_key.to_bytes(), kp2.signing_key.to_bytes());
    }

    #[test]
    fn invalid_mnemonic_rejected() {
        let result = recover_from_mnemonic("not a valid mnemonic phrase at all");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_mnemonic_wrong_word_count() {
        // Valid words but wrong count (12 instead of 24 is actually valid BIP39,
        // so use an odd number that isn't valid).
        let result = recover_from_mnemonic("abandon abandon abandon");
        assert!(result.is_err());
    }

    #[test]
    fn sync_bundle_round_trip() {
        let (mnemonic, _kp) = generate_mnemonic();

        let original = SyncData {
            node_memberships: vec!["node1.example.com".into(), "node2.example.com".into()],
            display_names: vec!["Alice".into(), "Bob".into()],
            settings: r#"{"theme":"dark","notifications":true}"#.into(),
        };

        let bundle = create_sync_bundle(
            &mnemonic,
            original.node_memberships.clone(),
            original.display_names.clone(),
            original.settings.clone(),
        )
        .unwrap();

        let restored = restore_sync_bundle(&mnemonic, &bundle).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn sync_bundle_wrong_mnemonic_fails() {
        let (m1, _) = generate_mnemonic();
        let (m2, _) = generate_mnemonic();

        let bundle = create_sync_bundle(&m1, vec![], vec![], String::new()).unwrap();
        let result = restore_sync_bundle(&m2, &bundle);
        assert!(result.is_err(), "decryption with wrong mnemonic must fail");
    }

    #[test]
    fn sync_bundle_corrupted_ciphertext_fails() {
        let (mnemonic, _) = generate_mnemonic();
        let mut bundle = create_sync_bundle(&mnemonic, vec![], vec![], String::new()).unwrap();
        // Flip a byte
        if let Some(b) = bundle.ciphertext.first_mut() {
            *b ^= 0xff;
        }
        assert!(restore_sync_bundle(&mnemonic, &bundle).is_err());
    }

    #[test]
    fn twelve_word_mnemonic_also_works() {
        // 12-word mnemonics are valid BIP39 — we should accept them for recovery
        let mut entropy = [0u8; 16]; // 128 bits → 12 words
        rand::thread_rng().fill_bytes(&mut entropy);
        let m = Mnemonic::from_entropy(&entropy).unwrap();
        let words = m.to_string();
        assert_eq!(m.word_count(), 12);

        let (_m2, _kp) = recover_from_mnemonic(&words).unwrap();
    }
}
