//! # Metadata Encryption
//!
//! Provides symmetric encryption for node/channel metadata (names, descriptions)
//! so the server stores encrypted blobs instead of plaintext.
//!
//! ## Design
//!
//! Each Node has a **node metadata key** (NMK) — a 256-bit symmetric key derived from
//! the node creator's identity key. This key is shared with members via the existing
//! Double Ratchet key exchange (piggybacks on session establishment).
//!
//! The server stores `encrypted_name` / `encrypted_description` fields as opaque blobs.
//! Clients with the NMK decrypt locally. Clients without it see only UUIDs.
//!
//! ## Wire Format
//!
//! `[version: 1 byte] [nonce: 12 bytes] [ciphertext+tag: variable]`

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use hkdf::Hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::Sha256;

/// Current metadata encryption version
const METADATA_VERSION: u8 = 1;
/// AES-256-GCM nonce size
const NONCE_SIZE: usize = 12;

/// A node metadata key used to encrypt/decrypt node and channel names.
#[derive(Clone)]
pub struct NodeMetadataKey {
    key_bytes: [u8; 32],
}

impl NodeMetadataKey {
    /// Derive a node metadata key from a creator's identity key material and the node ID.
    ///
    /// `identity_key_material` — the raw bytes of the creator's identity private key or a
    /// shared secret derived from it.
    /// `node_id` — the node's UUID bytes, used as salt for domain separation.
    pub fn derive(identity_key_material: &[u8], node_id: &[u8]) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(Some(node_id), identity_key_material);
        let mut key_bytes = [0u8; 32];
        hk.expand(b"accord-node-metadata-v1", &mut key_bytes)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
        Ok(Self { key_bytes })
    }

    /// Create from raw 32-byte key (e.g. received from key exchange).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { key_bytes: bytes }
    }

    /// Export the raw key bytes (for sharing via Double Ratchet).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key_bytes
    }

    /// Encrypt a metadata string. Returns the versioned ciphertext blob.
    pub fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.key_bytes)
            .map_err(|e| anyhow::anyhow!("cipher init: {}", e))?;

        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("RNG failed"))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;

        // Wire format: version || nonce || ciphertext
        let mut output = Vec::with_capacity(1 + NONCE_SIZE + ciphertext.len());
        output.push(METADATA_VERSION);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Decrypt a metadata blob back to a string.
    pub fn decrypt(&self, blob: &[u8]) -> Result<String> {
        if blob.is_empty() {
            anyhow::bail!("empty metadata blob");
        }

        let version = blob[0];
        if version != METADATA_VERSION {
            anyhow::bail!("unsupported metadata version: {}", version);
        }

        if blob.len() < 1 + NONCE_SIZE + 1 {
            anyhow::bail!("metadata blob too short");
        }

        let nonce_bytes = &blob[1..1 + NONCE_SIZE];
        let ciphertext = &blob[1 + NONCE_SIZE..];

        let cipher = Aes256Gcm::new_from_slice(&self.key_bytes)
            .map_err(|e| anyhow::anyhow!("cipher init: {}", e))?;

        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("metadata decryption failed (wrong key or tampered)"))?;

        String::from_utf8(plaintext).context("decrypted metadata is not valid UTF-8")
    }
}

/// Encrypted metadata bundle for a node or channel.
/// Clients send this to the server; the server stores it opaquely.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedMetadata {
    /// Base64-encoded encrypted blob
    pub encrypted_name: Option<String>,
    /// Base64-encoded encrypted blob
    pub encrypted_description: Option<String>,
}

impl EncryptedMetadata {
    /// Encrypt a name and optional description.
    pub fn encrypt(key: &NodeMetadataKey, name: &str, description: Option<&str>) -> Result<Self> {
        use base64::Engine;
        let enc_name = key.encrypt(name)?;
        let enc_desc = description.map(|d| key.encrypt(d)).transpose()?;

        Ok(Self {
            encrypted_name: Some(base64::engine::general_purpose::STANDARD.encode(&enc_name)),
            encrypted_description: enc_desc
                .map(|d| base64::engine::general_purpose::STANDARD.encode(&d)),
        })
    }

    /// Decrypt the name and description.
    pub fn decrypt(&self, key: &NodeMetadataKey) -> Result<(Option<String>, Option<String>)> {
        use base64::Engine;
        let name = self
            .encrypted_name
            .as_ref()
            .map(|b64| {
                let blob = base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .context("invalid base64 in encrypted_name")?;
                key.decrypt(&blob)
            })
            .transpose()?;

        let desc = self
            .encrypted_description
            .as_ref()
            .map(|b64| {
                let blob = base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .context("invalid base64 in encrypted_description")?;
                key.decrypt(&blob)
            })
            .transpose()?;

        Ok((name, desc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let key1 = NodeMetadataKey::derive(b"identity-key-material", b"node-uuid-1234").unwrap();
        let key2 = NodeMetadataKey::derive(b"identity-key-material", b"node-uuid-1234").unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_different_nodes_different_keys() {
        let key1 = NodeMetadataKey::derive(b"identity-key-material", b"node-A").unwrap();
        let key2 = NodeMetadataKey::derive(b"identity-key-material", b"node-B").unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = NodeMetadataKey::derive(b"test-key", b"test-node").unwrap();
        let plaintext = "My Secret Node Name";
        let blob = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&blob).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_unicode() {
        let key = NodeMetadataKey::derive(b"test-key", b"test-node").unwrap();
        let plaintext = "🔒 Ünïcödé Nödé 日本語";
        let blob = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&blob).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = NodeMetadataKey::derive(b"key-1", b"node").unwrap();
        let key2 = NodeMetadataKey::derive(b"key-2", b"node").unwrap();
        let blob = key1.encrypt("secret").unwrap();
        assert!(key2.decrypt(&blob).is_err());
    }

    #[test]
    fn test_tampered_blob_fails() {
        let key = NodeMetadataKey::derive(b"test-key", b"test-node").unwrap();
        let mut blob = key.encrypt("secret").unwrap();
        // Flip a byte in the ciphertext
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert!(key.decrypt(&blob).is_err());
    }

    #[test]
    fn test_empty_blob_fails() {
        let key = NodeMetadataKey::derive(b"test-key", b"test-node").unwrap();
        assert!(key.decrypt(&[]).is_err());
    }

    #[test]
    fn test_short_blob_fails() {
        let key = NodeMetadataKey::derive(b"test-key", b"test-node").unwrap();
        assert!(key.decrypt(&[1, 2, 3]).is_err());
    }

    #[test]
    fn test_bad_version_fails() {
        let key = NodeMetadataKey::derive(b"test-key", b"test-node").unwrap();
        let mut blob = key.encrypt("secret").unwrap();
        blob[0] = 99; // bad version
        assert!(key.decrypt(&blob).is_err());
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let key = NodeMetadataKey::derive(b"test-key", b"test-node").unwrap();
        let exported = *key.as_bytes();
        let reimported = NodeMetadataKey::from_bytes(exported);
        let blob = key.encrypt("test").unwrap();
        assert_eq!(reimported.decrypt(&blob).unwrap(), "test");
    }

    #[test]
    fn test_encrypted_metadata_bundle() {
        let key = NodeMetadataKey::derive(b"test-key", b"test-node").unwrap();
        let meta = EncryptedMetadata::encrypt(&key, "Node Name", Some("A cool node")).unwrap();

        assert!(meta.encrypted_name.is_some());
        assert!(meta.encrypted_description.is_some());

        let (name, desc) = meta.decrypt(&key).unwrap();
        assert_eq!(name.unwrap(), "Node Name");
        assert_eq!(desc.unwrap(), "A cool node");
    }

    #[test]
    fn test_encrypted_metadata_no_description() {
        let key = NodeMetadataKey::derive(b"test-key", b"test-node").unwrap();
        let meta = EncryptedMetadata::encrypt(&key, "Node Name", None).unwrap();

        assert!(meta.encrypted_name.is_some());
        assert!(meta.encrypted_description.is_none());

        let (name, desc) = meta.decrypt(&key).unwrap();
        assert_eq!(name.unwrap(), "Node Name");
        assert!(desc.is_none());
    }

    #[test]
    fn test_each_encryption_unique() {
        // Nonce randomization means same plaintext → different ciphertext
        let key = NodeMetadataKey::derive(b"test-key", b"test-node").unwrap();
        let blob1 = key.encrypt("same").unwrap();
        let blob2 = key.encrypt("same").unwrap();
        assert_ne!(blob1, blob2);
        // But both decrypt to same plaintext
        assert_eq!(key.decrypt(&blob1).unwrap(), "same");
        assert_eq!(key.decrypt(&blob2).unwrap(), "same");
    }
}
