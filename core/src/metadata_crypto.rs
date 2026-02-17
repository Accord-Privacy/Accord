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

// ---------------------------------------------------------------------------
// Node-level metadata encryption (extended API)
// ---------------------------------------------------------------------------

/// A 32-byte SHA-256 hash identifying a public key.
pub type PublicKeyHash = [u8; 32];

/// A Node-level symmetric key used for encrypting channel names, membership
/// lists, and other per-Node metadata.  Wraps a 256-bit key.
#[derive(Clone)]
pub struct NodeKey {
    key_bytes: [u8; 32],
}

impl NodeKey {
    /// Generate a fresh random NodeKey.
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let mut key_bytes = [0u8; 32];
        rng.fill(&mut key_bytes)
            .map_err(|_| anyhow::anyhow!("RNG failed"))?;
        Ok(Self { key_bytes })
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { key_bytes: bytes }
    }

    /// Export raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key_bytes
    }

    /// Derive a purpose-specific sub-key using HKDF with domain separation.
    fn derive_subkey(&self, info: &[u8]) -> Result<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(None, &self.key_bytes);
        let mut out = [0u8; 32];
        hk.expand(info, &mut out)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
        Ok(out)
    }

    /// Encrypt arbitrary bytes with a purpose-specific sub-key.
    fn encrypt_bytes(&self, plaintext: &[u8], domain: &[u8]) -> Result<Vec<u8>> {
        let subkey = self.derive_subkey(domain)?;
        let cipher = Aes256Gcm::new_from_slice(&subkey)
            .map_err(|e| anyhow::anyhow!("cipher init: {}", e))?;
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("RNG failed"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;
        // Wire: version || nonce || ciphertext
        let mut out = Vec::with_capacity(1 + NONCE_SIZE + ciphertext.len());
        out.push(METADATA_VERSION);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt bytes previously encrypted with `encrypt_bytes` and the same domain.
    fn decrypt_bytes(&self, blob: &[u8], domain: &[u8]) -> Result<Vec<u8>> {
        if blob.is_empty() {
            anyhow::bail!("empty blob");
        }
        if blob[0] != METADATA_VERSION {
            anyhow::bail!("unsupported metadata version: {}", blob[0]);
        }
        if blob.len() < 1 + NONCE_SIZE + 1 {
            anyhow::bail!("blob too short");
        }
        let nonce_bytes = &blob[1..1 + NONCE_SIZE];
        let ciphertext = &blob[1 + NONCE_SIZE..];
        let subkey = self.derive_subkey(domain)?;
        let cipher = Aes256Gcm::new_from_slice(&subkey)
            .map_err(|e| anyhow::anyhow!("cipher init: {}", e))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("decryption failed (wrong key or tampered)"))
    }
}

/// An encrypted opaque field: nonce + ciphertext stored together.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct EncryptedField {
    /// Base64-encoded versioned blob (version || nonce || ciphertext+tag)
    pub blob: String,
}

impl EncryptedField {
    fn from_raw(raw: Vec<u8>) -> Self {
        use base64::Engine;
        Self {
            blob: base64::engine::general_purpose::STANDARD.encode(&raw),
        }
    }

    fn to_raw(&self) -> Result<Vec<u8>> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&self.blob)
            .context("invalid base64 in EncryptedField")
    }
}

/// Plaintext node metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct NodeMetadata {
    pub description: String,
    pub icon_url: Option<String>,
    pub settings: serde_json::Value,
}

/// Encrypted node metadata — each field encrypted independently so partial
/// updates are possible.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedNodeMetadata {
    pub description: EncryptedField,
    pub icon_url: Option<EncryptedField>,
    pub settings: EncryptedField,
}

// Domain separation constants for HKDF sub-key derivation
const DOMAIN_CHANNEL_NAME: &[u8] = b"accord-node-channel-name-v1";
const DOMAIN_MEMBERSHIP: &[u8] = b"accord-node-membership-v1";
const DOMAIN_META_DESC: &[u8] = b"accord-node-meta-desc-v1";
const DOMAIN_META_ICON: &[u8] = b"accord-node-meta-icon-v1";
const DOMAIN_META_SETTINGS: &[u8] = b"accord-node-meta-settings-v1";

/// Encrypt a channel name.
pub fn encrypt_channel_name(name: &str, node_key: &NodeKey) -> Result<EncryptedField> {
    let raw = node_key.encrypt_bytes(name.as_bytes(), DOMAIN_CHANNEL_NAME)?;
    Ok(EncryptedField::from_raw(raw))
}

/// Decrypt a channel name.
pub fn decrypt_channel_name(encrypted: &EncryptedField, node_key: &NodeKey) -> Result<String> {
    let raw = encrypted.to_raw()?;
    let plaintext = node_key.decrypt_bytes(&raw, DOMAIN_CHANNEL_NAME)?;
    String::from_utf8(plaintext).context("decrypted channel name is not valid UTF-8")
}

/// Encrypt a membership list (list of public key hashes).
pub fn encrypt_membership_list(
    members: &[PublicKeyHash],
    node_key: &NodeKey,
) -> Result<EncryptedField> {
    // Serialize as concatenated 32-byte hashes prefixed with a u32 count
    let mut buf = Vec::with_capacity(4 + members.len() * 32);
    buf.extend_from_slice(&(members.len() as u32).to_le_bytes());
    for m in members {
        buf.extend_from_slice(m);
    }
    let raw = node_key.encrypt_bytes(&buf, DOMAIN_MEMBERSHIP)?;
    Ok(EncryptedField::from_raw(raw))
}

/// Decrypt a membership list.
pub fn decrypt_membership_list(
    encrypted: &EncryptedField,
    node_key: &NodeKey,
) -> Result<Vec<PublicKeyHash>> {
    let raw = encrypted.to_raw()?;
    let plaintext = node_key.decrypt_bytes(&raw, DOMAIN_MEMBERSHIP)?;
    if plaintext.len() < 4 {
        anyhow::bail!("membership plaintext too short");
    }
    let count = u32::from_le_bytes(plaintext[0..4].try_into().unwrap()) as usize;
    if plaintext.len() != 4 + count * 32 {
        anyhow::bail!(
            "membership plaintext length mismatch: expected {}, got {}",
            4 + count * 32,
            plaintext.len()
        );
    }
    let mut members = Vec::with_capacity(count);
    for i in 0..count {
        let start = 4 + i * 32;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&plaintext[start..start + 32]);
        members.push(hash);
    }
    Ok(members)
}

/// Encrypt full node metadata.
pub fn encrypt_node_metadata(
    metadata: &NodeMetadata,
    node_key: &NodeKey,
) -> Result<EncryptedNodeMetadata> {
    let desc_raw = node_key.encrypt_bytes(metadata.description.as_bytes(), DOMAIN_META_DESC)?;
    let icon_raw = metadata
        .icon_url
        .as_ref()
        .map(|url| node_key.encrypt_bytes(url.as_bytes(), DOMAIN_META_ICON))
        .transpose()?;
    let settings_bytes = serde_json::to_vec(&metadata.settings)?;
    let settings_raw = node_key.encrypt_bytes(&settings_bytes, DOMAIN_META_SETTINGS)?;

    Ok(EncryptedNodeMetadata {
        description: EncryptedField::from_raw(desc_raw),
        icon_url: icon_raw.map(EncryptedField::from_raw),
        settings: EncryptedField::from_raw(settings_raw),
    })
}

/// Decrypt full node metadata.
pub fn decrypt_node_metadata(
    encrypted: &EncryptedNodeMetadata,
    node_key: &NodeKey,
) -> Result<NodeMetadata> {
    let desc_plain = node_key.decrypt_bytes(&encrypted.description.to_raw()?, DOMAIN_META_DESC)?;
    let description = String::from_utf8(desc_plain).context("description not valid UTF-8")?;

    let icon_url = encrypted
        .icon_url
        .as_ref()
        .map(|ef| {
            let raw = ef.to_raw()?;
            let plain = node_key.decrypt_bytes(&raw, DOMAIN_META_ICON)?;
            String::from_utf8(plain).context("icon_url not valid UTF-8")
        })
        .transpose()?;

    let settings_plain =
        node_key.decrypt_bytes(&encrypted.settings.to_raw()?, DOMAIN_META_SETTINGS)?;
    let settings: serde_json::Value = serde_json::from_slice(&settings_plain)?;

    Ok(NodeMetadata {
        description,
        icon_url,
        settings,
    })
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

    // ---------------------------------------------------------------
    // Extended API tests (NodeKey, EncryptedField, etc.)
    // ---------------------------------------------------------------

    #[test]
    fn test_node_key_generate_unique() {
        let k1 = NodeKey::generate().unwrap();
        let k2 = NodeKey::generate().unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_node_key_from_bytes_roundtrip() {
        let k = NodeKey::generate().unwrap();
        let k2 = NodeKey::from_bytes(*k.as_bytes());
        assert_eq!(k.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_channel_name_roundtrip() {
        let key = NodeKey::generate().unwrap();
        let enc = encrypt_channel_name("general", &key).unwrap();
        assert_eq!(decrypt_channel_name(&enc, &key).unwrap(), "general");
    }

    #[test]
    fn test_channel_name_unicode() {
        let key = NodeKey::generate().unwrap();
        let name = "🔒 日本語チャンネル";
        let enc = encrypt_channel_name(name, &key).unwrap();
        assert_eq!(decrypt_channel_name(&enc, &key).unwrap(), name);
    }

    #[test]
    fn test_channel_name_empty() {
        let key = NodeKey::generate().unwrap();
        let enc = encrypt_channel_name("", &key).unwrap();
        assert_eq!(decrypt_channel_name(&enc, &key).unwrap(), "");
    }

    #[test]
    fn test_channel_name_wrong_key() {
        let k1 = NodeKey::generate().unwrap();
        let k2 = NodeKey::generate().unwrap();
        let enc = encrypt_channel_name("secret", &k1).unwrap();
        assert!(decrypt_channel_name(&enc, &k2).is_err());
    }

    #[test]
    fn test_channel_name_unique_ciphertexts() {
        let key = NodeKey::generate().unwrap();
        let e1 = encrypt_channel_name("same", &key).unwrap();
        let e2 = encrypt_channel_name("same", &key).unwrap();
        assert_ne!(e1.blob, e2.blob);
    }

    #[test]
    fn test_membership_roundtrip() {
        let key = NodeKey::generate().unwrap();
        let members: Vec<PublicKeyHash> = (0..5).map(|i| [i; 32]).collect();
        let enc = encrypt_membership_list(&members, &key).unwrap();
        let dec = decrypt_membership_list(&enc, &key).unwrap();
        assert_eq!(dec, members);
    }

    #[test]
    fn test_membership_empty() {
        let key = NodeKey::generate().unwrap();
        let enc = encrypt_membership_list(&[], &key).unwrap();
        let dec = decrypt_membership_list(&enc, &key).unwrap();
        assert!(dec.is_empty());
    }

    #[test]
    fn test_membership_large() {
        let key = NodeKey::generate().unwrap();
        let members: Vec<PublicKeyHash> = (0u32..1000)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..4].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();
        let enc = encrypt_membership_list(&members, &key).unwrap();
        let dec = decrypt_membership_list(&enc, &key).unwrap();
        assert_eq!(dec, members);
    }

    #[test]
    fn test_membership_wrong_key() {
        let k1 = NodeKey::generate().unwrap();
        let k2 = NodeKey::generate().unwrap();
        let enc = encrypt_membership_list(&[[1u8; 32]], &k1).unwrap();
        assert!(decrypt_membership_list(&enc, &k2).is_err());
    }

    #[test]
    fn test_node_metadata_roundtrip() {
        let key = NodeKey::generate().unwrap();
        let meta = NodeMetadata {
            description: "A private node".to_string(),
            icon_url: Some("https://example.com/icon.png".to_string()),
            settings: serde_json::json!({"notifications": true, "theme": "dark"}),
        };
        let enc = encrypt_node_metadata(&meta, &key).unwrap();
        let dec = decrypt_node_metadata(&enc, &key).unwrap();
        assert_eq!(dec, meta);
    }

    #[test]
    fn test_node_metadata_no_icon() {
        let key = NodeKey::generate().unwrap();
        let meta = NodeMetadata {
            description: "No icon".to_string(),
            icon_url: None,
            settings: serde_json::json!({}),
        };
        let enc = encrypt_node_metadata(&meta, &key).unwrap();
        let dec = decrypt_node_metadata(&enc, &key).unwrap();
        assert_eq!(dec, meta);
    }

    #[test]
    fn test_node_metadata_wrong_key() {
        let k1 = NodeKey::generate().unwrap();
        let k2 = NodeKey::generate().unwrap();
        let meta = NodeMetadata {
            description: "secret".to_string(),
            icon_url: None,
            settings: serde_json::json!(null),
        };
        let enc = encrypt_node_metadata(&meta, &k1).unwrap();
        assert!(decrypt_node_metadata(&enc, &k2).is_err());
    }

    #[test]
    fn test_node_metadata_empty_description() {
        let key = NodeKey::generate().unwrap();
        let meta = NodeMetadata {
            description: String::new(),
            icon_url: None,
            settings: serde_json::json!(null),
        };
        let enc = encrypt_node_metadata(&meta, &key).unwrap();
        let dec = decrypt_node_metadata(&enc, &key).unwrap();
        assert_eq!(dec, meta);
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
