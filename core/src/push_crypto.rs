//! Encrypted push notification metadata
//!
//! Allows the sender to encrypt push metadata (like their display name)
//! with the recipient's public key, so even the push payload content
//! is E2E encrypted. The server and push provider never see plaintext.
//!
//! Flow:
//! 1. Sender encrypts metadata with recipient's public key
//! 2. Server includes the opaque blob in the push payload
//! 3. Client decrypts on receipt to show notification content
//!
//! This is optional — clients can operate in "partial" or "stealth"
//! mode without ever using this.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Metadata that can be encrypted into the push payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushMetadata {
    /// Sender's display name
    pub sender_name: Option<String>,
    /// Channel name
    pub channel_name: Option<String>,
    /// Message preview (first N chars) — use with caution!
    pub preview: Option<String>,
}

/// Encrypted push metadata blob
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPushMetadata {
    /// Ephemeral public key used for ECDH
    pub ephemeral_public: [u8; 32],
    /// AES-256-GCM nonce
    pub nonce: [u8; 12],
    /// Encrypted + authenticated ciphertext
    pub ciphertext: Vec<u8>,
}

impl EncryptedPushMetadata {
    /// Serialize to base64 for inclusion in push payload
    pub fn to_base64(&self) -> String {
        let bytes = bincode::serialize(self).expect("serialization cannot fail");
        base64_encode(&bytes)
    }

    /// Deserialize from base64
    pub fn from_base64(s: &str) -> Result<Self, String> {
        let bytes = base64_decode(s).map_err(|e| format!("base64 decode: {}", e))?;
        bincode::deserialize(&bytes).map_err(|e| format!("deserialize: {}", e))
    }
}

/// Encrypt push metadata for a recipient using their X25519 public key.
///
/// Uses ephemeral ECDH + HKDF + AES-256-GCM.
pub fn encrypt_push_metadata(
    recipient_public_key: &[u8; 32],
    metadata: &PushMetadata,
) -> Result<EncryptedPushMetadata, String> {
    let recipient_pk = PublicKey::from(*recipient_public_key);

    // Generate ephemeral keypair
    let mut rng = rand::thread_rng();
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // ECDH shared secret
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pk);

    // Derive AES key via HKDF
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, shared_secret.as_bytes());
    let mut aes_key = [0u8; 32];
    hk.expand(b"accord-push-metadata-v1", &mut aes_key)
        .map_err(|_| "HKDF expand failed")?;

    // Encrypt
    let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|_| "AES key init failed")?;

    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext =
        serde_json::to_vec(metadata).map_err(|e| format!("serialize metadata: {}", e))?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| "AES-GCM encryption failed")?;

    aes_key.zeroize();

    Ok(EncryptedPushMetadata {
        ephemeral_public: ephemeral_public.to_bytes(),
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypt push metadata using the recipient's X25519 private key.
pub fn decrypt_push_metadata(
    recipient_private_key: &[u8; 32],
    encrypted: &EncryptedPushMetadata,
) -> Result<PushMetadata, String> {
    let recipient_sk = StaticSecret::from(*recipient_private_key);
    let ephemeral_pk = PublicKey::from(encrypted.ephemeral_public);

    // ECDH shared secret
    let shared_secret = recipient_sk.diffie_hellman(&ephemeral_pk);

    // Derive AES key
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, shared_secret.as_bytes());
    let mut aes_key = [0u8; 32];
    hk.expand(b"accord-push-metadata-v1", &mut aes_key)
        .map_err(|_| "HKDF expand failed")?;

    // Decrypt
    let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|_| "AES key init failed")?;
    let nonce = Nonce::from_slice(&encrypted.nonce);

    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| "AES-GCM decryption failed — wrong key or tampered data")?;

    aes_key.zeroize();

    serde_json::from_slice(&plaintext).map_err(|e| format!("deserialize metadata: {}", e))
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Generate recipient keypair
        let recipient_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let recipient_public = PublicKey::from(&recipient_secret);

        let metadata = PushMetadata {
            sender_name: Some("Alice".into()),
            channel_name: Some("general".into()),
            preview: None,
        };

        let encrypted = encrypt_push_metadata(&recipient_public.to_bytes(), &metadata).unwrap();

        let decrypted = decrypt_push_metadata(&recipient_secret.to_bytes(), &encrypted).unwrap();

        assert_eq!(decrypted.sender_name, Some("Alice".into()));
        assert_eq!(decrypted.channel_name, Some("general".into()));
        assert_eq!(decrypted.preview, None);
    }

    #[test]
    fn test_wrong_key_fails() {
        let recipient_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let recipient_public = PublicKey::from(&recipient_secret);

        let metadata = PushMetadata {
            sender_name: Some("Bob".into()),
            channel_name: None,
            preview: None,
        };

        let encrypted = encrypt_push_metadata(&recipient_public.to_bytes(), &metadata).unwrap();

        // Try decrypting with wrong key
        let wrong_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let result = decrypt_push_metadata(&wrong_secret.to_bytes(), &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_roundtrip() {
        let recipient_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let recipient_public = PublicKey::from(&recipient_secret);

        let metadata = PushMetadata {
            sender_name: Some("Charlie".into()),
            channel_name: None,
            preview: Some("Hey there!".into()),
        };

        let encrypted = encrypt_push_metadata(&recipient_public.to_bytes(), &metadata).unwrap();

        let b64 = encrypted.to_base64();
        let restored = EncryptedPushMetadata::from_base64(&b64).unwrap();

        let decrypted = decrypt_push_metadata(&recipient_secret.to_bytes(), &restored).unwrap();

        assert_eq!(decrypted.sender_name, Some("Charlie".into()));
        assert_eq!(decrypted.preview, Some("Hey there!".into()));
    }
}
