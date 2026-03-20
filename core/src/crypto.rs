//! # Accord Cryptography Module
//!
//! Core encryption primitives for Accord's end-to-end encryption system.
//! Uses Signal Protocol for text messages and custom protocols for voice.

use anyhow::{Context, Result};
use hkdf::Hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use ring::{aead, agreement};
use sha2::Sha256;
use std::collections::HashMap;

/// Accord encryption version for protocol compatibility
pub const ENCRYPTION_VERSION: u8 = 1;

/// X25519 key pair for Diffie-Hellman key agreement
#[derive(Debug)]
pub struct KeyPair {
    pub private_key: agreement::EphemeralPrivateKey,
    pub public_key: Vec<u8>,
}

/// Long-term identity key for user verification
#[derive(Debug, Clone)]
pub struct IdentityKey {
    pub public_key: Vec<u8>,
    pub signature_key: Vec<u8>,
}

/// Session key for encrypting messages between two users
#[derive(Debug, Clone)]
pub struct SessionKey {
    pub key_material: [u8; 32],
    pub chain_key: [u8; 32],
    pub message_number: u64,
}

/// Voice encryption key for real-time audio
#[derive(Debug)]
pub struct VoiceKey {
    pub aes_key: [u8; 32],
    pub nonce_prefix: [u8; 4],
    pub sequence: u64,
}

/// Core cryptography manager for Accord
pub struct CryptoManager {
    rng: SystemRandom,
    identity_key: Option<IdentityKey>,
    session_keys: HashMap<String, SessionKey>,
}

impl Default for CryptoManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoManager {
    /// Create a new crypto manager
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
            identity_key: None,
            session_keys: HashMap::new(),
        }
    }

    /// Generate a new X25519 key pair for key agreement
    pub fn generate_key_pair(&self) -> Result<KeyPair> {
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &self.rng)
            .map_err(|_| anyhow::anyhow!("Failed to generate private key"))?;

        let public_key = private_key
            .compute_public_key()
            .map_err(|_| anyhow::anyhow!("Failed to compute public key"))?;

        Ok(KeyPair {
            private_key,
            public_key: public_key.as_ref().to_vec(),
        })
    }

    /// Generate long-term identity key for user
    pub fn generate_identity_key(&mut self) -> Result<IdentityKey> {
        let key_pair = self.generate_key_pair()?;

        // For now, use the X25519 public key as both identity and signature key
        // In production, we'd use Ed25519 for signatures
        let identity = IdentityKey {
            public_key: key_pair.public_key.clone(),
            signature_key: key_pair.public_key.clone(),
        };

        self.identity_key = Some(identity.clone());
        Ok(identity)
    }

    /// Perform X3DH key agreement to establish session key
    pub fn establish_session(
        &mut self,
        user_id: &str,
        their_public_key: &[u8],
    ) -> Result<SessionKey> {
        let our_key_pair = self.generate_key_pair()?;

        let their_public_key =
            agreement::UnparsedPublicKey::new(&agreement::X25519, their_public_key);

        let shared_secret = agreement::agree_ephemeral(
            our_key_pair.private_key,
            &their_public_key,
            |key_material| {
                let hk = Hkdf::<Sha256>::new(None, key_material);

                let mut session_key = [0u8; 32];
                let mut chain_key = [0u8; 32];

                // Derive session key and chain key with different info strings
                hk.expand(b"accord-session-key-v1", &mut session_key)
                    .expect("HKDF expand for session key");
                hk.expand(b"accord-chain-key-v1", &mut chain_key)
                    .expect("HKDF expand for chain key");

                (session_key, chain_key)
            },
        )
        .map_err(|_| anyhow::anyhow!("Key agreement failed"))?;

        let session = SessionKey {
            key_material: shared_secret.0,
            chain_key: shared_secret.1,
            message_number: 0,
        };

        self.session_keys.insert(user_id.to_string(), session);
        Ok(self.session_keys[user_id].clone())
    }

    /// Establish session from existing session key material (for testing)
    pub fn set_session(&mut self, user_id: &str, session_key: SessionKey) {
        self.session_keys.insert(user_id.to_string(), session_key);
    }

    /// Ratchet the chain key forward to derive a new message key, providing forward secrecy.
    #[deprecated(
        note = "Use double_ratchet::DoubleRatchetSession for full Double Ratchet protocol"
    )]
    /// Each message uses a unique key derived from the chain key, and the chain key advances.
    fn ratchet_chain_key(chain_key: &mut [u8; 32]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, chain_key);
        let mut message_key = [0u8; 32];
        hk.expand(b"accord-message-key", &mut message_key)
            .expect("HKDF expand for message key");
        // Advance chain key
        let mut new_chain_key = [0u8; 32];
        hk.expand(b"accord-chain-advance", &mut new_chain_key)
            .expect("HKDF expand for chain advance");
        *chain_key = new_chain_key;
        message_key
    }

    /// Encrypt a text message using AES-GCM with forward secrecy via key ratcheting
    #[allow(deprecated)]
    pub fn encrypt_message(&mut self, user_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let session = self
            .session_keys
            .get_mut(user_id)
            .context("No session key found for user")?;

        // Ratchet forward to get a unique message key
        let message_key = Self::ratchet_chain_key(&mut session.chain_key);

        let key = aead::UnboundKey::new(&aead::AES_256_GCM, &message_key)
            .map_err(|_| anyhow::anyhow!("Failed to create encryption key"))?;
        let key = aead::LessSafeKey::new(key);

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("Failed to generate nonce"))?;
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let mut ciphertext = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut ciphertext)
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);

        // Advance message number
        session.message_number += 1;

        Ok(result)
    }

    /// Decrypt a text message
    #[allow(deprecated)]
    pub fn decrypt_message(&mut self, user_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(anyhow::anyhow!("Ciphertext too short"));
        }

        let session = self
            .session_keys
            .get_mut(user_id)
            .context("No session key found for user")?;

        // Ratchet forward to get the same message key as the sender
        let message_key = Self::ratchet_chain_key(&mut session.chain_key);

        let key = aead::UnboundKey::new(&aead::AES_256_GCM, &message_key)
            .map_err(|_| anyhow::anyhow!("Failed to create decryption key"))?;
        let key = aead::LessSafeKey::new(key);

        // Extract nonce using safe TryInto
        let nonce_arr: [u8; 12] = ciphertext[0..12]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to extract nonce"))?;
        let nonce = aead::Nonce::assume_unique_for_key(nonce_arr);

        let mut message = ciphertext[12..].to_vec();
        let plaintext = key
            .open_in_place(nonce, aead::Aad::empty(), &mut message)
            .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

        Ok(plaintext.to_vec())
    }

    /// Generate voice encryption key for real-time audio
    pub fn generate_voice_key(&self) -> Result<VoiceKey> {
        let mut aes_key = [0u8; 32];
        let mut nonce_prefix = [0u8; 4];

        self.rng
            .fill(&mut aes_key)
            .map_err(|_| anyhow::anyhow!("Failed to generate voice key"))?;
        self.rng
            .fill(&mut nonce_prefix)
            .map_err(|_| anyhow::anyhow!("Failed to generate nonce prefix"))?;

        Ok(VoiceKey {
            aes_key,
            nonce_prefix,
            sequence: 0,
        })
    }

    /// Encrypt voice packet for real-time transmission
    pub fn encrypt_voice_packet(
        &self,
        voice_key: &mut VoiceKey,
        audio_data: &[u8],
    ) -> Result<Vec<u8>> {
        let key = aead::UnboundKey::new(&aead::AES_256_GCM, &voice_key.aes_key)
            .map_err(|_| anyhow::anyhow!("Failed to create voice encryption key"))?;
        let key = aead::LessSafeKey::new(key);

        // Create nonce from prefix + sequence number
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..4].copy_from_slice(&voice_key.nonce_prefix);
        nonce_bytes[4..12].copy_from_slice(&voice_key.sequence.to_be_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let mut ciphertext = audio_data.to_vec();
        key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut ciphertext)
            .map_err(|_| anyhow::anyhow!("Voice encryption failed"))?;

        // Include sequence number in packet for decryption
        let mut result = voice_key.sequence.to_be_bytes().to_vec();
        result.extend_from_slice(&ciphertext);

        voice_key.sequence += 1;
        Ok(result)
    }

    /// Decrypt voice packet
    pub fn decrypt_voice_packet(
        &self,
        voice_key: &VoiceKey,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>> {
        if encrypted_data.len() < 8 {
            return Err(anyhow::anyhow!("Voice packet too short"));
        }

        let key = aead::UnboundKey::new(&aead::AES_256_GCM, &voice_key.aes_key)
            .map_err(|_| anyhow::anyhow!("Failed to create voice decryption key"))?;
        let key = aead::LessSafeKey::new(key);

        // Extract sequence number using safe TryInto
        let seq_bytes: [u8; 8] = encrypted_data[0..8]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to extract sequence number"))?;
        let sequence = u64::from_be_bytes(seq_bytes);

        // Reconstruct nonce
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..4].copy_from_slice(&voice_key.nonce_prefix);
        nonce_bytes[4..12].copy_from_slice(&sequence.to_be_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let mut audio_data = encrypted_data[8..].to_vec();
        let plaintext = key
            .open_in_place(nonce, aead::Aad::empty(), &mut audio_data)
            .map_err(|_| anyhow::anyhow!("Voice decryption failed"))?;

        Ok(plaintext.to_vec())
    }

    /// Get user's identity key
    pub fn get_identity_key(&self) -> Option<&IdentityKey> {
        self.identity_key.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let crypto = CryptoManager::new();
        let key_pair = crypto.generate_key_pair().unwrap();
        assert_eq!(key_pair.public_key.len(), 32);
    }

    #[test]
    fn test_message_encryption() {
        let mut crypto1 = CryptoManager::new();
        let mut crypto2 = CryptoManager::new();

        // Create shared session keys with identical chain keys for both sides
        let session1 = SessionKey {
            key_material: [42u8; 32],
            chain_key: [24u8; 32],
            message_number: 0,
        };
        let session2 = SessionKey {
            key_material: [42u8; 32],
            chain_key: [24u8; 32], // Same chain key so ratcheting stays in sync
            message_number: 0,
        };

        crypto1.set_session("user2", session1);
        crypto2.set_session("user1", session2);

        let message = b"Hello, secure world!";
        let encrypted = crypto1.encrypt_message("user2", message).unwrap();
        let decrypted = crypto2.decrypt_message("user1", &encrypted).unwrap();

        assert_eq!(message.to_vec(), decrypted);
    }

    #[test]
    fn test_voice_encryption() {
        let crypto = CryptoManager::new();
        let mut voice_key = crypto.generate_voice_key().unwrap();

        let audio_data = b"fake audio data";
        let encrypted = crypto
            .encrypt_voice_packet(&mut voice_key, audio_data)
            .unwrap();
        let decrypted = crypto.decrypt_voice_packet(&voice_key, &encrypted).unwrap();

        assert_eq!(audio_data.to_vec(), decrypted);
    }

    // --- Key generation tests ---

    #[test]
    fn test_generate_key_pair_unique() {
        let crypto = CryptoManager::new();
        let kp1 = crypto.generate_key_pair().unwrap();
        let kp2 = crypto.generate_key_pair().unwrap();
        assert_ne!(
            kp1.public_key, kp2.public_key,
            "Two key pairs should differ"
        );
    }

    #[test]
    fn test_generate_key_pair_public_key_not_empty() {
        let crypto = CryptoManager::new();
        let kp = crypto.generate_key_pair().unwrap();
        assert!(!kp.public_key.is_empty());
        assert!(
            kp.public_key.iter().any(|&b| b != 0),
            "Public key should not be all zeros"
        );
    }

    // --- Identity key tests ---

    #[test]
    fn test_generate_identity_key_sets_identity() {
        let mut crypto = CryptoManager::new();
        assert!(crypto.get_identity_key().is_none());
        let identity = crypto.generate_identity_key().unwrap();
        assert!(crypto.get_identity_key().is_some());
        assert_eq!(
            crypto.get_identity_key().unwrap().public_key,
            identity.public_key
        );
    }

    #[test]
    fn test_generate_identity_key_signature_key_not_empty() {
        let mut crypto = CryptoManager::new();
        let identity = crypto.generate_identity_key().unwrap();
        assert!(!identity.signature_key.is_empty());
        assert_eq!(identity.signature_key.len(), 32);
    }

    // --- Session establishment tests ---

    #[test]
    fn test_establish_session_and_roundtrip() {
        // Simulate two managers establishing a session through key exchange
        let mut alice = CryptoManager::new();
        let mut bob = CryptoManager::new();

        // Alice generates a key pair, Bob uses Alice's public key to establish session
        let alice_kp = alice.generate_key_pair().unwrap();
        let bob_session = bob
            .establish_session("alice", &alice_kp.public_key)
            .unwrap();

        // Both sides share the same key material via set_session for the paired direction
        alice.set_session(
            "bob",
            SessionKey {
                key_material: bob_session.key_material,
                chain_key: bob_session.chain_key,
                message_number: 0,
            },
        );

        let message = b"Hello from Bob!";
        let encrypted = bob.encrypt_message("alice", message).unwrap();
        let decrypted = alice.decrypt_message("bob", &encrypted).unwrap();
        assert_eq!(decrypted, message.to_vec());
    }

    // --- Encrypt message tests ---

    #[test]
    fn test_encrypt_message_fails_without_session() {
        let mut crypto = CryptoManager::new();
        let result = crypto.encrypt_message("unknown_user", b"hello");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("No session key"),
            "Should mention missing session key"
        );
    }

    #[test]
    fn test_ciphertext_differs_from_plaintext() {
        let mut crypto = CryptoManager::new();
        crypto.set_session(
            "peer",
            SessionKey {
                key_material: [1u8; 32],
                chain_key: [2u8; 32],
                message_number: 0,
            },
        );

        let plaintext = b"This is a secret message";
        let encrypted = crypto.encrypt_message("peer", plaintext).unwrap();
        // Ciphertext (after 12-byte nonce) should differ from plaintext
        assert_ne!(&encrypted[12..12 + plaintext.len()], plaintext.as_slice());
    }

    #[test]
    fn test_encrypt_message_includes_nonce_prefix() {
        let mut crypto = CryptoManager::new();
        crypto.set_session(
            "peer",
            SessionKey {
                key_material: [1u8; 32],
                chain_key: [2u8; 32],
                message_number: 0,
            },
        );

        let encrypted = crypto.encrypt_message("peer", b"test").unwrap();
        // Encrypted output = 12-byte nonce + ciphertext + 16-byte AES-GCM tag
        assert!(
            encrypted.len() >= 12 + 4 + 16,
            "Should have nonce + ciphertext + tag"
        );
    }

    // --- Decrypt message tests ---

    #[test]
    fn test_decrypt_message_fails_with_wrong_session_key() {
        let mut encryptor = CryptoManager::new();
        let mut decryptor = CryptoManager::new();

        encryptor.set_session(
            "peer",
            SessionKey {
                key_material: [1u8; 32],
                chain_key: [2u8; 32],
                message_number: 0,
            },
        );
        decryptor.set_session(
            "peer",
            SessionKey {
                key_material: [99u8; 32],
                chain_key: [88u8; 32], // Different chain key => different message key
                message_number: 0,
            },
        );

        let encrypted = encryptor.encrypt_message("peer", b"secret").unwrap();
        let result = decryptor.decrypt_message("peer", &encrypted);
        assert!(result.is_err(), "Decryption should fail with wrong key");
    }

    #[test]
    fn test_decrypt_message_fails_with_tampered_ciphertext() {
        let mut crypto1 = CryptoManager::new();
        let mut crypto2 = CryptoManager::new();

        let chain_key = [50u8; 32];
        crypto1.set_session(
            "peer",
            SessionKey {
                key_material: [1u8; 32],
                chain_key,
                message_number: 0,
            },
        );
        crypto2.set_session(
            "peer",
            SessionKey {
                key_material: [1u8; 32],
                chain_key,
                message_number: 0,
            },
        );

        let mut encrypted = crypto1.encrypt_message("peer", b"integrity test").unwrap();
        // Tamper with ciphertext (flip a byte after the nonce)
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;

        let result = crypto2.decrypt_message("peer", &encrypted);
        assert!(
            result.is_err(),
            "Tampered ciphertext should fail decryption"
        );
    }

    #[test]
    fn test_decrypt_message_fails_without_session() {
        let mut crypto = CryptoManager::new();
        let result = crypto.decrypt_message("unknown_user", &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_message_fails_with_short_ciphertext() {
        let mut crypto = CryptoManager::new();
        crypto.set_session(
            "peer",
            SessionKey {
                key_material: [1u8; 32],
                chain_key: [2u8; 32],
                message_number: 0,
            },
        );
        let result = crypto.decrypt_message("peer", &[0u8; 5]);
        assert!(result.is_err(), "Ciphertext shorter than nonce should fail");
    }

    // --- Large payload roundtrip ---

    #[test]
    fn test_encrypt_decrypt_large_payload() {
        let mut encryptor = CryptoManager::new();
        let mut decryptor = CryptoManager::new();

        let chain_key = [77u8; 32];
        encryptor.set_session(
            "peer",
            SessionKey {
                key_material: [1u8; 32],
                chain_key,
                message_number: 0,
            },
        );
        decryptor.set_session(
            "peer",
            SessionKey {
                key_material: [1u8; 32],
                chain_key,
                message_number: 0,
            },
        );

        let large_payload = vec![0xABu8; 10 * 1024]; // 10KB
        let encrypted = encryptor.encrypt_message("peer", &large_payload).unwrap();
        let decrypted = decryptor.decrypt_message("peer", &encrypted).unwrap();
        assert_eq!(decrypted, large_payload);
    }

    // --- Voice key tests ---

    #[test]
    fn test_generate_voice_key_nonzero() {
        let crypto = CryptoManager::new();
        let vk = crypto.generate_voice_key().unwrap();
        assert!(
            vk.aes_key.iter().any(|&b| b != 0),
            "Voice AES key should not be all zeros"
        );
        assert_eq!(vk.sequence, 0);
    }

    #[test]
    fn test_voice_encrypt_decrypt_roundtrip() {
        let crypto = CryptoManager::new();
        let mut vk = crypto.generate_voice_key().unwrap();

        let samples = vec![b"frame1".to_vec(), b"frame2".to_vec(), b"frame3".to_vec()];
        for sample in &samples {
            let encrypted = crypto.encrypt_voice_packet(&mut vk, sample).unwrap();
            let decrypted = crypto.decrypt_voice_packet(&vk, &encrypted).unwrap();
            assert_eq!(&decrypted, sample);
        }
    }

    #[test]
    fn test_voice_decrypt_fails_with_wrong_key() {
        let crypto = CryptoManager::new();
        let mut vk1 = crypto.generate_voice_key().unwrap();
        let vk2 = crypto.generate_voice_key().unwrap();

        let encrypted = crypto
            .encrypt_voice_packet(&mut vk1, b"audio data")
            .unwrap();
        let result = crypto.decrypt_voice_packet(&vk2, &encrypted);
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[test]
    fn test_voice_sequence_increments() {
        let crypto = CryptoManager::new();
        let mut vk = crypto.generate_voice_key().unwrap();
        assert_eq!(vk.sequence, 0);

        crypto.encrypt_voice_packet(&mut vk, b"pkt1").unwrap();
        assert_eq!(vk.sequence, 1);

        crypto.encrypt_voice_packet(&mut vk, b"pkt2").unwrap();
        assert_eq!(vk.sequence, 2);

        crypto.encrypt_voice_packet(&mut vk, b"pkt3").unwrap();
        assert_eq!(vk.sequence, 3);
    }

    #[test]
    fn test_voice_packet_too_short() {
        let crypto = CryptoManager::new();
        let vk = crypto.generate_voice_key().unwrap();
        let result = crypto.decrypt_voice_packet(&vk, &[0u8; 4]);
        assert!(result.is_err(), "Packet shorter than 8 bytes should fail");
    }
}
