//! # Minimal Cryptography Implementation
//! 
//! Simplified crypto for demonstration. Production uses proper libraries.
//! This shows the concepts without requiring system-level crypto dependencies.

use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use uuid::Uuid;
use base64::{Engine as _, engine::general_purpose};

/// Simplified encryption key
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimpleKey {
    pub key_material: [u8; 32],
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Encrypted message envelope
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub sender_fingerprint: String,
}

/// Minimal crypto manager for demonstration
pub struct SimpleCrypto {
    user_id: Uuid,
    private_key: SimpleKey,
    public_key_fingerprint: String,
    session_keys: HashMap<Uuid, SimpleKey>,
}

impl SimpleKey {
    /// Generate a new key (simplified - uses hash of random data)
    pub fn generate() -> Self {
        let random_data: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let mut hasher = Sha256::new();
        hasher.update(&random_data);
        let hash = hasher.finalize();
        
        let mut key_material = [0u8; 32];
        key_material.copy_from_slice(&hash[..32]);
        
        Self {
            key_material,
            created_at: chrono::Utc::now(),
        }
    }

    /// Get key fingerprint (first 16 bytes as hex)
    pub fn fingerprint(&self) -> String {
        hex::encode(&self.key_material[..16])
    }
}

impl SimpleCrypto {
    /// Create new crypto instance for a user
    pub fn new(user_id: Uuid) -> Self {
        let private_key = SimpleKey::generate();
        let public_key_fingerprint = private_key.fingerprint();
        
        Self {
            user_id,
            private_key,
            public_key_fingerprint,
            session_keys: HashMap::new(),
        }
    }

    /// Get user's public key fingerprint
    pub fn get_public_fingerprint(&self) -> &str {
        &self.public_key_fingerprint
    }

    /// Establish session with another user (simplified key exchange)
    pub fn establish_session(&mut self, other_user_id: Uuid, _their_public_key: &str) -> String {
        // In production: proper ECDH key exchange
        // For demo: generate shared session key
        let session_key = SimpleKey::generate();
        let fingerprint = session_key.fingerprint();
        
        self.session_keys.insert(other_user_id, session_key);
        fingerprint
    }

    /// Encrypt a message (simplified XOR cipher for demo)
    pub fn encrypt_message(&self, recipient_id: Uuid, plaintext: &[u8]) -> Result<EncryptedEnvelope, String> {
        let session_key = self.session_keys.get(&recipient_id)
            .ok_or_else(|| "No session key found".to_string())?;

        // Generate nonce (random bytes)
        let nonce: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();
        
        // Simplified encryption (XOR with key + nonce hash)
        let mut hasher = Sha256::new();
        hasher.update(&session_key.key_material);
        hasher.update(&nonce);
        let key_stream = hasher.finalize();
        
        let ciphertext: Vec<u8> = plaintext
            .iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ key_stream[i % 32])
            .collect();

        Ok(EncryptedEnvelope {
            nonce,
            ciphertext,
            sender_fingerprint: self.public_key_fingerprint.clone(),
        })
    }

    /// Decrypt a message
    pub fn decrypt_message(&self, sender_id: Uuid, envelope: &EncryptedEnvelope) -> Result<Vec<u8>, String> {
        let session_key = self.session_keys.get(&sender_id)
            .ok_or_else(|| "No session key found".to_string())?;

        // Reconstruct key stream
        let mut hasher = Sha256::new();
        hasher.update(&session_key.key_material);
        hasher.update(&envelope.nonce);
        let key_stream = hasher.finalize();
        
        // Decrypt (XOR again)
        let plaintext: Vec<u8> = envelope.ciphertext
            .iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ key_stream[i % 32])
            .collect();

        Ok(plaintext)
    }

    /// Encrypt voice packet (simplified)
    pub fn encrypt_voice(&self, recipient_id: Uuid, audio_data: &[u8]) -> Result<Vec<u8>, String> {
        // For voice, use simpler encryption due to real-time requirements
        let session_key = self.session_keys.get(&recipient_id)
            .ok_or_else(|| "No session key found".to_string())?;

        // Simple XOR with key rotation
        let encrypted: Vec<u8> = audio_data
            .iter()
            .enumerate()
            .map(|(i, &byte)| {
                let key_byte = session_key.key_material[i % 32];
                byte ^ key_byte
            })
            .collect();

        Ok(encrypted)
    }

    /// Decrypt voice packet
    pub fn decrypt_voice(&self, sender_id: Uuid, encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
        // Same as encryption (XOR is symmetric)
        self.encrypt_voice(sender_id, encrypted_data)
    }

    /// Generate invite code with embedded server info
    pub fn generate_invite_code(&self, server_id: Uuid, expires_hours: u32) -> String {
        let expires_at = chrono::Utc::now() + chrono::Duration::hours(expires_hours as i64);
        let invite_data = format!("{}:{}:{}", server_id, expires_at.timestamp(), self.user_id);
        
        // Simple encoding (production would use proper invite format)
        general_purpose::STANDARD.encode(&invite_data)
    }

    /// Validate and decode invite
    pub fn decode_invite(&self, invite_code: &str) -> Result<(Uuid, chrono::DateTime<chrono::Utc>, Uuid), String> {
        let decoded = general_purpose::STANDARD.decode(invite_code)
            .map_err(|_| "Invalid invite code format")?;
        let invite_data = String::from_utf8(decoded)
            .map_err(|_| "Invalid invite data")?;
        
        let parts: Vec<&str> = invite_data.split(':').collect();
        if parts.len() != 3 {
            return Err("Invalid invite format".to_string());
        }

        let server_id = Uuid::parse_str(parts[0])
            .map_err(|_| "Invalid server ID")?;
        let timestamp = parts[1].parse::<i64>()
            .map_err(|_| "Invalid timestamp")?;
        let creator_id = Uuid::parse_str(parts[2])
            .map_err(|_| "Invalid creator ID")?;
        
        let expires_at = chrono::DateTime::from_timestamp(timestamp, 0)
            .ok_or_else(|| "Invalid expiration time")?;

        if chrono::Utc::now() > expires_at {
            return Err("Invite has expired".to_string());
        }

        Ok((server_id, expires_at, creator_id))
    }
}

// Use hex crate for encoding, but implement simple version if not available
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key1 = SimpleKey::generate();
        let key2 = SimpleKey::generate();
        
        // Keys should be different
        assert_ne!(key1.key_material, key2.key_material);
        
        // Fingerprints should be different
        assert_ne!(key1.fingerprint(), key2.fingerprint());
    }

    #[test]
    fn test_message_encryption() {
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();
        
        let mut crypto1 = SimpleCrypto::new(user1);
        let mut crypto2 = SimpleCrypto::new(user2);
        
        // Establish session
        let _session1 = crypto1.establish_session(user2, crypto2.get_public_fingerprint());
        let _session2 = crypto2.establish_session(user1, crypto1.get_public_fingerprint());
        
        // Encrypt message
        let message = b"Hello, Accord!";
        let encrypted = crypto1.encrypt_message(user2, message).unwrap();
        
        // Decrypt message
        let decrypted = crypto2.decrypt_message(user1, &encrypted).unwrap();
        
        assert_eq!(message.to_vec(), decrypted);
    }

    #[test]
    fn test_invite_system() {
        let crypto = SimpleCrypto::new(Uuid::new_v4());
        let server_id = Uuid::new_v4();
        
        // Generate invite
        let invite_code = crypto.generate_invite_code(server_id, 24);
        
        // Decode invite
        let (decoded_server, _expires_at, _creator) = crypto.decode_invite(&invite_code).unwrap();
        
        assert_eq!(server_id, decoded_server);
    }

    #[test]
    fn test_voice_encryption() {
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();
        
        let mut crypto1 = SimpleCrypto::new(user1);
        let mut crypto2 = SimpleCrypto::new(user2);
        
        // Establish session
        crypto1.establish_session(user2, crypto2.get_public_fingerprint());
        crypto2.establish_session(user1, crypto1.get_public_fingerprint());
        
        // Encrypt voice data
        let voice_data = b"fake_audio_samples";
        let encrypted = crypto1.encrypt_voice(user2, voice_data).unwrap();
        let decrypted = crypto2.decrypt_voice(user1, &encrypted).unwrap();
        
        assert_eq!(voice_data.to_vec(), decrypted);
    }
}