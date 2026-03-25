//! # Sender Keys E2EE for Accord Channels
//!
//! Each channel member maintains their own symmetric ratchet chain.
//! Messages are encrypted once with the sender's key (O(1) per send).
//! Keys are distributed via Double Ratchet encrypted DMs.
//!
//! Wire format is JSON-compatible with the TypeScript frontend implementation.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hmac::Mac;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;

type HmacSha256 = hmac::Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_SKIP: u32 = 2000;
const MESSAGE_KEY_INFO: &[u8] = b"MessageKey";
const CHAIN_KEY_INFO: &[u8] = b"ChainKey";

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SenderKeyError {
    #[error("signature verification failed")]
    SignatureVerification,
    #[error("no cached key for iteration {0}")]
    NoCachedKey(u32),
    #[error("too many skipped messages: {0}")]
    TooManySkipped(u32),
    #[error("no sender key for user {user_id} in channel {channel_id}")]
    NoSenderKey { user_id: String, channel_id: String },
    #[error("unknown envelope version: {0}")]
    UnknownVersion(u32),
    #[error("encryption error: {0}")]
    Encryption(String),
    #[error("decryption error: {0}")]
    Decryption(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid key length")]
    InvalidKeyLength,
}

pub type Result<T> = std::result::Result<T, SenderKeyError>;

// ---------------------------------------------------------------------------
// Key Types
// ---------------------------------------------------------------------------

/// Private sender key — only held by the key owner.
#[derive(Clone)]
pub struct SenderKeyPrivate {
    pub chain_key: [u8; 32],
    pub signing_key: SigningKey,
    pub iteration: u32,
}

/// Public sender key — shared with channel members for decryption.
#[derive(Clone)]
pub struct SenderKeyPublic {
    pub chain_key: [u8; 32],
    pub signing_pub_key: VerifyingKey,
    pub iteration: u32,
    pub sender_key_id: String,
}

/// Receiver's state tracking a remote sender's key.
#[derive(Clone)]
pub struct SenderKeyState {
    pub key: SenderKeyPublic,
    pub current_chain_key: [u8; 32],
    pub current_iteration: u32,
    pub skipped_message_keys: HashMap<u32, [u8; 32]>,
}

// ---------------------------------------------------------------------------
// Wire Formats (JSON-compatible with TypeScript)
// ---------------------------------------------------------------------------

/// Compact wire format envelope (stored in message content).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKeyEnvelope {
    pub v: u32,
    pub sk: String,
    pub i: u32,
    pub iv: String,
    pub ct: String,
    pub sig: String,
}

/// Distribution message sent via DR DM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKeyDistributionMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub ch: String,
    pub skid: String,
    pub ck: String,
    pub spk: String,
    pub iter: u32,
    pub rep: Option<String>,
}

// ---------------------------------------------------------------------------
// Key Generation
// ---------------------------------------------------------------------------

/// Generate a fresh sender key for a channel.
pub fn generate_sender_key() -> SenderKeyPrivate {
    let mut chain_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut chain_key);
    let signing_key = SigningKey::generate(&mut OsRng);
    SenderKeyPrivate {
        chain_key,
        signing_key,
        iteration: 0,
    }
}

/// Compute a short hex fingerprint of a signing public key (SHA-256, first 8 bytes).
pub fn sender_key_fingerprint(pub_key: &VerifyingKey) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(pub_key.as_bytes());
    hex::encode(&hash[..8])
}

/// Extract the public portion of a sender key.
pub fn sender_key_to_public(sk: &SenderKeyPrivate) -> SenderKeyPublic {
    let pub_key = sk.signing_key.verifying_key();
    SenderKeyPublic {
        chain_key: sk.chain_key,
        signing_pub_key: pub_key,
        iteration: sk.iteration,
        sender_key_id: sender_key_fingerprint(&pub_key),
    }
}

/// Create a SenderKeyState for tracking a received public key.
pub fn create_sender_key_state(pub_key: SenderKeyPublic) -> SenderKeyState {
    SenderKeyState {
        current_chain_key: pub_key.chain_key,
        current_iteration: pub_key.iteration,
        skipped_message_keys: HashMap::new(),
        key: pub_key,
    }
}

// ---------------------------------------------------------------------------
// Chain Ratchet
// ---------------------------------------------------------------------------

fn derive_message_key(chain_key: &[u8; 32]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(chain_key).expect("HMAC accepts any key length");
    mac.update(MESSAGE_KEY_INFO);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn advance_chain_key(chain_key: &[u8; 32]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(chain_key).expect("HMAC accepts any key length");
    mac.update(CHAIN_KEY_INFO);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ---------------------------------------------------------------------------
// Encrypt (sender side)
// ---------------------------------------------------------------------------

/// Encrypt plaintext using the sender's own sender key.
/// Returns the wire envelope and the updated key (chain advanced).
pub fn sender_key_encrypt(
    sk: &SenderKeyPrivate,
    plaintext: &[u8],
) -> Result<(SenderKeyEnvelope, SenderKeyPrivate)> {
    let message_key = derive_message_key(&sk.chain_key);
    let next_chain_key = advance_chain_key(&sk.chain_key);

    let mut iv_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut OsRng, &mut iv_bytes);

    let cipher = Aes256Gcm::new_from_slice(&message_key)
        .map_err(|e| SenderKeyError::Encryption(e.to_string()))?;
    let nonce = Nonce::from_slice(&iv_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| SenderKeyError::Encryption(e.to_string()))?;

    // Sign iv || ciphertext
    let mut to_sign = Vec::with_capacity(iv_bytes.len() + ciphertext.len());
    to_sign.extend_from_slice(&iv_bytes);
    to_sign.extend_from_slice(&ciphertext);
    let signature = sk.signing_key.sign(&to_sign);

    let pub_key = sk.signing_key.verifying_key();
    let envelope = SenderKeyEnvelope {
        v: 1,
        sk: sender_key_fingerprint(&pub_key),
        i: sk.iteration,
        iv: BASE64.encode(iv_bytes),
        ct: BASE64.encode(&ciphertext),
        sig: BASE64.encode(signature.to_bytes()),
    };

    let updated_key = SenderKeyPrivate {
        chain_key: next_chain_key,
        signing_key: sk.signing_key.clone(),
        iteration: sk.iteration + 1,
    };

    Ok((envelope, updated_key))
}

// ---------------------------------------------------------------------------
// Decrypt (receiver side)
// ---------------------------------------------------------------------------

/// Decrypt a sender key envelope using the receiver's stored state.
/// Returns the plaintext and updated state.
pub fn sender_key_decrypt(
    state: &SenderKeyState,
    envelope: &SenderKeyEnvelope,
) -> Result<(Vec<u8>, SenderKeyState)> {
    if envelope.v != 1 {
        return Err(SenderKeyError::UnknownVersion(envelope.v));
    }

    let iv = BASE64.decode(&envelope.iv)?;
    let ciphertext = BASE64.decode(&envelope.ct)?;
    let sig_bytes = BASE64.decode(&envelope.sig)?;

    // Verify Ed25519 signature over iv || ciphertext
    let mut to_verify = Vec::with_capacity(iv.len() + ciphertext.len());
    to_verify.extend_from_slice(&iv);
    to_verify.extend_from_slice(&ciphertext);

    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|_| SenderKeyError::SignatureVerification)?;
    state
        .key
        .signing_pub_key
        .verify(&to_verify, &signature)
        .map_err(|_| SenderKeyError::SignatureVerification)?;

    let mut new_state = state.clone();
    let message_key;

    if envelope.i < state.current_iteration {
        // Out-of-order: use cached key
        let cached = new_state
            .skipped_message_keys
            .remove(&envelope.i)
            .ok_or(SenderKeyError::NoCachedKey(envelope.i))?;
        message_key = cached;
    } else {
        let skip_count = envelope.i - state.current_iteration;
        if skip_count > MAX_SKIP {
            return Err(SenderKeyError::TooManySkipped(skip_count));
        }

        let mut chain_key = new_state.current_chain_key;
        let mut iter = new_state.current_iteration;

        while iter < envelope.i {
            new_state
                .skipped_message_keys
                .insert(iter, derive_message_key(&chain_key));
            chain_key = advance_chain_key(&chain_key);
            iter += 1;
        }

        message_key = derive_message_key(&chain_key);
        new_state.current_chain_key = advance_chain_key(&chain_key);
        new_state.current_iteration = iter + 1;
    }

    // Prune excess skipped keys
    if new_state.skipped_message_keys.len() > MAX_SKIP as usize {
        let mut keys: Vec<u32> = new_state.skipped_message_keys.keys().copied().collect();
        keys.sort_unstable();
        while new_state.skipped_message_keys.len() > MAX_SKIP as usize {
            if let Some(oldest) = keys.first().copied() {
                new_state.skipped_message_keys.remove(&oldest);
                keys.remove(0);
            } else {
                break;
            }
        }
    }

    // Decrypt
    let cipher = Aes256Gcm::new_from_slice(&message_key)
        .map_err(|e| SenderKeyError::Decryption(e.to_string()))?;
    let nonce = Nonce::from_slice(&iv);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| SenderKeyError::Decryption(e.to_string()))?;

    Ok((plaintext, new_state))
}

// ---------------------------------------------------------------------------
// Distribution message helpers
// ---------------------------------------------------------------------------

/// Build a distribution message to send via DR DM.
pub fn build_distribution_message(
    channel_id: &str,
    sk: &SenderKeyPrivate,
    replaces_key_id: Option<&str>,
) -> SenderKeyDistributionMessage {
    let pub_key = sk.signing_key.verifying_key();
    SenderKeyDistributionMessage {
        msg_type: "skdm".to_string(),
        ch: channel_id.to_string(),
        skid: sender_key_fingerprint(&pub_key),
        ck: BASE64.encode(sk.chain_key),
        spk: BASE64.encode(pub_key.as_bytes()),
        iter: sk.iteration,
        rep: replaces_key_id.map(|s| s.to_string()),
    }
}

/// Parse a distribution message and create a SenderKeyPublic + State from it.
pub fn parse_distribution_message(
    msg: &SenderKeyDistributionMessage,
) -> Result<(SenderKeyPublic, SenderKeyState)> {
    let chain_key_bytes = BASE64.decode(&msg.ck)?;
    let spk_bytes = BASE64.decode(&msg.spk)?;

    if chain_key_bytes.len() != 32 || spk_bytes.len() != 32 {
        return Err(SenderKeyError::InvalidKeyLength);
    }

    let mut chain_key = [0u8; 32];
    chain_key.copy_from_slice(&chain_key_bytes);

    let signing_pub_key = VerifyingKey::from_bytes(
        spk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SenderKeyError::InvalidKeyLength)?,
    )
    .map_err(|_| SenderKeyError::InvalidKeyLength)?;

    let pub_key = SenderKeyPublic {
        chain_key,
        signing_pub_key,
        iteration: msg.iter,
        sender_key_id: msg.skid.clone(),
    };

    let state = create_sender_key_state(pub_key.clone());
    Ok((pub_key, state))
}

// ---------------------------------------------------------------------------
// Envelope detection
// ---------------------------------------------------------------------------

/// Check if a message content string is a sender key envelope.
pub fn is_sender_key_envelope(content: &str) -> bool {
    serde_json::from_str::<SenderKeyEnvelope>(content)
        .map(|e| e.v == 1)
        .unwrap_or(false)
}

/// Parse a sender key envelope from a message content string.
pub fn parse_sender_key_envelope(content: &str) -> Result<SenderKeyEnvelope> {
    let envelope: SenderKeyEnvelope = serde_json::from_str(content)?;
    if envelope.v != 1 {
        return Err(SenderKeyError::UnknownVersion(envelope.v));
    }
    Ok(envelope)
}

// ---------------------------------------------------------------------------
// SenderKeyStore
// ---------------------------------------------------------------------------

/// Manages all sender keys for all channels.
pub struct SenderKeyStore {
    /// My own sender keys: channel_id → SenderKeyPrivate
    my_keys: HashMap<String, SenderKeyPrivate>,
    /// Peer sender key states: channel_id → (user_id → SenderKeyState)
    peer_keys: HashMap<String, HashMap<String, SenderKeyState>>,
}

impl SenderKeyStore {
    pub fn new() -> Self {
        Self {
            my_keys: HashMap::new(),
            peer_keys: HashMap::new(),
        }
    }

    // ── My keys ──

    /// Get or generate my sender key for a channel.
    pub fn get_or_create_my_key(&mut self, channel_id: &str) -> &SenderKeyPrivate {
        self.my_keys
            .entry(channel_id.to_string())
            .or_insert_with(generate_sender_key)
    }

    pub fn get_my_key(&self, channel_id: &str) -> Option<&SenderKeyPrivate> {
        self.my_keys.get(channel_id)
    }

    pub fn set_my_key(&mut self, channel_id: &str, sk: SenderKeyPrivate) {
        self.my_keys.insert(channel_id.to_string(), sk);
    }

    pub fn update_my_key(&mut self, channel_id: &str, updated: SenderKeyPrivate) {
        self.my_keys.insert(channel_id.to_string(), updated);
    }

    /// Rotate my key for a channel. Returns the new key.
    pub fn rotate_my_key(&mut self, channel_id: &str) -> &SenderKeyPrivate {
        let sk = generate_sender_key();
        self.my_keys.insert(channel_id.to_string(), sk);
        self.my_keys.get(channel_id).unwrap()
    }

    // ── Peer keys ──

    pub fn set_peer_key(&mut self, channel_id: &str, user_id: &str, state: SenderKeyState) {
        self.peer_keys
            .entry(channel_id.to_string())
            .or_default()
            .insert(user_id.to_string(), state);
    }

    pub fn get_peer_key(&self, channel_id: &str, user_id: &str) -> Option<&SenderKeyState> {
        self.peer_keys.get(channel_id)?.get(user_id)
    }

    pub fn update_peer_key(&mut self, channel_id: &str, user_id: &str, state: SenderKeyState) {
        self.set_peer_key(channel_id, user_id, state);
    }

    pub fn remove_peer_key(&mut self, channel_id: &str, user_id: &str) {
        if let Some(peers) = self.peer_keys.get_mut(channel_id) {
            peers.remove(user_id);
        }
    }

    pub fn clear_channel_peer_keys(&mut self, channel_id: &str) {
        self.peer_keys.remove(channel_id);
    }

    pub fn has_channel_keys(&self, channel_id: &str) -> bool {
        self.my_keys.contains_key(channel_id)
    }

    pub fn has_peer_key(&self, channel_id: &str, user_id: &str) -> bool {
        self.peer_keys
            .get(channel_id)
            .map(|p| p.contains_key(user_id))
            .unwrap_or(false)
    }
}

impl Default for SenderKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// High-level encrypt/decrypt
// ---------------------------------------------------------------------------

/// Encrypt a channel message. Returns JSON envelope string.
pub fn encrypt_channel_message(
    store: &mut SenderKeyStore,
    channel_id: &str,
    plaintext: &str,
) -> Result<String> {
    let sk = store.get_or_create_my_key(channel_id).clone();
    let (envelope, updated) = sender_key_encrypt(&sk, plaintext.as_bytes())?;
    store.update_my_key(channel_id, updated);
    Ok(serde_json::to_string(&envelope)?)
}

/// Decrypt a channel message from a sender key envelope string.
pub fn decrypt_channel_message(
    store: &mut SenderKeyStore,
    channel_id: &str,
    sender_id: &str,
    envelope_str: &str,
) -> Result<String> {
    let envelope = parse_sender_key_envelope(envelope_str)?;
    let state = store
        .get_peer_key(channel_id, sender_id)
        .ok_or_else(|| SenderKeyError::NoSenderKey {
            user_id: sender_id.to_string(),
            channel_id: channel_id.to_string(),
        })?
        .clone();
    let (plaintext, updated_state) = sender_key_decrypt(&state, &envelope)?;
    store.update_peer_key(channel_id, sender_id, updated_state);
    String::from_utf8(plaintext).map_err(|e| SenderKeyError::Decryption(e.to_string()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_fingerprint() {
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        assert_eq!(pub_key.sender_key_id.len(), 16); // 8 bytes hex = 16 chars
        assert_eq!(pub_key.iteration, 0);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let sender_sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sender_sk);
        let receiver_state = create_sender_key_state(pub_key);

        let plaintext = b"hello, world!";
        let (envelope, _updated_sk) = sender_key_encrypt(&sender_sk, plaintext).unwrap();

        let (decrypted, _updated_state) = sender_key_decrypt(&receiver_state, &envelope).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chain_ratchet_advances() {
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let mut state = create_sender_key_state(pub_key);

        let (env1, sk) = sender_key_encrypt(&sk, b"msg1").unwrap();
        let (env2, sk) = sender_key_encrypt(&sk, b"msg2").unwrap();
        let (env3, _sk) = sender_key_encrypt(&sk, b"msg3").unwrap();

        assert_eq!(env1.i, 0);
        assert_eq!(env2.i, 1);
        assert_eq!(env3.i, 2);

        let (p1, new_state) = sender_key_decrypt(&state, &env1).unwrap();
        state = new_state;
        let (p2, new_state) = sender_key_decrypt(&state, &env2).unwrap();
        state = new_state;
        let (p3, _) = sender_key_decrypt(&state, &env3).unwrap();

        assert_eq!(p1, b"msg1");
        assert_eq!(p2, b"msg2");
        assert_eq!(p3, b"msg3");
    }

    #[test]
    fn test_out_of_order_messages() {
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let state = create_sender_key_state(pub_key);

        let (env0, sk) = sender_key_encrypt(&sk, b"msg0").unwrap();
        let (env1, sk) = sender_key_encrypt(&sk, b"msg1").unwrap();
        let (env2, _) = sender_key_encrypt(&sk, b"msg2").unwrap();

        // Receive out of order: 2, 0, 1
        let (p2, state) = sender_key_decrypt(&state, &env2).unwrap();
        assert_eq!(p2, b"msg2");

        let (p0, state) = sender_key_decrypt(&state, &env0).unwrap();
        assert_eq!(p0, b"msg0");

        let (p1, _) = sender_key_decrypt(&state, &env1).unwrap();
        assert_eq!(p1, b"msg1");
    }

    #[test]
    fn test_signature_verification_fails_on_tamper() {
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let state = create_sender_key_state(pub_key);

        let (mut envelope, _) = sender_key_encrypt(&sk, b"hello").unwrap();
        // Tamper with ciphertext
        envelope.ct = BASE64.encode(b"tampered");

        let result = sender_key_decrypt(&state, &envelope);
        assert!(result.is_err());
    }

    #[test]
    fn test_distribution_message_roundtrip() {
        let sk = generate_sender_key();
        let dist = build_distribution_message("channel-123", &sk, None);

        assert_eq!(dist.msg_type, "skdm");
        assert_eq!(dist.ch, "channel-123");
        assert!(dist.rep.is_none());

        let (pub_key, state) = parse_distribution_message(&dist).unwrap();
        assert_eq!(pub_key.sender_key_id, dist.skid);
        assert_eq!(state.current_iteration, sk.iteration);

        // Should be able to decrypt messages from the original key
        let (envelope, _) = sender_key_encrypt(&sk, b"test").unwrap();
        let (plaintext, _) = sender_key_decrypt(&state, &envelope).unwrap();
        assert_eq!(plaintext, b"test");
    }

    #[test]
    fn test_envelope_json_format() {
        let sk = generate_sender_key();
        let (envelope, _) = sender_key_encrypt(&sk, b"hello").unwrap();
        let json = serde_json::to_string(&envelope).unwrap();

        // Verify JSON has the right fields
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["v"], 1);
        assert!(parsed["sk"].is_string());
        assert!(parsed["i"].is_number());
        assert!(parsed["iv"].is_string());
        assert!(parsed["ct"].is_string());
        assert!(parsed["sig"].is_string());

        // Round-trip through string
        assert!(is_sender_key_envelope(&json));
        let parsed_env = parse_sender_key_envelope(&json).unwrap();
        assert_eq!(parsed_env.v, envelope.v);
        assert_eq!(parsed_env.sk, envelope.sk);
        assert_eq!(parsed_env.i, envelope.i);
    }

    #[test]
    fn test_store_encrypt_decrypt() {
        let mut sender_store = SenderKeyStore::new();
        let mut receiver_store = SenderKeyStore::new();

        let channel = "ch-1";
        let sender_id = "alice";

        // Sender creates key and distributes
        let sk = sender_store.get_or_create_my_key(channel).clone();
        let dist = build_distribution_message(channel, &sk, None);
        let (_, state) = parse_distribution_message(&dist).unwrap();
        receiver_store.set_peer_key(channel, sender_id, state);

        // Encrypt and decrypt via high-level API
        let envelope_str =
            encrypt_channel_message(&mut sender_store, channel, "hello accord").unwrap();
        let plaintext =
            decrypt_channel_message(&mut receiver_store, channel, sender_id, &envelope_str)
                .unwrap();
        assert_eq!(plaintext, "hello accord");
    }

    #[test]
    fn test_too_many_skipped() {
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let state = create_sender_key_state(pub_key);

        // Forge an envelope with iteration way ahead
        let (mut envelope, _) = sender_key_encrypt(&sk, b"x").unwrap();
        envelope.i = MAX_SKIP + 1;

        let result = sender_key_decrypt(&state, &envelope);
        assert!(matches!(result, Err(SenderKeyError::TooManySkipped(_))));
    }

    // ─── NEW TESTS: Edge Cases ──────────────────────────────────────────────

    #[test]
    fn test_encrypt_empty_message() {
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let state = create_sender_key_state(pub_key);

        let (envelope, _) = sender_key_encrypt(&sk, b"").unwrap();
        let (plaintext, _) = sender_key_decrypt(&state, &envelope).unwrap();
        assert_eq!(plaintext, b"");
    }

    #[test]
    fn test_encrypt_single_byte() {
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let state = create_sender_key_state(pub_key);

        let (envelope, _) = sender_key_encrypt(&sk, b"A").unwrap();
        let (plaintext, _) = sender_key_decrypt(&state, &envelope).unwrap();
        assert_eq!(plaintext, b"A");
    }

    #[test]
    fn test_encrypt_large_message() {
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let state = create_sender_key_state(pub_key);

        let large_msg = vec![0xCD; 100 * 1024]; // 100KB
        let (envelope, _) = sender_key_encrypt(&sk, &large_msg).unwrap();
        let (plaintext, _) = sender_key_decrypt(&state, &envelope).unwrap();
        assert_eq!(plaintext, large_msg);
    }

    #[test]
    fn test_repeated_encryption_different_ciphertexts() {
        let sk = generate_sender_key();
        let (env1, sk) = sender_key_encrypt(&sk, b"same").unwrap();
        let (env2, _) = sender_key_encrypt(&sk, b"same").unwrap();

        // Same plaintext should produce different ciphertexts (different IV)
        assert_ne!(env1.ct, env2.ct);
        assert_ne!(env1.iv, env2.iv);
    }

    #[test]
    fn test_iteration_starts_at_zero() {
        let sk = generate_sender_key();
        assert_eq!(sk.iteration, 0);
        let (envelope, _) = sender_key_encrypt(&sk, b"test").unwrap();
        assert_eq!(envelope.i, 0);
    }

    #[test]
    fn test_iteration_increments() {
        let sk = generate_sender_key();
        let (env0, sk) = sender_key_encrypt(&sk, b"0").unwrap();
        let (env1, sk) = sender_key_encrypt(&sk, b"1").unwrap();
        let (env2, sk) = sender_key_encrypt(&sk, b"2").unwrap();
        let (env3, _) = sender_key_encrypt(&sk, b"3").unwrap();

        assert_eq!(env0.i, 0);
        assert_eq!(env1.i, 1);
        assert_eq!(env2.i, 2);
        assert_eq!(env3.i, 3);
    }

    // ─── NEW TESTS: Error Paths ─────────────────────────────────────────────

    #[test]
    fn test_wrong_signature_key_fails() {
        let sk1 = generate_sender_key();
        let sk2 = generate_sender_key();
        let pub_key2 = sender_key_to_public(&sk2);
        let state = create_sender_key_state(pub_key2);

        // Encrypt with sk1, try to decrypt with sk2's state
        let (envelope, _) = sender_key_encrypt(&sk1, b"secret").unwrap();
        let result = sender_key_decrypt(&state, &envelope);
        assert!(matches!(result, Err(SenderKeyError::SignatureVerification)));
    }

    #[test]
    fn test_tampered_iv_fails() {
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let state = create_sender_key_state(pub_key);

        let (mut envelope, _) = sender_key_encrypt(&sk, b"data").unwrap();
        // Tamper with IV
        envelope.iv = BASE64.encode(b"fakefakefake");

        let result = sender_key_decrypt(&state, &envelope);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_signature_fails() {
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let state = create_sender_key_state(pub_key);

        let (mut envelope, _) = sender_key_encrypt(&sk, b"data").unwrap();
        // Replace signature with garbage
        envelope.sig = BASE64.encode(&[0u8; 64]);

        let result = sender_key_decrypt(&state, &envelope);
        assert!(matches!(result, Err(SenderKeyError::SignatureVerification)));
    }

    #[test]
    fn test_unknown_version_fails() {
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let state = create_sender_key_state(pub_key);

        let (mut envelope, _) = sender_key_encrypt(&sk, b"test").unwrap();
        envelope.v = 99; // Unknown version

        let result = sender_key_decrypt(&state, &envelope);
        assert!(matches!(result, Err(SenderKeyError::UnknownVersion(99))));
    }

    #[test]
    fn test_invalid_base64_iv_fails() {
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let state = create_sender_key_state(pub_key);

        let (mut envelope, _) = sender_key_encrypt(&sk, b"test").unwrap();
        envelope.iv = "!!!invalid-base64!!!".to_string();

        let result = sender_key_decrypt(&state, &envelope);
        assert!(matches!(result, Err(SenderKeyError::Base64(_))));
    }

    // ─── NEW TESTS: Chain Advancement ───────────────────────────────────────

    #[test]
    fn test_chain_key_advances() {
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let mut state = create_sender_key_state(pub_key);

        let initial_chain_key = state.current_chain_key;

        let (env, _) = sender_key_encrypt(&sk, b"msg").unwrap();
        let (_, new_state) = sender_key_decrypt(&state, &env).unwrap();
        state = new_state;

        // Chain key should have advanced
        assert_ne!(state.current_chain_key, initial_chain_key);
    }

    #[test]
    fn test_chain_iteration_advances() {
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let mut state = create_sender_key_state(pub_key);

        assert_eq!(state.current_iteration, 0);

        let (env, _) = sender_key_encrypt(&sk, b"msg").unwrap();
        let (_, new_state) = sender_key_decrypt(&state, &env).unwrap();
        state = new_state;

        assert_eq!(state.current_iteration, 1);
    }

    #[test]
    fn test_100_sequential_messages() {
        let mut sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let mut state = create_sender_key_state(pub_key);

        for i in 0..100 {
            let (env, new_sk) = sender_key_encrypt(&sk, format!("msg{}", i).as_bytes()).unwrap();
            sk = new_sk;
            let (plaintext, new_state) = sender_key_decrypt(&state, &env).unwrap();
            state = new_state;
            assert_eq!(plaintext, format!("msg{}", i).as_bytes());
        }
    }

    // ─── NEW TESTS: Out-of-Order Delivery ───────────────────────────────────

    #[test]
    fn test_receive_out_of_order_complex() {
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let mut state = create_sender_key_state(pub_key);

        let (env0, sk) = sender_key_encrypt(&sk, b"0").unwrap();
        let (env1, sk) = sender_key_encrypt(&sk, b"1").unwrap();
        let (env2, sk) = sender_key_encrypt(&sk, b"2").unwrap();
        let (env3, sk) = sender_key_encrypt(&sk, b"3").unwrap();
        let (env4, _) = sender_key_encrypt(&sk, b"4").unwrap();

        // Receive: 3, 1, 4, 0, 2
        let (p3, new_state) = sender_key_decrypt(&state, &env3).unwrap();
        state = new_state;
        assert_eq!(p3, b"3");

        let (p1, new_state) = sender_key_decrypt(&state, &env1).unwrap();
        state = new_state;
        assert_eq!(p1, b"1");

        let (p4, new_state) = sender_key_decrypt(&state, &env4).unwrap();
        state = new_state;
        assert_eq!(p4, b"4");

        let (p0, new_state) = sender_key_decrypt(&state, &env0).unwrap();
        state = new_state;
        assert_eq!(p0, b"0");

        let (p2, _) = sender_key_decrypt(&state, &env2).unwrap();
        assert_eq!(p2, b"2");
    }

    #[test]
    fn test_receive_only_last_message() {
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let state = create_sender_key_state(pub_key);

        // Send 10 messages but only receive the last one
        let mut last_env = None;
        let mut sk = sk;
        for _ in 0..10 {
            let (env, new_sk) = sender_key_encrypt(&sk, b"skip").unwrap();
            sk = new_sk;
            last_env = Some(env);
        }

        let (plaintext, _) = sender_key_decrypt(&state, &last_env.unwrap()).unwrap();
        assert_eq!(plaintext, b"skip");
    }

    #[test]
    fn test_skipped_keys_are_cached() {
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let state = create_sender_key_state(pub_key);

        let (env0, sk) = sender_key_encrypt(&sk, b"0").unwrap();
        let (env1, sk) = sender_key_encrypt(&sk, b"1").unwrap();
        let (env2, _) = sender_key_encrypt(&sk, b"2").unwrap();

        // Receive env2 first, should cache keys for 0 and 1
        let (_, state) = sender_key_decrypt(&state, &env2).unwrap();
        assert_eq!(state.skipped_message_keys.len(), 2);

        // Now decrypt env0 and env1
        let (p0, state) = sender_key_decrypt(&state, &env0).unwrap();
        assert_eq!(p0, b"0");
        assert_eq!(state.skipped_message_keys.len(), 1); // env1 still cached

        let (p1, state) = sender_key_decrypt(&state, &env1).unwrap();
        assert_eq!(p1, b"1");
        assert_eq!(state.skipped_message_keys.len(), 0); // All cached keys used
    }

    #[test]
    fn test_duplicate_message_fails() {
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let state = create_sender_key_state(pub_key);

        let (env, _) = sender_key_encrypt(&sk, b"once").unwrap();

        // First decrypt succeeds
        let (p, state) = sender_key_decrypt(&state, &env).unwrap();
        assert_eq!(p, b"once");

        // Second decrypt should fail (key consumed)
        let result = sender_key_decrypt(&state, &env);
        assert!(matches!(result, Err(SenderKeyError::NoCachedKey(_))));
    }

    // ─── NEW TESTS: Serialization ───────────────────────────────────────────

    #[test]
    fn test_envelope_json_serialization() {
        let sk = generate_sender_key();
        let (envelope, _) = sender_key_encrypt(&sk, b"test").unwrap();

        let json = serde_json::to_string(&envelope).unwrap();
        let deserialized: SenderKeyEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(envelope.v, deserialized.v);
        assert_eq!(envelope.sk, deserialized.sk);
        assert_eq!(envelope.i, deserialized.i);
        assert_eq!(envelope.iv, deserialized.iv);
        assert_eq!(envelope.ct, deserialized.ct);
        assert_eq!(envelope.sig, deserialized.sig);
    }

    #[test]
    fn test_distribution_message_json_roundtrip() {
        let sk = generate_sender_key();
        let dist = build_distribution_message("ch-123", &sk, Some("old-key-id"));

        let json = serde_json::to_string(&dist).unwrap();
        let parsed: SenderKeyDistributionMessage = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.msg_type, "skdm");
        assert_eq!(parsed.ch, "ch-123");
        assert_eq!(parsed.rep, Some("old-key-id".to_string()));
    }

    #[test]
    fn test_parse_distribution_with_invalid_chain_key_length() {
        let mut dist = SenderKeyDistributionMessage {
            msg_type: "skdm".to_string(),
            ch: "ch-1".to_string(),
            skid: "fingerprint".to_string(),
            ck: BASE64.encode(&[0u8; 16]), // Wrong length (should be 32)
            spk: BASE64.encode(&[0u8; 32]),
            iter: 0,
            rep: None,
        };

        let result = parse_distribution_message(&dist);
        assert!(matches!(result, Err(SenderKeyError::InvalidKeyLength)));

        // Also test with signing key wrong length
        dist.ck = BASE64.encode(&[0u8; 32]);
        dist.spk = BASE64.encode(&[0u8; 16]); // Wrong length
        let result = parse_distribution_message(&dist);
        assert!(matches!(result, Err(SenderKeyError::InvalidKeyLength)));
    }

    // ─── NEW TESTS: SenderKeyStore ──────────────────────────────────────────

    #[test]
    fn test_store_get_or_create_creates_on_first_access() {
        let mut store = SenderKeyStore::new();
        assert!(!store.has_channel_keys("ch-1"));

        let _key = store.get_or_create_my_key("ch-1");
        assert!(store.has_channel_keys("ch-1"));
    }

    #[test]
    fn test_store_get_or_create_returns_same_key() {
        let mut store = SenderKeyStore::new();

        let key1 = store.get_or_create_my_key("ch-1");
        let fingerprint1 = sender_key_fingerprint(&key1.signing_key.verifying_key());

        let key2 = store.get_or_create_my_key("ch-1");
        let fingerprint2 = sender_key_fingerprint(&key2.signing_key.verifying_key());

        assert_eq!(fingerprint1, fingerprint2);
    }

    #[test]
    fn test_store_rotate_changes_key() {
        let mut store = SenderKeyStore::new();

        let old_key = store.get_or_create_my_key("ch-1");
        let old_fp = sender_key_fingerprint(&old_key.signing_key.verifying_key());

        let new_key = store.rotate_my_key("ch-1");
        let new_fp = sender_key_fingerprint(&new_key.signing_key.verifying_key());

        assert_ne!(old_fp, new_fp);
    }

    #[test]
    fn test_store_set_and_get_peer_key() {
        let mut store = SenderKeyStore::new();
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let state = create_sender_key_state(pub_key);

        assert!(!store.has_peer_key("ch-1", "alice"));
        store.set_peer_key("ch-1", "alice", state.clone());
        assert!(store.has_peer_key("ch-1", "alice"));

        let retrieved = store.get_peer_key("ch-1", "alice").unwrap();
        assert_eq!(retrieved.current_iteration, state.current_iteration);
    }

    #[test]
    fn test_store_remove_peer_key() {
        let mut store = SenderKeyStore::new();
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        let state = create_sender_key_state(pub_key);

        store.set_peer_key("ch-1", "alice", state);
        assert!(store.has_peer_key("ch-1", "alice"));

        store.remove_peer_key("ch-1", "alice");
        assert!(!store.has_peer_key("ch-1", "alice"));
    }

    #[test]
    fn test_store_clear_channel_peer_keys() {
        let mut store = SenderKeyStore::new();
        let sk1 = generate_sender_key();
        let sk2 = generate_sender_key();
        let state1 = create_sender_key_state(sender_key_to_public(&sk1));
        let state2 = create_sender_key_state(sender_key_to_public(&sk2));

        store.set_peer_key("ch-1", "alice", state1);
        store.set_peer_key("ch-1", "bob", state2);
        assert!(store.has_peer_key("ch-1", "alice"));
        assert!(store.has_peer_key("ch-1", "bob"));

        store.clear_channel_peer_keys("ch-1");
        assert!(!store.has_peer_key("ch-1", "alice"));
        assert!(!store.has_peer_key("ch-1", "bob"));
    }

    #[test]
    fn test_encrypt_channel_message_creates_key_automatically() {
        let mut store = SenderKeyStore::new();
        assert!(!store.has_channel_keys("ch-1"));

        let _envelope = encrypt_channel_message(&mut store, "ch-1", "hello").unwrap();
        assert!(store.has_channel_keys("ch-1"));
    }

    #[test]
    fn test_decrypt_channel_message_without_peer_key_fails() {
        let mut store = SenderKeyStore::new();

        // Need a valid envelope JSON string, not just "{}"
        let sk = generate_sender_key();
        let (envelope, _) = sender_key_encrypt(&sk, b"test").unwrap();
        let envelope_str = serde_json::to_string(&envelope).unwrap();

        let result = decrypt_channel_message(&mut store, "ch-1", "alice", &envelope_str);
        assert!(matches!(result, Err(SenderKeyError::NoSenderKey { .. })));
    }

    #[test]
    fn test_store_full_roundtrip() {
        let mut sender_store = SenderKeyStore::new();
        let mut receiver_store = SenderKeyStore::new();

        let channel = "general";
        let sender_id = "alice";

        // Sender creates key and distributes
        let sk = sender_store.get_or_create_my_key(channel).clone();
        let dist = build_distribution_message(channel, &sk, None);
        let (_, state) = parse_distribution_message(&dist).unwrap();
        receiver_store.set_peer_key(channel, sender_id, state);

        // Send multiple messages
        for i in 0..10 {
            let msg = format!("Message {}", i);
            let envelope = encrypt_channel_message(&mut sender_store, channel, &msg).unwrap();
            let plaintext =
                decrypt_channel_message(&mut receiver_store, channel, sender_id, &envelope)
                    .unwrap();
            assert_eq!(plaintext, msg);
        }
    }

    // ─── NEW TESTS: Envelope Detection ──────────────────────────────────────

    #[test]
    fn test_is_sender_key_envelope_valid() {
        let sk = generate_sender_key();
        let (envelope, _) = sender_key_encrypt(&sk, b"test").unwrap();
        let json = serde_json::to_string(&envelope).unwrap();

        assert!(is_sender_key_envelope(&json));
    }

    #[test]
    fn test_is_sender_key_envelope_invalid_json() {
        assert!(!is_sender_key_envelope("not json"));
        assert!(!is_sender_key_envelope("{\"wrong\": \"fields\"}"));
    }

    #[test]
    fn test_is_sender_key_envelope_wrong_version() {
        let json = r#"{"v":2,"sk":"abc","i":0,"iv":"xyz","ct":"def","sig":"ghi"}"#;
        assert!(!is_sender_key_envelope(json));
    }

    #[test]
    fn test_parse_sender_key_envelope_valid() {
        let sk = generate_sender_key();
        let (envelope, _) = sender_key_encrypt(&sk, b"test").unwrap();
        let json = serde_json::to_string(&envelope).unwrap();

        let parsed = parse_sender_key_envelope(&json).unwrap();
        assert_eq!(parsed.v, 1);
    }

    #[test]
    fn test_parse_sender_key_envelope_wrong_version() {
        let json = r#"{"v":99,"sk":"abc","i":0,"iv":"xyz","ct":"def","sig":"ghi"}"#;
        let result = parse_sender_key_envelope(json);
        assert!(matches!(result, Err(SenderKeyError::UnknownVersion(99))));
    }

    // ─── NEW TESTS: Fingerprinting ──────────────────────────────────────────

    #[test]
    fn test_sender_key_fingerprint_length() {
        let sk = generate_sender_key();
        let pub_key = sender_key_to_public(&sk);
        assert_eq!(pub_key.sender_key_id.len(), 16); // 8 bytes hex = 16 chars
    }

    #[test]
    fn test_different_keys_different_fingerprints() {
        let sk1 = generate_sender_key();
        let sk2 = generate_sender_key();
        let fp1 = sender_key_fingerprint(&sk1.signing_key.verifying_key());
        let fp2 = sender_key_fingerprint(&sk2.signing_key.verifying_key());
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_same_key_same_fingerprint() {
        let sk = generate_sender_key();
        let fp1 = sender_key_fingerprint(&sk.signing_key.verifying_key());
        let fp2 = sender_key_fingerprint(&sk.signing_key.verifying_key());
        assert_eq!(fp1, fp2);
    }
}
