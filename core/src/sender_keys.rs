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
}
