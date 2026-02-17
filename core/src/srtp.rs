//! # SRTP Voice Encryption
//!
//! Implements SRTP-style encryption for real-time voice packets.
//!
//! - AES-128-CTR for payload encryption
//! - HMAC-SHA1 (truncated to 80 bits) for authentication
//! - HKDF-based key derivation from session keys
//! - Replay protection via 128-bit sliding window
//! - Automatic key rotation

use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::{bail, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
type HmacSha1 = Hmac<Sha1>;

/// SRTP authentication tag length (80 bits = 10 bytes, per RFC 3711)
const AUTH_TAG_LEN: usize = 10;

/// Default key rotation threshold (packets)
const KEY_ROTATION_PACKET_THRESHOLD: u64 = 10_000;

/// Default key rotation threshold (seconds)
const KEY_ROTATION_TIME_THRESHOLD_SECS: u64 = 30;

/// SRTP header size: SSRC(4) + sequence(2) + timestamp(4) = 10 bytes
const SRTP_HEADER_LEN: usize = 10;

/// Replay window size in bits
const REPLAY_WINDOW_SIZE: u64 = 128;

/// Derived SRTP key material from a shared secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SrtpKeyMaterial {
    /// AES-128 cipher key (16 bytes)
    cipher_key: [u8; 16],
    /// SRTP cipher salt (14 bytes)
    cipher_salt: [u8; 14],
    /// HMAC-SHA1 auth key (20 bytes)
    auth_key: [u8; 20],
}

/// Voice session key derived from a Double Ratchet session.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VoiceSessionKey {
    /// Raw key material (32 bytes from HKDF)
    key_material: [u8; 32],
}

impl VoiceSessionKey {
    /// Derive a voice-specific key from a session key and channel ID.
    ///
    /// `HKDF(session_key, "accord-voice-v1", channel_id_bytes)`
    pub fn derive(session_key: &[u8; 32], channel_id: &[u8; 16]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(channel_id), session_key);
        let mut key_material = [0u8; 32];
        hk.expand(b"accord-voice-v1", &mut key_material)
            .expect("HKDF expand for voice session key");
        Self { key_material }
    }

    /// Derive SRTP key material (cipher key, salt, auth key) from this voice key
    /// with a generation counter for key rotation.
    pub fn derive_srtp_keys(&self, generation: u32) -> SrtpKeyMaterial {
        let mut info = Vec::with_capacity(23);
        info.extend_from_slice(b"accord-srtp-keys-v1");
        info.extend_from_slice(&generation.to_be_bytes());

        let hk = Hkdf::<Sha256>::new(None, &self.key_material);
        let mut okm = [0u8; 50]; // 16 + 14 + 20
        hk.expand(&info, &mut okm)
            .expect("HKDF expand for SRTP keys");

        let mut cipher_key = [0u8; 16];
        let mut cipher_salt = [0u8; 14];
        let mut auth_key = [0u8; 20];
        cipher_key.copy_from_slice(&okm[..16]);
        cipher_salt.copy_from_slice(&okm[16..30]);
        auth_key.copy_from_slice(&okm[30..50]);

        SrtpKeyMaterial {
            cipher_key,
            cipher_salt,
            auth_key,
        }
    }

    /// Get raw key material (for wrapping/distribution in group voice).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key_material
    }

    /// Construct from raw bytes (after unwrapping a group key).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            key_material: bytes,
        }
    }
}

/// An encrypted SRTP voice packet on the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SrtpPacket {
    /// Synchronization source identifier
    pub ssrc: u32,
    /// 16-bit sequence number (wraps)
    pub sequence: u16,
    /// RTP timestamp
    pub timestamp: u32,
    /// Encrypted payload (AES-128-CTR)
    pub payload: Vec<u8>,
    /// HMAC-SHA1 authentication tag (10 bytes)
    pub auth_tag: [u8; AUTH_TAG_LEN],
    /// Key generation (for key rotation)
    pub key_generation: u32,
}

/// Replay protection state using a sliding window.
pub struct ReplayProtection {
    /// Whether we've received any packet yet
    initialized: bool,
    /// Highest sequence index seen so far
    highest_seq: u64,
    /// Bitmask for the window (bit i = highest_seq - i - 1 was seen)
    window: u128,
}

impl Default for ReplayProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayProtection {
    pub fn new() -> Self {
        Self {
            initialized: false,
            highest_seq: 0,
            window: 0,
        }
    }

    /// Check if a packet with this extended sequence number is acceptable.
    /// Returns true if it's new (not a replay), false if duplicate/too old.
    pub fn check_and_update(&mut self, seq_index: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.highest_seq = seq_index;
            return true;
        }

        if seq_index > self.highest_seq {
            let shift = seq_index - self.highest_seq;
            if shift < REPLAY_WINDOW_SIZE {
                self.window = self.window.checked_shl(shift as u32).unwrap_or(0);
                // Mark the old highest as seen in the window
                self.window |= 1 << (shift - 1);
            } else {
                self.window = 0;
            }
            self.highest_seq = seq_index;
            true
        } else if seq_index == self.highest_seq {
            // Duplicate of the highest
            false
        } else {
            let delta = self.highest_seq - seq_index;
            if delta > REPLAY_WINDOW_SIZE {
                // Too old
                false
            } else {
                let bit = 1u128 << (delta - 1);
                if self.window & bit != 0 {
                    // Already seen
                    false
                } else {
                    self.window |= bit;
                    true
                }
            }
        }
    }
}

/// Encrypts outgoing voice packets for a single SSRC stream.
pub struct VoiceEncryptor {
    ssrc: u32,
    keys: SrtpKeyMaterial,
    voice_key: VoiceSessionKey,
    sequence: u16,
    roc: u32, // rollover counter
    timestamp: u32,
    key_generation: u32,
    packets_since_rotation: u64,
    last_rotation_time: std::time::Instant,
}

impl VoiceEncryptor {
    /// Create a new encryptor for a given SSRC and voice session key.
    pub fn new(ssrc: u32, voice_key: VoiceSessionKey) -> Self {
        let key_generation = 0;
        let keys = voice_key.derive_srtp_keys(key_generation);
        Self {
            ssrc,
            keys,
            voice_key,
            sequence: 0,
            roc: 0,
            timestamp: 0,
            key_generation,
            packets_since_rotation: 0,
            last_rotation_time: std::time::Instant::now(),
        }
    }

    /// Encrypt an RTP audio payload into an SRTP packet.
    pub fn encrypt_packet(&mut self, rtp_payload: &[u8]) -> Result<SrtpPacket> {
        self.maybe_rotate_key();

        let seq = self.sequence;
        let ts = self.timestamp;

        // Build IV per RFC 3711: ssrc XOR'd into salt, then counter from seq+roc
        let iv = self.build_iv(seq, self.roc);

        // Encrypt payload with AES-128-CTR
        let mut encrypted = rtp_payload.to_vec();
        let mut cipher = Aes128Ctr::new(self.keys.cipher_key.as_ref().into(), iv.as_ref().into());
        cipher.apply_keystream(&mut encrypted);

        // Build authenticated portion: header || encrypted payload
        let header_bytes = self.build_header_bytes(seq, ts);
        let auth_tag = self.compute_auth_tag(&header_bytes, &encrypted, self.roc);

        let packet = SrtpPacket {
            ssrc: self.ssrc,
            sequence: seq,
            timestamp: ts,
            payload: encrypted,
            auth_tag,
            key_generation: self.key_generation,
        };

        // Advance sequence (with rollover)
        self.sequence = self.sequence.wrapping_add(1);
        if self.sequence == 0 {
            self.roc = self.roc.wrapping_add(1);
        }
        // Advance timestamp by one frame (960 samples at 48kHz/20ms)
        self.timestamp = self.timestamp.wrapping_add(960);
        self.packets_since_rotation += 1;

        Ok(packet)
    }

    /// Force a key rotation (e.g., when signaled by the group).
    pub fn rotate_key(&mut self) {
        self.key_generation += 1;
        self.keys = self.voice_key.derive_srtp_keys(self.key_generation);
        self.packets_since_rotation = 0;
        self.last_rotation_time = std::time::Instant::now();
    }

    /// Current key generation.
    pub fn key_generation(&self) -> u32 {
        self.key_generation
    }

    fn maybe_rotate_key(&mut self) {
        if self.packets_since_rotation >= KEY_ROTATION_PACKET_THRESHOLD
            || self.last_rotation_time.elapsed().as_secs() >= KEY_ROTATION_TIME_THRESHOLD_SECS
        {
            self.rotate_key();
        }
    }

    fn build_iv(&self, seq: u16, roc: u32) -> [u8; 16] {
        // IV construction per RFC 3711 §4.1.1
        // 16 bytes: 0x00 || ssrc(4) || roc(4) || seq(2) || 0x0000 padded, XOR with salt
        let mut iv = [0u8; 16];
        iv[2..6].copy_from_slice(&self.ssrc.to_be_bytes());
        iv[6..10].copy_from_slice(&roc.to_be_bytes());
        iv[10..12].copy_from_slice(&seq.to_be_bytes());
        // XOR with salt (14 bytes, applied to iv[2..16])
        for i in 0..14 {
            iv[i + 2] ^= self.keys.cipher_salt[i];
        }
        iv
    }

    fn build_header_bytes(&self, seq: u16, ts: u32) -> [u8; SRTP_HEADER_LEN] {
        let mut hdr = [0u8; SRTP_HEADER_LEN];
        hdr[0..4].copy_from_slice(&self.ssrc.to_be_bytes());
        hdr[4..6].copy_from_slice(&seq.to_be_bytes());
        hdr[6..10].copy_from_slice(&ts.to_be_bytes());
        hdr
    }

    fn compute_auth_tag(
        &self,
        header: &[u8],
        encrypted_payload: &[u8],
        roc: u32,
    ) -> [u8; AUTH_TAG_LEN] {
        let mut mac =
            HmacSha1::new_from_slice(&self.keys.auth_key).expect("HMAC key length is valid");
        mac.update(header);
        mac.update(encrypted_payload);
        mac.update(&roc.to_be_bytes());
        let result = mac.finalize().into_bytes();
        let mut tag = [0u8; AUTH_TAG_LEN];
        tag.copy_from_slice(&result[..AUTH_TAG_LEN]);
        tag
    }
}

/// Decrypts incoming SRTP voice packets from a single remote SSRC.
pub struct VoiceDecryptor {
    ssrc: u32,
    voice_key: VoiceSessionKey,
    /// Current key material (derived from key_generation)
    keys: SrtpKeyMaterial,
    current_key_generation: u32,
    /// Estimated ROC for the receiver
    roc: u32,
    highest_seq: u16,
    replay: ReplayProtection,
}

impl VoiceDecryptor {
    /// Create a new decryptor for a remote SSRC.
    pub fn new(ssrc: u32, voice_key: VoiceSessionKey) -> Self {
        let keys = voice_key.derive_srtp_keys(0);
        Self {
            ssrc,
            voice_key,
            keys,
            current_key_generation: 0,
            roc: 0,
            highest_seq: 0,
            replay: ReplayProtection::new(),
        }
    }

    /// Decrypt an SRTP packet, returning the plaintext RTP payload.
    pub fn decrypt_packet(&mut self, packet: &SrtpPacket) -> Result<Vec<u8>> {
        if packet.ssrc != self.ssrc {
            bail!("SSRC mismatch: expected {}, got {}", self.ssrc, packet.ssrc);
        }

        // Handle key rotation
        if packet.key_generation != self.current_key_generation {
            self.keys = self.voice_key.derive_srtp_keys(packet.key_generation);
            self.current_key_generation = packet.key_generation;
        }

        // Estimate ROC
        let (estimated_roc, seq_index) = self.estimate_roc(packet.sequence);

        // Replay check
        if !self.replay.check_and_update(seq_index) {
            bail!("Replay detected for sequence index {}", seq_index);
        }

        // Verify auth tag
        let header = self.build_header_bytes(packet.sequence, packet.timestamp);
        let expected_tag = self.compute_auth_tag(&header, &packet.payload, estimated_roc);
        if expected_tag != packet.auth_tag {
            bail!("Authentication tag mismatch");
        }

        // Decrypt payload
        let iv = self.build_iv(packet.sequence, estimated_roc);
        let mut decrypted = packet.payload.clone();
        let mut cipher = Aes128Ctr::new(self.keys.cipher_key.as_ref().into(), iv.as_ref().into());
        cipher.apply_keystream(&mut decrypted);

        // Update ROC tracking
        if seq_index > (self.roc as u64 * 65536 + self.highest_seq as u64) {
            self.roc = estimated_roc;
            self.highest_seq = packet.sequence;
        }

        Ok(decrypted)
    }

    fn estimate_roc(&self, seq: u16) -> (u32, u64) {
        // RFC 3711 §3.3.1 ROC estimation
        let roc = if !self.replay.initialized {
            // First packet
            0u32
        } else if seq < 0x8000 && self.highest_seq >= 0x8000 {
            // Sequence wrapped around
            self.roc.wrapping_add(1)
        } else if seq >= 0x8000 && self.highest_seq < 0x8000 && self.roc > 0 {
            self.roc.wrapping_sub(1)
        } else {
            self.roc
        };
        let seq_index = roc as u64 * 65536 + seq as u64;
        (roc, seq_index)
    }

    fn build_iv(&self, seq: u16, roc: u32) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv[2..6].copy_from_slice(&self.ssrc.to_be_bytes());
        iv[6..10].copy_from_slice(&roc.to_be_bytes());
        iv[10..12].copy_from_slice(&seq.to_be_bytes());
        for i in 0..14 {
            iv[i + 2] ^= self.keys.cipher_salt[i];
        }
        iv
    }

    fn build_header_bytes(&self, seq: u16, ts: u32) -> [u8; SRTP_HEADER_LEN] {
        let mut hdr = [0u8; SRTP_HEADER_LEN];
        hdr[0..4].copy_from_slice(&self.ssrc.to_be_bytes());
        hdr[4..6].copy_from_slice(&seq.to_be_bytes());
        hdr[6..10].copy_from_slice(&ts.to_be_bytes());
        hdr
    }

    fn compute_auth_tag(
        &self,
        header: &[u8],
        encrypted_payload: &[u8],
        roc: u32,
    ) -> [u8; AUTH_TAG_LEN] {
        let mut mac =
            HmacSha1::new_from_slice(&self.keys.auth_key).expect("HMAC key length is valid");
        mac.update(header);
        mac.update(encrypted_payload);
        mac.update(&roc.to_be_bytes());
        let result = mac.finalize().into_bytes();
        let mut tag = [0u8; AUTH_TAG_LEN];
        tag.copy_from_slice(&result[..AUTH_TAG_LEN]);
        tag
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_voice_key() -> VoiceSessionKey {
        let session_key = [42u8; 32];
        let channel_id = [1u8; 16];
        VoiceSessionKey::derive(&session_key, &channel_id)
    }

    #[test]
    fn test_voice_key_derivation() {
        let sk1 = [42u8; 32];
        let sk2 = [43u8; 32];
        let ch = [1u8; 16];

        let vk1 = VoiceSessionKey::derive(&sk1, &ch);
        let vk2 = VoiceSessionKey::derive(&sk2, &ch);
        let vk3 = VoiceSessionKey::derive(&sk1, &ch);

        // Different session keys produce different voice keys
        assert_ne!(vk1.key_material, vk2.key_material);
        // Same inputs produce same output (deterministic)
        assert_eq!(vk1.key_material, vk3.key_material);
    }

    #[test]
    fn test_srtp_encrypt_decrypt_roundtrip() {
        let voice_key = test_voice_key();
        let ssrc = 12345;

        let mut enc = VoiceEncryptor::new(ssrc, voice_key.clone());
        let mut dec = VoiceDecryptor::new(ssrc, voice_key);

        let payload = b"hello voice data 48khz opus frame";
        let packet = enc.encrypt_packet(payload).unwrap();

        // Encrypted payload differs from plaintext
        assert_ne!(&packet.payload, payload);

        let decrypted = dec.decrypt_packet(&packet).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_multiple_packets_roundtrip() {
        let voice_key = test_voice_key();
        let ssrc = 99;

        let mut enc = VoiceEncryptor::new(ssrc, voice_key.clone());
        let mut dec = VoiceDecryptor::new(ssrc, voice_key);

        for i in 0..100 {
            let payload = format!("packet-{}", i);
            let packet = enc.encrypt_packet(payload.as_bytes()).unwrap();
            let decrypted = dec.decrypt_packet(&packet).unwrap();
            assert_eq!(decrypted, payload.as_bytes());
        }
    }

    #[test]
    fn test_replay_protection_duplicate_rejected() {
        let voice_key = test_voice_key();
        let ssrc = 7;

        let mut enc = VoiceEncryptor::new(ssrc, voice_key.clone());
        let mut dec = VoiceDecryptor::new(ssrc, voice_key);

        let packet = enc.encrypt_packet(b"data").unwrap();
        assert!(dec.decrypt_packet(&packet).is_ok());
        // Replaying same packet must fail
        assert!(dec.decrypt_packet(&packet).is_err());
    }

    #[test]
    fn test_replay_protection_sliding_window() {
        let mut rp = ReplayProtection::new();

        // First packet
        assert!(rp.check_and_update(1));
        // Duplicate
        assert!(!rp.check_and_update(1));
        // New packet
        assert!(rp.check_and_update(2));
        // Jump ahead
        assert!(rp.check_and_update(100));
        // Old but within window
        assert!(rp.check_and_update(50));
        // Already seen
        assert!(!rp.check_and_update(50));
        // Seq 0 is within the 128-bit window from highest=100, so it's accepted
        assert!(rp.check_and_update(0));
        // But replaying it again fails
        assert!(!rp.check_and_update(0));
        // Something truly outside the window
        assert!(rp.check_and_update(300));
        assert!(!rp.check_and_update(100)); // now 300-100=200 > 128, too old
    }

    #[test]
    fn test_key_rotation() {
        let voice_key = test_voice_key();
        let ssrc = 42;

        let mut enc = VoiceEncryptor::new(ssrc, voice_key.clone());
        let mut dec = VoiceDecryptor::new(ssrc, voice_key);

        // Encrypt a packet with generation 0
        let pkt0 = enc.encrypt_packet(b"before rotation").unwrap();
        assert_eq!(pkt0.key_generation, 0);

        // Force rotation
        enc.rotate_key();
        assert_eq!(enc.key_generation(), 1);

        let pkt1 = enc.encrypt_packet(b"after rotation").unwrap();
        assert_eq!(pkt1.key_generation, 1);

        // Decryptor should handle both (process in order)
        let d0 = dec.decrypt_packet(&pkt0).unwrap();
        assert_eq!(d0, b"before rotation");

        let d1 = dec.decrypt_packet(&pkt1).unwrap();
        assert_eq!(d1, b"after rotation");
    }

    #[test]
    fn test_different_ssrc_streams_dont_interfere() {
        let voice_key = test_voice_key();

        let mut enc1 = VoiceEncryptor::new(100, voice_key.clone());
        let mut enc2 = VoiceEncryptor::new(200, voice_key.clone());
        let mut dec1 = VoiceDecryptor::new(100, voice_key.clone());
        let mut dec2 = VoiceDecryptor::new(200, voice_key);

        let pkt1 = enc1.encrypt_packet(b"stream 1").unwrap();
        let pkt2 = enc2.encrypt_packet(b"stream 2").unwrap();

        // Correct decryptor works
        assert_eq!(dec1.decrypt_packet(&pkt1).unwrap(), b"stream 1");
        assert_eq!(dec2.decrypt_packet(&pkt2).unwrap(), b"stream 2");

        // Wrong SSRC decryptor fails
        let pkt1b = enc1.encrypt_packet(b"stream 1b").unwrap();
        assert!(dec2.decrypt_packet(&pkt1b).is_err());
    }

    #[test]
    fn test_auth_tag_tampering_detected() {
        let voice_key = test_voice_key();
        let ssrc = 55;

        let mut enc = VoiceEncryptor::new(ssrc, voice_key.clone());
        let mut dec = VoiceDecryptor::new(ssrc, voice_key);

        let mut packet = enc.encrypt_packet(b"sensitive audio").unwrap();
        // Tamper with auth tag
        packet.auth_tag[0] ^= 0xFF;

        assert!(dec.decrypt_packet(&packet).is_err());
    }

    #[test]
    fn test_payload_tampering_detected() {
        let voice_key = test_voice_key();
        let ssrc = 55;

        let mut enc = VoiceEncryptor::new(ssrc, voice_key.clone());
        let mut dec = VoiceDecryptor::new(ssrc, voice_key);

        let mut packet = enc.encrypt_packet(b"sensitive audio").unwrap();
        // Tamper with payload
        if !packet.payload.is_empty() {
            packet.payload[0] ^= 0xFF;
        }

        assert!(dec.decrypt_packet(&packet).is_err());
    }

    #[test]
    fn test_voice_session_key_zeroize() {
        let mut vk = VoiceSessionKey::from_bytes([99u8; 32]);
        assert_eq!(vk.key_material, [99u8; 32]);
        vk.zeroize();
        assert_eq!(vk.key_material, [0u8; 32]);
    }
}
