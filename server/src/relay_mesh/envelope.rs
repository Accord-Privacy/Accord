//! Signed mesh envelopes for relay-to-relay communication.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::identity::RelayIdentity;

/// The type of payload carried in a mesh envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadType {
    /// Encrypted DM being forwarded across relays.
    DmForward,
    /// Relay announcing itself to peers.
    RelayAnnounce,
    /// Keepalive ping.
    RelayPing,
}

/// A signed envelope for relay mesh communication.
///
/// The signature covers: from_relay_id | to_relay_id | payload_type | encrypted_payload | timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshEnvelope {
    pub from_relay_id: String,
    pub to_relay_id: String,
    pub payload_type: PayloadType,
    /// Opaque encrypted payload bytes (base64 for JSON serialization).
    #[serde(with = "base64_bytes")]
    pub encrypted_payload: Vec<u8>,
    /// Unix timestamp in seconds.
    pub timestamp: u64,
    /// Ed25519 signature over the canonical signing data.
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
}

impl MeshEnvelope {
    /// Build the canonical bytes that get signed.
    fn signing_data(
        from_relay_id: &str,
        to_relay_id: &str,
        payload_type: PayloadType,
        encrypted_payload: &[u8],
        timestamp: u64,
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(from_relay_id.as_bytes());
        hasher.update(b"|");
        hasher.update(to_relay_id.as_bytes());
        hasher.update(b"|");
        hasher.update(serde_json::to_string(&payload_type).unwrap().as_bytes());
        hasher.update(b"|");
        hasher.update(encrypted_payload);
        hasher.update(b"|");
        hasher.update(timestamp.to_le_bytes());
        hasher.finalize().to_vec()
    }

    /// Create and sign a new envelope.
    pub fn create_signed(
        identity: &RelayIdentity,
        to_relay_id: String,
        payload_type: PayloadType,
        encrypted_payload: Vec<u8>,
        timestamp: u64,
    ) -> Self {
        let data = Self::signing_data(
            identity.relay_id(),
            &to_relay_id,
            payload_type,
            &encrypted_payload,
            timestamp,
        );
        let sig = identity.sign(&data);

        Self {
            from_relay_id: identity.relay_id().to_string(),
            to_relay_id,
            payload_type,
            encrypted_payload,
            timestamp,
            signature: sig.to_bytes().to_vec(),
        }
    }

    /// Verify the envelope signature against a sender's public key.
    pub fn verify(&self, sender_public_key: &VerifyingKey) -> bool {
        let data = Self::signing_data(
            &self.from_relay_id,
            &self.to_relay_id,
            self.payload_type,
            &self.encrypted_payload,
            self.timestamp,
        );
        let sig_bytes: [u8; 64] = match self.signature.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let signature = Signature::from_bytes(&sig_bytes);
        RelayIdentity::verify_with_key(sender_public_key, &data, &signature)
    }
}

/// Serde helper for Vec<u8> ↔ base64 string.
mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_verify_envelope() {
        let sender = RelayIdentity::generate();
        let receiver = RelayIdentity::generate();

        let envelope = MeshEnvelope::create_signed(
            &sender,
            receiver.relay_id().to_string(),
            PayloadType::DmForward,
            b"encrypted-dm-data".to_vec(),
            1700000000,
        );

        assert_eq!(envelope.from_relay_id, sender.relay_id());
        assert_eq!(envelope.to_relay_id, receiver.relay_id());
        assert!(envelope.verify(sender.verifying_key()));
    }

    #[test]
    fn test_verify_fails_wrong_key() {
        let sender = RelayIdentity::generate();
        let other = RelayIdentity::generate();

        let envelope = MeshEnvelope::create_signed(
            &sender,
            "target".to_string(),
            PayloadType::RelayPing,
            vec![],
            1700000000,
        );

        assert!(!envelope.verify(other.verifying_key()));
    }

    #[test]
    fn test_verify_fails_tampered_payload() {
        let sender = RelayIdentity::generate();

        let mut envelope = MeshEnvelope::create_signed(
            &sender,
            "target".to_string(),
            PayloadType::RelayAnnounce,
            b"original".to_vec(),
            1700000000,
        );

        envelope.encrypted_payload = b"tampered".to_vec();
        assert!(!envelope.verify(sender.verifying_key()));
    }

    #[test]
    fn test_verify_fails_tampered_timestamp() {
        let sender = RelayIdentity::generate();

        let mut envelope = MeshEnvelope::create_signed(
            &sender,
            "target".to_string(),
            PayloadType::RelayPing,
            vec![],
            1700000000,
        );

        envelope.timestamp = 9999999999;
        assert!(!envelope.verify(sender.verifying_key()));
    }

    #[test]
    fn test_envelope_json_roundtrip() {
        let sender = RelayIdentity::generate();

        let envelope = MeshEnvelope::create_signed(
            &sender,
            "dest".to_string(),
            PayloadType::DmForward,
            b"secret".to_vec(),
            1700000000,
        );

        let json = serde_json::to_string(&envelope).unwrap();
        let decoded: MeshEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.from_relay_id, envelope.from_relay_id);
        assert!(decoded.verify(sender.verifying_key()));
    }

    #[test]
    fn test_all_payload_types() {
        let sender = RelayIdentity::generate();

        for pt in [
            PayloadType::DmForward,
            PayloadType::RelayAnnounce,
            PayloadType::RelayPing,
        ] {
            let env =
                MeshEnvelope::create_signed(&sender, "peer".to_string(), pt, vec![1, 2, 3], 42);
            assert!(env.verify(sender.verifying_key()));
        }
    }
}
