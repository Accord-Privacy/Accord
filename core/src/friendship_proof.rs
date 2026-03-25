//! # Friendship Proof
//!
//! Cryptographic proof of friendship between two users, signed by both parties using Ed25519.
//! This proof can later be used for cross-relay DM routing.

use serde::{Deserialize, Serialize};
// sha2 will be used for canonical data hashing in future cross-relay routing

/// A cryptographic proof that two users are friends.
/// Both users sign the canonical friendship data with their Ed25519 keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendshipProof {
    /// SHA-256 hash of user A's public key (hex)
    pub user_a_public_key_hash: String,
    /// SHA-256 hash of user B's public key (hex)
    pub user_b_public_key_hash: String,
    /// Unix timestamp when the friendship was established
    pub established_at: u64,
    /// User A's Ed25519 signature over the canonical proof data
    pub signature_a: Vec<u8>,
    /// User B's Ed25519 signature over the canonical proof data
    pub signature_b: Vec<u8>,
}

/// A half-signed friendship proof (user A has signed, waiting for user B)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendshipProofRequest {
    pub user_a_public_key_hash: String,
    pub user_b_public_key_hash: String,
    pub established_at: u64,
    pub signature_a: Vec<u8>,
    /// User A's public key bytes (Ed25519, 32 bytes) needed for verification
    pub user_a_public_key: Vec<u8>,
}

impl FriendshipProof {
    /// Compute the canonical bytes that both parties sign.
    /// Format: "accord-friendship-v1" || user_a_hash || user_b_hash || established_at (BE)
    pub fn canonical_bytes(
        user_a_public_key_hash: &str,
        user_b_public_key_hash: &str,
        established_at: u64,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"accord-friendship-v1");
        data.extend_from_slice(user_a_public_key_hash.as_bytes());
        data.extend_from_slice(user_b_public_key_hash.as_bytes());
        data.extend_from_slice(&established_at.to_be_bytes());
        data
    }

    /// Serialize the proof to bytes (for storage)
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize a proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        bincode::deserialize(bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize proof: {}", e))
    }
}

/// Create the first half of a friendship proof (user A signs).
///
/// `signing_key_bytes` is the Ed25519 secret key (32 bytes seed or 64 bytes expanded).
/// Returns a `FriendshipProofRequest` that can be sent to user B.
pub fn create_proof_request(
    user_a_public_key_hash: &str,
    user_b_public_key_hash: &str,
    established_at: u64,
    signing_key_bytes: &[u8; 32],
    public_key_bytes: &[u8; 32],
) -> Result<FriendshipProofRequest, anyhow::Error> {
    use ring::signature::Ed25519KeyPair;

    // Build the Ed25519 keypair from seed
    let keypair = Ed25519KeyPair::from_seed_unchecked(signing_key_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid Ed25519 seed: {}", e))?;

    let canonical = FriendshipProof::canonical_bytes(
        user_a_public_key_hash,
        user_b_public_key_hash,
        established_at,
    );

    let signature = keypair.sign(&canonical);

    Ok(FriendshipProofRequest {
        user_a_public_key_hash: user_a_public_key_hash.to_string(),
        user_b_public_key_hash: user_b_public_key_hash.to_string(),
        established_at,
        signature_a: signature.as_ref().to_vec(),
        user_a_public_key: public_key_bytes.to_vec(),
    })
}

/// Complete a friendship proof (user B verifies A's signature and adds their own).
///
/// Returns the complete `FriendshipProof` with both signatures.
pub fn complete_proof(
    request: &FriendshipProofRequest,
    user_b_signing_key: &[u8; 32],
    _user_b_public_key: &[u8; 32],
) -> Result<FriendshipProof, anyhow::Error> {
    use ring::signature::{self, Ed25519KeyPair, UnparsedPublicKey};

    let canonical = FriendshipProof::canonical_bytes(
        &request.user_a_public_key_hash,
        &request.user_b_public_key_hash,
        request.established_at,
    );

    // Verify user A's signature first
    let user_a_pk = UnparsedPublicKey::new(&signature::ED25519, &request.user_a_public_key);
    user_a_pk
        .verify(&canonical, &request.signature_a)
        .map_err(|_| anyhow::anyhow!("User A's signature is invalid"))?;

    // Sign with user B's key
    let keypair_b = Ed25519KeyPair::from_seed_unchecked(user_b_signing_key)
        .map_err(|e| anyhow::anyhow!("Invalid Ed25519 seed for user B: {}", e))?;

    let signature_b = keypair_b.sign(&canonical);

    Ok(FriendshipProof {
        user_a_public_key_hash: request.user_a_public_key_hash.clone(),
        user_b_public_key_hash: request.user_b_public_key_hash.clone(),
        established_at: request.established_at,
        signature_a: request.signature_a.clone(),
        signature_b: signature_b.as_ref().to_vec(),
    })
}

/// Verify a complete friendship proof (both signatures valid).
pub fn verify_proof(
    proof: &FriendshipProof,
    user_a_public_key: &[u8],
    user_b_public_key: &[u8],
) -> Result<bool, anyhow::Error> {
    use ring::signature::{self, UnparsedPublicKey};

    let canonical = FriendshipProof::canonical_bytes(
        &proof.user_a_public_key_hash,
        &proof.user_b_public_key_hash,
        proof.established_at,
    );

    let pk_a = UnparsedPublicKey::new(&signature::ED25519, user_a_public_key);
    if pk_a.verify(&canonical, &proof.signature_a).is_err() {
        return Ok(false);
    }

    let pk_b = UnparsedPublicKey::new(&signature::ED25519, user_b_public_key);
    if pk_b.verify(&canonical, &proof.signature_b).is_err() {
        return Ok(false);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use sha2::{Digest, Sha256};

    fn gen_keypair() -> ([u8; 32], [u8; 32]) {
        let rng = ring::rand::SystemRandom::new();
        let seed: [u8; 32] = {
            let mut buf = [0u8; 32];
            ring::rand::SecureRandom::fill(&rng, &mut buf).unwrap();
            buf
        };
        let kp = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let pub_bytes: [u8; 32] = kp.public_key().as_ref().try_into().unwrap();
        (seed, pub_bytes)
    }

    #[test]
    fn test_friendship_proof_round_trip() {
        let (seed_a, pub_a) = gen_keypair();
        let (seed_b, pub_b) = gen_keypair();

        let hash_a = hex::encode(Sha256::digest(pub_a));
        let hash_b = hex::encode(Sha256::digest(pub_b));
        let now = 1700000000u64;

        let request = create_proof_request(&hash_a, &hash_b, now, &seed_a, &pub_a).unwrap();
        let proof = complete_proof(&request, &seed_b, &pub_b).unwrap();
        assert!(verify_proof(&proof, &pub_a, &pub_b).unwrap());
    }

    #[test]
    fn test_friendship_proof_bad_signature_rejected() {
        let (seed_a, pub_a) = gen_keypair();
        let (seed_b, pub_b) = gen_keypair();
        let (_seed_c, pub_c) = gen_keypair();

        let hash_a = hex::encode(Sha256::digest(pub_a));
        let hash_b = hex::encode(Sha256::digest(pub_b));

        let request = create_proof_request(&hash_a, &hash_b, 100, &seed_a, &pub_a).unwrap();
        let proof = complete_proof(&request, &seed_b, &pub_b).unwrap();

        // Wrong key for user A
        assert!(!verify_proof(&proof, &pub_c, &pub_b).unwrap());
        // Wrong key for user B
        assert!(!verify_proof(&proof, &pub_a, &pub_c).unwrap());
    }

    #[test]
    fn test_serialization_round_trip() {
        let (seed_a, pub_a) = gen_keypair();
        let (seed_b, pub_b) = gen_keypair();
        let hash_a = hex::encode(Sha256::digest(pub_a));
        let hash_b = hex::encode(Sha256::digest(pub_b));

        let request = create_proof_request(&hash_a, &hash_b, 42, &seed_a, &pub_a).unwrap();
        let proof = complete_proof(&request, &seed_b, &pub_b).unwrap();

        let bytes = proof.to_bytes();
        let decoded = FriendshipProof::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.user_a_public_key_hash, proof.user_a_public_key_hash);
        assert_eq!(decoded.signature_a, proof.signature_a);
    }

    #[test]
    fn test_canonical_bytes_deterministic() {
        let hash_a = "abc123";
        let hash_b = "def456";
        let timestamp = 1234567890u64;

        let bytes1 = FriendshipProof::canonical_bytes(hash_a, hash_b, timestamp);
        let bytes2 = FriendshipProof::canonical_bytes(hash_a, hash_b, timestamp);

        assert_eq!(bytes1, bytes2);
        assert!(bytes1.starts_with(b"accord-friendship-v1"));
    }

    #[test]
    fn test_canonical_bytes_different_order() {
        let hash_a = "user_a";
        let hash_b = "user_b";
        let timestamp = 100u64;

        let bytes_ab = FriendshipProof::canonical_bytes(hash_a, hash_b, timestamp);
        let bytes_ba = FriendshipProof::canonical_bytes(hash_b, hash_a, timestamp);

        // Different order should produce different bytes
        assert_ne!(bytes_ab, bytes_ba);
    }

    #[test]
    fn test_canonical_bytes_different_timestamps() {
        let hash_a = "hash_a";
        let hash_b = "hash_b";

        let bytes1 = FriendshipProof::canonical_bytes(hash_a, hash_b, 100);
        let bytes2 = FriendshipProof::canonical_bytes(hash_a, hash_b, 200);

        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_canonical_bytes_empty_hashes() {
        let bytes = FriendshipProof::canonical_bytes("", "", 0);
        assert!(bytes.starts_with(b"accord-friendship-v1"));
        assert_eq!(bytes.len(), b"accord-friendship-v1".len() + 8); // only version + timestamp
    }

    #[test]
    fn test_canonical_bytes_max_timestamp() {
        let bytes = FriendshipProof::canonical_bytes("a", "b", u64::MAX);
        assert!(bytes.ends_with(&u64::MAX.to_be_bytes()));
    }

    #[test]
    fn test_create_proof_request_with_invalid_seed() {
        let invalid_seed = [0u8; 32]; // All zeros may be valid, so we just test the function
        let hash_a = "hash_a";
        let hash_b = "hash_b";
        let pub_key = [1u8; 32];

        // This should succeed - Ed25519 accepts any 32-byte seed
        let result = create_proof_request(hash_a, hash_b, 100, &invalid_seed, &pub_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_proof_request_contains_correct_data() {
        let (seed_a, pub_a) = gen_keypair();
        let hash_a = "hash_alice";
        let hash_b = "hash_bob";
        let timestamp = 9999u64;

        let request = create_proof_request(hash_a, hash_b, timestamp, &seed_a, &pub_a).unwrap();

        assert_eq!(request.user_a_public_key_hash, hash_a);
        assert_eq!(request.user_b_public_key_hash, hash_b);
        assert_eq!(request.established_at, timestamp);
        assert_eq!(request.user_a_public_key, pub_a.to_vec());
        assert_eq!(request.signature_a.len(), 64); // Ed25519 signatures are 64 bytes
    }

    #[test]
    fn test_complete_proof_rejects_invalid_signature() {
        let (seed_a, pub_a) = gen_keypair();
        let (seed_b, pub_b) = gen_keypair();
        let hash_a = hex::encode(Sha256::digest(pub_a));
        let hash_b = hex::encode(Sha256::digest(pub_b));

        let mut request = create_proof_request(&hash_a, &hash_b, 100, &seed_a, &pub_a).unwrap();

        // Corrupt the signature
        request.signature_a[0] ^= 0xFF;

        let result = complete_proof(&request, &seed_b, &pub_b);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid"));
    }

    #[test]
    fn test_complete_proof_rejects_tampered_public_key() {
        let (seed_a, pub_a) = gen_keypair();
        let (seed_b, pub_b) = gen_keypair();
        let (_seed_c, pub_c) = gen_keypair();
        let hash_a = hex::encode(Sha256::digest(pub_a));
        let hash_b = hex::encode(Sha256::digest(pub_b));

        let mut request = create_proof_request(&hash_a, &hash_b, 100, &seed_a, &pub_a).unwrap();

        // Replace public key with wrong one
        request.user_a_public_key = pub_c.to_vec();

        let result = complete_proof(&request, &seed_b, &pub_b);
        assert!(result.is_err());
    }

    #[test]
    fn test_complete_proof_success() {
        let (seed_a, pub_a) = gen_keypair();
        let (seed_b, pub_b) = gen_keypair();
        let hash_a = hex::encode(Sha256::digest(pub_a));
        let hash_b = hex::encode(Sha256::digest(pub_b));

        let request = create_proof_request(&hash_a, &hash_b, 555, &seed_a, &pub_a).unwrap();
        let proof = complete_proof(&request, &seed_b, &pub_b).unwrap();

        assert_eq!(proof.user_a_public_key_hash, hash_a);
        assert_eq!(proof.user_b_public_key_hash, hash_b);
        assert_eq!(proof.established_at, 555);
        assert_eq!(proof.signature_a.len(), 64);
        assert_eq!(proof.signature_b.len(), 64);
    }

    #[test]
    fn test_verify_proof_with_swapped_keys() {
        let (seed_a, pub_a) = gen_keypair();
        let (seed_b, pub_b) = gen_keypair();
        let hash_a = hex::encode(Sha256::digest(pub_a));
        let hash_b = hex::encode(Sha256::digest(pub_b));

        let request = create_proof_request(&hash_a, &hash_b, 100, &seed_a, &pub_a).unwrap();
        let proof = complete_proof(&request, &seed_b, &pub_b).unwrap();

        // Swap the keys
        assert!(!verify_proof(&proof, &pub_b, &pub_a).unwrap());
    }

    #[test]
    fn test_verify_proof_with_corrupted_signature_a() {
        let (seed_a, pub_a) = gen_keypair();
        let (seed_b, pub_b) = gen_keypair();
        let hash_a = hex::encode(Sha256::digest(pub_a));
        let hash_b = hex::encode(Sha256::digest(pub_b));

        let request = create_proof_request(&hash_a, &hash_b, 200, &seed_a, &pub_a).unwrap();
        let mut proof = complete_proof(&request, &seed_b, &pub_b).unwrap();

        // Corrupt signature A
        proof.signature_a[10] ^= 0xFF;

        assert!(!verify_proof(&proof, &pub_a, &pub_b).unwrap());
    }

    #[test]
    fn test_verify_proof_with_corrupted_signature_b() {
        let (seed_a, pub_a) = gen_keypair();
        let (seed_b, pub_b) = gen_keypair();
        let hash_a = hex::encode(Sha256::digest(pub_a));
        let hash_b = hex::encode(Sha256::digest(pub_b));

        let request = create_proof_request(&hash_a, &hash_b, 300, &seed_a, &pub_a).unwrap();
        let mut proof = complete_proof(&request, &seed_b, &pub_b).unwrap();

        // Corrupt signature B
        proof.signature_b[20] ^= 0xFF;

        assert!(!verify_proof(&proof, &pub_a, &pub_b).unwrap());
    }

    #[test]
    fn test_from_bytes_empty_input() {
        let result = FriendshipProof::from_bytes(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_bytes_corrupted_data() {
        let corrupted = vec![0xFF, 0xAA, 0x55, 0x00];
        let result = FriendshipProof::from_bytes(&corrupted);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialization_preserves_all_fields() {
        let (seed_a, pub_a) = gen_keypair();
        let (seed_b, pub_b) = gen_keypair();
        let hash_a = hex::encode(Sha256::digest(pub_a));
        let hash_b = hex::encode(Sha256::digest(pub_b));

        let request = create_proof_request(&hash_a, &hash_b, 777, &seed_a, &pub_a).unwrap();
        let proof = complete_proof(&request, &seed_b, &pub_b).unwrap();

        let bytes = proof.to_bytes();
        let decoded = FriendshipProof::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.user_a_public_key_hash, proof.user_a_public_key_hash);
        assert_eq!(decoded.user_b_public_key_hash, proof.user_b_public_key_hash);
        assert_eq!(decoded.established_at, proof.established_at);
        assert_eq!(decoded.signature_a, proof.signature_a);
        assert_eq!(decoded.signature_b, proof.signature_b);
    }

    #[test]
    fn test_proof_with_long_hash_strings() {
        let (seed_a, pub_a) = gen_keypair();
        let (seed_b, pub_b) = gen_keypair();
        let hash_a = "a".repeat(100);
        let hash_b = "b".repeat(100);

        let request = create_proof_request(&hash_a, &hash_b, 1000, &seed_a, &pub_a).unwrap();
        let proof = complete_proof(&request, &seed_b, &pub_b).unwrap();

        assert!(verify_proof(&proof, &pub_a, &pub_b).unwrap());
    }

    #[test]
    fn test_proof_with_timestamp_zero() {
        let (seed_a, pub_a) = gen_keypair();
        let (seed_b, pub_b) = gen_keypair();
        let hash_a = hex::encode(Sha256::digest(pub_a));
        let hash_b = hex::encode(Sha256::digest(pub_b));

        let request = create_proof_request(&hash_a, &hash_b, 0, &seed_a, &pub_a).unwrap();
        let proof = complete_proof(&request, &seed_b, &pub_b).unwrap();

        assert_eq!(proof.established_at, 0);
        assert!(verify_proof(&proof, &pub_a, &pub_b).unwrap());
    }

    #[test]
    fn test_multiple_proofs_with_same_keys() {
        let (seed_a, pub_a) = gen_keypair();
        let (seed_b, pub_b) = gen_keypair();
        let hash_a = hex::encode(Sha256::digest(pub_a));
        let hash_b = hex::encode(Sha256::digest(pub_b));

        // Create two different proofs with different timestamps
        let request1 = create_proof_request(&hash_a, &hash_b, 100, &seed_a, &pub_a).unwrap();
        let proof1 = complete_proof(&request1, &seed_b, &pub_b).unwrap();

        let request2 = create_proof_request(&hash_a, &hash_b, 200, &seed_a, &pub_a).unwrap();
        let proof2 = complete_proof(&request2, &seed_b, &pub_b).unwrap();

        // Both should verify independently
        assert!(verify_proof(&proof1, &pub_a, &pub_b).unwrap());
        assert!(verify_proof(&proof2, &pub_a, &pub_b).unwrap());

        // But they should have different signatures due to different canonical data
        assert_ne!(proof1.signature_a, proof2.signature_a);
        assert_ne!(proof1.signature_b, proof2.signature_b);
    }
}
