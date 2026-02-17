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

        let hash_a = hex::encode(Sha256::digest(&pub_a));
        let hash_b = hex::encode(Sha256::digest(&pub_b));
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

        let hash_a = hex::encode(Sha256::digest(&pub_a));
        let hash_b = hex::encode(Sha256::digest(&pub_b));

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
        let hash_a = hex::encode(Sha256::digest(&pub_a));
        let hash_b = hex::encode(Sha256::digest(&pub_b));

        let request = create_proof_request(&hash_a, &hash_b, 42, &seed_a, &pub_a).unwrap();
        let proof = complete_proof(&request, &seed_b, &pub_b).unwrap();

        let bytes = proof.to_bytes();
        let decoded = FriendshipProof::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.user_a_public_key_hash, proof.user_a_public_key_hash);
        assert_eq!(decoded.signature_a, proof.signature_a);
    }
}
