//! Ed25519 release signing and verification.
//!
//! Provides cryptographic signing of individual release entries so that
//! HASHES.json consumers can verify each build was published by a trusted key.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A signed release entry that can be included in HASHES.json.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedRelease {
    pub build_hash: String,
    pub version: String,
    pub timestamp: String,
    /// Base64-encoded Ed25519 signature over the canonical message.
    pub signature: String,
}

impl SignedRelease {
    /// Build the canonical message that gets signed.
    fn canonical_message(build_hash: &str, version: &str, timestamp: &str) -> Vec<u8> {
        // Domain-separated, deterministic message format
        let mut hasher = Sha256::new();
        hasher.update(b"accord-release-v1:");
        hasher.update(build_hash.as_bytes());
        hasher.update(b":");
        hasher.update(version.as_bytes());
        hasher.update(b":");
        hasher.update(timestamp.as_bytes());
        hasher.finalize().to_vec()
    }
}

/// Sign a release entry, producing a `SignedRelease`.
pub fn sign_release(
    signing_key: &SigningKey,
    build_hash: &str,
    version: &str,
    timestamp: &str,
) -> SignedRelease {
    let message = SignedRelease::canonical_message(build_hash, version, timestamp);
    let sig = signing_key.sign(&message);
    SignedRelease {
        build_hash: build_hash.to_string(),
        version: version.to_string(),
        timestamp: timestamp.to_string(),
        signature: B64.encode(sig.to_bytes()),
    }
}

/// Verify a `SignedRelease` against a public key. Returns `true` if valid.
pub fn verify_release(public_key: &VerifyingKey, signed: &SignedRelease) -> bool {
    let message =
        SignedRelease::canonical_message(&signed.build_hash, &signed.version, &signed.timestamp);
    let sig_bytes = match B64.decode(&signed.signature) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&sig_arr);
    public_key.verify(&message, &signature).is_ok()
}

/// Result of verifying a build entry that has a signature.
#[derive(Debug, Clone)]
pub struct VerifiedBuild {
    pub version: String,
    pub platform: String,
    pub hash: String,
    pub revoked: bool,
    pub signature_valid: bool,
}

/// Verify all signed entries in a list of `KnownBuild`s.
///
/// Entries without signatures get `signature_valid = false`.
pub fn verify_signed_hashes(
    public_key: &VerifyingKey,
    builds: &[super::build_hash::KnownBuild],
) -> Vec<VerifiedBuild> {
    builds
        .iter()
        .map(|b| {
            let sig_valid = match (&b.signature, &b.signature_timestamp) {
                (Some(sig), Some(ts)) => {
                    let sr = SignedRelease {
                        build_hash: b.hash.clone(),
                        version: b.version.clone(),
                        timestamp: ts.clone(),
                        signature: sig.clone(),
                    };
                    verify_release(public_key, &sr)
                }
                _ => false,
            };
            VerifiedBuild {
                version: b.version.clone(),
                platform: b.platform.clone(),
                hash: b.hash.clone(),
                revoked: b.revoked,
                signature_valid: sig_valid,
            }
        })
        .collect()
}

/// Generate a new Ed25519 signing keypair. Returns (signing_key, verifying_key).
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let (sk, vk) = generate_keypair();
        let signed = sign_release(&sk, "deadbeef", "0.1.0", "2026-02-18T00:00:00Z");
        assert!(verify_release(&vk, &signed));
    }

    #[test]
    fn test_tampered_hash_rejected() {
        let (sk, vk) = generate_keypair();
        let mut signed = sign_release(&sk, "deadbeef", "0.1.0", "2026-02-18T00:00:00Z");
        signed.build_hash = "tampered".to_string();
        assert!(!verify_release(&vk, &signed));
    }

    #[test]
    fn test_wrong_key_rejected() {
        let (sk, _) = generate_keypair();
        let (_, wrong_vk) = generate_keypair();
        let signed = sign_release(&sk, "deadbeef", "0.1.0", "2026-02-18T00:00:00Z");
        assert!(!verify_release(&wrong_vk, &signed));
    }

    #[test]
    fn test_invalid_signature_base64() {
        let (_, vk) = generate_keypair();
        let signed = SignedRelease {
            build_hash: "abc".into(),
            version: "0.1.0".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
            signature: "not-valid-base64!!!".into(),
        };
        assert!(!verify_release(&vk, &signed));
    }

    #[test]
    fn test_verify_signed_hashes() {
        use crate::build_hash::KnownBuild;

        let (sk, vk) = generate_keypair();
        let sr = sign_release(&sk, "abc123", "0.1.0", "2026-02-18T00:00:00Z");

        let builds = vec![
            KnownBuild {
                version: "0.1.0".into(),
                platform: "linux".into(),
                hash: "abc123".into(),
                revoked: false,
                signature: Some(sr.signature),
                signature_timestamp: Some(sr.timestamp),
            },
            KnownBuild {
                version: "0.2.0".into(),
                platform: "linux".into(),
                hash: "xyz789".into(),
                revoked: false,
                signature: None,
                signature_timestamp: None,
            },
        ];

        let results = verify_signed_hashes(&vk, &builds);
        assert_eq!(results.len(), 2);
        assert!(results[0].signature_valid);
        assert!(!results[1].signature_valid);
    }
}
