//! Build hash verification system for Accord binaries.
//!
//! Embeds build identity (commit, timestamp, target) at compile time and provides
//! verification against a signed registry of known builds.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Build information embedded at compile time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildInfo {
    pub commit_hash: String,
    pub build_timestamp: String,
    pub target_triple: String,
    pub build_hash: String,
    pub version: String,
}

impl BuildInfo {
    /// Compute the build hash from the identity fields.
    pub fn compute_hash(commit: &str, timestamp: &str, target: &str, version: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(commit.as_bytes());
        hasher.update(timestamp.as_bytes());
        hasher.update(target.as_bytes());
        hasher.update(version.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Get the build info for the current binary (populated at compile time).
    pub fn current() -> Self {
        let commit_hash = env!("ACCORD_COMMIT_HASH").to_string();
        let build_timestamp = env!("ACCORD_BUILD_TIMESTAMP").to_string();
        let target_triple = env!("TARGET").to_string();
        let version = env!("CARGO_PKG_VERSION").to_string();
        let build_hash =
            Self::compute_hash(&commit_hash, &build_timestamp, &target_triple, &version);
        Self {
            commit_hash,
            build_timestamp,
            target_triple,
            build_hash,
            version,
        }
    }
}

/// Trust level of a build hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildTrust {
    /// Matches an official, non-revoked release.
    Verified,
    /// Valid hash format but not in the known list.
    Unknown,
    /// Hash has been revoked.
    Revoked,
}

/// An entry in the official hash registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownBuild {
    pub version: String,
    pub platform: String,
    pub hash: String,
    pub revoked: bool,
}

/// A signed hash registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHashes {
    /// JSON-encoded `Vec<KnownBuild>`.
    pub payload: String,
    /// Ed25519 signature over `payload`.
    pub signature: Vec<u8>,
}

/// Verify a build hash against a list of known builds.
pub fn verify_build_hash(hash: &str, known_hashes: &[KnownBuild]) -> BuildTrust {
    for entry in known_hashes {
        if entry.hash == hash {
            return if entry.revoked {
                BuildTrust::Revoked
            } else {
                BuildTrust::Verified
            };
        }
    }
    BuildTrust::Unknown
}

/// Parse a HASHES.json string into known builds.
pub fn parse_hashes_json(json: &str) -> Result<Vec<KnownBuild>, serde_json::Error> {
    serde_json::from_str(json)
}

/// Sign a list of known builds with an Ed25519 signing key.
pub fn sign_hashes(hashes: &[KnownBuild], signing_key: &SigningKey) -> SignedHashes {
    let payload = serde_json::to_string(hashes).expect("serialize known builds");
    let signature = signing_key.sign(payload.as_bytes());
    SignedHashes {
        payload,
        signature: signature.to_bytes().to_vec(),
    }
}

/// Verify and deserialize a signed hash registry.
pub fn verify_signed_hashes(
    signed: &SignedHashes,
    public_key: &VerifyingKey,
) -> anyhow::Result<Vec<KnownBuild>> {
    let sig_bytes: [u8; 64] = signed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid signature length"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    public_key
        .verify(signed.payload.as_bytes(), &signature)
        .map_err(|e| anyhow::anyhow!("signature verification failed: {e}"))?;
    Ok(serde_json::from_str(&signed.payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_build_info_current() {
        let info = BuildInfo::current();
        assert!(!info.commit_hash.is_empty());
        assert!(!info.build_hash.is_empty());
        assert!(!info.version.is_empty());
        // Hash should be deterministic
        let expected = BuildInfo::compute_hash(
            &info.commit_hash,
            &info.build_timestamp,
            &info.target_triple,
            &info.version,
        );
        assert_eq!(info.build_hash, expected);
    }

    #[test]
    fn test_compute_hash_deterministic() {
        let h1 = BuildInfo::compute_hash(
            "abc",
            "2026-01-01T00:00:00Z",
            "x86_64-unknown-linux-gnu",
            "0.1.0",
        );
        let h2 = BuildInfo::compute_hash(
            "abc",
            "2026-01-01T00:00:00Z",
            "x86_64-unknown-linux-gnu",
            "0.1.0",
        );
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // hex-encoded SHA-256
    }

    #[test]
    fn test_verify_build_hash_verified() {
        let known = vec![KnownBuild {
            version: "0.1.0".into(),
            platform: "linux".into(),
            hash: "abc123".into(),
            revoked: false,
        }];
        assert_eq!(verify_build_hash("abc123", &known), BuildTrust::Verified);
    }

    #[test]
    fn test_verify_build_hash_unknown() {
        let known = vec![KnownBuild {
            version: "0.1.0".into(),
            platform: "linux".into(),
            hash: "abc123".into(),
            revoked: false,
        }];
        assert_eq!(verify_build_hash("xyz789", &known), BuildTrust::Unknown);
    }

    #[test]
    fn test_verify_build_hash_revoked() {
        let known = vec![KnownBuild {
            version: "0.1.0".into(),
            platform: "linux".into(),
            hash: "abc123".into(),
            revoked: true,
        }];
        assert_eq!(verify_build_hash("abc123", &known), BuildTrust::Revoked);
    }

    #[test]
    fn test_parse_hashes_json() {
        let json = r#"[{"version":"0.1.0","platform":"linux","hash":"abc","revoked":false}]"#;
        let builds = parse_hashes_json(json).unwrap();
        assert_eq!(builds.len(), 1);
        assert_eq!(builds[0].version, "0.1.0");
    }

    #[test]
    fn test_signed_hashes_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let hashes = vec![KnownBuild {
            version: "0.1.0".into(),
            platform: "linux".into(),
            hash: "deadbeef".into(),
            revoked: false,
        }];

        let signed = sign_hashes(&hashes, &signing_key);
        let verified = verify_signed_hashes(&signed, &verifying_key).unwrap();
        assert_eq!(verified, hashes);
    }

    #[test]
    fn test_signed_hashes_tampered_rejection() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let hashes = vec![KnownBuild {
            version: "0.1.0".into(),
            platform: "linux".into(),
            hash: "deadbeef".into(),
            revoked: false,
        }];

        let mut signed = sign_hashes(&hashes, &signing_key);
        signed.payload = signed.payload.replace("0.1.0", "0.2.0"); // tamper

        assert!(verify_signed_hashes(&signed, &verifying_key).is_err());
    }

    #[test]
    fn test_signed_hashes_wrong_key_rejection() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng).verifying_key();

        let hashes = vec![KnownBuild {
            version: "0.1.0".into(),
            platform: "linux".into(),
            hash: "deadbeef".into(),
            revoked: false,
        }];

        let signed = sign_hashes(&hashes, &signing_key);
        assert!(verify_signed_hashes(&signed, &wrong_key).is_err());
    }
}
