//! Relay identity — Ed25519 keypair and relay ID derivation.

use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// A relay's cryptographic identity.
#[derive(Debug)]
pub struct RelayIdentity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    relay_id: String,
}

impl RelayIdentity {
    /// Derive the relay ID from a public key: first 16 hex chars of SHA-256.
    pub fn derive_relay_id(public_key: &VerifyingKey) -> String {
        let hash = Sha256::digest(public_key.as_bytes());
        hex::encode(hash)[..16].to_string()
    }

    /// Generate a brand-new identity.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let relay_id = Self::derive_relay_id(&verifying_key);
        Self {
            signing_key,
            verifying_key,
            relay_id,
        }
    }

    /// Load from data dir, or generate and persist on first run.
    pub fn load_or_generate(data_dir: &Path) -> Result<Self> {
        let priv_path = data_dir.join("relay_key");
        let pub_path = data_dir.join("relay_key.pub");

        if priv_path.exists() {
            let priv_bytes = std::fs::read(&priv_path).context("reading relay private key")?;
            let key_bytes: [u8; 32] = priv_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid relay_key length"))?;
            let signing_key = SigningKey::from_bytes(&key_bytes);
            let verifying_key = signing_key.verifying_key();
            let relay_id = Self::derive_relay_id(&verifying_key);
            Ok(Self {
                signing_key,
                verifying_key,
                relay_id,
            })
        } else {
            let identity = Self::generate();
            std::fs::create_dir_all(data_dir)?;
            std::fs::write(&priv_path, identity.signing_key.to_bytes())?;
            std::fs::write(&pub_path, identity.verifying_key.to_bytes())?;
            Ok(identity)
        }
    }

    /// Sign arbitrary bytes.
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.signing_key.sign(data)
    }

    /// Verify a signature against this relay's public key.
    pub fn verify(&self, data: &[u8], signature: &Signature) -> bool {
        self.verifying_key.verify(data, signature).is_ok()
    }

    /// Verify using an arbitrary public key.
    pub fn verify_with_key(public_key: &VerifyingKey, data: &[u8], signature: &Signature) -> bool {
        public_key.verify(data, signature).is_ok()
    }

    pub fn relay_id(&self) -> &str {
        &self.relay_id
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_and_sign_verify() {
        let id = RelayIdentity::generate();
        assert_eq!(id.relay_id().len(), 16);

        let msg = b"hello mesh";
        let sig = id.sign(msg);
        assert!(id.verify(msg, &sig));
        assert!(!id.verify(b"tampered", &sig));
    }

    #[test]
    fn test_relay_id_deterministic() {
        let id = RelayIdentity::generate();
        let id2 = RelayIdentity::derive_relay_id(id.verifying_key());
        assert_eq!(id.relay_id(), id2);
    }

    #[test]
    fn test_verify_with_key() {
        let id = RelayIdentity::generate();
        let msg = b"cross-relay dm";
        let sig = id.sign(msg);
        assert!(RelayIdentity::verify_with_key(
            id.verifying_key(),
            msg,
            &sig
        ));
    }

    #[test]
    fn test_persistence() {
        let dir = TempDir::new().unwrap();
        let id1 = RelayIdentity::load_or_generate(dir.path()).unwrap();
        let id2 = RelayIdentity::load_or_generate(dir.path()).unwrap();
        assert_eq!(id1.relay_id(), id2.relay_id());
        assert_eq!(id1.public_key_bytes(), id2.public_key_bytes());
    }

    #[test]
    fn test_different_identities_differ() {
        let a = RelayIdentity::generate();
        let b = RelayIdentity::generate();
        assert_ne!(a.relay_id(), b.relay_id());
    }
}
