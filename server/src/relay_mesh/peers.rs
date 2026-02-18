//! In-memory peer registry with JSON persistence.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// Information about a known peer relay.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub public_key: VerifyingKey,
    pub address: String,
    pub last_seen: u64,
}

/// Serializable form for persistence.
#[derive(Serialize, Deserialize)]
struct PeerRecord {
    relay_id: String,
    #[serde(with = "hex_bytes")]
    public_key: Vec<u8>,
    address: String,
    last_seen: u64,
}

/// Registry of known peer relays.
#[derive(Debug)]
pub struct PeerRegistry {
    peers: HashMap<String, PeerInfo>,
    persist_path: Option<PathBuf>,
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerRegistry {
    /// Create an empty registry (no persistence).
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            persist_path: None,
        }
    }

    /// Create a registry backed by a JSON file.
    pub fn with_persistence(path: PathBuf) -> Self {
        Self {
            peers: HashMap::new(),
            persist_path: Some(path),
        }
    }

    /// Load peers from the persistence file, if it exists.
    pub fn load(&mut self) -> Result<()> {
        let path = match &self.persist_path {
            Some(p) if p.exists() => p.clone(),
            _ => return Ok(()),
        };
        let data = std::fs::read_to_string(&path).context("reading relay_peers.json")?;
        let records: Vec<PeerRecord> = serde_json::from_str(&data)?;
        for r in records {
            let key_bytes: [u8; 32] = r
                .public_key
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid public key length for {}", r.relay_id))?;
            let public_key = VerifyingKey::from_bytes(&key_bytes)
                .map_err(|e| anyhow::anyhow!("invalid public key for {}: {}", r.relay_id, e))?;
            self.peers.insert(
                r.relay_id,
                PeerInfo {
                    public_key,
                    address: r.address,
                    last_seen: r.last_seen,
                },
            );
        }
        Ok(())
    }

    /// Save current peers to the persistence file.
    pub fn save(&self) -> Result<()> {
        let path = match &self.persist_path {
            Some(p) => p,
            None => return Ok(()),
        };
        let records: Vec<PeerRecord> = self
            .peers
            .iter()
            .map(|(id, info)| PeerRecord {
                relay_id: id.clone(),
                public_key: info.public_key.to_bytes().to_vec(),
                address: info.address.clone(),
                last_seen: info.last_seen,
            })
            .collect();
        let json = serde_json::to_string_pretty(&records)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Add or update a peer.
    pub fn upsert(&mut self, relay_id: String, info: PeerInfo) {
        self.peers.insert(relay_id, info);
    }

    /// Remove a peer by relay ID. Returns whether it existed.
    pub fn remove(&mut self, relay_id: &str) -> bool {
        self.peers.remove(relay_id).is_some()
    }

    /// Look up a peer by relay ID.
    pub fn get(&self, relay_id: &str) -> Option<&PeerInfo> {
        self.peers.get(relay_id)
    }

    /// Number of known peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Iterate over all peers.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &PeerInfo)> {
        self.peers.iter()
    }
}

/// Serde helper for Vec<u8> ↔ hex string.
mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_mesh::identity::RelayIdentity;
    use tempfile::TempDir;

    fn make_peer(id: &RelayIdentity) -> PeerInfo {
        PeerInfo {
            public_key: *id.verifying_key(),
            address: "127.0.0.1:9443".to_string(),
            last_seen: 1700000000,
        }
    }

    #[test]
    fn test_add_lookup_remove() {
        let mut reg = PeerRegistry::new();
        let id = RelayIdentity::generate();
        let relay_id = id.relay_id().to_string();

        assert!(reg.is_empty());
        reg.upsert(relay_id.clone(), make_peer(&id));
        assert_eq!(reg.len(), 1);
        assert!(reg.get(&relay_id).is_some());

        assert!(reg.remove(&relay_id));
        assert!(reg.is_empty());
        assert!(!reg.remove(&relay_id));
    }

    #[test]
    fn test_upsert_overwrites() {
        let mut reg = PeerRegistry::new();
        let id = RelayIdentity::generate();
        let relay_id = id.relay_id().to_string();

        reg.upsert(relay_id.clone(), make_peer(&id));
        let mut updated = make_peer(&id);
        updated.address = "10.0.0.1:9443".to_string();
        reg.upsert(relay_id.clone(), updated);

        assert_eq!(reg.len(), 1);
        assert_eq!(reg.get(&relay_id).unwrap().address, "10.0.0.1:9443");
    }

    #[test]
    fn test_persistence_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("relay_peers.json");

        let id = RelayIdentity::generate();
        let relay_id = id.relay_id().to_string();

        {
            let mut reg = PeerRegistry::with_persistence(path.clone());
            reg.upsert(relay_id.clone(), make_peer(&id));
            reg.save().unwrap();
        }

        {
            let mut reg = PeerRegistry::with_persistence(path);
            reg.load().unwrap();
            assert_eq!(reg.len(), 1);
            let peer = reg.get(&relay_id).unwrap();
            assert_eq!(peer.public_key.to_bytes(), id.verifying_key().to_bytes());
        }
    }

    #[test]
    fn test_load_nonexistent_file() {
        let mut reg = PeerRegistry::with_persistence(PathBuf::from("/tmp/nonexistent_peers.json"));
        assert!(reg.load().is_ok());
        assert!(reg.is_empty());
    }

    #[test]
    fn test_iter() {
        let mut reg = PeerRegistry::new();
        for _ in 0..3 {
            let id = RelayIdentity::generate();
            reg.upsert(id.relay_id().to_string(), make_peer(&id));
        }
        assert_eq!(reg.iter().count(), 3);
    }
}
