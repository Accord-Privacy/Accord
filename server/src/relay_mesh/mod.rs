//! Relay mesh infrastructure — foundation layer.
//!
//! Routes DMs across relay boundaries. No Node data ever crosses.
//! Nodes are always isolated; users join Nodes, not relays.
//! Friendship proof is required for cross-relay DMs.

pub mod config;
pub mod envelope;
pub mod identity;
pub mod peers;

use std::path::Path;

use anyhow::Result;

use self::config::MeshConfig;
use self::identity::RelayIdentity;
use self::peers::PeerRegistry;

/// Top-level mesh node tying identity, peers, and config together.
#[derive(Debug)]
pub struct MeshNode {
    pub identity: RelayIdentity,
    pub peers: PeerRegistry,
    pub config: MeshConfig,
}

impl MeshNode {
    /// Initialize a mesh node from a data directory and config.
    pub fn init(data_dir: &Path, config: MeshConfig) -> Result<Self> {
        let identity = RelayIdentity::load_or_generate(data_dir)?;
        let mut peers = PeerRegistry::with_persistence(data_dir.join("relay_peers.json"));
        peers.load()?;

        Ok(Self {
            identity,
            peers,
            config,
        })
    }

    /// The relay's short ID.
    pub fn relay_id(&self) -> &str {
        self.identity.relay_id()
    }

    /// Persist peer registry to disk.
    pub fn save_peers(&self) -> Result<()> {
        self.peers.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_mesh_node_init() {
        let dir = TempDir::new().unwrap();
        let node = MeshNode::init(dir.path(), MeshConfig::default()).unwrap();
        assert_eq!(node.relay_id().len(), 16);
        assert!(node.peers.is_empty());
        assert!(!node.config.enabled);
    }

    #[test]
    fn test_mesh_node_persistence() {
        let dir = TempDir::new().unwrap();

        let id1 = {
            let node = MeshNode::init(dir.path(), MeshConfig::default()).unwrap();
            node.relay_id().to_string()
        };

        let id2 = {
            let node = MeshNode::init(dir.path(), MeshConfig::default()).unwrap();
            node.relay_id().to_string()
        };

        assert_eq!(id1, id2);
    }
}
