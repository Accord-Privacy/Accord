//! Mesh configuration.

use serde::{Deserialize, Serialize};

/// Configuration for the relay mesh subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    /// Whether the mesh is enabled.
    pub enabled: bool,
    /// Port to listen for mesh peer connections.
    pub listen_port: u16,
    /// Bootstrap peer addresses (host:port).
    pub known_peers: Vec<String>,
    /// Maximum number of connected peers.
    pub max_peers: u16,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_port: 9443,
            known_peers: Vec::new(),
            max_peers: 50,
        }
    }
}

/// CLI arguments for mesh configuration (to be integrated with clap).
#[derive(Debug, Clone)]
pub struct MeshCliArgs {
    pub mesh_enabled: bool,
    pub mesh_port: Option<u16>,
    pub mesh_peers: Vec<String>,
}

impl MeshConfig {
    /// Merge CLI arguments into this config (CLI takes precedence).
    pub fn apply_cli(&mut self, args: &MeshCliArgs) {
        if args.mesh_enabled {
            self.enabled = true;
        }
        if let Some(port) = args.mesh_port {
            self.listen_port = port;
        }
        if !args.mesh_peers.is_empty() {
            self.known_peers = args.mesh_peers.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let cfg = MeshConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.listen_port, 9443);
        assert!(cfg.known_peers.is_empty());
        assert_eq!(cfg.max_peers, 50);
    }

    #[test]
    fn test_apply_cli() {
        let mut cfg = MeshConfig::default();
        let args = MeshCliArgs {
            mesh_enabled: true,
            mesh_port: Some(9999),
            mesh_peers: vec!["10.0.0.1:9443".to_string()],
        };
        cfg.apply_cli(&args);
        assert!(cfg.enabled);
        assert_eq!(cfg.listen_port, 9999);
        assert_eq!(cfg.known_peers, vec!["10.0.0.1:9443"]);
    }

    #[test]
    fn test_serde_roundtrip() {
        let cfg = MeshConfig {
            enabled: true,
            listen_port: 8000,
            known_peers: vec!["a:1".into(), "b:2".into()],
            max_peers: 25,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let decoded: MeshConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.listen_port, 8000);
        assert_eq!(decoded.max_peers, 25);
    }
}
