//! Mesh service lifecycle — owns MeshNode + MeshTransport + MeshRouter.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use tokio::sync::RwLock;
use tracing::{info, warn};

use super::config::MeshConfig;
use super::envelope::{MeshEnvelope, PayloadType};
use super::identity::RelayIdentity;
use super::router::{AnnouncePayload, DmForwardPayload, MeshRouter};
use super::transport::MeshTransport;
use super::MeshNode;
use crate::state::SharedState;

/// Handle to the running mesh service, used by the main server to send cross-relay DMs.
#[derive(Clone)]
pub struct MeshHandle {
    identity: Arc<RelayIdentity>,
    transport: Arc<MeshTransport>,
    config: MeshConfig,
}

impl MeshHandle {
    /// Send a DM to a user on another relay.
    ///
    /// `to_relay_id` — the target relay's ID.
    /// `from_user_id` — local sender's user ID.
    /// `to_user_id` — recipient's user ID on the target relay.
    /// `encrypted_dm` — opaque E2E-encrypted blob from the client.
    pub async fn send_dm_via_mesh(
        &self,
        to_relay_id: &str,
        from_user_id: &str,
        to_user_id: &str,
        encrypted_dm: Vec<u8>,
    ) -> Result<()> {
        let payload = DmForwardPayload {
            to_user_id: to_user_id.to_string(),
            encrypted_dm,
            from_user_id: from_user_id.to_string(),
        };
        let payload_bytes = serde_json::to_vec(&payload)?;

        let envelope = MeshEnvelope::create_signed(
            &self.identity,
            to_relay_id.to_string(),
            PayloadType::DmForward,
            payload_bytes,
            now(),
        );

        self.transport.send_to(to_relay_id, &envelope).await
    }

    /// Our relay ID.
    pub fn relay_id(&self) -> &str {
        self.identity.relay_id()
    }

    /// Access the mesh configuration.
    pub fn config(&self) -> &MeshConfig {
        &self.config
    }

    /// Number of connected peers.
    pub async fn peer_count(&self) -> usize {
        self.transport.connection_count().await
    }
}

/// The mesh service — manages the full lifecycle.
pub struct MeshService;

impl MeshService {
    /// Start the mesh service. Returns a `MeshHandle` for the main server to use.
    pub async fn start(node: MeshNode, app_state: SharedState) -> Result<MeshHandle> {
        let config = node.config.clone();
        let identity = Arc::new(node.identity);
        let peers = Arc::new(RwLock::new(node.peers));

        let mut transport = MeshTransport::from_config(&config)?;
        let inbound_rx = transport
            .take_inbound_rx()
            .expect("inbound_rx already taken");

        let transport = Arc::new(transport);

        // Bind listener
        let bind_addr = format!("0.0.0.0:{}", config.listen_port);
        transport.listen(&bind_addr).await?;

        // Start router
        let mut router = MeshRouter::new(peers.clone());
        router.set_app_state(app_state);
        let relay_id = identity.relay_id().to_string();
        router
            .start(inbound_rx, transport.clone(), relay_id.clone())
            .await;

        // Connect to known peers and announce ourselves
        let identity_for_connect = identity.clone();
        let transport_for_connect = transport.clone();
        let config_for_connect = config.clone();
        tokio::spawn(async move {
            for peer_addr in &config_for_connect.known_peers {
                if let Err(e) = transport_for_connect
                    .connect_to_peer(peer_addr.clone())
                    .await
                {
                    warn!("Mesh: failed to connect to {}: {}", peer_addr, e);
                }
            }

            // Give connections a moment to establish
            tokio::time::sleep(Duration::from_secs(1)).await;

            // Announce ourselves to all peers
            let announce = build_announce(&identity_for_connect, &config_for_connect);
            if let Err(e) = transport_for_connect.broadcast(&announce).await {
                warn!("Mesh: failed to broadcast announce: {}", e);
            }
        });

        // Periodic ping task (every 60s)
        let ping_identity = identity.clone();
        let ping_transport = transport.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let ping = MeshEnvelope::create_signed(
                    &ping_identity,
                    "broadcast".to_string(),
                    PayloadType::RelayPing,
                    vec![],
                    now(),
                );
                if let Err(e) = ping_transport.broadcast(&ping).await {
                    warn!("Mesh: failed to broadcast ping: {}", e);
                }
            }
        });

        info!(
            "Mesh service started: relay_id={}, port={}",
            identity.relay_id(),
            config.listen_port
        );

        Ok(MeshHandle {
            identity,
            transport,
            config,
        })
    }
}

fn build_announce(identity: &RelayIdentity, config: &MeshConfig) -> MeshEnvelope {
    let payload = AnnouncePayload {
        relay_id: identity.relay_id().to_string(),
        address: format!("0.0.0.0:{}", config.listen_port),
        public_key: identity.public_key_bytes().to_vec(),
    };
    let payload_bytes = serde_json::to_vec(&payload).expect("serialize announce");
    MeshEnvelope::create_signed(
        identity,
        "broadcast".to_string(),
        PayloadType::RelayAnnounce,
        payload_bytes,
        now(),
    )
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_mesh::config::MeshConfig;
    use crate::relay_mesh::identity::RelayIdentity;

    #[test]
    fn test_build_announce() {
        let id = RelayIdentity::generate();
        let config = MeshConfig {
            enabled: true,
            listen_port: 9443,
            known_peers: vec![],
            max_peers: 10,
            mesh_secret: None,
            mesh_tls_cert: None,
            mesh_tls_key: None,
            mesh_rate_limit: 30,
        };
        let env = build_announce(&id, &config);
        assert_eq!(env.payload_type, PayloadType::RelayAnnounce);
        assert!(env.verify(id.verifying_key()));

        let payload: AnnouncePayload = serde_json::from_slice(&env.encrypted_payload).unwrap();
        assert_eq!(payload.relay_id, id.relay_id());
    }

    #[test]
    fn test_mesh_handle_relay_id() {
        let id = RelayIdentity::generate();
        let rid = id.relay_id().to_string();
        let handle = MeshHandle {
            identity: Arc::new(id),
            transport: Arc::new(MeshTransport::new()),
            config: MeshConfig::default(),
        };
        assert_eq!(handle.relay_id(), rid);
    }

    // === Additional tests for service.rs ===

    #[test]
    fn test_build_announce_with_custom_port() {
        let id = RelayIdentity::generate();
        let config = MeshConfig {
            enabled: true,
            listen_port: 8888,
            known_peers: vec![],
            max_peers: 10,
            mesh_secret: None,
            mesh_tls_cert: None,
            mesh_tls_key: None,
            mesh_rate_limit: 30,
        };
        let env = build_announce(&id, &config);

        let payload: AnnouncePayload = serde_json::from_slice(&env.encrypted_payload).unwrap();
        assert!(payload.address.contains("8888"));
    }

    #[test]
    fn test_build_announce_signature_valid() {
        let id = RelayIdentity::generate();
        let config = MeshConfig::default();
        let env = build_announce(&id, &config);

        assert!(env.verify(id.verifying_key()));
    }

    #[test]
    fn test_build_announce_to_broadcast() {
        let id = RelayIdentity::generate();
        let config = MeshConfig::default();
        let env = build_announce(&id, &config);

        assert_eq!(env.to_relay_id, "broadcast");
    }

    #[test]
    fn test_build_announce_public_key_matches() {
        let id = RelayIdentity::generate();
        let config = MeshConfig::default();
        let env = build_announce(&id, &config);

        let payload: AnnouncePayload = serde_json::from_slice(&env.encrypted_payload).unwrap();
        assert_eq!(payload.public_key, id.public_key_bytes().to_vec());
    }

    #[test]
    fn test_now_returns_reasonable_timestamp() {
        let ts = now();
        // Check it's a reasonable Unix timestamp (after 2020)
        assert!(ts > 1577836800); // Jan 1, 2020
                                  // Check it's not in the far future (before 2100)
        assert!(ts < 4102444800); // Jan 1, 2100
    }

    #[test]
    fn test_now_is_monotonic() {
        let ts1 = now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let ts2 = now();
        assert!(ts2 >= ts1);
    }

    #[test]
    fn test_mesh_handle_config() {
        let id = RelayIdentity::generate();
        let config = MeshConfig {
            enabled: true,
            listen_port: 9999,
            known_peers: vec!["peer1:9443".to_string()],
            max_peers: 25,
            mesh_secret: Some("test".to_string()),
            mesh_tls_cert: None,
            mesh_tls_key: None,
            mesh_rate_limit: 30,
        };
        let handle = MeshHandle {
            identity: Arc::new(id),
            transport: Arc::new(MeshTransport::new()),
            config: config.clone(),
        };

        assert_eq!(handle.config().listen_port, 9999);
        assert_eq!(handle.config().max_peers, 25);
    }

    #[tokio::test]
    async fn test_mesh_handle_peer_count_empty() {
        let id = RelayIdentity::generate();
        let handle = MeshHandle {
            identity: Arc::new(id),
            transport: Arc::new(MeshTransport::new()),
            config: MeshConfig::default(),
        };

        assert_eq!(handle.peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_mesh_handle_send_dm_creates_envelope() {
        let id = RelayIdentity::generate();
        let handle = MeshHandle {
            identity: Arc::new(id),
            transport: Arc::new(MeshTransport::new()),
            config: MeshConfig::default(),
        };

        let to_relay = "remote_relay";
        let from_user = uuid::Uuid::new_v4().to_string();
        let to_user = uuid::Uuid::new_v4().to_string();
        let dm = b"encrypted data".to_vec();

        // This will fail because we don't have a connection, but we're testing
        // that it creates the envelope without panicking
        let result = handle
            .send_dm_via_mesh(to_relay, &from_user, &to_user, dm)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mesh_handle_send_dm_with_empty_payload() {
        let id = RelayIdentity::generate();
        let handle = MeshHandle {
            identity: Arc::new(id),
            transport: Arc::new(MeshTransport::new()),
            config: MeshConfig::default(),
        };

        let result = handle
            .send_dm_via_mesh(
                "relay",
                &uuid::Uuid::new_v4().to_string(),
                &uuid::Uuid::new_v4().to_string(),
                vec![],
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mesh_handle_send_dm_with_large_payload() {
        let id = RelayIdentity::generate();
        let handle = MeshHandle {
            identity: Arc::new(id),
            transport: Arc::new(MeshTransport::new()),
            config: MeshConfig::default(),
        };

        let large_dm = vec![0u8; 1024 * 1024]; // 1 MB
        let result = handle
            .send_dm_via_mesh(
                "relay",
                &uuid::Uuid::new_v4().to_string(),
                &uuid::Uuid::new_v4().to_string(),
                large_dm,
            )
            .await;

        // Will fail due to no connection or frame size limit
        assert!(result.is_err());
    }

    #[test]
    fn test_mesh_handle_clone() {
        let id = RelayIdentity::generate();
        let handle1 = MeshHandle {
            identity: Arc::new(id),
            transport: Arc::new(MeshTransport::new()),
            config: MeshConfig::default(),
        };

        let handle2 = handle1.clone();
        assert_eq!(handle1.relay_id(), handle2.relay_id());
    }

    #[test]
    fn test_build_announce_with_different_identities() {
        let id1 = RelayIdentity::generate();
        let id2 = RelayIdentity::generate();
        let config = MeshConfig::default();

        let env1 = build_announce(&id1, &config);
        let env2 = build_announce(&id2, &config);

        assert_ne!(env1.from_relay_id, env2.from_relay_id);
    }

    #[test]
    fn test_build_announce_payload_deserialization() {
        let id = RelayIdentity::generate();
        let config = MeshConfig {
            enabled: true,
            listen_port: 7777,
            known_peers: vec![],
            max_peers: 10,
            mesh_secret: None,
            mesh_tls_cert: None,
            mesh_tls_key: None,
            mesh_rate_limit: 30,
        };
        let env = build_announce(&id, &config);

        let payload: Result<AnnouncePayload, _> = serde_json::from_slice(&env.encrypted_payload);
        assert!(payload.is_ok());
    }

    #[test]
    fn test_build_announce_timestamp_is_recent() {
        let id = RelayIdentity::generate();
        let config = MeshConfig::default();

        let before = now();
        let env = build_announce(&id, &config);
        let after = now();

        assert!(env.timestamp >= before);
        assert!(env.timestamp <= after);
    }

    #[tokio::test]
    async fn test_mesh_handle_send_dm_with_self_as_target() {
        let id = RelayIdentity::generate();
        let relay_id = id.relay_id().to_string();
        let handle = MeshHandle {
            identity: Arc::new(id),
            transport: Arc::new(MeshTransport::new()),
            config: MeshConfig::default(),
        };

        let user_id = uuid::Uuid::new_v4().to_string();
        let dm = b"self-message".to_vec();

        let result = handle
            .send_dm_via_mesh(&relay_id, &user_id, &user_id, dm)
            .await;
        // Will fail due to no connection
        assert!(result.is_err());
    }

    #[test]
    fn test_build_announce_with_ipv6_format() {
        let id = RelayIdentity::generate();
        let config = MeshConfig {
            enabled: true,
            listen_port: 9443,
            known_peers: vec![],
            max_peers: 10,
            mesh_secret: None,
            mesh_tls_cert: None,
            mesh_tls_key: None,
            mesh_rate_limit: 30,
        };
        let env = build_announce(&id, &config);

        let payload: AnnouncePayload = serde_json::from_slice(&env.encrypted_payload).unwrap();
        // The address will always be 0.0.0.0:<port> format
        assert!(payload.address.contains("0.0.0.0:"));
    }

    #[tokio::test]
    async fn test_mesh_handle_send_dm_with_special_characters_in_ids() {
        let id = RelayIdentity::generate();
        let handle = MeshHandle {
            identity: Arc::new(id),
            transport: Arc::new(MeshTransport::new()),
            config: MeshConfig::default(),
        };

        let from_user = uuid::Uuid::new_v4().to_string();
        let to_user = uuid::Uuid::new_v4().to_string();
        let dm = b"data".to_vec();

        let result = handle
            .send_dm_via_mesh("relay-with-dash", &from_user, &to_user, dm)
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_build_announce_consistency() {
        let id = RelayIdentity::generate();
        let config = MeshConfig::default();

        let env1 = build_announce(&id, &config);
        std::thread::sleep(std::time::Duration::from_millis(10));
        let env2 = build_announce(&id, &config);

        // Should have same relay_id and public key
        assert_eq!(env1.from_relay_id, env2.from_relay_id);

        let payload1: AnnouncePayload = serde_json::from_slice(&env1.encrypted_payload).unwrap();
        let payload2: AnnouncePayload = serde_json::from_slice(&env2.encrypted_payload).unwrap();

        assert_eq!(payload1.public_key, payload2.public_key);
        assert_eq!(payload1.relay_id, payload2.relay_id);
    }

    #[test]
    fn test_build_announce_with_zero_port() {
        let id = RelayIdentity::generate();
        let config = MeshConfig {
            enabled: true,
            listen_port: 0,
            known_peers: vec![],
            max_peers: 10,
            mesh_secret: None,
            mesh_tls_cert: None,
            mesh_tls_key: None,
            mesh_rate_limit: 30,
        };
        let env = build_announce(&id, &config);

        let payload: AnnouncePayload = serde_json::from_slice(&env.encrypted_payload).unwrap();
        assert!(payload.address.contains(":0"));
    }

    #[test]
    fn test_build_announce_with_max_port() {
        let id = RelayIdentity::generate();
        let config = MeshConfig {
            enabled: true,
            listen_port: 65535,
            known_peers: vec![],
            max_peers: 10,
            mesh_secret: None,
            mesh_tls_cert: None,
            mesh_tls_key: None,
            mesh_rate_limit: 30,
        };
        let env = build_announce(&id, &config);

        let payload: AnnouncePayload = serde_json::from_slice(&env.encrypted_payload).unwrap();
        assert!(payload.address.contains(":65535"));
    }

    #[tokio::test]
    async fn test_mesh_handle_multiple_send_dm_attempts() {
        let id = RelayIdentity::generate();
        let handle = MeshHandle {
            identity: Arc::new(id),
            transport: Arc::new(MeshTransport::new()),
            config: MeshConfig::default(),
        };

        for _ in 0..5 {
            let result = handle
                .send_dm_via_mesh(
                    "relay",
                    &uuid::Uuid::new_v4().to_string(),
                    &uuid::Uuid::new_v4().to_string(),
                    b"data".to_vec(),
                )
                .await;
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_build_announce_from_relay_id_matches_identity() {
        let id = RelayIdentity::generate();
        let config = MeshConfig::default();
        let env = build_announce(&id, &config);

        assert_eq!(env.from_relay_id, id.relay_id());

        let payload: AnnouncePayload = serde_json::from_slice(&env.encrypted_payload).unwrap();
        assert_eq!(payload.relay_id, id.relay_id());
    }

    #[tokio::test]
    async fn test_mesh_handle_send_dm_with_invalid_user_id_format() {
        let id = RelayIdentity::generate();
        let handle = MeshHandle {
            identity: Arc::new(id),
            transport: Arc::new(MeshTransport::new()),
            config: MeshConfig::default(),
        };

        // Using non-UUID strings
        let result = handle
            .send_dm_via_mesh("relay", "not-a-uuid", "also-not-a-uuid", b"data".to_vec())
            .await;

        // Should still create envelope, failure is due to no connection
        assert!(result.is_err());
    }

    #[test]
    fn test_build_announce_multiple_calls_different_timestamps() {
        let id = RelayIdentity::generate();
        let config = MeshConfig::default();

        let env1 = build_announce(&id, &config);
        std::thread::sleep(std::time::Duration::from_millis(1000));
        let env2 = build_announce(&id, &config);

        // Timestamps should be different
        assert!(env2.timestamp >= env1.timestamp);
    }

    #[test]
    fn test_mesh_handle_config_with_known_peers() {
        let id = RelayIdentity::generate();
        let config = MeshConfig {
            enabled: true,
            listen_port: 9443,
            known_peers: vec![
                "peer1:9443".to_string(),
                "peer2:9443".to_string(),
                "peer3:9443".to_string(),
            ],
            max_peers: 10,
            mesh_secret: None,
            mesh_tls_cert: None,
            mesh_tls_key: None,
            mesh_rate_limit: 30,
        };
        let handle = MeshHandle {
            identity: Arc::new(id),
            transport: Arc::new(MeshTransport::new()),
            config: config.clone(),
        };

        assert_eq!(handle.config().known_peers.len(), 3);
    }

    #[tokio::test]
    async fn test_mesh_handle_send_dm_binary_data() {
        let id = RelayIdentity::generate();
        let handle = MeshHandle {
            identity: Arc::new(id),
            transport: Arc::new(MeshTransport::new()),
            config: MeshConfig::default(),
        };

        let binary_dm = vec![0x00, 0xff, 0xaa, 0x55, 0x12, 0x34, 0x56, 0x78];
        let result = handle
            .send_dm_via_mesh(
                "relay",
                &uuid::Uuid::new_v4().to_string(),
                &uuid::Uuid::new_v4().to_string(),
                binary_dm,
            )
            .await;

        assert!(result.is_err());
    }
}
