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
        .unwrap()
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
}
