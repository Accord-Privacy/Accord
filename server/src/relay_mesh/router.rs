//! Mesh message router — dispatches inbound `MeshEnvelope`s.
//!
//! - `DmForward` → deliver to local user's WebSocket, or drop.
//! - `RelayAnnounce` → update peer registry.
//! - `RelayPing` → update last_seen, respond with pong.

use std::sync::Arc;

use base64::Engine;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use super::envelope::{MeshEnvelope, PayloadType};
use super::peers::{PeerInfo, PeerRegistry};
use super::transport::MeshTransport;
use crate::state::SharedState;

/// Payload for a RelayAnnounce message (deserialized from encrypted_payload).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AnnouncePayload {
    pub relay_id: String,
    pub address: String,
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
}

/// Payload for a DmForward message (deserialized from encrypted_payload).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DmForwardPayload {
    /// Target user ID (UUID string) on the receiving relay.
    pub to_user_id: String,
    /// Opaque E2E-encrypted DM blob from the sender client.
    #[serde(with = "base64_blob")]
    pub encrypted_dm: Vec<u8>,
    /// Sender user ID for routing the reply path.
    pub from_user_id: String,
}

/// Mesh router — processes inbound envelopes and dispatches them.
pub struct MeshRouter {
    peers: Arc<RwLock<PeerRegistry>>,
    app_state: Option<SharedState>,
}

impl MeshRouter {
    pub fn new(peers: Arc<RwLock<PeerRegistry>>) -> Self {
        Self {
            peers,
            app_state: None,
        }
    }

    /// Set the app state for local user delivery.
    pub fn set_app_state(&mut self, state: SharedState) {
        self.app_state = Some(state);
    }

    /// Start processing inbound envelopes from the transport.
    pub async fn start(
        self,
        mut inbound_rx: mpsc::Receiver<MeshEnvelope>,
        transport: Arc<MeshTransport>,
        our_relay_id: String,
    ) {
        let peers = self.peers;
        let app_state = self.app_state;

        tokio::spawn(async move {
            while let Some(envelope) = inbound_rx.recv().await {
                if let Err(e) = Self::handle_envelope(
                    &envelope,
                    &peers,
                    &transport,
                    &our_relay_id,
                    app_state.as_ref(),
                )
                .await
                {
                    warn!("Mesh router: error handling envelope: {}", e);
                }
            }
            info!("Mesh router: inbound channel closed, stopping");
        });
    }

    async fn handle_envelope(
        envelope: &MeshEnvelope,
        peers: &Arc<RwLock<PeerRegistry>>,
        transport: &Arc<MeshTransport>,
        our_relay_id: &str,
        app_state: Option<&SharedState>,
    ) -> anyhow::Result<()> {
        match envelope.payload_type {
            PayloadType::DmForward => {
                Self::handle_dm_forward(envelope, our_relay_id, app_state).await
            }
            PayloadType::RelayAnnounce => {
                Self::handle_relay_announce(envelope, peers, transport).await
            }
            PayloadType::RelayPing => {
                Self::handle_relay_ping(envelope, peers, transport, our_relay_id).await
            }
        }
    }

    async fn handle_dm_forward(
        envelope: &MeshEnvelope,
        our_relay_id: &str,
        app_state: Option<&SharedState>,
    ) -> anyhow::Result<()> {
        // Only process DMs addressed to us
        if envelope.to_relay_id != our_relay_id {
            debug!(
                "Mesh: dropping DM not addressed to us (to={})",
                envelope.to_relay_id
            );
            return Ok(());
        }

        let payload: DmForwardPayload = serde_json::from_slice(&envelope.encrypted_payload)?;
        let user_id: uuid::Uuid = payload.to_user_id.parse()?;

        if let Some(state) = app_state {
            // Build a WebSocket message for the recipient
            let ws_msg = serde_json::json!({
                "type": "mesh_dm",
                "from_relay": envelope.from_relay_id,
                "from_user_id": payload.from_user_id,
                "encrypted_dm": base64::engine::general_purpose::STANDARD.encode(&payload.encrypted_dm),
            })
            .to_string();

            match state.send_to_user(user_id, ws_msg).await {
                Ok(_) => debug!("Mesh: delivered DM to local user {}", user_id),
                Err(e) => debug!("Mesh: user {} not online, dropping DM: {}", user_id, e),
            }
        } else {
            debug!("Mesh: no app_state, cannot deliver DM");
        }

        Ok(())
    }

    async fn handle_relay_announce(
        envelope: &MeshEnvelope,
        peers: &Arc<RwLock<PeerRegistry>>,
        transport: &Arc<MeshTransport>,
    ) -> anyhow::Result<()> {
        let payload: AnnouncePayload = serde_json::from_slice(&envelope.encrypted_payload)?;

        let key_bytes: [u8; 32] = payload
            .public_key
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid public key in announce"))?;
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)?;

        info!(
            "Mesh: relay announce from {} at {}",
            payload.relay_id, payload.address
        );

        // Update peer registry
        {
            let mut reg = peers.write().await;
            reg.upsert(
                payload.relay_id.clone(),
                PeerInfo {
                    public_key,
                    address: payload.address.clone(),
                    last_seen: envelope.timestamp,
                },
            );
        }

        // Update transport relay_id → address mapping
        transport
            .register_relay_id(payload.relay_id, payload.address)
            .await;

        Ok(())
    }

    async fn handle_relay_ping(
        envelope: &MeshEnvelope,
        peers: &Arc<RwLock<PeerRegistry>>,
        _transport: &Arc<MeshTransport>,
        our_relay_id: &str,
    ) -> anyhow::Result<()> {
        let from = &envelope.from_relay_id;
        debug!("Mesh: ping from {}", from);

        // Update last_seen
        {
            let mut reg = peers.write().await;
            if let Some(peer) = reg.get(from) {
                let mut updated = peer.clone();
                updated.last_seen = envelope.timestamp;
                reg.upsert(from.clone(), updated);
            }
        }

        // Respond with pong — the service layer handles proper signed pongs
        if envelope.to_relay_id == our_relay_id {
            debug!(
                "Mesh: received ping from {}, pong handled by service layer",
                from
            );
        }

        Ok(())
    }
}

/// Serde helper: hex bytes
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

/// Serde helper: base64 bytes
mod base64_blob {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_mesh::envelope::MeshEnvelope;
    use crate::relay_mesh::identity::RelayIdentity;

    #[test]
    fn test_announce_payload_roundtrip() {
        let payload = AnnouncePayload {
            relay_id: "abc123".to_string(),
            address: "10.0.0.1:9443".to_string(),
            public_key: vec![0u8; 32],
        };
        let json = serde_json::to_vec(&payload).unwrap();
        let decoded: AnnouncePayload = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.relay_id, "abc123");
        assert_eq!(decoded.public_key.len(), 32);
    }

    #[test]
    fn test_dm_forward_payload_roundtrip() {
        let payload = DmForwardPayload {
            to_user_id: uuid::Uuid::new_v4().to_string(),
            encrypted_dm: b"secret-blob".to_vec(),
            from_user_id: uuid::Uuid::new_v4().to_string(),
        };
        let json = serde_json::to_vec(&payload).unwrap();
        let decoded: DmForwardPayload = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.encrypted_dm, b"secret-blob");
    }

    #[tokio::test]
    async fn test_router_handles_announce() {
        let peers = Arc::new(RwLock::new(PeerRegistry::new()));
        let mut transport = MeshTransport::new();
        let _rx = transport.take_inbound_rx();
        let transport = Arc::new(transport);

        let sender = RelayIdentity::generate();
        let announce = AnnouncePayload {
            relay_id: sender.relay_id().to_string(),
            address: "10.0.0.1:9443".to_string(),
            public_key: sender.public_key_bytes().to_vec(),
        };
        let announce_bytes = serde_json::to_vec(&announce).unwrap();

        let envelope = MeshEnvelope::create_signed(
            &sender,
            "us".to_string(),
            PayloadType::RelayAnnounce,
            announce_bytes,
            1000,
        );

        MeshRouter::handle_envelope(&envelope, &peers, &transport, "us", None)
            .await
            .unwrap();

        let reg = peers.read().await;
        assert!(reg.get(sender.relay_id()).is_some());
        assert_eq!(reg.get(sender.relay_id()).unwrap().address, "10.0.0.1:9443");
    }

    #[tokio::test]
    async fn test_router_handles_ping() {
        let peers = Arc::new(RwLock::new(PeerRegistry::new()));
        let mut transport = MeshTransport::new();
        let _rx = transport.take_inbound_rx();
        let transport = Arc::new(transport);

        let sender = RelayIdentity::generate();

        // Pre-register the peer
        {
            let mut reg = peers.write().await;
            reg.upsert(
                sender.relay_id().to_string(),
                PeerInfo {
                    public_key: *sender.verifying_key(),
                    address: "1.2.3.4:9443".to_string(),
                    last_seen: 0,
                },
            );
        }

        let envelope = MeshEnvelope::create_signed(
            &sender,
            "us".to_string(),
            PayloadType::RelayPing,
            vec![],
            5000,
        );

        MeshRouter::handle_envelope(&envelope, &peers, &transport, "us", None)
            .await
            .unwrap();

        let reg = peers.read().await;
        assert_eq!(reg.get(sender.relay_id()).unwrap().last_seen, 5000);
    }

    #[tokio::test]
    async fn test_router_drops_dm_not_for_us() {
        let peers = Arc::new(RwLock::new(PeerRegistry::new()));
        let mut transport = MeshTransport::new();
        let _rx = transport.take_inbound_rx();
        let transport = Arc::new(transport);

        let sender = RelayIdentity::generate();
        let dm = DmForwardPayload {
            to_user_id: uuid::Uuid::new_v4().to_string(),
            encrypted_dm: b"blob".to_vec(),
            from_user_id: uuid::Uuid::new_v4().to_string(),
        };

        let envelope = MeshEnvelope::create_signed(
            &sender,
            "other_relay".to_string(),
            PayloadType::DmForward,
            serde_json::to_vec(&dm).unwrap(),
            100,
        );

        // Should not error, just drop silently
        MeshRouter::handle_envelope(&envelope, &peers, &transport, "us", None)
            .await
            .unwrap();
    }
}
