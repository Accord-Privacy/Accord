//! TCP mesh transport — length-prefixed JSON framing over plain TCP.
//!
//! Each frame: 4-byte big-endian length prefix + JSON payload (a `MeshEnvelope`).
//! TLS can be layered on top later via tokio-rustls; for now we rely on the
//! fact that all payloads are already E2E encrypted by clients.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use super::envelope::MeshEnvelope;

/// Maximum frame size: 1 MB. Prevents a malicious peer from exhausting memory.
const MAX_FRAME_SIZE: u32 = 1_048_576;

/// A handle to a single peer connection (outbound or accepted inbound).
#[derive(Debug)]
struct PeerConnection {
    relay_id: Option<String>,
    address: String,
    tx: mpsc::Sender<Vec<u8>>,
}

/// Mesh transport layer — manages TCP connections to peer relays.
pub struct MeshTransport {
    /// Connected peers keyed by address (since we may not know relay_id at connect time).
    connections: Arc<RwLock<HashMap<String, PeerConnection>>>,
    /// Relay-id → address index (populated after handshake / first envelope).
    relay_index: Arc<RwLock<HashMap<String, String>>>,
    /// Channel for inbound envelopes from any peer.
    inbound_tx: mpsc::Sender<MeshEnvelope>,
    /// Receiver side — consumed by the router.
    inbound_rx: Option<mpsc::Receiver<MeshEnvelope>>,
}

impl Default for MeshTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshTransport {
    /// Create a new transport. Returns the transport; call `take_inbound_rx()` to get
    /// the receiver for inbound envelopes before starting the listener.
    pub fn new() -> Self {
        let (inbound_tx, inbound_rx) = mpsc::channel(512);
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            relay_index: Arc::new(RwLock::new(HashMap::new())),
            inbound_tx,
            inbound_rx: Some(inbound_rx),
        }
    }

    /// Take the inbound envelope receiver (can only be called once).
    pub fn take_inbound_rx(&mut self) -> Option<mpsc::Receiver<MeshEnvelope>> {
        self.inbound_rx.take()
    }

    /// Start listening for inbound peer connections.
    pub async fn listen(&self, bind_addr: &str) -> Result<()> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("mesh: failed to bind {}", bind_addr))?;
        info!("Mesh transport listening on {}", bind_addr);

        let connections = self.connections.clone();
        let relay_index = self.relay_index.clone();
        let inbound_tx = self.inbound_tx.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let addr_str = addr.to_string();
                        info!("Mesh: inbound connection from {}", addr_str);
                        Self::spawn_connection(
                            stream,
                            addr_str,
                            connections.clone(),
                            relay_index.clone(),
                            inbound_tx.clone(),
                        );
                    }
                    Err(e) => {
                        error!("Mesh: accept error: {}", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });
        Ok(())
    }

    /// Connect to a peer relay at the given address. Auto-reconnects on failure.
    pub async fn connect_to_peer(&self, address: String) -> Result<()> {
        // Don't double-connect
        {
            let conns = self.connections.read().await;
            if conns.contains_key(&address) {
                debug!("Mesh: already connected to {}", address);
                return Ok(());
            }
        }

        let connections = self.connections.clone();
        let relay_index = self.relay_index.clone();
        let inbound_tx = self.inbound_tx.clone();
        let addr = address.clone();

        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            let max_backoff = Duration::from_secs(60);

            loop {
                match TcpStream::connect(&addr).await {
                    Ok(stream) => {
                        info!("Mesh: connected to peer {}", addr);
                        backoff = Duration::from_secs(1); // reset
                        Self::spawn_connection(
                            stream,
                            addr.clone(),
                            connections.clone(),
                            relay_index.clone(),
                            inbound_tx.clone(),
                        );
                        // Wait for disconnection before reconnecting
                        // We detect this by polling the connection map
                        loop {
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            let conns = connections.read().await;
                            if !conns.contains_key(&addr) {
                                break;
                            }
                        }
                        warn!("Mesh: lost connection to {}, reconnecting...", addr);
                    }
                    Err(e) => {
                        warn!(
                            "Mesh: failed to connect to {}: {}. Retrying in {:?}",
                            addr, e, backoff
                        );
                    }
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        });

        Ok(())
    }

    /// Broadcast an envelope to all connected peers.
    pub async fn broadcast(&self, envelope: &MeshEnvelope) -> Result<()> {
        let data = encode_frame(envelope)?;
        let conns = self.connections.read().await;
        for (addr, conn) in conns.iter() {
            if let Err(e) = conn.tx.try_send(data.clone()) {
                warn!("Mesh: failed to send to {}: {}", addr, e);
            }
        }
        Ok(())
    }

    /// Send an envelope to a specific relay by relay_id.
    pub async fn send_to(&self, relay_id: &str, envelope: &MeshEnvelope) -> Result<()> {
        let data = encode_frame(envelope)?;
        let index = self.relay_index.read().await;
        if let Some(addr) = index.get(relay_id) {
            let conns = self.connections.read().await;
            if let Some(conn) = conns.get(addr) {
                conn.tx
                    .send(data)
                    .await
                    .with_context(|| format!("mesh: send to {} failed", relay_id))?;
                return Ok(());
            }
        }
        anyhow::bail!("mesh: no connection to relay {}", relay_id)
    }

    /// Register a relay_id → address mapping (called by router on RelayAnnounce).
    pub async fn register_relay_id(&self, relay_id: String, address: String) {
        let mut conns = self.connections.write().await;
        if let Some(conn) = conns.get_mut(&address) {
            conn.relay_id = Some(relay_id.clone());
        }
        self.relay_index.write().await.insert(relay_id, address);
    }

    /// Number of active connections.
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    // ── Internal ──

    fn spawn_connection(
        stream: TcpStream,
        address: String,
        connections: Arc<RwLock<HashMap<String, PeerConnection>>>,
        relay_index: Arc<RwLock<HashMap<String, String>>>,
        inbound_tx: mpsc::Sender<MeshEnvelope>,
    ) {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(128);

        // Store connection
        let addr = address.clone();
        let conns = connections.clone();
        let ridx = relay_index.clone();

        tokio::spawn(async move {
            // Register connection
            {
                let mut c = conns.write().await;
                c.insert(
                    addr.clone(),
                    PeerConnection {
                        relay_id: None,
                        address: addr.clone(),
                        tx,
                    },
                );
            }

            let (mut reader, mut writer) = stream.into_split();

            // Writer task
            let write_addr = addr.clone();
            let write_handle = tokio::spawn(async move {
                while let Some(data) = rx.recv().await {
                    if let Err(e) = writer.write_all(&data).await {
                        warn!("Mesh: write error to {}: {}", write_addr, e);
                        break;
                    }
                }
            });

            // Reader loop
            loop {
                match read_frame(&mut reader).await {
                    Ok(Some(envelope)) => {
                        if inbound_tx.send(envelope).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        info!("Mesh: peer {} disconnected", addr);
                        break;
                    }
                    Err(e) => {
                        warn!("Mesh: read error from {}: {}", addr, e);
                        break;
                    }
                }
            }

            // Cleanup
            write_handle.abort();
            {
                let mut c = conns.write().await;
                // Remove relay_index entry if we know the relay_id
                if let Some(conn) = c.get(&addr) {
                    if let Some(ref rid) = conn.relay_id {
                        ridx.write().await.remove(rid);
                    }
                }
                c.remove(&addr);
            }
        });
    }
}

/// Encode a `MeshEnvelope` into a length-prefixed frame.
pub fn encode_frame(envelope: &MeshEnvelope) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(envelope)?;
    let len = json.len() as u32;
    if len > MAX_FRAME_SIZE {
        anyhow::bail!("mesh frame too large: {} bytes", len);
    }
    let mut buf = Vec::with_capacity(4 + json.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&json);
    Ok(buf)
}

/// Decode a length-prefixed frame from JSON bytes.
pub fn decode_frame(data: &[u8]) -> Result<MeshEnvelope> {
    Ok(serde_json::from_slice(data)?)
}

/// Read a single frame from an async reader. Returns `None` on clean EOF.
async fn read_frame<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<MeshEnvelope>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        anyhow::bail!(
            "mesh frame too large: {} bytes (max {})",
            len,
            MAX_FRAME_SIZE
        );
    }

    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    let envelope = decode_frame(&payload)?;
    Ok(Some(envelope))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_mesh::envelope::PayloadType;
    use crate::relay_mesh::identity::RelayIdentity;

    #[test]
    fn test_encode_decode_frame() {
        let id = RelayIdentity::generate();
        let env = MeshEnvelope::create_signed(
            &id,
            "target".to_string(),
            PayloadType::RelayPing,
            vec![1, 2, 3],
            42,
        );

        let frame = encode_frame(&env).unwrap();
        // First 4 bytes are length
        let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(len + 4, frame.len());

        let decoded = decode_frame(&frame[4..]).unwrap();
        assert_eq!(decoded.from_relay_id, env.from_relay_id);
        assert_eq!(decoded.timestamp, 42);
    }

    #[test]
    fn test_frame_too_large() {
        let id = RelayIdentity::generate();
        let env = MeshEnvelope::create_signed(
            &id,
            "target".to_string(),
            PayloadType::DmForward,
            vec![0u8; MAX_FRAME_SIZE as usize + 1],
            1,
        );
        assert!(encode_frame(&env).is_err());
    }

    #[tokio::test]
    async fn test_read_write_frame_roundtrip() {
        let id = RelayIdentity::generate();
        let env = MeshEnvelope::create_signed(
            &id,
            "dest".to_string(),
            PayloadType::DmForward,
            b"encrypted-dm".to_vec(),
            9999,
        );

        let frame = encode_frame(&env).unwrap();
        let mut cursor = std::io::Cursor::new(frame);
        let decoded = read_frame(&mut cursor).await.unwrap().unwrap();
        assert_eq!(decoded.from_relay_id, id.relay_id());
        assert_eq!(decoded.encrypted_payload, b"encrypted-dm");
    }

    #[tokio::test]
    async fn test_read_frame_eof() {
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        let result = read_frame(&mut cursor).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_transport_listen_and_connect() {
        let mut transport_a = MeshTransport::new();
        let mut rx_a = transport_a.take_inbound_rx().unwrap();

        // Bind to random port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener); // free the port for transport_a

        transport_a.listen(&addr).await.unwrap();

        // Give listener time to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Transport B connects and sends an envelope
        let id_b = RelayIdentity::generate();
        let env = MeshEnvelope::create_signed(
            &id_b,
            "target".to_string(),
            PayloadType::RelayPing,
            vec![],
            100,
        );
        let frame = encode_frame(&env).unwrap();

        let mut stream = TcpStream::connect(&addr).await.unwrap();
        stream.write_all(&frame).await.unwrap();

        // Transport A should receive it
        let received = tokio::time::timeout(Duration::from_secs(2), rx_a.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.from_relay_id, id_b.relay_id());
    }
}
