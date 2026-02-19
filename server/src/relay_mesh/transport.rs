//! TCP mesh transport — length-prefixed JSON framing over optional TLS.
//!
//! Each frame: 4-byte big-endian length prefix + JSON payload (a `MeshEnvelope`).
//! When TLS is configured, connections are wrapped with rustls.
//! When a mesh_secret is configured, a handshake authenticates peers before
//! accepting envelopes.

use std::collections::HashMap;
use std::io::BufReader;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

use super::config::MeshConfig;
use super::envelope::MeshEnvelope;

/// Maximum frame size: 1 MB.
const MAX_FRAME_SIZE: u32 = 1_048_576;

/// Handshake protocol version.
const HANDSHAKE_VERSION: u8 = 1;

/// Handshake magic bytes: "ACRD"
const HANDSHAKE_MAGIC: &[u8; 4] = b"ACRD";

/// Maximum time allowed for handshake completion.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A handle to a single peer connection (outbound or accepted inbound).
#[derive(Debug)]
struct PeerConnection {
    relay_id: Option<String>,
    address: String,
    tx: mpsc::Sender<Vec<u8>>,
}

/// Tracks connection attempts per IP for rate limiting.
#[derive(Debug)]
struct RateLimiter {
    /// IP → (count, window_start)
    buckets: HashMap<IpAddr, (u32, Instant)>,
    max_per_minute: u32,
}

impl RateLimiter {
    fn new(max_per_minute: u32) -> Self {
        Self {
            buckets: HashMap::new(),
            max_per_minute,
        }
    }

    /// Returns true if the connection should be allowed.
    fn check(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let entry = self.buckets.entry(ip).or_insert((0, now));

        // Reset window if >60s old
        if now.duration_since(entry.1) > Duration::from_secs(60) {
            *entry = (0, now);
        }

        entry.0 += 1;
        entry.0 <= self.max_per_minute
    }

    /// Periodic cleanup of stale entries.
    fn cleanup(&mut self) {
        let now = Instant::now();
        self.buckets
            .retain(|_, (_, start)| now.duration_since(*start) < Duration::from_secs(120));
    }
}

/// TLS configuration for mesh connections.
#[derive(Clone)]
struct MeshTlsConfig {
    acceptor: tokio_rustls::TlsAcceptor,
    connector: tokio_rustls::TlsConnector,
}

/// Build TLS config from cert/key files.
fn build_tls_config(cert_path: &str, key_path: &str) -> Result<MeshTlsConfig> {
    use rustls::pki_types::PrivateKeyDer;

    // Load certs
    let cert_file = std::fs::File::open(cert_path)
        .with_context(|| format!("mesh TLS: failed to open cert {}", cert_path))?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("mesh TLS: failed to parse certs")?;

    if certs.is_empty() {
        anyhow::bail!("mesh TLS: no certificates found in {}", cert_path);
    }

    // Load private key
    let key_file = std::fs::File::open(key_path)
        .with_context(|| format!("mesh TLS: failed to open key {}", key_path))?;
    let key: PrivateKeyDer = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .context("mesh TLS: failed to parse private key")?
        .ok_or_else(|| anyhow::anyhow!("mesh TLS: no private key found in {}", key_path))?;

    // Server config (for accepting connections)
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key.clone_key())
        .context("mesh TLS: invalid server config")?;

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    // Client config (for connecting to peers) — accept any cert since we
    // authenticate via the mesh_secret handshake + Ed25519 envelope signatures.
    // In production, operators can use a private CA for their mesh.
    let client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DangerousNoCertVerifier))
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    Ok(MeshTlsConfig {
        acceptor,
        connector,
    })
}

/// Certificate verifier that accepts any cert (mesh authentication is done at
/// the handshake/envelope layer via shared secrets + Ed25519 signatures).
#[derive(Debug)]
struct DangerousNoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for DangerousNoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Mesh transport layer — manages TCP (optionally TLS) connections to peer relays.
pub struct MeshTransport {
    connections: Arc<RwLock<HashMap<String, PeerConnection>>>,
    relay_index: Arc<RwLock<HashMap<String, String>>>,
    inbound_tx: mpsc::Sender<MeshEnvelope>,
    inbound_rx: Option<mpsc::Receiver<MeshEnvelope>>,
    tls: Option<MeshTlsConfig>,
    mesh_secret: Option<String>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
}

impl Default for MeshTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshTransport {
    /// Create a new transport with no TLS and no auth.
    pub fn new() -> Self {
        let (inbound_tx, inbound_rx) = mpsc::channel(512);
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            relay_index: Arc::new(RwLock::new(HashMap::new())),
            inbound_tx,
            inbound_rx: Some(inbound_rx),
            tls: None,
            mesh_secret: None,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(30))),
        }
    }

    /// Create a transport from mesh config, optionally setting up TLS and auth.
    pub fn from_config(config: &MeshConfig) -> Result<Self> {
        let (inbound_tx, inbound_rx) = mpsc::channel(512);

        let tls = if config.tls_enabled() {
            let tls_config = build_tls_config(
                config.mesh_tls_cert.as_ref().unwrap(),
                config.mesh_tls_key.as_ref().unwrap(),
            )?;
            info!("Mesh transport: TLS enabled");
            Some(tls_config)
        } else {
            warn!("Mesh transport: TLS disabled — connections are unencrypted");
            None
        };

        if config.mesh_secret.is_some() {
            info!("Mesh transport: shared-secret authentication enabled");
        } else {
            warn!("Mesh transport: no mesh_secret — peers are unauthenticated");
        }

        Ok(Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            relay_index: Arc::new(RwLock::new(HashMap::new())),
            inbound_tx,
            inbound_rx: Some(inbound_rx),
            tls,
            mesh_secret: config.mesh_secret.clone(),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(config.mesh_rate_limit))),
        })
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
        let tls = self.tls.clone();
        let mesh_secret = self.mesh_secret.clone();
        let rate_limiter = self.rate_limiter.clone();

        // Spawn rate limiter cleanup task
        let rl_cleanup = rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                rl_cleanup.lock().await.cleanup();
            }
        });

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let addr_str = addr.to_string();
                        let ip = addr.ip();

                        // Rate limit check
                        {
                            let mut rl = rate_limiter.lock().await;
                            if !rl.check(ip) {
                                warn!(
                                    "Mesh: rate limit exceeded for {}, rejecting connection",
                                    ip
                                );
                                drop(stream);
                                continue;
                            }
                        }

                        info!("Mesh: inbound connection from {}", addr_str);

                        let connections = connections.clone();
                        let relay_index = relay_index.clone();
                        let inbound_tx = inbound_tx.clone();
                        let tls = tls.clone();
                        let mesh_secret = mesh_secret.clone();

                        tokio::spawn(async move {
                            match Self::accept_connection(
                                stream,
                                addr_str.clone(),
                                tls,
                                mesh_secret,
                            )
                            .await
                            {
                                Ok((reader, writer)) => {
                                    Self::run_connection(
                                        reader,
                                        writer,
                                        addr_str,
                                        connections,
                                        relay_index,
                                        inbound_tx,
                                    );
                                }
                                Err(e) => {
                                    warn!(
                                        "Mesh: failed to accept connection from {}: {}",
                                        addr_str, e
                                    );
                                }
                            }
                        });
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

    /// Accept an inbound connection: optional TLS upgrade + handshake auth.
    async fn accept_connection(
        stream: TcpStream,
        addr: String,
        tls: Option<MeshTlsConfig>,
        mesh_secret: Option<String>,
    ) -> Result<(
        Box<dyn AsyncRead + Unpin + Send>,
        Box<dyn AsyncWrite + Unpin + Send>,
    )> {
        if let Some(tls_config) = tls {
            // TLS accept
            let tls_stream = tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                tls_config.acceptor.accept(stream),
            )
            .await
            .with_context(|| format!("mesh TLS handshake timeout from {}", addr))?
            .with_context(|| format!("mesh TLS handshake failed from {}", addr))?;

            let (reader, writer) = tokio::io::split(tls_stream);
            let mut reader: Box<dyn AsyncRead + Unpin + Send> = Box::new(reader);
            let mut writer: Box<dyn AsyncWrite + Unpin + Send> = Box::new(writer);

            // Auth handshake over TLS
            if let Some(ref secret) = mesh_secret {
                Self::server_handshake(&mut reader, &mut writer, secret).await?;
            }

            Ok((reader, writer))
        } else {
            let (reader, writer) = stream.into_split();
            let mut reader: Box<dyn AsyncRead + Unpin + Send> = Box::new(reader);
            let mut writer: Box<dyn AsyncWrite + Unpin + Send> = Box::new(writer);

            // Auth handshake over plain TCP
            if let Some(ref secret) = mesh_secret {
                Self::server_handshake(&mut reader, &mut writer, secret).await?;
            }

            Ok((reader, writer))
        }
    }

    /// Server side of the HMAC handshake.
    ///
    /// Protocol:
    /// 1. Server sends: MAGIC(4) + VERSION(1) + challenge(32)
    /// 2. Client responds: HMAC-SHA256(secret, challenge)(32)
    /// 3. Server verifies and sends: 0x01 (ok) or 0x00 (reject)
    async fn server_handshake(
        reader: &mut (dyn AsyncRead + Unpin + Send),
        writer: &mut (dyn AsyncWrite + Unpin + Send),
        secret: &str,
    ) -> Result<()> {
        // Generate random challenge
        let challenge: [u8; 32] = rand::random();

        // Send magic + version + challenge
        let mut hello = Vec::with_capacity(37);
        hello.extend_from_slice(HANDSHAKE_MAGIC);
        hello.push(HANDSHAKE_VERSION);
        hello.extend_from_slice(&challenge);
        writer.write_all(&hello).await?;
        writer.flush().await?;

        // Read client's HMAC response
        let mut response = [0u8; 32];
        tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.read_exact(&mut response))
            .await
            .context("mesh handshake: timeout waiting for client response")?
            .context("mesh handshake: failed to read client response")?;

        // Compute expected HMAC
        let expected = compute_hmac(secret.as_bytes(), &challenge);

        // Constant-time comparison
        if !constant_time_eq(&response, &expected) {
            writer.write_all(&[0x00]).await?;
            writer.flush().await?;
            anyhow::bail!("mesh handshake: invalid secret from peer");
        }

        writer.write_all(&[0x01]).await?;
        writer.flush().await?;
        debug!("Mesh handshake: peer authenticated successfully");
        Ok(())
    }

    /// Client side of the HMAC handshake.
    async fn client_handshake(
        reader: &mut (dyn AsyncRead + Unpin + Send),
        writer: &mut (dyn AsyncWrite + Unpin + Send),
        secret: &str,
    ) -> Result<()> {
        // Read magic + version + challenge
        let mut hello = [0u8; 37];
        tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.read_exact(&mut hello))
            .await
            .context("mesh handshake: timeout waiting for server hello")?
            .context("mesh handshake: failed to read server hello")?;

        if &hello[0..4] != HANDSHAKE_MAGIC {
            anyhow::bail!("mesh handshake: invalid magic bytes");
        }
        if hello[4] != HANDSHAKE_VERSION {
            anyhow::bail!(
                "mesh handshake: unsupported version {} (expected {})",
                hello[4],
                HANDSHAKE_VERSION
            );
        }

        let challenge = &hello[5..37];

        // Compute and send HMAC
        let hmac = compute_hmac(secret.as_bytes(), challenge);
        writer.write_all(&hmac).await?;
        writer.flush().await?;

        // Read result
        let mut result = [0u8; 1];
        tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.read_exact(&mut result))
            .await
            .context("mesh handshake: timeout waiting for auth result")?
            .context("mesh handshake: failed to read auth result")?;

        if result[0] != 0x01 {
            anyhow::bail!("mesh handshake: server rejected our secret");
        }

        debug!("Mesh handshake: authenticated with server");
        Ok(())
    }

    /// Connect to a peer relay at the given address. Auto-reconnects on failure.
    pub async fn connect_to_peer(&self, address: String) -> Result<()> {
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
        let tls = self.tls.clone();
        let mesh_secret = self.mesh_secret.clone();

        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            let max_backoff = Duration::from_secs(60);

            loop {
                match TcpStream::connect(&addr).await {
                    Ok(stream) => {
                        info!("Mesh: connected to peer {}", addr);
                        backoff = Duration::from_secs(1);

                        match Self::establish_outbound(
                            stream,
                            addr.clone(),
                            tls.clone(),
                            mesh_secret.clone(),
                        )
                        .await
                        {
                            Ok((reader, writer)) => {
                                Self::run_connection(
                                    reader,
                                    writer,
                                    addr.clone(),
                                    connections.clone(),
                                    relay_index.clone(),
                                    inbound_tx.clone(),
                                );
                                // Wait for disconnection
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
                                warn!("Mesh: handshake failed with {}: {}", addr, e);
                            }
                        }
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

    /// Establish an outbound connection: optional TLS + handshake auth.
    async fn establish_outbound(
        stream: TcpStream,
        addr: String,
        tls: Option<MeshTlsConfig>,
        mesh_secret: Option<String>,
    ) -> Result<(
        Box<dyn AsyncRead + Unpin + Send>,
        Box<dyn AsyncWrite + Unpin + Send>,
    )> {
        if let Some(tls_config) = tls {
            let server_name = rustls::pki_types::ServerName::try_from("mesh.local")
                .unwrap()
                .to_owned();
            let tls_stream = tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                tls_config.connector.connect(server_name, stream),
            )
            .await
            .with_context(|| format!("mesh TLS connect timeout to {}", addr))?
            .with_context(|| format!("mesh TLS connect failed to {}", addr))?;

            let (reader, writer) = tokio::io::split(tls_stream);
            let mut reader: Box<dyn AsyncRead + Unpin + Send> = Box::new(reader);
            let mut writer: Box<dyn AsyncWrite + Unpin + Send> = Box::new(writer);

            if let Some(ref secret) = mesh_secret {
                Self::client_handshake(&mut reader, &mut writer, secret).await?;
            }

            Ok((reader, writer))
        } else {
            let (reader, writer) = stream.into_split();
            let mut reader: Box<dyn AsyncRead + Unpin + Send> = Box::new(reader);
            let mut writer: Box<dyn AsyncWrite + Unpin + Send> = Box::new(writer);

            if let Some(ref secret) = mesh_secret {
                Self::client_handshake(&mut reader, &mut writer, secret).await?;
            }

            Ok((reader, writer))
        }
    }

    /// Spawn reader/writer tasks for an established connection.
    fn run_connection(
        reader: Box<dyn AsyncRead + Unpin + Send>,
        writer: Box<dyn AsyncWrite + Unpin + Send>,
        address: String,
        connections: Arc<RwLock<HashMap<String, PeerConnection>>>,
        relay_index: Arc<RwLock<HashMap<String, String>>>,
        inbound_tx: mpsc::Sender<MeshEnvelope>,
    ) {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(128);
        let addr = address.clone();
        let conns = connections.clone();
        let ridx = relay_index.clone();

        tokio::spawn(async move {
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

            let mut reader = reader;
            let mut writer = writer;

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
                if let Some(conn) = c.get(&addr) {
                    if let Some(ref rid) = conn.relay_id {
                        ridx.write().await.remove(rid);
                    }
                }
                c.remove(&addr);
            }
        });
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

    /// Register a relay_id → address mapping.
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
}

/// Compute HMAC-SHA256(key, data) using a simple HMAC construction.
fn compute_hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    // Standard HMAC construction: H((K' ⊕ opad) || H((K' ⊕ ipad) || message))
    let block_size = 64;
    let mut padded_key = vec![0u8; block_size];

    if key.len() > block_size {
        let hash = Sha256::digest(key);
        padded_key[..32].copy_from_slice(&hash);
    } else {
        padded_key[..key.len()].copy_from_slice(key);
    }

    let mut ipad = vec![0x36u8; block_size];
    let mut opad = vec![0x5cu8; block_size];
    for i in 0..block_size {
        ipad[i] ^= padded_key[i];
        opad[i] ^= padded_key[i];
    }

    // Inner hash
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    // Outer hash
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner_hash);
    let result = outer.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Constant-time comparison of two 32-byte arrays.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
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

    #[test]
    fn test_hmac_deterministic() {
        let key = b"mesh-secret-key";
        let data = b"challenge-data";
        let h1 = compute_hmac(key, data);
        let h2 = compute_hmac(key, data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hmac_different_keys() {
        let data = b"challenge";
        let h1 = compute_hmac(b"key1", data);
        let h2 = compute_hmac(b"key2", data);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let c = [2u8; 32];
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[test]
    fn test_rate_limiter() {
        let mut rl = RateLimiter::new(3);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert!(rl.check(ip));
        assert!(rl.check(ip));
        assert!(rl.check(ip));
        assert!(!rl.check(ip)); // 4th should fail

        // Different IP should still work
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();
        assert!(rl.check(ip2));
    }

    #[tokio::test]
    async fn test_handshake_roundtrip() {
        let secret = "test-mesh-secret";

        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (mut sr, mut sw) = tokio::io::split(server_stream);
        let (mut cr, mut cw) = tokio::io::split(client_stream);

        let server = tokio::spawn(async move {
            let mut reader: Box<dyn AsyncRead + Unpin + Send> = Box::new(&mut sr);
            let mut writer: Box<dyn AsyncWrite + Unpin + Send> = Box::new(&mut sw);
            MeshTransport::server_handshake(&mut *reader, &mut *writer, secret).await
        });

        let client = tokio::spawn(async move {
            let mut reader: Box<dyn AsyncRead + Unpin + Send> = Box::new(&mut cr);
            let mut writer: Box<dyn AsyncWrite + Unpin + Send> = Box::new(&mut cw);
            MeshTransport::client_handshake(&mut *reader, &mut *writer, secret).await
        });

        let (s_result, c_result) = tokio::join!(server, client);
        s_result.unwrap().unwrap();
        c_result.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_handshake_wrong_secret() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (mut sr, mut sw) = tokio::io::split(server_stream);
        let (mut cr, mut cw) = tokio::io::split(client_stream);

        let server = tokio::spawn(async move {
            let mut reader: Box<dyn AsyncRead + Unpin + Send> = Box::new(&mut sr);
            let mut writer: Box<dyn AsyncWrite + Unpin + Send> = Box::new(&mut sw);
            MeshTransport::server_handshake(&mut *reader, &mut *writer, "correct-secret").await
        });

        let client = tokio::spawn(async move {
            let mut reader: Box<dyn AsyncRead + Unpin + Send> = Box::new(&mut cr);
            let mut writer: Box<dyn AsyncWrite + Unpin + Send> = Box::new(&mut cw);
            MeshTransport::client_handshake(&mut *reader, &mut *writer, "wrong-secret").await
        });

        let (s_result, c_result) = tokio::join!(server, client);
        // Server should reject
        assert!(s_result.unwrap().is_err());
        // Client should see rejection
        assert!(c_result.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_transport_listen_and_connect() {
        let mut transport_a = MeshTransport::new();
        let mut rx_a = transport_a.take_inbound_rx().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);

        transport_a.listen(&addr).await.unwrap();
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

        let received = tokio::time::timeout(Duration::from_secs(2), rx_a.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.from_relay_id, id_b.relay_id());
    }
}
