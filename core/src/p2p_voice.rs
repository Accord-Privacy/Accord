//! # Peer-to-Peer Voice Transport
//!
//! Provides direct peer-to-peer voice communication for small groups (≤4 participants),
//! bypassing the server relay for lower latency.
//!
//! Architecture:
//! - **ICE-lite** candidate gathering via STUN binding requests
//! - **Mesh topology**: each peer connects directly to every other peer
//! - **Fallback**: automatic relay fallback when P2P connectivity fails
//! - Uses the existing SRTP encryption layer for media protection
//! - Integrates with [`crate::jitter_buffer::JitterBuffer`] for playout

use crate::jitter_buffer::{JitterBuffer, JitterBufferConfig};
use crate::srtp::{SrtpPacket, VoiceDecryptor, VoiceEncryptor, VoiceSessionKey};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use uuid::Uuid;

// ─── Constants ───────────────────────────────────────────────────────────────

/// Maximum peers in a P2P mesh (including self).
pub const MAX_P2P_PEERS: usize = 4;

/// STUN magic cookie (RFC 5389 §6)
pub const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN Binding Request type
pub const STUN_BINDING_REQUEST: u16 = 0x0001;
/// STUN Binding Response type
pub const STUN_BINDING_RESPONSE: u16 = 0x0101;

/// Default STUN server
pub const DEFAULT_STUN_SERVER: &str = "stun.l.google.com:19302";

/// Connectivity check interval in milliseconds
pub const ICE_CHECK_INTERVAL_MS: u64 = 500;

/// Maximum connectivity check attempts before declaring failure
pub const ICE_MAX_CHECK_ATTEMPTS: u32 = 10;

/// Consent freshness interval (RFC 7675): re-check connectivity periodically
pub const CONSENT_INTERVAL_MS: u64 = 15_000;

/// Warning displayed to users when enabling any non-AlwaysRelay mode.
pub const P2P_WARNING: &str = "P2P voice may reveal your IP address to other participants.";

// ─── Voice Privacy Settings ──────────────────────────────────────────────────

/// Controls when P2P (direct) voice connections are allowed.
/// Default is `AlwaysRelay` for maximum privacy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoicePrivacyMode {
    /// Default — all voice routed through relay, no IP exposure.
    #[default]
    AlwaysRelay,
    /// P2P only with users on the friends list.
    FriendsOnly,
    /// P2P only with explicitly whitelisted users.
    Whitelist,
    /// P2P with anyone in the voice channel.
    Everyone,
}

/// Per-user voice privacy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoicePrivacyConfig {
    /// Which mode governs P2P consent.
    pub mode: VoicePrivacyMode,
    /// Public-key hashes of users explicitly allowed for P2P (used in `Whitelist` mode).
    pub p2p_whitelist: HashSet<String>,
    /// Public-key hashes of users explicitly blocked from P2P.
    /// Overrides `FriendsOnly` and `Everyone` modes.
    pub p2p_blocklist: HashSet<String>,
}

impl Default for VoicePrivacyConfig {
    fn default() -> Self {
        Self {
            mode: VoicePrivacyMode::AlwaysRelay,
            p2p_whitelist: HashSet::new(),
            p2p_blocklist: HashSet::new(),
        }
    }
}

impl VoicePrivacyConfig {
    /// Check whether this user's config allows a P2P connection with `peer_key_hash`.
    /// `is_friend` indicates whether the peer is on this user's friends list.
    pub fn allows_p2p(&self, peer_key_hash: &str, is_friend: bool) -> bool {
        // Blocklist always wins
        if self.p2p_blocklist.contains(peer_key_hash) {
            return false;
        }
        match self.mode {
            VoicePrivacyMode::AlwaysRelay => false,
            VoicePrivacyMode::FriendsOnly => is_friend,
            VoicePrivacyMode::Whitelist => self.p2p_whitelist.contains(peer_key_hash),
            VoicePrivacyMode::Everyone => true,
        }
    }
}

/// Check whether a P2P connection is mutually consented between two users.
///
/// Both users must independently allow P2P with each other.
/// `is_friends` is true if the two users are mutual friends.
pub fn check_p2p_consent(
    config_a: &VoicePrivacyConfig,
    key_hash_a: &str,
    config_b: &VoicePrivacyConfig,
    key_hash_b: &str,
    is_friends: bool,
) -> bool {
    config_a.allows_p2p(key_hash_b, is_friends) && config_b.allows_p2p(key_hash_a, is_friends)
}

// ─── Routing Decision ────────────────────────────────────────────────────────

/// How a specific peer pair is routed in a hybrid voice channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PairRouting {
    /// Direct P2P — both users consented.
    DirectP2P,
    /// Routed through the server relay.
    Relay,
}

// ─── ICE Candidate Types ─────────────────────────────────────────────────────

/// ICE candidate type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CandidateType {
    /// Host candidate (local interface address)
    Host,
    /// Server-reflexive candidate (public address from STUN)
    ServerReflexive,
    /// Relay candidate (TURN server — used as fallback)
    Relay,
}

/// An ICE candidate representing a potential transport address.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IceCandidate {
    /// Candidate type
    pub candidate_type: CandidateType,
    /// Transport address
    pub addr: SocketAddr,
    /// Priority (higher = preferred)
    pub priority: u32,
    /// Foundation (for candidate pairing)
    pub foundation: String,
}

impl IceCandidate {
    /// Create a host candidate from a local address.
    pub fn host(addr: SocketAddr) -> Self {
        // Priority calculation per RFC 5245 §4.1.2.1
        // type_pref=126 for host, local_pref=65535, component=1
        let priority = (126 << 24) | (65535 << 8) | (256 - 1);
        Self {
            candidate_type: CandidateType::Host,
            addr,
            priority,
            foundation: format!("host-{}", addr.ip()),
        }
    }

    /// Create a server-reflexive candidate from a STUN response.
    pub fn server_reflexive(addr: SocketAddr) -> Self {
        let priority = (100 << 24) | (65535 << 8) | (256 - 1);
        Self {
            candidate_type: CandidateType::ServerReflexive,
            addr,
            priority,
            foundation: format!("srflx-{}", addr.ip()),
        }
    }

    /// Create a relay (server-fallback) candidate.
    pub fn relay(addr: SocketAddr) -> Self {
        let priority = (65535 << 8) | (256 - 1);
        Self {
            candidate_type: CandidateType::Relay,
            addr,
            priority,
            foundation: format!("relay-{}", addr.ip()),
        }
    }
}

// ─── STUN Messages ───────────────────────────────────────────────────────────

/// Minimal STUN Binding Request builder.
#[derive(Debug, Clone)]
pub struct StunBindingRequest {
    pub transaction_id: [u8; 12],
}

impl StunBindingRequest {
    pub fn new() -> Self {
        let mut tid = [0u8; 12];
        // Use random transaction ID
        for byte in tid.iter_mut() {
            *byte = rand::random();
        }
        Self {
            transaction_id: tid,
        }
    }

    /// Serialize to wire format (RFC 5389 §6).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20);
        buf.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // message length = 0 (no attributes)
        buf.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&self.transaction_id);
        buf
    }
}

impl Default for StunBindingRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Parsed STUN Binding Response (minimal: just extracts XOR-MAPPED-ADDRESS).
#[derive(Debug, Clone)]
pub struct StunBindingResponse {
    pub transaction_id: [u8; 12],
    pub mapped_address: Option<SocketAddr>,
}

impl StunBindingResponse {
    /// Parse a STUN response from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 20 {
            bail!("STUN response too short");
        }

        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        if msg_type != STUN_BINDING_RESPONSE {
            bail!("Not a STUN Binding Response: 0x{:04x}", msg_type);
        }

        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if cookie != STUN_MAGIC_COOKIE {
            bail!("Invalid STUN magic cookie");
        }

        let mut tid = [0u8; 12];
        tid.copy_from_slice(&data[8..20]);

        // Parse attributes looking for XOR-MAPPED-ADDRESS (0x0020)
        let mut mapped_address = None;
        let mut offset = 20;
        let end = 20 + msg_len.min(data.len() - 20);

        while offset + 4 <= end {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if attr_type == 0x0020 && attr_len >= 8 {
                // XOR-MAPPED-ADDRESS
                let family = data[offset + 1];
                let xor_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) ^ 0x2112; // XOR with top 16 bits of magic cookie

                if family == 0x01 && attr_len >= 8 {
                    // IPv4
                    let xor_ip = u32::from_be_bytes([
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]) ^ STUN_MAGIC_COOKIE;
                    let ip = std::net::Ipv4Addr::from(xor_ip);
                    mapped_address = Some(SocketAddr::new(ip.into(), xor_port));
                }
                // IPv6 support would go here (family == 0x02)
            }

            // Attributes are padded to 4-byte boundary
            offset += (attr_len + 3) & !3;
        }

        Ok(Self {
            transaction_id: tid,
            mapped_address,
        })
    }
}

// ─── Peer Connection State ───────────────────────────────────────────────────

/// Connection state for a single peer in the mesh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerConnectionState {
    /// Gathering ICE candidates
    Gathering,
    /// Checking connectivity (ICE checks in progress)
    Checking,
    /// Connected — P2P media flowing
    Connected,
    /// P2P failed — falling back to relay
    RelayFallback,
    /// Disconnected / closed
    Disconnected,
}

/// A peer in the voice mesh.
pub struct PeerConnection {
    /// Remote user ID
    pub peer_id: Uuid,
    /// Connection state
    pub state: PeerConnectionState,
    /// Remote ICE candidates received via signaling
    pub remote_candidates: Vec<IceCandidate>,
    /// Local ICE candidates gathered for this peer
    pub local_candidates: Vec<IceCandidate>,
    /// Selected candidate pair (local, remote) once connected
    pub selected_pair: Option<(IceCandidate, IceCandidate)>,
    /// SRTP encryptor for sending to this peer
    pub encryptor: Option<VoiceEncryptor>,
    /// SRTP decryptor for receiving from this peer
    pub decryptor: Option<VoiceDecryptor>,
    /// Jitter buffer for this peer's incoming stream
    pub jitter_buffer: JitterBuffer,
    /// Connectivity check attempts
    pub check_attempts: u32,
    /// Round-trip time estimate in milliseconds
    pub rtt_ms: Option<f64>,
    /// Last successful connectivity check timestamp (monotonic ms)
    pub last_consent_ms: Option<u64>,
}

impl PeerConnection {
    pub fn new(peer_id: Uuid) -> Self {
        Self {
            peer_id,
            state: PeerConnectionState::Gathering,
            remote_candidates: Vec::new(),
            local_candidates: Vec::new(),
            selected_pair: None,
            encryptor: None,
            decryptor: None,
            jitter_buffer: JitterBuffer::new(JitterBufferConfig::default()),
            check_attempts: 0,
            rtt_ms: None,
            last_consent_ms: None,
        }
    }

    /// Initialize SRTP for this peer connection.
    pub fn init_srtp(&mut self, local_ssrc: u32, remote_ssrc: u32, voice_key: VoiceSessionKey) {
        self.encryptor = Some(VoiceEncryptor::new(local_ssrc, voice_key.clone()));
        self.decryptor = Some(VoiceDecryptor::new(remote_ssrc, voice_key));
    }

    /// Add a remote ICE candidate received via signaling.
    pub fn add_remote_candidate(&mut self, candidate: IceCandidate) {
        self.remote_candidates.push(candidate);
        // If we were gathering, transition to checking
        if self.state == PeerConnectionState::Gathering && !self.local_candidates.is_empty() {
            self.state = PeerConnectionState::Checking;
        }
    }

    /// Record a successful connectivity check.
    pub fn on_check_success(
        &mut self,
        local: IceCandidate,
        remote: IceCandidate,
        rtt_ms: f64,
        now_ms: u64,
    ) {
        self.selected_pair = Some((local, remote));
        self.rtt_ms = Some(rtt_ms);
        self.last_consent_ms = Some(now_ms);
        self.state = PeerConnectionState::Connected;
        self.check_attempts = 0;
    }

    /// Record a failed connectivity check.
    pub fn on_check_failure(&mut self) {
        self.check_attempts += 1;
        if self.check_attempts >= ICE_MAX_CHECK_ATTEMPTS {
            self.state = PeerConnectionState::RelayFallback;
        }
    }

    /// Check if consent (RFC 7675) has expired.
    pub fn is_consent_expired(&self, now_ms: u64) -> bool {
        match self.last_consent_ms {
            Some(last) => now_ms.saturating_sub(last) > CONSENT_INTERVAL_MS * 2,
            None => false,
        }
    }

    /// Encrypt an audio frame for sending to this peer.
    pub fn encrypt_frame(&mut self, audio: &[u8]) -> Result<SrtpPacket> {
        let enc = self
            .encryptor
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("SRTP not initialized for peer {}", self.peer_id))?;
        enc.encrypt_packet(audio)
    }

    /// Decrypt a received SRTP packet from this peer and feed into jitter buffer.
    pub fn receive_packet(&mut self, packet: &SrtpPacket, arrival_ms: u64) -> Result<()> {
        let dec = self
            .decryptor
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("SRTP not initialized for peer {}", self.peer_id))?;
        let audio = dec.decrypt_packet(packet)?;
        self.jitter_buffer
            .push(packet.sequence, packet.timestamp, audio, arrival_ms);
        Ok(())
    }

    /// Pull the next audio frame from the jitter buffer.
    pub fn pull_audio(&mut self) -> Option<Vec<u8>> {
        self.jitter_buffer.pull()
    }
}

// ─── Signaling Messages ──────────────────────────────────────────────────────

/// Signaling messages exchanged via the WebSocket relay for P2P setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2PSignal {
    /// Offer to establish P2P connection
    Offer {
        from: Uuid,
        to: Uuid,
        channel_id: Uuid,
        /// Local SSRC for the sender's audio stream
        ssrc: u32,
        /// ICE candidates
        candidates: Vec<IceCandidate>,
    },
    /// Answer accepting P2P connection
    Answer {
        from: Uuid,
        to: Uuid,
        channel_id: Uuid,
        ssrc: u32,
        candidates: Vec<IceCandidate>,
    },
    /// Additional ICE candidate (trickle ICE)
    IceTrickle {
        from: Uuid,
        to: Uuid,
        channel_id: Uuid,
        candidate: IceCandidate,
    },
    /// Notify that P2P failed, fallback to relay
    FallbackToRelay { from: Uuid, channel_id: Uuid },
}

// ─── Voice Mesh Session ──────────────────────────────────────────────────────

/// Manages the P2P mesh for a single voice channel.
pub struct VoiceMeshSession {
    /// Voice channel ID
    pub channel_id: Uuid,
    /// Local user ID
    pub local_user_id: Uuid,
    /// Local SSRC for our outgoing audio
    pub local_ssrc: u32,
    /// Peer connections indexed by remote user ID
    pub peers: HashMap<Uuid, PeerConnection>,
    /// Whether we're using relay fallback for the whole session
    pub relay_mode: bool,
    /// Voice session key (shared across the group)
    voice_key: VoiceSessionKey,
    /// Per-peer routing decisions (hybrid: some P2P, some relay in same channel)
    pub pair_routing: HashMap<Uuid, PairRouting>,
    /// Local user's voice privacy config
    pub local_privacy: VoicePrivacyConfig,
}

impl VoiceMeshSession {
    /// Create a new mesh session for a voice channel.
    pub fn new(
        channel_id: Uuid,
        local_user_id: Uuid,
        local_ssrc: u32,
        voice_key: VoiceSessionKey,
    ) -> Self {
        Self {
            channel_id,
            local_user_id,
            local_ssrc,
            peers: HashMap::new(),
            relay_mode: false,
            voice_key,
            pair_routing: HashMap::new(),
            local_privacy: VoicePrivacyConfig::default(),
        }
    }

    /// Create a new mesh session with a specific privacy configuration.
    pub fn with_privacy(
        channel_id: Uuid,
        local_user_id: Uuid,
        local_ssrc: u32,
        voice_key: VoiceSessionKey,
        privacy: VoicePrivacyConfig,
    ) -> Self {
        Self {
            channel_id,
            local_user_id,
            local_ssrc,
            peers: HashMap::new(),
            relay_mode: false,
            voice_key,
            pair_routing: HashMap::new(),
            local_privacy: privacy,
        }
    }

    /// Decide routing for a peer based on mutual consent.
    ///
    /// `peer_config` is the remote user's privacy config.
    /// `local_key_hash` / `peer_key_hash` are the respective public key hashes.
    /// `is_friends` is whether the two users are mutual friends.
    ///
    /// Returns the routing decision and stores it internally.
    pub fn decide_routing(
        &mut self,
        peer_id: Uuid,
        peer_config: &VoicePrivacyConfig,
        local_key_hash: &str,
        peer_key_hash: &str,
        is_friends: bool,
    ) -> PairRouting {
        let routing = if check_p2p_consent(
            &self.local_privacy,
            local_key_hash,
            peer_config,
            peer_key_hash,
            is_friends,
        ) {
            PairRouting::DirectP2P
        } else {
            PairRouting::Relay
        };
        self.pair_routing.insert(peer_id, routing);
        routing
    }

    /// Get the routing decision for a specific peer.
    pub fn get_routing(&self, peer_id: &Uuid) -> PairRouting {
        self.pair_routing
            .get(peer_id)
            .copied()
            .unwrap_or(PairRouting::Relay)
    }

    /// Get all peers using a specific routing mode.
    pub fn peers_by_routing(&self, routing: PairRouting) -> Vec<Uuid> {
        self.pair_routing
            .iter()
            .filter(|(_, &r)| r == routing)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Add a peer to the mesh. Fails if MAX_P2P_PEERS would be exceeded.
    pub fn add_peer(&mut self, peer_id: Uuid, remote_ssrc: u32) -> Result<()> {
        // +1 for local user
        if self.peers.len() + 1 >= MAX_P2P_PEERS {
            bail!(
                "Cannot add peer: mesh full ({}/{})",
                self.peers.len() + 1,
                MAX_P2P_PEERS
            );
        }

        if self.peers.contains_key(&peer_id) {
            bail!("Peer {} already in mesh", peer_id);
        }

        let mut conn = PeerConnection::new(peer_id);
        conn.init_srtp(self.local_ssrc, remote_ssrc, self.voice_key.clone());
        self.peers.insert(peer_id, conn);
        Ok(())
    }

    /// Remove a peer from the mesh.
    pub fn remove_peer(&mut self, peer_id: &Uuid) -> Option<PeerConnection> {
        self.peers.remove(peer_id)
    }

    /// Process an incoming signaling message.
    pub fn handle_signal(&mut self, signal: &P2PSignal) -> Result<Option<P2PSignal>> {
        match signal {
            P2PSignal::Offer {
                from,
                candidates,
                ssrc,
                ..
            } => {
                // Ensure peer exists
                if !self.peers.contains_key(from) {
                    self.add_peer(*from, *ssrc)?;
                }

                let peer = self.peers.get_mut(from).unwrap();
                for candidate in candidates {
                    peer.add_remote_candidate(candidate.clone());
                }

                // Generate answer (in real implementation, gather local candidates first)
                Ok(Some(P2PSignal::Answer {
                    from: self.local_user_id,
                    to: *from,
                    channel_id: self.channel_id,
                    ssrc: self.local_ssrc,
                    candidates: peer.local_candidates.clone(),
                }))
            }
            P2PSignal::Answer {
                from, candidates, ..
            } => {
                if let Some(peer) = self.peers.get_mut(from) {
                    for candidate in candidates {
                        peer.add_remote_candidate(candidate.clone());
                    }
                }
                Ok(None)
            }
            P2PSignal::IceTrickle {
                from, candidate, ..
            } => {
                if let Some(peer) = self.peers.get_mut(from) {
                    peer.add_remote_candidate(candidate.clone());
                }
                Ok(None)
            }
            P2PSignal::FallbackToRelay { from, .. } => {
                if let Some(peer) = self.peers.get_mut(from) {
                    peer.state = PeerConnectionState::RelayFallback;
                }
                // If all peers are relay, switch the whole session
                if self
                    .peers
                    .values()
                    .all(|p| p.state == PeerConnectionState::RelayFallback)
                {
                    self.relay_mode = true;
                }
                Ok(None)
            }
        }
    }

    /// Encrypt an audio frame and return packets for each connected peer.
    /// For relay-mode peers, the caller should route through the server.
    pub fn encrypt_for_all(&mut self, audio: &[u8]) -> Vec<(Uuid, SrtpPacket, bool)> {
        let mut results = Vec::new();
        // We need to collect peer IDs first to avoid borrow issues
        let peer_ids: Vec<Uuid> = self.peers.keys().copied().collect();

        for peer_id in peer_ids {
            let peer = self.peers.get_mut(&peer_id).unwrap();
            let is_relay = peer.state == PeerConnectionState::RelayFallback;
            match peer.encrypt_frame(audio) {
                Ok(packet) => results.push((peer_id, packet, is_relay)),
                Err(_) => continue, // skip peers with SRTP errors
            }
        }
        results
    }

    /// Get the number of connected peers (P2P or relay).
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get all peers in a specific state.
    pub fn peers_in_state(&self, state: PeerConnectionState) -> Vec<Uuid> {
        self.peers
            .iter()
            .filter(|(_, p)| p.state == state)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Check consent freshness for all connected peers.
    pub fn check_consent(&mut self, now_ms: u64) -> Vec<Uuid> {
        let mut expired = Vec::new();
        for (id, peer) in &mut self.peers {
            if peer.state == PeerConnectionState::Connected && peer.is_consent_expired(now_ms) {
                peer.state = PeerConnectionState::RelayFallback;
                expired.push(*id);
            }
        }
        expired
    }

    /// Tear down the session, closing all peer connections.
    pub fn close(&mut self) {
        for peer in self.peers.values_mut() {
            peer.state = PeerConnectionState::Disconnected;
        }
        self.peers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_voice_key() -> VoiceSessionKey {
        VoiceSessionKey::derive(&[42u8; 32], &[1u8; 16])
    }

    fn test_session() -> VoiceMeshSession {
        VoiceMeshSession::new(Uuid::new_v4(), Uuid::new_v4(), 1000, test_voice_key())
    }

    // ── Mesh topology tests ──────────────────────────────────────────────

    #[test]
    fn test_add_peers_up_to_max() {
        let mut session = test_session();

        // Can add up to MAX_P2P_PEERS - 1 peers (self counts as 1)
        for i in 0..(MAX_P2P_PEERS - 1) {
            assert!(
                session.add_peer(Uuid::new_v4(), 2000 + i as u32).is_ok(),
                "Failed to add peer {}",
                i
            );
        }

        // One more should fail
        assert!(session.add_peer(Uuid::new_v4(), 9999).is_err());
    }

    #[test]
    fn test_duplicate_peer_rejected() {
        let mut session = test_session();
        let peer_id = Uuid::new_v4();

        assert!(session.add_peer(peer_id, 2000).is_ok());
        assert!(session.add_peer(peer_id, 2000).is_err());
    }

    #[test]
    fn test_remove_peer() {
        let mut session = test_session();
        let peer_id = Uuid::new_v4();

        session.add_peer(peer_id, 2000).unwrap();
        assert_eq!(session.peer_count(), 1);

        session.remove_peer(&peer_id);
        assert_eq!(session.peer_count(), 0);
    }

    #[test]
    fn test_close_session() {
        let mut session = test_session();
        session.add_peer(Uuid::new_v4(), 2000).unwrap();
        session.add_peer(Uuid::new_v4(), 3000).unwrap();

        session.close();
        assert_eq!(session.peer_count(), 0);
    }

    // ── SRTP integration tests ───────────────────────────────────────────

    #[test]
    fn test_encrypt_decrypt_between_peers() {
        let voice_key = test_voice_key();
        let channel_id = Uuid::new_v4();
        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();

        let mut session_a = VoiceMeshSession::new(channel_id, user_a, 1000, voice_key.clone());
        let mut session_b = VoiceMeshSession::new(channel_id, user_b, 2000, voice_key);

        session_a.add_peer(user_b, 2000).unwrap();
        session_b.add_peer(user_a, 1000).unwrap();

        // A encrypts audio
        let audio = vec![42u8; 160]; // 10ms of 16kHz mono
        let packets = session_a.encrypt_for_all(&audio);
        assert_eq!(packets.len(), 1);

        let (target, packet, _relay) = &packets[0];
        assert_eq!(*target, user_b);

        // B receives and decrypts
        let peer_a = session_b.peers.get_mut(&user_a).unwrap();
        peer_a.receive_packet(packet, 0).unwrap();
    }

    #[test]
    fn test_encrypt_for_all_multiple_peers() {
        let mut session = test_session();
        let peer1 = Uuid::new_v4();
        let peer2 = Uuid::new_v4();

        session.add_peer(peer1, 2000).unwrap();
        session.add_peer(peer2, 3000).unwrap();

        let audio = vec![1u8; 100];
        let packets = session.encrypt_for_all(&audio);

        assert_eq!(packets.len(), 2);
    }

    // ── Signaling tests ──────────────────────────────────────────────────

    #[test]
    fn test_offer_answer_flow() {
        let voice_key = test_voice_key();
        let channel_id = Uuid::new_v4();
        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();

        let mut session_b = VoiceMeshSession::new(channel_id, user_b, 2000, voice_key);

        let offer = P2PSignal::Offer {
            from: user_a,
            to: user_b,
            channel_id,
            ssrc: 1000,
            candidates: vec![IceCandidate::host("192.168.1.1:5000".parse().unwrap())],
        };

        let response = session_b.handle_signal(&offer).unwrap();
        assert!(response.is_some());

        // Should have added user_a as a peer
        assert!(session_b.peers.contains_key(&user_a));

        // The peer should have the remote candidate
        let peer = session_b.peers.get(&user_a).unwrap();
        assert_eq!(peer.remote_candidates.len(), 1);
    }

    #[test]
    fn test_ice_trickle() {
        let mut session = test_session();
        let peer_id = Uuid::new_v4();
        session.add_peer(peer_id, 2000).unwrap();

        let trickle = P2PSignal::IceTrickle {
            from: peer_id,
            to: session.local_user_id,
            channel_id: session.channel_id,
            candidate: IceCandidate::server_reflexive("1.2.3.4:9000".parse().unwrap()),
        };

        session.handle_signal(&trickle).unwrap();

        let peer = session.peers.get(&peer_id).unwrap();
        assert_eq!(peer.remote_candidates.len(), 1);
        assert_eq!(
            peer.remote_candidates[0].candidate_type,
            CandidateType::ServerReflexive
        );
    }

    // ── Fallback tests ───────────────────────────────────────────────────

    #[test]
    fn test_fallback_to_relay_on_failure() {
        let mut session = test_session();
        let peer_id = Uuid::new_v4();
        session.add_peer(peer_id, 2000).unwrap();

        let peer = session.peers.get_mut(&peer_id).unwrap();

        // Simulate ICE check failures
        for _ in 0..ICE_MAX_CHECK_ATTEMPTS {
            peer.on_check_failure();
        }

        assert_eq!(peer.state, PeerConnectionState::RelayFallback);
    }

    #[test]
    fn test_relay_flag_in_encrypt() {
        let mut session = test_session();
        let peer_id = Uuid::new_v4();
        session.add_peer(peer_id, 2000).unwrap();

        // Force relay mode
        session.peers.get_mut(&peer_id).unwrap().state = PeerConnectionState::RelayFallback;

        let packets = session.encrypt_for_all(&[0u8; 100]);
        assert_eq!(packets.len(), 1);
        assert!(packets[0].2); // is_relay = true
    }

    #[test]
    fn test_all_peers_relay_triggers_session_relay() {
        let mut session = test_session();
        let peer1 = Uuid::new_v4();
        let peer2 = Uuid::new_v4();
        session.add_peer(peer1, 2000).unwrap();
        session.add_peer(peer2, 3000).unwrap();

        // Both peers signal fallback
        for peer_id in [peer1, peer2] {
            let sig = P2PSignal::FallbackToRelay {
                from: peer_id,
                channel_id: session.channel_id,
            };
            session.handle_signal(&sig).unwrap();
        }

        assert!(session.relay_mode);
    }

    // ── Connection state tests ───────────────────────────────────────────

    #[test]
    fn test_peer_connection_state_transitions() {
        let mut conn = PeerConnection::new(Uuid::new_v4());
        assert_eq!(conn.state, PeerConnectionState::Gathering);

        // Add local candidates
        conn.local_candidates
            .push(IceCandidate::host("0.0.0.0:5000".parse().unwrap()));

        // Add remote candidate → transitions to Checking
        conn.add_remote_candidate(IceCandidate::host("1.2.3.4:5000".parse().unwrap()));
        assert_eq!(conn.state, PeerConnectionState::Checking);

        // Successful check → Connected
        conn.on_check_success(
            IceCandidate::host("0.0.0.0:5000".parse().unwrap()),
            IceCandidate::host("1.2.3.4:5000".parse().unwrap()),
            25.0,
            1000,
        );
        assert_eq!(conn.state, PeerConnectionState::Connected);
        assert_eq!(conn.rtt_ms, Some(25.0));
    }

    #[test]
    fn test_consent_expiry() {
        let mut conn = PeerConnection::new(Uuid::new_v4());
        conn.state = PeerConnectionState::Connected;
        conn.last_consent_ms = Some(0);

        // Not expired yet
        assert!(!conn.is_consent_expired(CONSENT_INTERVAL_MS));

        // Expired
        assert!(conn.is_consent_expired(CONSENT_INTERVAL_MS * 3));
    }

    #[test]
    fn test_consent_check_triggers_fallback() {
        let mut session = test_session();
        let peer_id = Uuid::new_v4();
        session.add_peer(peer_id, 2000).unwrap();

        let peer = session.peers.get_mut(&peer_id).unwrap();
        peer.state = PeerConnectionState::Connected;
        peer.last_consent_ms = Some(0);

        let expired = session.check_consent(CONSENT_INTERVAL_MS * 3);
        assert_eq!(expired, vec![peer_id]);
        assert_eq!(
            session.peers.get(&peer_id).unwrap().state,
            PeerConnectionState::RelayFallback
        );
    }

    // ── ICE candidate tests ──────────────────────────────────────────────

    #[test]
    fn test_candidate_priorities() {
        let host = IceCandidate::host("0.0.0.0:5000".parse().unwrap());
        let srflx = IceCandidate::server_reflexive("1.2.3.4:5000".parse().unwrap());
        let relay = IceCandidate::relay("5.6.7.8:5000".parse().unwrap());

        assert!(host.priority > srflx.priority);
        assert!(srflx.priority > relay.priority);
    }

    // ── STUN message tests ───────────────────────────────────────────────

    #[test]
    fn test_stun_binding_request_format() {
        let req = StunBindingRequest::new();
        let bytes = req.to_bytes();

        assert_eq!(bytes.len(), 20);
        // Message type
        assert_eq!(
            u16::from_be_bytes([bytes[0], bytes[1]]),
            STUN_BINDING_REQUEST
        );
        // Length = 0
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0);
        // Magic cookie
        assert_eq!(
            u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            STUN_MAGIC_COOKIE
        );
        // Transaction ID matches
        assert_eq!(&bytes[8..20], &req.transaction_id);
    }

    #[test]
    fn test_stun_response_parse() {
        // Construct a minimal STUN Binding Response with XOR-MAPPED-ADDRESS
        let mut data = Vec::new();
        // Header
        data.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        data.extend_from_slice(&12u16.to_be_bytes()); // msg length = 12 (1 attribute)
        data.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        let tid = [1u8; 12];
        data.extend_from_slice(&tid);

        // XOR-MAPPED-ADDRESS attribute
        data.extend_from_slice(&0x0020u16.to_be_bytes()); // type
        data.extend_from_slice(&8u16.to_be_bytes()); // length
        data.push(0x00); // reserved
        data.push(0x01); // family = IPv4
                         // Port 5000 XOR'd with 0x2112
        let xor_port = 5000u16 ^ 0x2112;
        data.extend_from_slice(&xor_port.to_be_bytes());
        // IP 192.168.1.1 XOR'd with magic cookie
        let ip: u32 = u32::from_be_bytes([192, 168, 1, 1]);
        let xor_ip = ip ^ STUN_MAGIC_COOKIE;
        data.extend_from_slice(&xor_ip.to_be_bytes());

        let resp = StunBindingResponse::parse(&data).unwrap();
        assert_eq!(resp.transaction_id, tid);
        let addr = resp.mapped_address.unwrap();
        assert_eq!(addr.ip().to_string(), "192.168.1.1");
        assert_eq!(addr.port(), 5000);
    }

    // ── Jitter buffer integration ────────────────────────────────────────

    #[test]
    fn test_peer_receive_and_pull_audio() {
        let voice_key = test_voice_key();
        let mut peer_a_enc = VoiceEncryptor::new(1000, voice_key.clone());
        let mut peer_b = PeerConnection::new(Uuid::new_v4());
        peer_b.init_srtp(2000, 1000, voice_key);

        // Send 5 packets
        for i in 0u64..5 {
            let audio = vec![(i & 0xFF) as u8; 160];
            let packet = peer_a_enc.encrypt_packet(&audio).unwrap();
            peer_b.receive_packet(&packet, i * 20).unwrap();
        }

        // Pull — initial fill then actual frames
        // With default min_delay_frames=2, first pull might be None or the first frame
        let mut pulled = Vec::new();
        for _ in 0..5 {
            if let Some(frame) = peer_b.pull_audio() {
                pulled.push(frame);
            }
        }
        assert!(!pulled.is_empty());
    }

    #[test]
    fn test_peers_in_state() {
        let mut session = test_session();
        let p1 = Uuid::new_v4();
        let p2 = Uuid::new_v4();
        session.add_peer(p1, 2000).unwrap();
        session.add_peer(p2, 3000).unwrap();

        session.peers.get_mut(&p1).unwrap().state = PeerConnectionState::Connected;

        let connected = session.peers_in_state(PeerConnectionState::Connected);
        assert_eq!(connected, vec![p1]);
    }

    // ── Voice Privacy & Consent tests ────────────────────────────────────

    #[test]
    fn test_default_privacy_is_always_relay() {
        let config = VoicePrivacyConfig::default();
        assert_eq!(config.mode, VoicePrivacyMode::AlwaysRelay);
        assert!(!config.allows_p2p("somehash", true));
        assert!(!config.allows_p2p("somehash", false));
    }

    #[test]
    fn test_friends_only_mode() {
        let config = VoicePrivacyConfig {
            mode: VoicePrivacyMode::FriendsOnly,
            ..Default::default()
        };
        assert!(config.allows_p2p("friend_hash", true));
        assert!(!config.allows_p2p("stranger_hash", false));
    }

    #[test]
    fn test_whitelist_mode() {
        let mut whitelist = HashSet::new();
        whitelist.insert("allowed_hash".to_string());
        let config = VoicePrivacyConfig {
            mode: VoicePrivacyMode::Whitelist,
            p2p_whitelist: whitelist,
            ..Default::default()
        };
        assert!(config.allows_p2p("allowed_hash", false));
        assert!(!config.allows_p2p("other_hash", true));
    }

    #[test]
    fn test_everyone_mode() {
        let config = VoicePrivacyConfig {
            mode: VoicePrivacyMode::Everyone,
            ..Default::default()
        };
        assert!(config.allows_p2p("anyone", false));
    }

    #[test]
    fn test_blocklist_overrides_all_modes() {
        let mut blocklist = HashSet::new();
        blocklist.insert("blocked_hash".to_string());

        for mode in [
            VoicePrivacyMode::FriendsOnly,
            VoicePrivacyMode::Everyone,
            VoicePrivacyMode::Whitelist,
        ] {
            let mut whitelist = HashSet::new();
            whitelist.insert("blocked_hash".to_string());
            let config = VoicePrivacyConfig {
                mode,
                p2p_whitelist: whitelist,
                p2p_blocklist: blocklist.clone(),
            };
            assert!(
                !config.allows_p2p("blocked_hash", true),
                "Blocklist should override mode {:?}",
                config.mode,
            );
        }
    }

    #[test]
    fn test_mutual_consent_both_allow() {
        let config_a = VoicePrivacyConfig {
            mode: VoicePrivacyMode::Everyone,
            ..Default::default()
        };
        let config_b = VoicePrivacyConfig {
            mode: VoicePrivacyMode::Everyone,
            ..Default::default()
        };
        assert!(check_p2p_consent(&config_a, "a", &config_b, "b", false));
    }

    #[test]
    fn test_mutual_consent_one_denies() {
        let config_a = VoicePrivacyConfig {
            mode: VoicePrivacyMode::Everyone,
            ..Default::default()
        };
        let config_b = VoicePrivacyConfig {
            mode: VoicePrivacyMode::AlwaysRelay,
            ..Default::default()
        };
        assert!(!check_p2p_consent(&config_a, "a", &config_b, "b", false));
    }

    #[test]
    fn test_mutual_consent_friends_only_symmetric() {
        let config = VoicePrivacyConfig {
            mode: VoicePrivacyMode::FriendsOnly,
            ..Default::default()
        };
        // Both friends → P2P
        assert!(check_p2p_consent(&config, "a", &config, "b", true));
        // Not friends → relay
        assert!(!check_p2p_consent(&config, "a", &config, "b", false));
    }

    #[test]
    fn test_hybrid_routing_in_session() {
        let voice_key = test_voice_key();
        let channel_id = Uuid::new_v4();
        let local_id = Uuid::new_v4();

        let privacy_everyone = VoicePrivacyConfig {
            mode: VoicePrivacyMode::Everyone,
            ..Default::default()
        };
        let privacy_relay = VoicePrivacyConfig::default();

        let mut session = VoiceMeshSession::with_privacy(
            channel_id,
            local_id,
            1000,
            voice_key,
            privacy_everyone.clone(),
        );

        let peer_p2p = Uuid::new_v4();
        let peer_relay = Uuid::new_v4();

        session.add_peer(peer_p2p, 2000).unwrap();
        session.add_peer(peer_relay, 3000).unwrap();

        // peer_p2p also has Everyone → mutual consent → P2P
        let r1 = session.decide_routing(peer_p2p, &privacy_everyone, "local", "peer1", false);
        assert_eq!(r1, PairRouting::DirectP2P);

        // peer_relay has AlwaysRelay → no consent → Relay
        let r2 = session.decide_routing(peer_relay, &privacy_relay, "local", "peer2", false);
        assert_eq!(r2, PairRouting::Relay);

        // Both peers exist in same session with different routing
        assert_eq!(session.get_routing(&peer_p2p), PairRouting::DirectP2P);
        assert_eq!(session.get_routing(&peer_relay), PairRouting::Relay);

        let p2p_peers = session.peers_by_routing(PairRouting::DirectP2P);
        assert_eq!(p2p_peers, vec![peer_p2p]);
        let relay_peers = session.peers_by_routing(PairRouting::Relay);
        assert_eq!(relay_peers, vec![peer_relay]);
    }

    #[test]
    fn test_unknown_peer_defaults_to_relay() {
        let session = test_session();
        assert_eq!(session.get_routing(&Uuid::new_v4()), PairRouting::Relay);
    }

    #[test]
    fn test_p2p_warning_constant() {
        assert!(P2P_WARNING.contains("IP address"));
    }
}
