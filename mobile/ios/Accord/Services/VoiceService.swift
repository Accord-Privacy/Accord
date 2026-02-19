// VoiceService.swift — WebRTC voice channel service
// Privacy-first: relay-routed by default, P2P is opt-in.

import Foundation
import Combine
import WebRTC
import AVFoundation

// MARK: - Voice Connection State

enum VoiceConnectionState: String {
    case disconnected
    case connecting
    case connected
}

// MARK: - Peer Connection Wrapper

private final class PeerEntry {
    let pc: RTCPeerConnection
    var makingOffer = false
    var ignoreOffer = false
    var remoteAudioTrack: RTCAudioTrack?

    init(pc: RTCPeerConnection) {
        self.pc = pc
    }
}

// MARK: - VoiceService

@Observable
final class VoiceService: NSObject {
    var state = VoiceState()
    var connectionState: VoiceConnectionState = .disconnected

    // Dependencies
    private weak var webSocketService: WebSocketService?
    private var userId: String = ""

    // WebRTC
    private static let factory: RTCPeerConnectionFactory = {
        RTCInitializeSSL()
        let encoderFactory = RTCDefaultVideoEncoderFactory()
        let decoderFactory = RTCDefaultVideoDecoderFactory()
        return RTCPeerConnectionFactory(encoderFactory: encoderFactory, decoderFactory: decoderFactory)
    }()

    private var localAudioTrack: RTCAudioTrack?
    private var peers: [String: PeerEntry] = [:] // userId → PeerEntry

    // VAD
    private var vadTimer: Timer?
    private var isSpeaking = false
    private let vadThreshold: Float = 0.015

    // Subscriptions
    private var cancellables = Set<AnyCancellable>()

    // ICE servers — STUN only (relay-routed via server, not TURN)
    private let iceServers: [RTCIceServer] = [
        RTCIceServer(urlStrings: ["stun:stun.l.google.com:19302"]),
        RTCIceServer(urlStrings: ["stun:stun1.l.google.com:19302"]),
    ]

    // MARK: - Configuration

    func configure(webSocketService: WebSocketService, userId: String) {
        self.webSocketService = webSocketService
        self.userId = userId
        subscribeToWSMessages()
    }

    // MARK: - Join / Leave

    func joinChannel(channelId: String) async throws {
        guard let ws = webSocketService else { return }

        connectionState = .connecting
        state.currentChannelId = channelId

        // Configure audio session
        configureAudioSession()

        // Create local audio track
        let audioSource = Self.factory.audioSource(with: audioConstraints())
        let audioTrack = Self.factory.audioTrack(with: audioSource, trackId: "audio0")
        audioTrack.isEnabled = !state.isSelfMuted
        localAudioTrack = audioTrack

        // Join via WS — server responds with participant list
        try await ws.joinVoiceChannel(channelId: channelId)

        connectionState = .connected
        state.isConnected = true

        // Start VAD
        startVAD()
    }

    func leaveChannel() {
        guard let channelId = state.currentChannelId, let ws = webSocketService else { return }

        // Signal leave
        Task {
            try? await ws.leaveVoiceChannel(channelId: channelId)
        }

        // Teardown
        stopVAD()
        closeAllPeers()

        localAudioTrack = nil

        // Deactivate audio session
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)

        // Reset state
        state.currentChannelId = nil
        state.participants = []
        state.isConnected = false
        state.isSelfMuted = false
        state.isSelfDeafened = false
        connectionState = .disconnected
    }

    // MARK: - Mute / Deafen

    func toggleMute() {
        state.isSelfMuted.toggle()
        localAudioTrack?.isEnabled = !state.isSelfMuted

        if state.isSelfMuted && isSpeaking {
            isSpeaking = false
            sendSpeakingState(false)
        }
    }

    func toggleDeafen() {
        state.isSelfDeafened.toggle()
        if state.isSelfDeafened {
            state.isSelfMuted = true
            localAudioTrack?.isEnabled = false
        }

        // Mute/unmute all remote audio tracks
        for (_, entry) in peers {
            entry.remoteAudioTrack?.isEnabled = !state.isSelfDeafened
        }
    }

    // MARK: - WebSocket Subscription

    private func subscribeToWSMessages() {
        webSocketService?.messagePublisher
            .receive(on: DispatchQueue.main)
            .sink { [weak self] msg in
                self?.handleWSMessage(msg)
            }
            .store(in: &cancellables)
    }

    private func handleWSMessage(_ msg: WSIncomingMessage) {
        guard let channelId = state.currentChannelId else { return }

        switch msg {
        case .voiceChannelJoined(let ch, let participants):
            guard ch == channelId else { return }
            // Create peer connections to all existing participants (we offer)
            for peerId in participants where peerId != userId {
                createPeerConnection(peerId: peerId, createOffer: true)
                addParticipant(userId: peerId)
            }

        case .voicePeerJoined(let ch, let peerId):
            guard ch == channelId, peerId != userId else { return }
            addParticipant(userId: peerId)
            // New peer will offer to us based on server's participant list

        case .voicePeerLeft(let ch, let peerId):
            guard ch == channelId else { return }
            removePeer(peerId)
            state.participants.removeAll { $0.id == peerId }

        case .voiceSignaling(let ch, let fromUserId, _, let data):
            guard ch == channelId else { return }
            handleSignaling(from: fromUserId, rawJSON: data)

        case .voiceSpeakingState(let ch, let uid, let speaking):
            guard ch == channelId else { return }
            if let idx = state.participants.firstIndex(where: { $0.id == uid }) {
                state.participants[idx].isSpeaking = speaking
            }

        default:
            break
        }
    }

    // MARK: - Peer Connection Management

    private func createPeerConnection(peerId: String, createOffer: Bool) {
        // Close existing
        if let existing = peers[peerId] {
            existing.pc.close()
        }

        let config = RTCConfiguration()
        config.iceServers = iceServers
        config.sdpSemantics = .unifiedPlan
        config.continualGatheringPolicy = .gatherContinually
        // Relay-first: prefer relay candidates
        config.iceTransportPolicy = .relay

        let constraints = RTCMediaConstraints(mandatoryConstraints: nil, optionalConstraints: nil)
        guard let pc = Self.factory.peerConnection(with: config, constraints: constraints, delegate: nil) else {
            print("[Voice] Failed to create peer connection for \(peerId)")
            return
        }

        let entry = PeerEntry(pc: pc)
        peers[peerId] = entry

        // Add local audio track
        if let audioTrack = localAudioTrack {
            pc.add(audioTrack, streamIds: ["stream0"])
        }

        // Set delegate (using wrapper to route per-peer)
        let delegate = PeerConnectionDelegate(service: self, peerId: peerId)
        pc.delegate = delegate
        // Store delegate ref to prevent dealloc
        objc_setAssociatedObject(pc, "delegate", delegate, .OBJC_ASSOCIATION_RETAIN)

        if createOffer {
            // Trigger offer creation
            createOffer(for: peerId, pc: pc)
        }
    }

    private func createOffer(for peerId: String, pc: RTCPeerConnection) {
        guard let entry = peers[peerId] else { return }
        entry.makingOffer = true

        let constraints = RTCMediaConstraints(
            mandatoryConstraints: ["OfferToReceiveAudio": "true"],
            optionalConstraints: nil
        )
        pc.offer(for: constraints) { [weak self] sdp, error in
            guard let self, let sdp, error == nil else {
                self?.peers[peerId]?.makingOffer = false
                return
            }
            pc.setLocalDescription(sdp) { error in
                guard error == nil else {
                    self.peers[peerId]?.makingOffer = false
                    return
                }
                self.peers[peerId]?.makingOffer = false
                self.sendSignal(to: peerId, signal: [
                    "type": "sdp",
                    "sdp": ["type": sdp.type == .offer ? "offer" : "answer", "sdp": sdp.sdp]
                ])
            }
        }
    }

    private func handleSignaling(from peerId: String, rawJSON: String) {
        guard let data = rawJSON.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }

        // Extract signal_data if it's a P2P signal envelope, or parse inline
        let signalData: [String: Any]
        if let sd = json["signal_data"] as? String,
           let sdData = sd.data(using: .utf8),
           let parsed = try? JSONSerialization.jsonObject(with: sdData) as? [String: Any] {
            signalData = parsed
        } else {
            signalData = json
        }

        var entry = peers[peerId]
        if entry == nil {
            createPeerConnection(peerId: peerId, createOffer: false)
            entry = peers[peerId]
            addParticipant(userId: peerId)
        }
        guard let entry else { return }

        let pc = entry.pc
        let polite = userId < peerId // Polite peer pattern

        if let type = signalData["type"] as? String, type == "sdp",
           let sdpDict = signalData["sdp"] as? [String: Any] ?? signalData["sdp"] as? [String: String],
           let sdpType = sdpDict["type"] as? String,
           let sdpString = sdpDict["sdp"] as? String {

            let rtcType: RTCSdpType = sdpType == "offer" ? .offer : .answer
            let remoteSDP = RTCSessionDescription(type: rtcType, sdp: sdpString)

            let isOffer = rtcType == .offer
            let offerCollision = isOffer && (entry.makingOffer || pc.signalingState != .stable)
            entry.ignoreOffer = !polite && offerCollision
            if entry.ignoreOffer { return }

            pc.setRemoteDescription(remoteSDP) { [weak self] error in
                guard error == nil else { return }
                if isOffer {
                    let constraints = RTCMediaConstraints(
                        mandatoryConstraints: ["OfferToReceiveAudio": "true"],
                        optionalConstraints: nil
                    )
                    pc.answer(for: constraints) { answer, error in
                        guard let answer, error == nil else { return }
                        pc.setLocalDescription(answer) { error in
                            guard error == nil else { return }
                            self?.sendSignal(to: peerId, signal: [
                                "type": "sdp",
                                "sdp": ["type": "answer", "sdp": answer.sdp]
                            ])
                        }
                    }
                }
            }
        } else if let type = signalData["type"] as? String, type == "ice-candidate",
                  let candidateDict = signalData["candidate"] as? [String: Any],
                  let sdp = candidateDict["candidate"] as? String ?? candidateDict["sdp"] as? String {
            let sdpMLineIndex = candidateDict["sdpMLineIndex"] as? Int32 ?? 0
            let sdpMid = candidateDict["sdpMid"] as? String
            let candidate = RTCIceCandidate(sdp: sdp, sdpMLineIndex: sdpMLineIndex, sdpMid: sdpMid)
            pc.add(candidate) { error in
                if let error, !entry.ignoreOffer {
                    print("[Voice] ICE candidate error: \(error)")
                }
            }
        }
    }

    private func sendSignal(to peerId: String, signal: [String: Any]) {
        guard let channelId = state.currentChannelId, let ws = webSocketService else { return }
        guard let signalData = try? JSONSerialization.data(withJSONObject: signal),
              let signalString = String(data: signalData, encoding: .utf8) else { return }
        Task {
            try? await ws.sendP2PSignal(channelId: channelId, targetUserId: peerId, signalData: signalString)
        }
    }

    private func removePeer(_ peerId: String) {
        if let entry = peers.removeValue(forKey: peerId) {
            entry.pc.close()
        }
    }

    private func closeAllPeers() {
        for (_, entry) in peers {
            entry.pc.close()
        }
        peers.removeAll()
    }

    private func addParticipant(userId: String) {
        guard !state.participants.contains(where: { $0.id == userId }) else { return }
        state.participants.append(VoiceParticipant(id: userId, displayName: userId))
    }

    // MARK: - Audio Configuration

    private func configureAudioSession() {
        let session = AVAudioSession.sharedInstance()
        do {
            try session.setCategory(.playAndRecord, mode: .voiceChat, options: [.defaultToSpeaker, .allowBluetooth])
            try session.setActive(true)
        } catch {
            print("[Voice] Audio session error: \(error)")
        }
    }

    private func audioConstraints() -> RTCMediaConstraints {
        RTCMediaConstraints(mandatoryConstraints: nil, optionalConstraints: [
            "googEchoCancellation": "true",
            "googNoiseSuppression": "true",
            "googAutoGainControl": "true",
        ])
    }

    // MARK: - Voice Activity Detection

    private func startVAD() {
        vadTimer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [weak self] _ in
            self?.checkVAD()
        }
    }

    private func stopVAD() {
        vadTimer?.invalidate()
        vadTimer = nil
        if isSpeaking {
            isSpeaking = false
            sendSpeakingState(false)
        }
    }

    private func checkVAD() {
        guard !state.isSelfMuted, let audioTrack = localAudioTrack else {
            if isSpeaking {
                isSpeaking = false
                sendSpeakingState(false)
            }
            return
        }

        // WebRTC provides audio level via RTP stats — simplified check:
        // In production, use RTCPeerConnection.statistics to get audioLevel
        // For now, rely on the audio track being enabled as a proxy
        // Real VAD would use RTCAudioSession or custom audio processing
        let speaking = audioTrack.isEnabled // Placeholder — real impl uses audio level stats
        _ = speaking // Suppress unused warning — VAD requires stats API integration
    }

    private func sendSpeakingState(_ speaking: Bool) {
        guard let channelId = state.currentChannelId, let ws = webSocketService else { return }
        Task {
            try? await ws.sendVoiceSpeakingState(channelId: channelId, userId: userId, speaking: speaking)
        }
    }

    // MARK: - Peer Connection Delegate Callbacks

    fileprivate func peerConnection(peerId: String, didGenerate candidate: RTCIceCandidate) {
        sendSignal(to: peerId, signal: [
            "type": "ice-candidate",
            "candidate": [
                "candidate": candidate.sdp,
                "sdpMLineIndex": candidate.sdpMLineIndex,
                "sdpMid": candidate.sdpMid ?? "",
            ] as [String: Any]
        ])
    }

    fileprivate func peerConnection(peerId: String, didAdd stream: RTCMediaStream) {
        if let audioTrack = stream.audioTracks.first {
            audioTrack.isEnabled = !state.isSelfDeafened
            peers[peerId]?.remoteAudioTrack = audioTrack
        }
    }

    fileprivate func peerConnection(peerId: String, didChange newState: RTCIceConnectionState) {
        DispatchQueue.main.async { [weak self] in
            switch newState {
            case .connected, .completed:
                // Peer is fully connected
                break
            case .failed, .disconnected, .closed:
                self?.removePeer(peerId)
                self?.state.participants.removeAll { $0.id == peerId }
            default:
                break
            }
        }
    }
}

// MARK: - Per-Peer RTCPeerConnectionDelegate

private class PeerConnectionDelegate: NSObject, RTCPeerConnectionDelegate {
    private weak var service: VoiceService?
    private let peerId: String

    init(service: VoiceService, peerId: String) {
        self.service = service
        self.peerId = peerId
    }

    func peerConnection(_ peerConnection: RTCPeerConnection, didChange stateChanged: RTCSignalingState) {}
    func peerConnection(_ peerConnection: RTCPeerConnection, didRemove stream: RTCMediaStream) {}
    func peerConnection(_ peerConnection: RTCPeerConnection, didChange newState: RTCIceGatheringState) {}
    func peerConnection(_ peerConnection: RTCPeerConnection, didRemove candidates: [RTCIceCandidate]) {}
    func peerConnectionShouldNegotiate(_ peerConnection: RTCPeerConnection) {}
    func peerConnection(_ peerConnection: RTCPeerConnection, didOpen dataChannel: RTCDataChannel) {}

    func peerConnection(_ peerConnection: RTCPeerConnection, didGenerate candidate: RTCIceCandidate) {
        service?.peerConnection(peerId: peerId, didGenerate: candidate)
    }

    func peerConnection(_ peerConnection: RTCPeerConnection, didAdd stream: RTCMediaStream) {
        service?.peerConnection(peerId: peerId, didAdd: stream)
    }

    func peerConnection(_ peerConnection: RTCPeerConnection, didChange newState: RTCIceConnectionState) {
        service?.peerConnection(peerId: peerId, didChange: newState)
    }
}
