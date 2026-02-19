package com.accord.data.service

import android.content.Context
import android.media.AudioManager
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import org.json.JSONObject
import org.webrtc.*

/**
 * Voice channel service using WebRTC (stream-webrtc-android).
 * Privacy-first: relay-routed by default, P2P is opt-in.
 */
class VoiceService(
    private val context: Context,
    private val webSocketService: WebSocketService,
    private val userId: String,
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.Default + SupervisorJob()),
) {
    // ── Public state ──────────────────────────────────────────────────

    data class State(
        val channelId: String = "",
        val isConnected: Boolean = false,
        val isMuted: Boolean = false,
        val isDeafened: Boolean = false,
        val participants: List<Participant> = emptyList(),
        val connectionState: ConnectionState = ConnectionState.Disconnected,
    )

    data class Participant(
        val userId: String,
        val displayName: String = "",
        val isMuted: Boolean = false,
        val isSpeaking: Boolean = false,
    )

    enum class ConnectionState { Disconnected, Connecting, Connected }

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state.asStateFlow()

    // ── WebRTC ────────────────────────────────────────────────────────

    private var factory: PeerConnectionFactory? = null
    private var localAudioTrack: AudioTrack? = null
    private var localAudioSource: AudioSource? = null
    private val peers = mutableMapOf<String, PeerEntry>()
    private var wsCollectorJob: Job? = null

    private val iceServers = listOf(
        PeerConnection.IceServer.builder("stun:stun.l.google.com:19302").createIceServer(),
        PeerConnection.IceServer.builder("stun:stun1.l.google.com:19302").createIceServer(),
    )

    private class PeerEntry(
        val pc: PeerConnection,
        var makingOffer: Boolean = false,
        var ignoreOffer: Boolean = false,
        var remoteAudioTrack: AudioTrack? = null,
    )

    // ── Lifecycle ─────────────────────────────────────────────────────

    fun join(channelId: String) {
        _state.value = _state.value.copy(
            channelId = channelId,
            connectionState = ConnectionState.Connecting,
        )

        initFactory()
        requestAudioFocus()
        createLocalAudioTrack()
        subscribeToWS()

        // Signal join via WS
        webSocketService.joinVoiceChannel(channelId)

        _state.value = _state.value.copy(
            isConnected = true,
            connectionState = ConnectionState.Connected,
        )
    }

    fun leave() {
        val channelId = _state.value.channelId
        if (channelId.isNotEmpty()) {
            webSocketService.leaveVoiceChannel(channelId)
        }

        wsCollectorJob?.cancel()
        wsCollectorJob = null
        closeAllPeers()

        localAudioTrack?.dispose()
        localAudioTrack = null
        localAudioSource?.dispose()
        localAudioSource = null

        abandonAudioFocus()

        _state.value = State()
    }

    fun toggleMute() {
        val newMuted = !_state.value.isMuted
        _state.value = _state.value.copy(isMuted = newMuted)
        localAudioTrack?.setEnabled(!newMuted)
    }

    fun toggleDeafen() {
        val newDeafened = !_state.value.isDeafened
        _state.value = _state.value.copy(
            isDeafened = newDeafened,
            isMuted = if (newDeafened) true else _state.value.isMuted,
        )
        if (newDeafened) {
            localAudioTrack?.setEnabled(false)
        }
        // Mute/unmute all remote audio
        for ((_, entry) in peers) {
            entry.remoteAudioTrack?.setEnabled(!newDeafened)
        }
    }

    // ── WebRTC Factory ────────────────────────────────────────────────

    private fun initFactory() {
        if (factory != null) return
        PeerConnectionFactory.initialize(
            PeerConnectionFactory.InitializationOptions.builder(context)
                .setEnableInternalTracer(false)
                .createInitializationOptions()
        )
        factory = PeerConnectionFactory.builder()
            .setAudioDeviceModule(
                JavaAudioDeviceModule.builder(context)
                    .setUseHardwareAcousticEchoCanceler(true)
                    .setUseHardwareNoiseSuppressor(true)
                    .createAudioDeviceModule()
            )
            .createPeerConnectionFactory()
    }

    private fun createLocalAudioTrack() {
        val f = factory ?: return
        val constraints = MediaConstraints().apply {
            mandatory.add(MediaConstraints.KeyValuePair("googEchoCancellation", "true"))
            mandatory.add(MediaConstraints.KeyValuePair("googNoiseSuppression", "true"))
            mandatory.add(MediaConstraints.KeyValuePair("googAutoGainControl", "true"))
        }
        localAudioSource = f.createAudioSource(constraints)
        localAudioTrack = f.createAudioTrack("audio0", localAudioSource).apply {
            setEnabled(!_state.value.isMuted)
        }
    }

    // ── Audio Focus ───────────────────────────────────────────────────

    private val audioManager get() = context.getSystemService(Context.AUDIO_SERVICE) as AudioManager

    @Suppress("DEPRECATION")
    private fun requestAudioFocus() {
        audioManager.requestAudioFocus(null, AudioManager.STREAM_VOICE_CALL, AudioManager.AUDIOFOCUS_GAIN)
        audioManager.mode = AudioManager.MODE_IN_COMMUNICATION
        audioManager.isSpeakerphoneOn = true
    }

    @Suppress("DEPRECATION")
    private fun abandonAudioFocus() {
        audioManager.abandonAudioFocus(null)
        audioManager.mode = AudioManager.MODE_NORMAL
        audioManager.isSpeakerphoneOn = false
    }

    // ── WS Message Handling ───────────────────────────────────────────

    private fun subscribeToWS() {
        wsCollectorJob?.cancel()
        wsCollectorJob = scope.launch {
            webSocketService.incoming.collect { msg ->
                val channelId = _state.value.channelId
                when (msg) {
                    is WsIncoming.VoicePeerJoined -> {
                        if (msg.channelId == channelId && msg.userId != userId) {
                            addParticipant(msg.userId)
                        }
                    }
                    is WsIncoming.VoicePeerLeft -> {
                        if (msg.channelId == channelId) {
                            removePeer(msg.userId)
                        }
                    }
                    is WsIncoming.VoiceSignaling -> {
                        if (msg.channelId == channelId) {
                            handleSignaling(msg.fromUserId, msg.data)
                        }
                    }
                    else -> {} // voice_channel_joined with participant list handled via signaling
                }
            }
        }

        // Also handle voice_channel_joined (participant list on join)
        scope.launch {
            webSocketService.incoming.collect { msg ->
                if (msg is WsIncoming.Unknown) {
                    val type = msg.raw.optString("type")
                    if (type == "voice_channel_joined" && msg.raw.optString("channel_id") == _state.value.channelId) {
                        val arr = msg.raw.optJSONArray("participants")
                        if (arr != null) {
                            for (i in 0 until arr.length()) {
                                val peerId = arr.optString(i)
                                if (peerId.isNotEmpty() && peerId != userId) {
                                    addParticipant(peerId)
                                    createPeerConnection(peerId, createOffer = true)
                                }
                            }
                        }
                    }
                    // Speaking state
                    if (type == "voice_speaking_state" && msg.raw.optString("channel_id") == _state.value.channelId) {
                        val uid = msg.raw.optString("user_id")
                        val speaking = msg.raw.optBoolean("speaking", false)
                        updateSpeaking(uid, speaking)
                    }
                }
            }
        }
    }

    // ── Peer Connection Management ────────────────────────────────────

    private fun createPeerConnection(peerId: String, createOffer: Boolean) {
        peers[peerId]?.pc?.close()

        val f = factory ?: return
        val config = PeerConnection.RTCConfiguration(iceServers).apply {
            sdpSemantics = PeerConnection.SdpSemantics.UNIFIED_PLAN
            continualGatheringPolicy = PeerConnection.ContinualGatheringPolicy.GATHER_CONTINUALLY
            iceTransportsType = PeerConnection.IceTransportsType.RELAY // Privacy-first: relay only
        }

        val observer = createPeerObserver(peerId)
        val pc = f.createPeerConnection(config, observer) ?: return
        val entry = PeerEntry(pc)
        peers[peerId] = entry

        // Add local audio
        localAudioTrack?.let { pc.addTrack(it, listOf("stream0")) }

        if (createOffer) {
            createOffer(peerId, pc, entry)
        }
    }

    private fun createOffer(peerId: String, pc: PeerConnection, entry: PeerEntry) {
        entry.makingOffer = true
        val constraints = MediaConstraints().apply {
            mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveAudio", "true"))
        }
        pc.createOffer(object : SdpObserverAdapter() {
            override fun onCreateSuccess(sdp: SessionDescription) {
                pc.setLocalDescription(object : SdpObserverAdapter() {
                    override fun onSetSuccess() {
                        entry.makingOffer = false
                        sendSignal(peerId, JSONObject().apply {
                            put("type", "sdp")
                            put("sdp", JSONObject().apply {
                                put("type", sdp.type.canonicalForm())
                                put("sdp", sdp.description)
                            })
                        })
                    }
                    override fun onSetFailure(error: String?) { entry.makingOffer = false }
                }, sdp)
            }
            override fun onCreateFailure(error: String?) { entry.makingOffer = false }
        }, constraints)
    }

    private fun handleSignaling(fromUserId: String, rawJSON: String) {
        val json = try { JSONObject(rawJSON) } catch (_: Exception) { return }

        // Extract signal_data if wrapped
        val signalData = if (json.has("signal_data")) {
            try { JSONObject(json.getString("signal_data")) } catch (_: Exception) { json }
        } else json

        var entry = peers[fromUserId]
        if (entry == null) {
            createPeerConnection(fromUserId, createOffer = false)
            entry = peers[fromUserId]
            addParticipant(fromUserId)
        }
        entry ?: return
        val pc = entry.pc
        val polite = userId < fromUserId

        val type = signalData.optString("type")
        when (type) {
            "sdp" -> {
                val sdpObj = signalData.optJSONObject("sdp") ?: return
                val sdpType = sdpObj.optString("type")
                val sdpString = sdpObj.optString("sdp")
                val rtcType = if (sdpType == "offer") SessionDescription.Type.OFFER else SessionDescription.Type.ANSWER
                val remoteSdp = SessionDescription(rtcType, sdpString)

                val isOffer = rtcType == SessionDescription.Type.OFFER
                val offerCollision = isOffer && (entry.makingOffer || pc.signalingState() != PeerConnection.SignalingState.STABLE)
                entry.ignoreOffer = !polite && offerCollision
                if (entry.ignoreOffer) return

                pc.setRemoteDescription(object : SdpObserverAdapter() {
                    override fun onSetSuccess() {
                        if (isOffer) {
                            val constraints = MediaConstraints().apply {
                                mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveAudio", "true"))
                            }
                            pc.createAnswer(object : SdpObserverAdapter() {
                                override fun onCreateSuccess(sdp: SessionDescription) {
                                    pc.setLocalDescription(object : SdpObserverAdapter() {
                                        override fun onSetSuccess() {
                                            sendSignal(fromUserId, JSONObject().apply {
                                                put("type", "sdp")
                                                put("sdp", JSONObject().apply {
                                                    put("type", "answer")
                                                    put("sdp", sdp.description)
                                                })
                                            })
                                        }
                                    }, sdp)
                                }
                            }, constraints)
                        }
                    }
                }, remoteSdp)
            }
            "ice-candidate" -> {
                val candidateObj = signalData.optJSONObject("candidate") ?: return
                val candidate = IceCandidate(
                    candidateObj.optString("sdpMid", ""),
                    candidateObj.optInt("sdpMLineIndex", 0),
                    candidateObj.optString("candidate", candidateObj.optString("sdp")),
                )
                pc.addIceCandidate(candidate)
            }
        }
    }

    private fun sendSignal(targetUserId: String, signal: JSONObject) {
        val channelId = _state.value.channelId
        val type = JSONObject().apply {
            put("P2PSignal", JSONObject().apply {
                put("channel_id", channelId)
                put("target_user_id", targetUserId)
                put("signal_data", signal.toString())
            })
        }
        val envelope = JSONObject().apply {
            put("message_type", type)
            put("message_id", java.util.UUID.randomUUID().toString())
            put("timestamp", System.currentTimeMillis() / 1000)
        }
        webSocketService.send(envelope.toString())
    }

    private fun createPeerObserver(peerId: String) = object : PeerConnection.Observer {
        override fun onIceCandidate(candidate: IceCandidate) {
            sendSignal(peerId, JSONObject().apply {
                put("type", "ice-candidate")
                put("candidate", JSONObject().apply {
                    put("candidate", candidate.sdp)
                    put("sdpMLineIndex", candidate.sdpMLineIndex)
                    put("sdpMid", candidate.sdpMid ?: "")
                })
            })
        }
        override fun onAddStream(stream: MediaStream) {
            stream.audioTracks.firstOrNull()?.let { track ->
                track.setEnabled(!_state.value.isDeafened)
                peers[peerId]?.remoteAudioTrack = track
            }
        }
        override fun onIceConnectionChange(state: PeerConnection.IceConnectionState) {
            when (state) {
                PeerConnection.IceConnectionState.FAILED,
                PeerConnection.IceConnectionState.DISCONNECTED,
                PeerConnection.IceConnectionState.CLOSED -> {
                    scope.launch(Dispatchers.Main) { removePeer(peerId) }
                }
                else -> {}
            }
        }
        override fun onSignalingChange(state: PeerConnection.SignalingState) {}
        override fun onIceConnectionReceivingChange(receiving: Boolean) {}
        override fun onIceGatheringChange(state: PeerConnection.IceGatheringState) {}
        override fun onRemoveStream(stream: MediaStream) {}
        override fun onDataChannel(dc: DataChannel) {}
        override fun onRenegotiationNeeded() {}
        override fun onAddTrack(receiver: RtpReceiver, streams: Array<out MediaStream>) {}
    }

    private fun removePeer(peerId: String) {
        peers.remove(peerId)?.pc?.close()
        _state.value = _state.value.copy(
            participants = _state.value.participants.filter { it.userId != peerId }
        )
    }

    private fun closeAllPeers() {
        peers.values.forEach { it.pc.close() }
        peers.clear()
    }

    private fun addParticipant(peerId: String) {
        if (_state.value.participants.any { it.userId == peerId }) return
        _state.value = _state.value.copy(
            participants = _state.value.participants + Participant(userId = peerId, displayName = peerId)
        )
    }

    private fun updateSpeaking(userId: String, speaking: Boolean) {
        _state.value = _state.value.copy(
            participants = _state.value.participants.map {
                if (it.userId == userId) it.copy(isSpeaking = speaking) else it
            }
        )
    }
}

/** Convenience adapter for SdpObserver — override only what you need. */
private open class SdpObserverAdapter : SdpObserver {
    override fun onCreateSuccess(sdp: SessionDescription) {}
    override fun onSetSuccess() {}
    override fun onCreateFailure(error: String?) {}
    override fun onSetFailure(error: String?) {}
}
