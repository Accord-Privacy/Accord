package com.accord.data.service

import com.accord.data.model.VoiceParticipant
import com.accord.data.model.VoiceState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Voice channel service using WebRTC (via stream-webrtc-android).
 * No Google Play Services dependency.
 */
class VoiceService {
    private val _state = MutableStateFlow(
        VoiceState(channelId = "", isConnected = false)
    )
    val state: StateFlow<VoiceState> = _state.asStateFlow()

    /** Join a voice channel. Sets up WebRTC peer connection. */
    fun join(channelId: String) {
        // TODO: Initialize WebRTC PeerConnectionFactory
        // TODO: Create local audio track from microphone
        // TODO: Signal offer/answer via WebSocket relay
        // TODO: Handle ICE candidates
        _state.value = VoiceState(
            channelId = channelId,
            isConnected = true,
        )
    }

    fun leave() {
        // TODO: Close peer connections and release audio resources
        _state.value = VoiceState(channelId = "", isConnected = false)
    }

    fun toggleMute() {
        _state.value = _state.value.copy(isMuted = !_state.value.isMuted)
        // TODO: Actually mute the local audio track
    }

    fun toggleDeafen() {
        _state.value = _state.value.copy(isDeafened = !_state.value.isDeafened)
        // TODO: Mute remote audio tracks
    }
}
