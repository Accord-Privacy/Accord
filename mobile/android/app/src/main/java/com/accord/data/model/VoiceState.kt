package com.accord.data.model

data class VoiceState(
    val channelId: String,
    val participants: List<VoiceParticipant> = emptyList(),
    val isMuted: Boolean = false,
    val isDeafened: Boolean = false,
    val isConnected: Boolean = false,
)

data class VoiceParticipant(
    val userId: String,
    val displayName: String,
    val isMuted: Boolean = false,
    val isSpeaking: Boolean = false,
)
