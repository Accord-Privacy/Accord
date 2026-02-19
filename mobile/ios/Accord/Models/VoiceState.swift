// VoiceState.swift — Voice channel participation state

import Foundation

struct VoiceParticipant: Identifiable, Hashable {
    let id: String      // User ID
    var displayName: String
    var isMuted: Bool = false
    var isDeafened: Bool = false
    var isSpeaking: Bool = false
}

@Observable
final class VoiceState {
    var isConnected: Bool = false
    var currentChannelId: String?
    var participants: [VoiceParticipant] = []
    var isSelfMuted: Bool = false
    var isSelfDeafened: Bool = false
}
