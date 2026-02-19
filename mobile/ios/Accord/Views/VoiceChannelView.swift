// VoiceChannelView.swift — Active voice channel UI with participants

import SwiftUI

struct VoiceChannelView: View {
    let channel: Channel
    @Environment(AppState.self) private var appState

    /// Use the shared VoiceService from AppState (configured with WS + userId)
    private var voiceService: VoiceService {
        appState.voiceService ?? VoiceService()
    }

    var body: some View {
        VStack(spacing: 24) {
            // Connection state banner
            if voiceService.connectionState == .connecting {
                HStack(spacing: 8) {
                    ProgressView()
                    Text("Connecting…")
                        .foregroundStyle(.secondary)
                }
                .padding(.top, 20)
            }

            // Participants grid
            if voiceService.state.participants.isEmpty && voiceService.state.isConnected {
                Text("No one else is here yet")
                    .foregroundStyle(.secondary)
                    .padding(.top, 40)
            }

            LazyVGrid(columns: [GridItem(.adaptive(minimum: 80))], spacing: 16) {
                ForEach(voiceService.state.participants) { participant in
                    VStack(spacing: 6) {
                        Circle()
                            .fill(participant.isSpeaking ? .green : .secondary.opacity(0.3))
                            .frame(width: 60, height: 60)
                            .overlay {
                                Text(String(participant.displayName.prefix(1)).uppercased())
                                    .font(.title2)
                                    .foregroundStyle(.white)
                            }
                            .overlay(alignment: .bottomTrailing) {
                                if participant.isMuted {
                                    Image(systemName: "mic.slash.fill")
                                        .font(.caption)
                                        .foregroundStyle(.red)
                                        .padding(2)
                                        .background(.ultraThinMaterial, in: Circle())
                                }
                            }
                            .animation(.easeInOut(duration: 0.2), value: participant.isSpeaking)
                        Text(participant.displayName)
                            .font(.caption)
                            .lineLimit(1)
                    }
                }
            }
            .padding()

            Spacer()

            // Controls
            HStack(spacing: 32) {
                Button {
                    voiceService.toggleMute()
                } label: {
                    Image(systemName: voiceService.state.isSelfMuted ? "mic.slash.fill" : "mic.fill")
                        .font(.title2)
                        .frame(width: 56, height: 56)
                        .background(voiceService.state.isSelfMuted ? .red.opacity(0.2) : .secondary.opacity(0.1))
                        .clipShape(Circle())
                }

                Button {
                    voiceService.toggleDeafen()
                } label: {
                    Image(systemName: voiceService.state.isSelfDeafened ? "speaker.slash.fill" : "speaker.wave.2.fill")
                        .font(.title2)
                        .frame(width: 56, height: 56)
                        .background(voiceService.state.isSelfDeafened ? .red.opacity(0.2) : .secondary.opacity(0.1))
                        .clipShape(Circle())
                }

                Button {
                    voiceService.leaveChannel()
                } label: {
                    Image(systemName: "phone.down.fill")
                        .font(.title2)
                        .frame(width: 56, height: 56)
                        .background(.red.opacity(0.2))
                        .clipShape(Circle())
                        .foregroundStyle(.red)
                }
            }
            .padding(.bottom)
        }
        .navigationTitle("🔊 \(channel.name)")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            // Configure VoiceService with WS and user info if not already done
            if let ws = appState.webSocketService, let user = appState.currentUser {
                voiceService.configure(webSocketService: ws, userId: user.id)
            }
            do {
                try await voiceService.joinChannel(channelId: channel.id)
            } catch {
                print("[VoiceChannelView] Failed to join: \(error)")
            }
        }
        .onDisappear {
            // Don't auto-leave — user may navigate away but stay in voice
            // Leave only happens via the disconnect button
        }
    }
}
