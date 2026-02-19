// VoiceChannelView.swift — Active voice channel UI with participants

import SwiftUI

struct VoiceChannelView: View {
    let channel: Channel
    @Environment(AppState.self) private var appState
    @State private var voiceService = VoiceService()

    var body: some View {
        VStack(spacing: 24) {
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
                                Text(String(participant.displayName.prefix(1)))
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
            // TODO: Join voice channel via VoiceService
            do {
                try await voiceService.joinChannel(channelId: channel.id)
            } catch {
                // TODO: Error handling
            }
        }
    }
}
