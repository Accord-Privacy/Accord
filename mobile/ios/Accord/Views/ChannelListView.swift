// ChannelListView.swift — Channels within a Node, grouped by category

import SwiftUI

struct ChannelListView: View {
    let node: Node
    @Environment(AppState.self) private var appState
    @State private var channels: [Channel] = []

    private var grouped: [(String, [Channel])] {
        let dict = Dictionary(grouping: channels) { $0.category ?? "General" }
        return dict.sorted { $0.key < $1.key }
    }

    var body: some View {
        List {
            ForEach(grouped, id: \.0) { category, channels in
                Section(category.uppercased()) {
                    ForEach(channels) { channel in
                        NavigationLink {
                            if channel.type == .voice {
                                VoiceChannelView(channel: channel)
                            } else {
                                ChatView(channel: channel)
                            }
                        } label: {
                            Label(channel.name, systemImage: channel.type == .voice ? "speaker.wave.2" : "number")
                        }
                    }
                }
            }
        }
        .navigationTitle(node.name)
        .task {
            // TODO: Fetch channels from API
            do {
                channels = try await appState.apiService?.fetchChannels(nodeId: node.id) ?? []
            } catch {
                // TODO: Error handling
            }
        }
    }
}
