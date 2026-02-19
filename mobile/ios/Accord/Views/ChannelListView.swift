// ChannelListView.swift — Channels within a Node, grouped by category

import SwiftUI

struct ChannelListView: View {
    let node: Node
    @Environment(AppState.self) private var appState
    @State private var channels: [Channel] = []
    @State private var isLoading = false

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
        .refreshable {
            await fetchChannels()
        }
        .overlay {
            if isLoading && channels.isEmpty {
                ProgressView()
            }
        }
        .task {
            await fetchChannels()
        }
    }

    private func fetchChannels() async {
        guard let api = appState.apiService else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            let dtos = try await api.fetchChannels(nodeId: node.id)
            channels = dtos.map { APIService.channelFromDTO($0) }
        } catch {
            print("[ChannelList] Failed to fetch channels: \(error)")
        }
    }
}
