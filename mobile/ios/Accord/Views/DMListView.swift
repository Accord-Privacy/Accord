// DMListView.swift — Direct message conversations

import SwiftUI

struct DMListView: View {
    @Environment(AppState.self) private var appState
    @State private var conversations: [(User, Message?)] = []

    var body: some View {
        NavigationStack {
            List(conversations, id: \.0.id) { user, lastMessage in
                NavigationLink {
                    // TODO: DM chat view (reuse ChatView with DM channel)
                    ChatView(channel: Channel(
                        id: "dm-\(user.id)",
                        name: user.displayName,
                        type: .text,
                        nodeId: "dm",
                        isEncrypted: true
                    ))
                } label: {
                    HStack {
                        Circle()
                            .fill(user.isOnline ? .green : .gray)
                            .frame(width: 10, height: 10)
                        VStack(alignment: .leading) {
                            Text(user.displayName)
                                .font(.headline)
                            if let msg = lastMessage {
                                Text(msg.content)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Direct Messages")
            .overlay {
                if conversations.isEmpty {
                    ContentUnavailableView("No Messages", systemImage: "bubble.left.and.bubble.right", description: Text("Start an encrypted conversation."))
                }
            }
            .task {
                // TODO: Fetch DM conversations from API
                do {
                    conversations = try await appState.apiService?.fetchDMConversations() ?? []
                } catch {
                    // TODO: Error handling
                }
            }
        }
    }
}
