// DMListView.swift — Direct message conversations

import SwiftUI

@Observable
final class DMListViewModel {
    var conversations: [DMConversation] = []
    var isLoading = false

    struct DMConversation: Identifiable {
        let id: String // channel ID
        let user: User
        let lastMessage: Message?
    }

    func load(appState: AppState) async {
        guard let api = appState.apiService else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            let dtos = try await api.fetchDMChannels()
            conversations = dtos.map { dto in
                let user = User(
                    id: dto.other_user_id ?? "",
                    displayName: dto.other_user_display_name ?? "Unknown"
                )
                let lastMsg = dto.last_message.map { APIService.messageFromDTO($0) }
                return DMConversation(id: dto.id, user: user, lastMessage: lastMsg)
            }
        } catch {
            print("[DMList] Failed to fetch DMs: \(error)")
        }
    }
}

struct DMListView: View {
    @Environment(AppState.self) private var appState
    @State private var viewModel = DMListViewModel()

    var body: some View {
        NavigationStack {
            List(viewModel.conversations) { convo in
                NavigationLink {
                    ChatView(channel: Channel(
                        id: convo.id,
                        name: convo.user.displayName,
                        type: .text,
                        nodeId: "dm",
                        isEncrypted: true
                    ))
                } label: {
                    HStack {
                        Circle()
                            .fill(convo.user.isOnline ? .green : .gray)
                            .frame(width: 10, height: 10)
                        VStack(alignment: .leading) {
                            Text(convo.user.displayName)
                                .font(.headline)
                            if let msg = convo.lastMessage {
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
            .refreshable {
                await viewModel.load(appState: appState)
            }
            .overlay {
                if viewModel.isLoading && viewModel.conversations.isEmpty {
                    ProgressView()
                } else if viewModel.conversations.isEmpty {
                    ContentUnavailableView("No Messages", systemImage: "bubble.left.and.bubble.right", description: Text("Start an encrypted conversation."))
                }
            }
            .task {
                await viewModel.load(appState: appState)
            }
        }
    }
}
