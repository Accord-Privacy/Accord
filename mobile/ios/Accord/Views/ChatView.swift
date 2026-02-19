// ChatView.swift — Message list + input bar for a text channel

import SwiftUI

@Observable
final class ChatViewModel {
    var messages: [Message] = []
    var messageText: String = ""
    var isLoading = false

    func loadMessages(channelId: String, api: APIService?) async {
        guard let api else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            messages = try await api.fetchMessages(channelId: channelId)
        } catch {
            // TODO: Error handling
        }
    }

    func sendMessage(channelId: String, appState: AppState) async {
        let text = messageText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }

        // TODO: Encrypt message via CryptoService before sending
        // TODO: Send via WebSocket or REST API
        // For now, add locally as placeholder
        let msg = Message(
            id: UUID().uuidString,
            channelId: channelId,
            authorId: appState.currentUser?.id ?? "me",
            content: text,
            timestamp: Date(),
            authorName: appState.currentUser?.displayName
        )
        messages.append(msg)
        messageText = ""
    }
}

struct ChatView: View {
    let channel: Channel
    @Environment(AppState.self) private var appState
    @State private var viewModel = ChatViewModel()

    var body: some View {
        VStack(spacing: 0) {
            // Message list
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        ForEach(viewModel.messages) { message in
                            MessageBubble(message: message)
                                .id(message.id)
                        }
                    }
                    .padding()
                }
                .onChange(of: viewModel.messages.count) {
                    if let last = viewModel.messages.last {
                        proxy.scrollTo(last.id, anchor: .bottom)
                    }
                }
            }

            Divider()

            // Input bar
            HStack(spacing: 12) {
                TextField("Message #\(channel.name)", text: $viewModel.messageText, axis: .vertical)
                    .textFieldStyle(.plain)
                    .lineLimit(1...5)

                Button {
                    Task { await viewModel.sendMessage(channelId: channel.id, appState: appState) }
                } label: {
                    Image(systemName: "arrow.up.circle.fill")
                        .font(.title2)
                }
                .disabled(viewModel.messageText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
        }
        .navigationTitle("#\(channel.name)")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            await viewModel.loadMessages(channelId: channel.id, api: appState.apiService)
        }
    }
}

// MARK: - Message Bubble

private struct MessageBubble: View {
    let message: Message

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Text(message.authorName ?? message.authorId)
                    .font(.caption.bold())
                Text(message.timestamp, style: .time)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                if message.isEncrypted {
                    Image(systemName: "lock.fill")
                        .font(.caption2)
                        .foregroundStyle(.green)
                }
            }
            Text(message.content)
                .font(.body)
        }
    }
}
