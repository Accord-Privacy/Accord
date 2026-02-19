// ChatView.swift — Message list + input bar for a text channel

import SwiftUI
import Combine

@Observable
final class ChatViewModel {
    var messages: [Message] = []
    var messageText: String = ""
    var isLoading = false
    private var cancellable: AnyCancellable?

    func loadMessages(channelId: String, appState: AppState) async {
        guard let api = appState.apiService else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            let resp = try await api.fetchMessages(channelId: channelId)
            let token = appState.authToken ?? ""
            messages = resp.messages.map { dto in
                var msg = APIService.messageFromDTO(dto)
                // Decrypt content
                let encrypted = dto.encrypted_payload ?? dto.encrypted_data ?? ""
                if !encrypted.isEmpty, let crypto = appState.cryptoService {
                    // Determine if DM
                    let isDM = channelId.hasPrefix("dm-") || dto.channel_id?.hasPrefix("dm-") == true
                    if isDM, let senderId = dto.sender_id {
                        if let decrypted = try? crypto.decryptDMMessage(
                            encrypted, peerUserId: senderId, channelId: channelId
                        ) {
                            msg.content = decrypted
                        }
                    } else {
                        if let decrypted = try? crypto.decryptChannelMessage(
                            encrypted, channelId: channelId, token: token
                        ) {
                            msg.content = decrypted
                        }
                    }
                }
                return msg
            }
        } catch {
            print("[Chat] Failed to load messages: \(error)")
        }
    }

    /// Subscribe to real-time incoming messages for this channel.
    func subscribeToIncoming(channelId: String, appState: AppState) {
        // Poll appState.incomingMessages for new messages on this channel.
        // Since AppState is @Observable, SwiftUI will re-render when it changes.
        // We merge incoming messages not already in our list.
        cancellable = Timer.publish(every: 0.5, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                guard let self else { return }
                guard let incoming = appState.incomingMessages[channelId], !incoming.isEmpty else { return }
                let existingIds = Set(self.messages.map(\.id))
                let newMessages = incoming.filter { !existingIds.contains($0.id) }
                if !newMessages.isEmpty {
                    self.messages.append(contentsOf: newMessages)
                }
            }
    }

    func stopSubscription() {
        cancellable?.cancel()
        cancellable = nil
    }

    func sendMessage(channelId: String, appState: AppState) async {
        let text = messageText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        guard let crypto = appState.cryptoService,
              let token = appState.authToken,
              let ws = appState.webSocketService else { return }

        let isDM = channelId.hasPrefix("dm-")

        do {
            let encryptedData: String
            if isDM {
                // Extract peer user ID from DM channel ID
                let peerUserId = String(channelId.dropFirst(3))
                encryptedData = try await crypto.establishAndEncryptDM(
                    text,
                    peerUserId: peerUserId,
                    channelId: channelId,
                    api: appState.apiService!
                )
            } else {
                encryptedData = try crypto.encryptChannelMessage(text, channelId: channelId, token: token)
            }

            try await ws.sendChannelMessage(channelId: channelId, encryptedData: encryptedData)

            // Optimistically add to local messages
            let msg = Message(
                id: UUID().uuidString,
                channelId: channelId,
                authorId: appState.currentUser?.id ?? "me",
                content: text,
                timestamp: Date(),
                authorName: appState.currentUser?.displayName
            )
            await MainActor.run {
                messages.append(msg)
                messageText = ""
            }
        } catch {
            print("[Chat] Send failed: \(error)")
        }
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
                        if viewModel.isLoading {
                            ProgressView()
                                .frame(maxWidth: .infinity)
                                .padding()
                        }
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
            await viewModel.loadMessages(channelId: channel.id, appState: appState)
            viewModel.subscribeToIncoming(channelId: channel.id, appState: appState)
        }
        .onDisappear {
            viewModel.stopSubscription()
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
                if message.isEdited {
                    Text("(edited)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            Text(message.content)
                .font(.body)
        }
    }
}
