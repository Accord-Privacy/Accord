// WebSocketService.swift — WebSocket connection to the Accord relay

import Foundation

/// Handles persistent WebSocket connection to the relay for real-time events.
@Observable
final class WebSocketService {
    private let relayURL: String
    private var webSocketTask: URLSessionWebSocketTask?
    private let session = URLSession(configuration: .default)

    var isConnected: Bool = false

    init(relayURL: String) {
        self.relayURL = relayURL
    }

    // MARK: - Connection

    func connect() {
        // TODO: Add auth token to request headers
        guard let url = URL(string: relayURL.replacingOccurrences(of: "http", with: "ws") + "/ws") else { return }
        let task = session.webSocketTask(with: url)
        self.webSocketTask = task
        task.resume()
        isConnected = true
        listenForMessages()
    }

    func disconnect() {
        webSocketTask?.cancel(with: .goingAway, reason: nil)
        webSocketTask = nil
        isConnected = false
    }

    // MARK: - Send

    func send(_ text: String) async throws {
        guard let task = webSocketTask else { return }
        try await task.send(.string(text))
    }

    func send(_ data: Data) async throws {
        guard let task = webSocketTask else { return }
        try await task.send(.data(data))
    }

    // MARK: - Receive

    /// Handler called when a message arrives. Set by the consumer.
    var onMessage: ((String) -> Void)?
    var onData: ((Data) -> Void)?

    private func listenForMessages() {
        webSocketTask?.receive { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let message):
                switch message {
                case .string(let text):
                    self.onMessage?(text)
                case .data(let data):
                    self.onData?(data)
                @unknown default:
                    break
                }
                self.listenForMessages() // Continue listening
            case .failure:
                // TODO: Implement reconnection with exponential backoff
                self.isConnected = false
            }
        }
    }
}
