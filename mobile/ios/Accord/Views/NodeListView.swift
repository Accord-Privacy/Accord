// NodeListView.swift — List of joined Nodes

import SwiftUI

@Observable
final class NodeListViewModel {
    var nodes: [Node] = []
    var isLoading = false

    func load(api: APIService?) async {
        guard let api else { return }
        isLoading = true
        defer { isLoading = false }
        // TODO: Fetch real data
        do {
            nodes = try await api.fetchNodes()
        } catch {
            // TODO: Error handling
        }
    }
}

struct NodeListView: View {
    @Environment(AppState.self) private var appState
    @State private var viewModel = NodeListViewModel()

    var body: some View {
        NavigationStack {
            List(viewModel.nodes) { node in
                NavigationLink(value: node) {
                    HStack {
                        // TODO: Node icon
                        Circle()
                            .fill(.secondary)
                            .frame(width: 40, height: 40)
                            .overlay {
                                Text(String(node.name.prefix(1)))
                                    .font(.headline)
                                    .foregroundStyle(.white)
                            }

                        VStack(alignment: .leading) {
                            Text(node.name)
                                .font(.headline)
                            if let desc = node.description {
                                Text(desc)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Nodes")
            .navigationDestination(for: Node.self) { node in
                ChannelListView(node: node)
            }
            .overlay {
                if viewModel.nodes.isEmpty && !viewModel.isLoading {
                    ContentUnavailableView("No Nodes", systemImage: "server.rack", description: Text("Join or create a Node to get started."))
                }
            }
            .task {
                await viewModel.load(api: appState.apiService)
            }
        }
    }
}
