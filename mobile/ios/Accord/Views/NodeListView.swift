// NodeListView.swift — List of joined Nodes

import SwiftUI

@Observable
final class NodeListViewModel {
    var nodes: [Node] = []
    var isLoading = false
    var errorMessage: String?

    func load(api: APIService?) async {
        guard let api else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            let dtos = try await api.fetchNodes()
            nodes = dtos.map { APIService.nodeFromDTO($0) }
        } catch {
            errorMessage = error.localizedDescription
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
            .refreshable {
                await viewModel.load(api: appState.apiService)
            }
            .overlay {
                if viewModel.isLoading && viewModel.nodes.isEmpty {
                    ProgressView()
                } else if viewModel.nodes.isEmpty {
                    ContentUnavailableView("No Nodes", systemImage: "server.rack", description: Text("Join or create a Node to get started."))
                }
            }
            .task {
                await viewModel.load(api: appState.apiService)
            }
        }
    }
}
