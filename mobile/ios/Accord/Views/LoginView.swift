// LoginView.swift — Keypair generation/import and relay URL input

import SwiftUI

struct LoginView: View {
    @Environment(AppState.self) private var appState
    @State private var relayURL: String = ""
    @State private var displayName: String = ""
    @State private var isGenerating = false
    @State private var showImport = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            VStack(spacing: 32) {
                Spacer()

                // Logo
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 64))
                    .foregroundStyle(.accent)
                Text("Accord")
                    .font(.largeTitle.bold())
                Text("Privacy-first communication")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                Spacer()

                // Inputs
                VStack(spacing: 16) {
                    TextField("Display Name", text: $displayName)
                        .textFieldStyle(.roundedBorder)
                        .textContentType(.name)

                    TextField("Relay URL (e.g. https://relay.example.com)", text: $relayURL)
                        .textFieldStyle(.roundedBorder)
                        .textContentType(.URL)
                        .autocapitalization(.none)
                        .keyboardType(.URL)
                }
                .padding(.horizontal)

                if let error = errorMessage {
                    Text(error)
                        .foregroundStyle(.red)
                        .font(.caption)
                }

                // Actions
                VStack(spacing: 12) {
                    Button {
                        generateAndLogin()
                    } label: {
                        if isGenerating {
                            ProgressView()
                                .frame(maxWidth: .infinity)
                        } else {
                            Text("Generate New Identity")
                                .frame(maxWidth: .infinity)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(relayURL.isEmpty || displayName.isEmpty || isGenerating)

                    Button("Import Existing Key") {
                        showImport = true
                    }
                    .buttonStyle(.bordered)
                }
                .padding(.horizontal)

                Spacer()
            }
            .sheet(isPresented: $showImport) {
                // TODO: Key import UI (paste or scan QR)
                Text("TODO: Import key from backup")
                    .presentationDetents([.medium])
            }
        }
    }

    private func generateAndLogin() {
        isGenerating = true
        errorMessage = nil

        // Generate key material on background thread
        Task.detached {
            let km = KeyMaterial(oneTimePrekeys: 10)
            await MainActor.run {
                appState.login(relayURL: relayURL, keyMaterial: km)
                appState.currentUser = User(
                    id: UUID().uuidString, // TODO: Derive from identity key
                    displayName: displayName
                )
                isGenerating = false
            }
            // TODO: Upload publishable bundle to relay
        }
    }
}
