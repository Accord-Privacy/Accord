// LoginView.swift — Keypair generation/import and relay URL input

import SwiftUI

struct LoginView: View {
    @Environment(AppState.self) private var appState
    @State private var relayURL: String = ""
    @State private var displayName: String = ""
    @State private var password: String = ""
    @State private var isLoading = false
    @State private var isRegistering = true
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

                // Mode toggle
                Picker("Mode", selection: $isRegistering) {
                    Text("Register").tag(true)
                    Text("Login").tag(false)
                }
                .pickerStyle(.segmented)
                .padding(.horizontal)

                // Inputs
                VStack(spacing: 16) {
                    if isRegistering {
                        TextField("Display Name", text: $displayName)
                            .textFieldStyle(.roundedBorder)
                            .textContentType(.name)
                    }

                    TextField("Relay URL (e.g. https://relay.example.com)", text: $relayURL)
                        .textFieldStyle(.roundedBorder)
                        .textContentType(.URL)
                        .autocapitalization(.none)
                        .keyboardType(.URL)

                    SecureField("Password", text: $password)
                        .textFieldStyle(.roundedBorder)
                        .textContentType(isRegistering ? .newPassword : .password)
                }
                .padding(.horizontal)

                if let error = errorMessage {
                    Text(error)
                        .foregroundStyle(.red)
                        .font(.caption)
                        .padding(.horizontal)
                }

                // Actions
                VStack(spacing: 12) {
                    Button {
                        performAuth()
                    } label: {
                        if isLoading {
                            ProgressView()
                                .frame(maxWidth: .infinity)
                        } else {
                            Text(isRegistering ? "Create Account" : "Sign In")
                                .frame(maxWidth: .infinity)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isButtonDisabled)

                    Button("Import Existing Key") {
                        showImport = true
                    }
                    .buttonStyle(.bordered)
                }
                .padding(.horizontal)

                Spacer()
            }
            .sheet(isPresented: $showImport) {
                Text("TODO: Import key from backup")
                    .presentationDetents([.medium])
            }
        }
    }

    private var isButtonDisabled: Bool {
        relayURL.isEmpty || password.isEmpty || isLoading ||
        (isRegistering && displayName.isEmpty)
    }

    private func performAuth() {
        isLoading = true
        errorMessage = nil

        Task.detached {
            do {
                // 1. Generate key material
                let km = KeyMaterial(oneTimePrekeys: 10)
                let idKeyHex = try km.identityKey.map { String(format: "%02x", $0) }.joined()

                let url = relayURL.trimmingCharacters(in: .whitespacesAndNewlines)
                let api = APIService(baseURL: url)

                let token: String
                let userId: String

                if isRegistering {
                    // 2a. Register
                    let regResp = try await api.register(
                        publicKey: idKeyHex,
                        password: password,
                        displayName: displayName
                    )
                    userId = regResp.user_id

                    // 2b. Login to get token
                    let authResp = try await api.login(publicKey: idKeyHex, password: password)
                    token = authResp.token
                } else {
                    // 2. Login directly
                    let authResp = try await api.login(publicKey: idKeyHex, password: password)
                    token = authResp.token
                    userId = authResp.user_id
                }

                // 3. Set token and publish key bundle
                api.setAuthToken(token)
                let crypto = CryptoService(keyMaterial: km)
                try await crypto.publishKeyBundle(api: api)

                // 4. Complete login on main thread
                await MainActor.run {
                    appState.login(relayURL: url, token: token, userId: userId, keyMaterial: km)
                    if isRegistering {
                        appState.currentUser?.displayName = displayName
                    }
                    isLoading = false
                }
            } catch {
                await MainActor.run {
                    errorMessage = error.localizedDescription
                    isLoading = false
                }
            }
        }
    }
}
