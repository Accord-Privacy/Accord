# Contributing to Accord

Thank you for your interest in Accord! This guide covers everything you need to start contributing.

## Code of Conduct

Be respectful. We're building privacy tools for everyone — harassment-free experience regardless of background. Focus on constructive collaboration.

---

## Development Environment Setup

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Rust | 1.86+ | [rustup.rs](https://rustup.rs) |
| Node.js | 20+ | [nodejs.org](https://nodejs.org) |
| npm | 10+ | Comes with Node.js |

### System Dependencies (Debian/Ubuntu)

```bash
# Build essentials
sudo apt install build-essential pkg-config libssl-dev

# Tauri/desktop dependencies
sudo apt install libgtk-3-dev libwebkit2gtk-4.1-dev libsoup-2.4-dev

# Optional: for voice channel development
sudo apt install libasound2-dev
```

### First-Time Setup

```bash
git clone https://github.com/Accord-Privacy/Accord.git
cd Accord

# Verify Rust toolchain
cargo check

# Install frontend dependencies
cd desktop/frontend && npm ci && cd ../..

# Run the test suite
cargo test
```

---

## Project Structure

```
Accord/
├── core/                 # 🔐 Cryptography, protocol, channels, voice, bots
│   └── src/
│       ├── crypto/       # Double Ratchet, X3DH, AES-256-GCM
│       ├── channels/     # Channel & category management
│       ├── voice/        # Voice channel protocol
│       ├── bots/         # Bot API
│       └── ...
├── core-minimal/         # Lightweight core for constrained targets
├── server/               # 🌐 WebSocket relay server
│   └── src/
│       ├── main.rs       # Entry point
│       ├── ws/           # WebSocket handling
│       └── ...
├── desktop/              # 🖥️ Tauri desktop app
│   ├── src/              # Rust backend (Tauri commands)
│   └── frontend/         # React/TypeScript UI
│       ├── src/
│       └── package.json
├── accord-cli/           # ⌨️ Command-line client
├── standalone-demo/      # Demo/showcase build
├── scripts/              # Build & QA scripts
│   └── pre-push-qa.sh   # Mandatory pre-push checks
├── docs/                 # Documentation
└── deploy/               # Deployment configs
```

---

## Building

### Relay Server

```bash
# Debug build (faster compilation)
cargo build -p accord-server

# Release build (optimized)
cargo build --release -p accord-server

# Run
./target/release/accord-server
```

### Desktop App (Frontend)

```bash
cd desktop/frontend
npm ci
npm run build          # Production build
npm run dev            # Dev server with hot reload (port 1420)
```

### Desktop App (Full Tauri Build)

```bash
# Ensure frontend is built first
cd desktop/frontend && npm ci && npm run build && cd ../..

# Build the Tauri app
cargo build --release -p accord-desktop

# Or use the Tauri CLI for packaged builds (.deb, .AppImage, .msi)
cargo install tauri-cli
cargo tauri build
```

### CLI Client

```bash
cargo build --release -p accord-cli
```

### Running Tests

```bash
# Full test suite
cargo test

# Specific crate
cargo test -p accord-core
cargo test -p accord-server

# With output
cargo test -- --nocapture
```

---

## Code Style & Quality

### Formatting

```bash
cargo fmt --all           # Format all code
cargo fmt --all -- --check  # Check without modifying (CI uses this)
```

### Linting

```bash
cargo clippy --workspace -- -D warnings
```

### Pre-Push QA Gate (Mandatory)

Before **every** push, run:

```bash
bash scripts/pre-push-qa.sh
```

This runs fmt, clippy, tests, and `cargo audit`. If it fails, fix the issue before pushing.

### Security Auditing

```bash
cargo audit               # Check for known vulnerabilities in dependencies
```

We take dependency security seriously. Every `cargo audit` finding is investigated. See [SECURITY.md](SECURITY.md).

---

## Making Changes

### Branch Naming

- `feat/short-description` — new features
- `fix/short-description` — bug fixes
- `docs/short-description` — documentation
- `refactor/short-description` — code restructuring

### Pull Request Process

1. **Fork & branch** from `main`
2. **Make your changes** — one logical change per PR
3. **Add tests** for new functionality
4. **Run the QA gate** — `bash scripts/pre-push-qa.sh`
5. **Update docs** if behavior changes
6. **Open a PR** — fill out the template
7. **Address review feedback**

### PR Requirements

- [ ] `cargo fmt` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo test` passes
- [ ] `cargo audit` has no unaddressed findings
- [ ] Documentation updated (if applicable)
- [ ] No credentials, keys, or PII in the diff

---

## Architecture Decisions

Understanding these principles will help you contribute effectively:

### The Relay is a Dumb Pipe

The relay server **never** decrypts content. It routes opaque encrypted blobs between clients. This is by design — it minimizes the trust surface. If you're adding a relay feature, ask: "Does the relay need to understand this data?" The answer should almost always be **no**.

### Node Isolation

Each Node (community space) is cryptographically isolated. A user's profile, display name, and avatar are encrypted per-Node. The relay can't correlate a user's identity across Nodes. Preserve this isolation in any changes.

### Keypair Identity

Identity is a keypair. No emails, no phone numbers, no usernames at the relay level. Display names exist only inside encrypted Node contexts. Any feature that requires PII at the relay level is a non-starter.

### Client-Side Everything

Crypto happens on the client. The server never touches plaintext. If you're tempted to decrypt something server-side "for convenience," stop and redesign.

### No Central Moderation

Accord performs **no** relay-side or otherwise centralized moderation, and it never will — the relay cannot read node content, and it must not be able to. Moderation is the **node owner's** duty and runs client-side or within the node's own trust boundary. The relay owner is a landlord (localhost access = authority) who can see node names/descriptions, create/delete nodes, and ban an IP for abuse defense — nothing about who is inside a node, and no end user's IP is ever exposed to node owners, admins, or other users. Any feature that gives the relay content inspection, cross-node ban lists, keyword scanning, or IP↔node correlation is a non-starter. Read **[GOVERNANCE.md](GOVERNANCE.md)** before proposing anything that touches moderation or the relay.

---

## Security Contributions

The `core/` crate is the most security-sensitive part of the codebase.

- **Never commit credentials, keys, or secrets**
- **Crypto changes require extra review** — tag security-sensitive PRs
- **Prefer well-maintained, audited crates** for cryptographic primitives
- **Run `cargo audit`** before adding any new dependency
- **Report vulnerabilities** via [GitHub Security Advisories](https://github.com/Accord-Privacy/Accord/security/advisories), not public issues

---

## Community

- **[GitHub Issues](https://github.com/Accord-Privacy/Accord/issues)** — bug reports and feature requests
- **[GitHub Discussions](https://github.com/Accord-Privacy/Accord/discussions)** — Q&A and brainstorming
- **[Roadmap](ROADMAP.md)** — what's planned
- **[Community Guide](COMMUNITY.md)** — community guidelines

---

## License

By contributing, you agree that your contributions will be licensed under the [AGPL-3.0](LICENSE).
