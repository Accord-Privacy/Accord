# Contributing to Accord

## Code of Conduct

Be respectful. Harassment-free experience for everyone regardless of background. Focus on constructive collaboration.

## Getting Started

1. Fork the repo
2. Install Rust 1.86+ and system deps (`build-essential pkg-config libssl-dev`)
3. `cargo check` to verify your environment
4. Create a feature branch from `main`

## Development Workflow

```bash
# Check compilation
cargo check

# Run tests
cargo test

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt
```

## Pull Requests

- One feature/fix per PR
- Include tests for new functionality
- Update documentation if behavior changes
- Security-sensitive changes require extra review

## Security Contributions

- **Never commit credentials or keys**
- **Review crypto changes carefully** — get a second pair of eyes
- **Run `cargo audit`** before adding dependencies
- **Prefer well-maintained, audited crates** for security-critical code

## Project Structure

- `core/` — Cryptography and protocol (most security-sensitive)
- `server/` — Relay infrastructure
- `desktop/` — Tauri app (Rust backend + TypeScript frontend)
- `accord-cli/` — CLI client

## Reporting Bugs

Use GitHub Issues for non-security bugs. For security vulnerabilities, see [README.md](README.md#security).
