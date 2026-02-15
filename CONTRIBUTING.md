# Contributing to Accord

Thank you for your interest in contributing to Accord! This document outlines the process for contributing to this privacy-first communication platform.

## 🚀 Quick Start

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/accord
   cd accord
   ```
3. **Set up development environment:**
   ```bash
   # Install Rust
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   
   # Build the project
   cargo build
   
   # Run tests
   cargo test
   ```

## 🔒 Security First

**All contributions must prioritize security:**
- Never compromise on encryption or privacy
- Document security implications of changes
- Follow secure coding practices
- Submit security issues privately to security@accord.chat

## 🛠️ Development Guidelines

### **Code Style**
- Follow `rustfmt` formatting: `cargo fmt`
- Pass all lints: `cargo clippy -- -D warnings`
- Add tests for new functionality
- Document public APIs with examples

### **Commit Messages**
```
type(scope): brief description

Longer explanation if needed

Closes #123
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

### **Pull Request Process**
1. Create feature branch: `git checkout -b feature/your-feature`
2. Make changes with tests and documentation
3. Ensure all CI checks pass
4. Submit PR with clear description
5. Address review feedback
6. Squash merge after approval

## 🎯 Priority Areas

We especially need help with:

### **Core Development**
- **Cryptography** - Signal Protocol implementation
- **Voice Encryption** - Real-time audio encryption
- **Networking** - Efficient relay protocols
- **Performance** - Optimization and benchmarking

### **Client Applications**
- **Desktop UI** - Tauri + TypeScript interface
- **Mobile Apps** - iOS/Android native development
- **Accessibility** - Screen readers, keyboard navigation
- **Internationalization** - Multi-language support

### **Infrastructure**
- **Server Optimization** - Scalable relay infrastructure
- **DevOps** - CI/CD, automated testing, deployments
- **Documentation** - User guides, API docs, tutorials
- **Security Auditing** - Code review, penetration testing

## 🧪 Testing

### **Running Tests**
```bash
# Unit tests
cargo test

# Integration tests
cargo test --features integration

# Benchmarks
cargo bench

# Security tests
cargo audit
```

### **Test Requirements**
- All new features need tests
- Maintain >90% code coverage
- Include both positive and negative test cases
- Test cryptographic functions extensively

## 📋 Issue Guidelines

### **Bug Reports**
Include:
- Accord version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs (redact sensitive data)

### **Feature Requests**
Include:
- Use case and motivation
- Proposed implementation approach
- Security and privacy implications
- Alternatives considered

### **Security Issues**
**DO NOT** file public issues for security vulnerabilities.
Email: security@accord.chat

## 🏗️ Architecture Guidelines

### **Core Principles**
- **Zero-knowledge server** - Server cannot decrypt content
- **End-to-end encryption** - All communications encrypted
- **Forward secrecy** - Keys rotate automatically
- **Minimal metadata** - Collect only what's necessary

### **Code Organization**
```
accord/
├── core/          # Cryptography and networking primitives
├── server/        # Relay server implementation  
├── desktop/       # Desktop client (Tauri)
├── mobile/        # Mobile clients (iOS/Android)
├── docs/          # Documentation
└── security/      # Security policies and audits
```

### **Dependencies**
- Prefer well-audited cryptographic libraries
- Minimize dependency count
- Document security properties of all deps
- Regular dependency updates and audits

## 🤝 Code of Conduct

### **Our Standards**
- Respectful and inclusive communication
- Focus on technical merit and user privacy
- Welcome constructive criticism and feedback
- Support newcomers and help them learn

### **Unacceptable Behavior**
- Harassment, discrimination, or personal attacks
- Sharing others' private information
- Compromising security or privacy features
- Spam, trolling, or off-topic discussions

## 📄 License

By contributing to Accord, you agree that your contributions will be licensed under the [GPL v3](LICENSE) license.

## 🙋 Questions?

- **General questions:** Open a discussion on GitHub
- **Development chat:** #accord-dev on Matrix
- **Email:** dev@accord.chat

**Welcome to the Accord community! Together we're building the future of private, secure communication.**