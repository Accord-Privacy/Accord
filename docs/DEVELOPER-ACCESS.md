# Developer Access Guide

This guide explains how to join the Accord development community and start contributing.

## Quick Start Checklist

- [ ] Star the GitHub repository
- [ ] Read [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] Read [COMMUNITY.md](../COMMUNITY.md)
- [ ] Look for `good-first-issue` labels

## GitHub Access

### Repository
- **Main repo**: https://github.com/your-org/accord
- **Fork the repo** to contribute code
- **Star the repo** to show support and stay updated

### Issues & Pull Requests
1. **Check existing issues** before creating new ones
2. **Use templates** for bug reports and feature requests
3. **Follow [CONTRIBUTING.md](../CONTRIBUTING.md)** guidelines
4. **Be specific** — provide reproduction steps, environment details

### GitHub Discussions
Great for:
- Open-ended questions about project direction
- Sharing usage experiences
- Community polls and feedback
- General brainstorming

### Security Vulnerabilities
- Report via **GitHub Security Advisories**
- Never post security issues publicly
- Include detailed reproduction steps
- Provide impact assessment if possible

## Development Environment Setup

### Prerequisites
- **Rust 1.86+**: Latest stable Rust toolchain
- **System deps**: `build-essential pkg-config libssl-dev`
- **GUI deps** (for desktop): `libgtk-3-dev libwebkit2gtk-4.1-dev libsoup-2.4-dev`

### First Steps
```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/accord
cd accord

# Check your environment
cargo check

# Run tests
cargo test

# Build everything
cargo build --release
```

### Development Workflow
1. **Create feature branch** from `main`
2. **Make changes** and test thoroughly
3. **Run formatting**: `cargo fmt`
4. **Run lints**: `cargo clippy -- -D warnings`
5. **Create pull request** with clear description

## Finding Your First Contribution

### Good Starting Points
- **Documentation**: Improve README, add examples, fix typos
- **Testing**: Add test cases, improve test coverage
- **Small features**: Look for `good-first-issue` labels
- **Bug fixes**: Reproduce and fix reported bugs

### Issue Labels to Look For
- `good-first-issue`: Perfect for newcomers
- `help-wanted`: Community contributions welcome
- `documentation`: Writing and docs improvements
- `bug`: Something that needs fixing
- `enhancement`: New feature or improvement

### Areas That Need Help
- **Mobile development**: iOS/Android apps
- **Documentation**: User guides, API docs, tutorials
- **Testing**: Unit tests, integration tests, UI testing
- **Security review**: Code audits, crypto implementation review
- **UI/UX**: Desktop app improvements

## Getting Help

### Stuck? Ask for Help!
- **GitHub Discussions**: Longer-form questions and community help
- **GitHub Issues**: Specific problems or bugs

### Mentorship
We're happy to mentor new contributors:
- **Technical guidance**: Architecture and design decisions
- **Code review**: Learning from feedback
- **Career development**: Open source contribution skills
- **Project planning**: Understanding roadmaps and priorities

## Community Values

### What We Value
- **Privacy first**: Every decision prioritizes user privacy
- **Open source**: Transparent development and community-driven
- **Security**: Rigorous security practices and review
- **Usability**: Privacy shouldn't compromise user experience
- **Collaboration**: Respectful, inclusive development community

---

**Welcome to Accord development! We're excited to have you join us in building the future of private communications.** 🚀

Questions? Open a GitHub Discussion: https://github.com/your-org/accord/discussions
