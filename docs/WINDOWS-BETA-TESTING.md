# Accord Windows Beta Testing Guide

## Quick Start

### Download
1. Go to **[GitHub Releases](https://github.com/Accord-Privacy/Accord/releases)** (or check Actions → Windows Build → latest run → Artifacts)
2. Download `Accord_0.1.0_x64-setup.exe` (NSIS installer)

### Install
1. Run the downloaded `.exe`
2. **Windows SmartScreen warning** will appear (expected for unsigned beta):
   - Click **"More info"**
   - Click **"Run anyway"**
3. Follow the installer — default settings are fine
4. Accord appears in your Start Menu

### Uninstall
- Settings → Apps → Accord → Uninstall
- Or: Start Menu → Accord → right-click → Uninstall

---

## Connecting to the Server

The relay server address will be provided separately. Enter it in Accord's connection settings when prompted.

Default: `ws://SERVER_IP:3724`

---

## Reporting Issues

When reporting bugs or design feedback:
1. **Screenshot** the issue if visual
2. Note what you were doing when it happened
3. Check `%APPDATA%\chat.accord.desktop\logs` for error logs
4. Open a GitHub issue or message Gage directly

---

## Known Beta Limitations

- Windows SmartScreen warning (no code signing yet)
- Some features may be incomplete
- Voice channels are experimental
- This is a beta — crashes and rough edges are expected

---

## System Requirements

- Windows 10 (1803+) or Windows 11
- WebView2 runtime (installer will download it automatically if missing)
- ~100MB disk space
- Internet connection for relay server

---

## Building from Source (Advanced)

If you want to build locally instead:

```powershell
# Prerequisites: Rust, Node.js 20+, cargo-tauri
cargo install tauri-cli

# Build
cd desktop/frontend
npm install
npm run build
cd ..
cargo tauri build

# Installer will be in target/release/bundle/nsis/
```
