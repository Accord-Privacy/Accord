# Accord Quick Start Guide

## Architecture
- **Linux Server**: Runs `accord-server` (Rust binary)  
- **Desktop Client**: React web app (runs in browser via Vite dev server, or in Tauri desktop shell)

## Setup

### Prerequisites
- **Linux server**: Rust toolchain (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **Windows/any client**: Node.js v18+ (`https://nodejs.org`)

### 1. Start the Server (Linux)

```bash
./start-server.sh
# Server starts on 0.0.0.0:8080 (accessible from other machines)
# Custom port: ./start-server.sh 9090
```

Note your Linux machine's IP address (shown in startup output, or run `hostname -I`).

### 2. Start the Desktop Client (Windows)

```batch
REM Replace 192.168.1.100 with your Linux server's IP
start-desktop.bat http://192.168.1.100:8080
```

Or on Linux for local testing:
```bash
./start-desktop.sh http://localhost:8080
```

This opens a Vite dev server at `http://localhost:1420` — open it in your browser.

### 3. Use the App

1. **Register**: Click "Need to register?", enter a username, click Register
2. **Login**: Enter username + password, click Login  
3. **Create a Node**: Click the `+` in the server list (left sidebar)
4. **Chat**: Select a channel and start messaging!

## Configuration

### Server URL
Set via environment variable or `.env` file:

**Environment variable:**
```bash
VITE_ACCORD_SERVER_URL=http://192.168.1.100:8080 npm run dev
```

**`.env` file** (in `desktop/frontend/.env`):
```
VITE_ACCORD_SERVER_URL=http://192.168.1.100:8080
```

### Server Bind Address
```bash
# Listen on specific interface
./start-server.sh 8080 192.168.1.100

# Listen on all interfaces (default)
./start-server.sh 8080 0.0.0.0
```

## Troubleshooting

- **"Server unavailable"**: Check that the server is running and the URL is correct
- **Can't connect from Windows**: Make sure Linux firewall allows port 8080 (`sudo ufw allow 8080`)
- **CORS errors**: The server has CORS configured to allow all origins for development
