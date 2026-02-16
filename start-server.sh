#!/bin/bash
# Start Accord server on Linux
# Usage: ./start-server.sh [port] [host]
# Default: binds to 0.0.0.0:8080 (accessible from other machines)

set -e
cd "$(dirname "$0")"

PORT="${1:-8080}"
HOST="${2:-0.0.0.0}"

echo "🚀 Starting Accord Server..."
echo "📡 Binding to ${HOST}:${PORT}"
echo "🌐 Other machines can connect at: http://$(hostname -I | awk '{print $1}'):${PORT}"
echo ""

# Build if needed
export PATH="$HOME/.cargo/bin:$PATH"
if [ ! -f target/debug/accord-server ] && [ ! -f target/release/accord-server ]; then
    echo "📦 Building server (first time)..."
    cargo build --bin accord-server
fi

# Run the server
if [ -f target/release/accord-server ]; then
    ./target/release/accord-server --host "$HOST" --port "$PORT"
else
    cargo run --bin accord-server -- --host "$HOST" --port "$PORT"
fi
