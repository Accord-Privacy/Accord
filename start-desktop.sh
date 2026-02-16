#!/bin/bash
# Start Accord Desktop (frontend dev server) on Linux
# Usage: ./start-desktop.sh [server_url]
# Default: connects to http://localhost:8080

set -e
cd "$(dirname "$0")/desktop/frontend"

SERVER_URL="${1:-http://localhost:8080}"

echo "🖥️  Starting Accord Desktop..."
echo "📡 Connecting to server: ${SERVER_URL}"
echo ""

# Set the server URL
export VITE_ACCORD_SERVER_URL="$SERVER_URL"

# Install deps if needed
if [ ! -d node_modules ]; then
    echo "📦 Installing dependencies..."
    npm install
fi

# Start dev server
npm run dev
