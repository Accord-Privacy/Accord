#!/usr/bin/env bash
set -euo pipefail

echo "🚀 Accord Server — Quick Deploy"
echo "================================"

# ── Dependency checks ───────────────────────────────────────────
for cmd in docker; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "❌ $cmd is required but not installed."
        exit 1
    fi
done

if ! docker compose version &>/dev/null; then
    echo "❌ Docker Compose v2 is required (docker compose plugin)."
    exit 1
fi

echo "✅ Docker and Docker Compose detected."

# ── Prompt for config ───────────────────────────────────────────
read -rp "Domain name (e.g. chat.example.com): " ACCORD_DOMAIN
read -rp "Admin token (leave blank to auto-generate): " ACCORD_ADMIN_TOKEN

if [ -z "$ACCORD_ADMIN_TOKEN" ]; then
    ACCORD_ADMIN_TOKEN=$(openssl rand -hex 24 2>/dev/null || head -c 48 /dev/urandom | base64 | tr -d '/+=' | head -c 48)
    echo "🔑 Generated admin token: $ACCORD_ADMIN_TOKEN"
fi

# ── Write .env ──────────────────────────────────────────────────
cat > .env <<EOF
ACCORD_DOMAIN=${ACCORD_DOMAIN}
ACCORD_PORT=8080
ACCORD_ADMIN_TOKEN=${ACCORD_ADMIN_TOKEN}
EOF

echo "📝 Wrote .env"

# ── Launch ──────────────────────────────────────────────────────
echo "🐳 Starting containers..."
docker compose up -d --build

echo ""
echo "✅ Accord is running!"
echo "   https://${ACCORD_DOMAIN}"
echo "   Admin token: ${ACCORD_ADMIN_TOKEN}"
echo ""
echo "   Logs:    docker compose logs -f"
echo "   Stop:    docker compose down"
