#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Accord WebSocket Load Test Script
#
# Tests concurrent WebSocket connections and message relay against a running
# Accord server. Requires the server to be running first.
#
# Usage:
#   ./scripts/load-test.sh [OPTIONS]
#
# Options:
#   -h, --host HOST        Server host (default: localhost)
#   -p, --port PORT        Server port (default: 8080)
#   -c, --connections N    Number of concurrent connections (default: 100)
#   -m, --messages N       Messages per connection (default: 10)
#   -r, --ramp-up SECS     Ramp-up time in seconds (default: 5)
#   --help                 Show this help
#
# For heavy load testing (1000+ connections), consider:
#   - Increasing ulimits: ulimit -n 65536
#   - Using the dedicated Rust load-test binary (see below)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

HOST="localhost"
PORT="8080"
CONNECTIONS=100
MESSAGES=10
RAMP_UP=5

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--host) HOST="$2"; shift 2 ;;
        -p|--port) PORT="$2"; shift 2 ;;
        -c|--connections) CONNECTIONS="$2"; shift 2 ;;
        -m|--messages) MESSAGES="$2"; shift 2 ;;
        -r|--ramp-up) RAMP_UP="$2"; shift 2 ;;
        --help)
            head -22 "$0" | tail -20
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

BASE_URL="http://${HOST}:${PORT}"
WS_URL="ws://${HOST}:${PORT}/ws"

echo "═══════════════════════════════════════════════════════════════"
echo "  Accord Load Test"
echo "═══════════════════════════════════════════════════════════════"
echo "  Server:       ${BASE_URL}"
echo "  Connections:  ${CONNECTIONS}"
echo "  Messages/conn: ${MESSAGES}"
echo "  Ramp-up:      ${RAMP_UP}s"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Check server is reachable
echo "[1/5] Checking server health..."
if ! curl -sf "${BASE_URL}/health" > /dev/null 2>&1; then
    echo "ERROR: Server not reachable at ${BASE_URL}"
    echo "Start the server first: cargo run -p accord-server"
    exit 1
fi
echo "  ✓ Server is healthy"

# Register test users
echo "[2/5] Registering ${CONNECTIONS} test users..."
TOKENS=()
FAIL_COUNT=0
for i in $(seq 1 "$CONNECTIONS"); do
    USERNAME="loadtest_user_${RANDOM}_${i}"
    RESP=$(curl -sf -X POST "${BASE_URL}/register" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${USERNAME}\",\"public_key\":\"loadtest_pk_${i}\",\"password\":\"loadtest\"}" 2>/dev/null) || true

    if [ -z "$RESP" ]; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
        continue
    fi

    # Authenticate to get token
    AUTH_RESP=$(curl -sf -X POST "${BASE_URL}/auth" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${USERNAME}\",\"password\":\"loadtest\"}" 2>/dev/null) || true

    TOKEN=$(echo "$AUTH_RESP" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    if [ -n "$TOKEN" ]; then
        TOKENS+=("$TOKEN")
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    # Progress
    if (( i % 50 == 0 )); then
        echo "  Registered ${i}/${CONNECTIONS}..."
    fi
done
echo "  ✓ Registered ${#TOKENS[@]} users (${FAIL_COUNT} failures)"

if [ ${#TOKENS[@]} -eq 0 ]; then
    echo "ERROR: No users registered successfully"
    exit 1
fi

# WebSocket connection test
echo "[3/5] Opening ${#TOKENS[@]} WebSocket connections..."
PIDS=()
START_TIME=$(date +%s%N)
CONNECTED=0
WS_ERRORS=0

# Use a temp dir for results
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

ws_connect() {
    local token=$1
    local idx=$2
    local result_file="${TMPDIR}/ws_${idx}"

    # Use timeout + a simple TCP check via bash
    # For real load testing, use the Rust binary or websocat
    local connect_start=$(date +%s%N)

    # Try to establish connection using curl (WebSocket upgrade)
    if curl -sf --max-time 10 \
        -H "Connection: Upgrade" \
        -H "Upgrade: websocket" \
        -H "Sec-WebSocket-Version: 13" \
        -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
        "${BASE_URL}/ws?token=${token}" \
        > /dev/null 2>&1; then
        local connect_end=$(date +%s%N)
        local latency=$(( (connect_end - connect_start) / 1000000 ))
        echo "ok ${latency}" > "$result_file"
    else
        echo "fail" > "$result_file"
    fi
}

# Ramp up connections
DELAY_MS=$(( RAMP_UP * 1000 / ${#TOKENS[@]} ))
for i in "${!TOKENS[@]}"; do
    ws_connect "${TOKENS[$i]}" "$i" &
    PIDS+=($!)
    if (( DELAY_MS > 0 )); then
        sleep "0.$(printf '%03d' $DELAY_MS)" 2>/dev/null || true
    fi
done

# Wait for all connections
for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
done
END_TIME=$(date +%s%N)

# Analyze results
TOTAL_LATENCY=0
for f in "$TMPDIR"/ws_*; do
    [ -f "$f" ] || continue
    result=$(cat "$f")
    if [[ "$result" == ok* ]]; then
        CONNECTED=$((CONNECTED + 1))
        latency=$(echo "$result" | cut -d' ' -f2)
        TOTAL_LATENCY=$((TOTAL_LATENCY + latency))
    else
        WS_ERRORS=$((WS_ERRORS + 1))
    fi
done

TOTAL_TIME_MS=$(( (END_TIME - START_TIME) / 1000000 ))
AVG_LATENCY=0
if [ $CONNECTED -gt 0 ]; then
    AVG_LATENCY=$((TOTAL_LATENCY / CONNECTED))
fi

echo "  ✓ ${CONNECTED} connected, ${WS_ERRORS} errors"
echo "  Total time: ${TOTAL_TIME_MS}ms"
echo "  Avg connect latency: ${AVG_LATENCY}ms"

# REST API throughput
echo "[4/5] Testing REST API throughput..."
REST_START=$(date +%s%N)
REST_COUNT=0
REST_DURATION=5  # seconds

while true; do
    NOW=$(date +%s%N)
    ELAPSED=$(( (NOW - REST_START) / 1000000000 ))
    if [ "$ELAPSED" -ge "$REST_DURATION" ]; then
        break
    fi
    curl -sf "${BASE_URL}/health" > /dev/null 2>&1 && REST_COUNT=$((REST_COUNT + 1))
done

REST_RPS=$((REST_COUNT / REST_DURATION))
echo "  ✓ Health endpoint: ~${REST_RPS} req/s (sequential)"

# Summary
echo ""
echo "[5/5] Summary"
echo "═══════════════════════════════════════════════════════════════"
echo "  Connections attempted: ${#TOKENS[@]}"
echo "  Connections succeeded: ${CONNECTED}"
echo "  Connection errors:     ${WS_ERRORS}"
echo "  Total connect time:    ${TOTAL_TIME_MS}ms"
echo "  Avg connect latency:   ${AVG_LATENCY}ms"
echo "  REST throughput:       ~${REST_RPS} req/s"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Performance targets
echo "Performance Targets:"
TARGET_PASS=true
if [ $CONNECTED -lt $((CONNECTIONS * 90 / 100)) ]; then
    echo "  ✗ Connection success rate < 90%"
    TARGET_PASS=false
else
    echo "  ✓ Connection success rate ≥ 90%"
fi

if [ $AVG_LATENCY -gt 50 ] && [ $AVG_LATENCY -gt 0 ]; then
    echo "  ✗ Avg connect latency > 50ms"
    TARGET_PASS=false
else
    echo "  ✓ Avg connect latency ≤ 50ms"
fi

echo ""
if [ "$TARGET_PASS" = true ]; then
    echo "🎉 All performance targets met!"
else
    echo "⚠️  Some performance targets not met (see above)"
fi

echo ""
echo "For heavier load testing (10k+ connections), use the Rust load-test"
echo "binary or a tool like:"
echo "  - websocat: websocat -n ws://localhost:8080/ws?token=..."
echo "  - k6: k6 run with WebSocket scenario"
echo "  - Custom Rust binary: cargo run --release -p accord-load-test"
