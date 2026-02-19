#!/usr/bin/env bash
# concurrent_connections.sh — Spin up N concurrent WebSocket connections
# Usage: ./concurrent_connections.sh [N]
# Env: ACCORD_URL (default http://localhost:8443)
set -euo pipefail

N="${1:-100}"
ACCORD_URL="${ACCORD_URL:-http://localhost:8443}"
WS_URL="${ACCORD_URL/http/ws}/ws"

echo "=== Concurrent WebSocket Connections Test ==="
echo "Target: $WS_URL | Connections: $N"
echo ""

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

SUCCESS=0
FAIL=0
START=$(date +%s%N)

connect_ws() {
    local id=$1
    local start_ns=$(date +%s%N)
    if command -v websocat &>/dev/null; then
        # Connect, wait 2s, then close
        echo "" | timeout 5 websocat -1 "$WS_URL" 2>/dev/null && status=0 || status=$?
    else
        # Fall back to Python websockets
        timeout 5 python3 -c "
import asyncio, websockets
async def go():
    async with websockets.connect('$WS_URL') as ws:
        await asyncio.sleep(2)
asyncio.run(go())
" 2>/dev/null && status=0 || status=$?
    fi
    local end_ns=$(date +%s%N)
    local elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
    if [ "$status" -eq 0 ]; then
        echo "$elapsed_ms" > "$TMPDIR/ok_$id"
    else
        echo "$elapsed_ms" > "$TMPDIR/fail_$id"
    fi
}

echo "Launching $N connections..."
for i in $(seq 1 "$N"); do
    connect_ws "$i" &
    # Stagger slightly to avoid thundering herd on OS level
    if (( i % 50 == 0 )); then
        sleep 0.1
    fi
done

echo "Waiting for all connections to complete..."
wait

END=$(date +%s%N)
TOTAL_MS=$(( (END - START) / 1000000 ))

# Tally results
SUCCESS=$(ls "$TMPDIR"/ok_* 2>/dev/null | wc -l)
FAIL=$(ls "$TMPDIR"/fail_* 2>/dev/null | wc -l)

# Compute latency stats from successful connections
if [ "$SUCCESS" -gt 0 ]; then
    LATENCIES=$(cat "$TMPDIR"/ok_* | sort -n)
    P50=$(echo "$LATENCIES" | awk "NR==int($(echo "$SUCCESS * 0.5" | bc)+1)")
    P95=$(echo "$LATENCIES" | awk "NR==int($(echo "$SUCCESS * 0.95" | bc)+1)")
    P99=$(echo "$LATENCIES" | awk "NR==int($(echo "$SUCCESS * 0.99" | bc)+1)")
    AVG=$(echo "$LATENCIES" | awk '{s+=$1} END {printf "%.0f", s/NR}')
else
    P50="-"; P95="-"; P99="-"; AVG="-"
fi

echo ""
echo "=== Results ==="
echo "Total time:    ${TOTAL_MS}ms"
echo "Success:       $SUCCESS / $N"
echo "Failed:        $FAIL / $N"
echo "Success rate:  $(awk "BEGIN {printf \"%.1f\", $SUCCESS/$N*100}")%"
echo ""
echo "Connection latency (successful):"
echo "  avg: ${AVG}ms | p50: ${P50}ms | p95: ${P95}ms | p99: ${P99}ms"
