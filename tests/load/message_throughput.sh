#!/usr/bin/env bash
# message_throughput.sh — Measure message send throughput
# Usage: ./message_throughput.sh [USERS] [MESSAGES_PER_USER]
# Env: ACCORD_URL, TEST_CHANNEL_ID, TEST_NODE_ID
set -euo pipefail

USERS="${1:-10}"
MSGS="${2:-50}"
ACCORD_URL="${ACCORD_URL:-http://localhost:8443}"
WS_URL="${ACCORD_URL/http/ws}/ws"
CHANNEL_ID="${TEST_CHANNEL_ID:-1}"
NODE_ID="${TEST_NODE_ID:-1}"

echo "=== Message Throughput Test ==="
echo "Target: $ACCORD_URL | Users: $USERS | Messages/user: $MSGS"
echo "Channel: $CHANNEL_ID"
echo ""

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Register test users and get tokens
register_user() {
    local idx=$1
    local resp
    resp=$(curl -s -X POST "$ACCORD_URL/register" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"loadtest_tp_${idx}_$$\",\"password\":\"TestPass123!\"}" 2>/dev/null)
    local token=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo "")
    if [ -z "$token" ]; then
        # Try auth if already registered
        resp=$(curl -s -X POST "$ACCORD_URL/auth" \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"loadtest_tp_${idx}_$$\",\"password\":\"TestPass123!\"}" 2>/dev/null)
        token=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo "")
    fi
    echo "$token"
}

send_messages() {
    local user_id=$1
    local token=$2
    local count=0
    local start_ns=$(date +%s%N)
    for j in $(seq 1 "$MSGS"); do
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
            "$ACCORD_URL/channels/$CHANNEL_ID/messages" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $token" \
            -d "{\"content\":\"Load test msg $j from user $user_id\",\"nonce\":\"lt-${user_id}-${j}-$$\"}" 2>/dev/null)
        if [ "$status" = "200" ] || [ "$status" = "201" ]; then
            count=$((count + 1))
        fi
    done
    local end_ns=$(date +%s%N)
    local elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
    echo "$count $elapsed_ms" > "$TMPDIR/user_$user_id"
}

echo "Registering $USERS test users..."
declare -a TOKENS
for i in $(seq 1 "$USERS"); do
    TOKENS[$i]=$(register_user "$i")
    if [ -z "${TOKENS[$i]}" ]; then
        echo "  WARNING: Failed to get token for user $i"
    fi
done
echo "Registration complete."

# Join node (best effort)
for i in $(seq 1 "$USERS"); do
    [ -n "${TOKENS[$i]}" ] && curl -s -o /dev/null -X POST "$ACCORD_URL/nodes/$NODE_ID/join" \
        -H "Authorization: Bearer ${TOKENS[$i]}" 2>/dev/null &
done
wait

echo "Sending $MSGS messages per user ($((USERS * MSGS)) total)..."
START=$(date +%s%N)

for i in $(seq 1 "$USERS"); do
    [ -n "${TOKENS[$i]}" ] && send_messages "$i" "${TOKENS[$i]}" &
done
wait

END=$(date +%s%N)
TOTAL_MS=$(( (END - START) / 1000000 ))
TOTAL_SECS=$(awk "BEGIN {printf \"%.2f\", $TOTAL_MS/1000}")

# Tally
TOTAL_SENT=0
for f in "$TMPDIR"/user_*; do
    [ -f "$f" ] && TOTAL_SENT=$((TOTAL_SENT + $(awk '{print $1}' "$f")))
done

THROUGHPUT=$(awk "BEGIN {printf \"%.1f\", $TOTAL_SENT / ($TOTAL_MS/1000)}")

echo ""
echo "=== Results ==="
echo "Total time:      ${TOTAL_SECS}s"
echo "Messages sent:   $TOTAL_SENT / $((USERS * MSGS))"
echo "Throughput:      $THROUGHPUT msgs/sec"
