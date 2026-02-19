#!/usr/bin/env bash
# registration_stress.sh — Rapid-fire registration to test rate limiting
# Usage: ./registration_stress.sh [REQUESTS]
# Env: ACCORD_URL
set -euo pipefail

REQUESTS="${1:-200}"
ACCORD_URL="${ACCORD_URL:-http://localhost:8443}"

echo "=== Registration Stress Test ==="
echo "Target: $ACCORD_URL/register | Requests: $REQUESTS"
echo ""

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

START=$(date +%s%N)

for i in $(seq 1 "$REQUESTS"); do
    (
        start_ns=$(date +%s%N)
        resp=$(curl -s -o "$TMPDIR/body_$i" -w "%{http_code}" -X POST "$ACCORD_URL/register" \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"stresstest_${i}_$$_$(date +%s%N)\",\"password\":\"TestPass123!\"}" 2>/dev/null)
        end_ns=$(date +%s%N)
        elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
        echo "$resp $elapsed_ms" > "$TMPDIR/result_$i"
    ) &

    # Fire in bursts of 20
    if (( i % 20 == 0 )); then
        wait
    fi
done
wait

END=$(date +%s%N)
TOTAL_MS=$(( (END - START) / 1000000 ))

# Analyze responses
SUCCESS=0
RATE_LIMITED=0
ERRORS=0
declare -A STATUS_COUNTS

for f in "$TMPDIR"/result_*; do
    code=$(awk '{print $1}' "$f")
    STATUS_COUNTS[$code]=$(( ${STATUS_COUNTS[$code]:-0} + 1 ))
    case "$code" in
        200|201) SUCCESS=$((SUCCESS + 1)) ;;
        429)     RATE_LIMITED=$((RATE_LIMITED + 1)) ;;
        *)       ERRORS=$((ERRORS + 1)) ;;
    esac
done

# Latency stats
ALL_LATENCIES=$(for f in "$TMPDIR"/result_*; do awk '{print $2}' "$f"; done | sort -n)
COUNT=$(echo "$ALL_LATENCIES" | wc -l)
P50=$(echo "$ALL_LATENCIES" | awk "NR==int($COUNT * 0.5 + 1)")
P95=$(echo "$ALL_LATENCIES" | awk "NR==int($COUNT * 0.95 + 1)")
P99=$(echo "$ALL_LATENCIES" | awk "NR==int($COUNT * 0.99 + 1)")

echo ""
echo "=== Results ==="
echo "Total time:     ${TOTAL_MS}ms"
echo "Successful:     $SUCCESS"
echo "Rate limited:   $RATE_LIMITED (HTTP 429)"
echo "Other errors:   $ERRORS"
echo ""
echo "Status code breakdown:"
for code in $(echo "${!STATUS_COUNTS[@]}" | tr ' ' '\n' | sort); do
    echo "  HTTP $code: ${STATUS_COUNTS[$code]}"
done
echo ""
echo "Latency: p50=${P50}ms | p95=${P95}ms | p99=${P99}ms"
echo ""

if [ "$RATE_LIMITED" -gt 0 ]; then
    echo "✅ Rate limiting is working — $RATE_LIMITED requests were throttled."
else
    echo "⚠️  No rate limiting detected! All $REQUESTS requests succeeded."
    echo "   This may indicate rate limiting is not configured."
fi
