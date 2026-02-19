#!/usr/bin/env bash
# api_latency.sh — Benchmark REST endpoints under load
# Usage: ./api_latency.sh [REQUESTS_PER_ENDPOINT] [CONCURRENCY]
# Env: ACCORD_URL, TEST_AUTH_TOKEN, TEST_CHANNEL_ID, TEST_NODE_ID
set -euo pipefail

REQUESTS="${1:-500}"
CONCURRENCY="${2:-10}"
ACCORD_URL="${ACCORD_URL:-http://localhost:8443}"
AUTH_TOKEN="${TEST_AUTH_TOKEN:-}"
CHANNEL_ID="${TEST_CHANNEL_ID:-1}"
NODE_ID="${TEST_NODE_ID:-1}"

echo "=== API Latency Benchmark ==="
echo "Target: $ACCORD_URL | Requests: $REQUESTS | Concurrency: $CONCURRENCY"
echo ""

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

auth_header=""
[ -n "$AUTH_TOKEN" ] && auth_header="-H \"Authorization: Bearer $AUTH_TOKEN\""

# Endpoints to test (name url needs_auth)
declare -a ENDPOINTS=(
    "health|/health|no"
    "build-info|/api/build-info|no"
    "node-info|/nodes/$NODE_ID|yes"
    "channel-messages|/channels/$CHANNEL_ID/messages|yes"
    "node-members|/nodes/$NODE_ID|yes"
)

benchmark_endpoint() {
    local name=$1
    local path=$2
    local needs_auth=$3
    local url="$ACCORD_URL$path"
    local results_file="$TMPDIR/${name}_latencies"

    echo "Benchmarking: $name ($path)"

    # Build curl command
    local auth_args=()
    if [ "$needs_auth" = "yes" ] && [ -n "$AUTH_TOKEN" ]; then
        auth_args=(-H "Authorization: Bearer $AUTH_TOKEN")
    elif [ "$needs_auth" = "yes" ] && [ -z "$AUTH_TOKEN" ]; then
        echo "  SKIP (needs auth token, set TEST_AUTH_TOKEN)"
        return
    fi

    # Run concurrent requests
    local pids=()
    local batch_size=$(( REQUESTS / CONCURRENCY ))

    for c in $(seq 1 "$CONCURRENCY"); do
        (
            for r in $(seq 1 "$batch_size"); do
                local ms
                ms=$(curl -s -o /dev/null -w "%{time_total}" "${auth_args[@]}" "$url" 2>/dev/null)
                # Convert seconds to ms
                echo "$ms" | awk '{printf "%.1f\n", $1 * 1000}'
            done >> "$results_file.$c"
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    # Merge and compute stats
    cat "$results_file".* 2>/dev/null | sort -n > "$results_file" || true
    local count=$(wc -l < "$results_file" 2>/dev/null || echo 0)

    if [ "$count" -gt 0 ]; then
        local p50=$(awk "NR==int($count*0.50+1)" "$results_file")
        local p95=$(awk "NR==int($count*0.95+1)" "$results_file")
        local p99=$(awk "NR==int($count*0.99+1)" "$results_file")
        local avg=$(awk '{s+=$1} END {printf "%.1f", s/NR}' "$results_file")
        local min=$(head -1 "$results_file")
        local max=$(tail -1 "$results_file")
        printf "  %d reqs | avg: %sms | p50: %sms | p95: %sms | p99: %sms | min: %sms | max: %sms\n" \
            "$count" "$avg" "$p50" "$p95" "$p99" "$min" "$max"
    else
        echo "  No successful requests"
    fi
}

for endpoint in "${ENDPOINTS[@]}"; do
    IFS='|' read -r name path needs_auth <<< "$endpoint"
    benchmark_endpoint "$name" "$path" "$needs_auth"
    echo ""
done

echo "=== Done ==="
