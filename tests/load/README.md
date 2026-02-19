# Load Testing Suite

Lightweight load tests for the Accord server using bash + curl (and Python for WebSocket tests when websocat isn't available).

## Prerequisites

- **Required:** `bash`, `curl`, `python3`, `awk`, `bc`
- **Optional:** `websocat` (for WebSocket tests; falls back to Python `websockets` library)
- A running Accord server

## Configuration

All scripts use environment variables:

| Variable | Default | Description |
|---|---|---|
| `ACCORD_URL` | `http://localhost:8443` | Server base URL |
| `TEST_AUTH_TOKEN` | _(none)_ | Bearer token for authenticated endpoints |
| `TEST_CHANNEL_ID` | `1` | Channel ID for message tests |
| `TEST_NODE_ID` | `1` | Node (server/guild) ID |

## Tests

### 1. Concurrent WebSocket Connections

```bash
./concurrent_connections.sh [N]     # default N=100
```

Spawns N simultaneous WebSocket connections and measures success rate and connection latency (p50/p95/p99).

### 2. Message Throughput

```bash
./message_throughput.sh [USERS] [MESSAGES_PER_USER]   # defaults: 10 users, 50 msgs each
```

Registers test users, connects them, and sends messages concurrently. Reports messages/second throughput.

### 3. Registration Stress

```bash
./registration_stress.sh [REQUESTS]   # default 200
```

Fires rapid registration requests to verify rate limiting. Reports how many were throttled (HTTP 429) vs succeeded.

**Expected:** Rate limiting should kick in after a burst, returning 429 responses.

### 4. API Latency

```bash
./api_latency.sh [REQUESTS] [CONCURRENCY]   # defaults: 500 reqs, 10 concurrent
```

Benchmarks REST endpoints (`/health`, `/api/build-info`, node info, channel messages) with concurrent requests. Reports p50/p95/p99 latencies.

**Note:** Authenticated endpoints require `TEST_AUTH_TOKEN` to be set.

## Quick Start

```bash
# Start the server
cd /path/to/Accord && cargo run -p accord-server

# In another terminal
cd tests/load
chmod +x *.sh

# Run all tests
export ACCORD_URL=http://localhost:8443
./concurrent_connections.sh 50
./registration_stress.sh 100
./api_latency.sh 200 5
./message_throughput.sh 5 20
```

## Interpreting Results

- **concurrent_connections:** >95% success rate is healthy. Connection times >500ms suggest server strain.
- **message_throughput:** Baseline depends on hardware. Track regressions across runs.
- **registration_stress:** If 0 rate-limited responses, rate limiting may not be configured.
- **api_latency:** `/health` should be <10ms p99. Authenticated endpoints depend on DB load.
