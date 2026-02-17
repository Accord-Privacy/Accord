# Accord Performance Benchmarks

## Quick Start

```bash
# Run all benchmarks
cargo bench

# Run only crypto benchmarks (core)
cargo bench -p accord-core

# Run only server benchmarks
cargo bench -p accord-server

# Run a specific benchmark group
cargo bench -p accord-core -- double_ratchet
cargo bench -p accord-core -- x3dh
cargo bench -p accord-core -- srtp
cargo bench -p accord-server -- broadcast
```

## What We Benchmark

### Core Crypto (`core/benches/crypto_benchmarks.rs`)

| Benchmark | What it measures |
|-----------|-----------------|
| `double_ratchet/encrypt` | Raw encrypt throughput at various payload sizes (64B–4KB) |
| `double_ratchet/encrypt_decrypt_cycle` | Full encrypt→decrypt round-trip |
| `double_ratchet/alternating_messages` | Encrypt+decrypt with DH ratchet rotation each turn |
| `x3dh/initiate` | Alice-side X3DH key agreement |
| `x3dh/respond` | Bob-side X3DH key agreement |
| `x3dh/full_handshake` | Complete X3DH including key generation |
| `srtp/encrypt_packet` | SRTP voice packet encryption at typical Opus frame sizes |
| `srtp/encrypt_decrypt_cycle` | Full SRTP encrypt→decrypt round-trip |
| `srtp/voice_key_derivation` | HKDF-based voice session key derivation |
| `srtp/srtp_key_derivation` | SRTP cipher/auth key derivation from voice key |

### Server (`server/benches/server_benchmarks.rs`)

| Benchmark | What it measures |
|-----------|-----------------|
| `state/init_in_memory` | In-memory database + state initialization |
| `user/register` | User registration throughput |
| `user/authenticate` | Authentication (Argon2 verify) throughput |
| `user/validate_token` | Token validation (in-memory HashMap lookup) |
| `node/create` | Node creation throughput |
| `node/join` | Node join (register + join) throughput |
| `message/store` | Message storage at various payload sizes |
| `broadcast/send_to_channel` | Fan-out broadcast to 10/100/1000 connected users |

### Load Testing (`scripts/load-test.sh`)

Integration-level load testing against a running server:
- Concurrent WebSocket connection establishment
- REST API throughput (health endpoint)
- Connection success rate under load

```bash
# Start server first
cargo run --release -p accord-server &

# Run load test
./scripts/load-test.sh -c 500 -m 10

# Heavy load test (increase ulimit first)
ulimit -n 65536
./scripts/load-test.sh -c 5000 -m 5 -r 30
```

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Concurrent WebSocket connections | **10,000+** | Per server instance |
| Message relay latency (server-side) | **< 50ms** | Time from receive to fan-out |
| WebSocket connection establishment | **< 100ms** | Including auth |
| Double Ratchet encrypt (256B) | **> 50,000 ops/s** | Per core |
| X3DH full handshake | **> 5,000 ops/s** | Per core |
| SRTP encrypt (160B Opus frame) | **> 200,000 ops/s** | Per core |
| REST API throughput | **> 10,000 req/s** | Health endpoint, per core |
| Broadcast to 1000 users | **< 5ms** | In-process fan-out |

## Reading Results

Criterion outputs HTML reports in `target/criterion/`. After running benchmarks:

```bash
# Open the report
open target/criterion/report/index.html  # macOS
xdg-open target/criterion/report/index.html  # Linux
```

Each benchmark shows:
- **Mean time** per iteration
- **Throughput** (bytes/sec for sized benchmarks)
- **Comparison** with previous run (if available)

## CI Integration

Benchmarks are not run in CI by default (they need stable hardware for meaningful results). To compare performance across commits:

```bash
# Save baseline
cargo bench -- --save-baseline before-change

# Make changes, then compare
cargo bench -- --baseline before-change
```

## Scaling Notes

The Accord server is designed around:
- **Tokio async runtime** — non-blocking I/O for all connections
- **broadcast::channel** — efficient fan-out for WebSocket messages
- **SQLite** — single-writer, many-reader for persistence
- **In-memory auth tokens** — O(1) token validation via HashMap

For 10k+ concurrent users, key bottlenecks to watch:
1. **File descriptor limits** — `ulimit -n 65536`
2. **SQLite write contention** — consider PostgreSQL for production
3. **Memory per connection** — broadcast channel buffer size
4. **Argon2 CPU cost** — authentication is intentionally slow (security trade-off)
