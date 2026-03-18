# Accord Benchmark Suite

Criterion-based micro-benchmarks for the Accord server and core cryptography library.
These establish baseline performance metrics and catch regressions.

## Structure

```
core/benches/crypto_benchmarks.rs   — Cryptography: Double Ratchet, X3DH, Sender Keys, SRTP
server/benches/server_benchmarks.rs — Server: registration, auth, token validation,
                                      node/channel ops, message storage/query, broadcast
tests/load/                         — End-to-end load tests (requires running server)
```

## Running the Benchmarks

### All benchmarks

```bash
source ~/.cargo/env
cargo bench
```

### Specific crate

```bash
# Crypto only (accord-core)
cargo bench -p accord-core

# Server only (accord-server)
cargo bench -p accord-server
```

### Single benchmark group

```bash
# Only double_ratchet benchmarks
cargo bench -p accord-core -- double_ratchet

# Only message storage benchmarks
cargo bench -p accord-server -- message/store
```

### Dry run (compile only, no timing runs)

```bash
cargo bench --no-run
```

## Benchmark Groups

### `accord-core` — `crypto_benchmarks`

| Group | What it measures |
|---|---|
| `double_ratchet/encrypt` | AES-GCM encrypt + header serialization at 64/256/1024/4096B |
| `double_ratchet/encrypt_decrypt_cycle` | Full encrypt→decrypt roundtrip |
| `double_ratchet/alternating_messages` | DH ratchet step cost (Alice↔Bob turn-taking) |
| `x3dh/initiate` | Alice-side X3DH key agreement |
| `x3dh/respond` | Bob-side X3DH key agreement |
| `x3dh/full_handshake` | Complete key generation + exchange |
| `srtp/encrypt_packet` | SRTP voice packet encryption (80–640B Opus frames) |
| `srtp/encrypt_decrypt_cycle` | SRTP full packet roundtrip |
| `srtp/voice_key_derivation` | VoiceSessionKey derivation from session material |
| `srtp/srtp_key_derivation` | Per-SSRC SRTP key derivation |
| `sender_keys/generate_key` | SenderKey key generation (signing + chain key) |
| `sender_keys/encrypt` | Sender key encrypt at 64/256/1024/4096B |
| `sender_keys/encrypt_decrypt_cycle` | Full sender key encrypt→decrypt roundtrip |
| `sender_key_store/channel_encrypt` | High-level `encrypt_channel_message` (with store) |

### `accord-server` — `server_benchmarks`

| Group | What it measures |
|---|---|
| `state/init_in_memory` | AppState cold-start with in-memory SQLite |
| `user/register` | User registration (bcrypt hash + DB insert) |
| `user/authenticate` | Password auth (bcrypt verify + token issue) |
| `user/validate_token` | Token lookup from in-memory store |
| `node/create` | Node creation (DB insert + channel bootstrap) |
| `node/join` | User joining a node |
| `message/store` | Message insert at 64/256/1024/4096B payload |
| `db_query/messages_paginated` | Paginated message fetch (10/50/100 rows) |
| `db_query/message_search` | Full-text message search |
| `broadcast/send_to_channel` | Fan-out to 10/100/1000 connected users |

## Interpreting Results

Criterion reports:
- **mean / median** — central tendency for one iteration
- **std dev** — spread; high std dev = noisy measurement
- **outliers** — spikes, often from OS scheduling or GC-equivalent jitter

**Regression detection:** Criterion compares against a saved baseline in
`target/criterion/`. If a run is significantly slower it prints a ⚠ regression
warning. Commit `target/criterion/` to track baselines in CI (or use
`--save-baseline <name>` / `--baseline <name>` for named comparisons).

### Expected baseline ranges (commodity Linux x86-64, release build)

| Operation | Rough target |
|---|---|
| Double Ratchet encrypt (256B) | < 50 µs |
| X3DH full handshake | < 1 ms |
| Sender key encrypt (256B) | < 100 µs |
| Message store | < 2 ms |
| Message query (50 rows) | < 5 ms |
| Broadcast (100 users) | < 1 ms |

> These are order-of-magnitude targets for a healthy system, not hard SLOs.
> Actual numbers vary by hardware and load. Use the baseline comparison workflow
> to detect regressions rather than comparing against these absolute numbers.

## Relationship to Load Tests

The Criterion benchmarks in `core/benches/` and `server/benches/` are
**unit-level microbenchmarks** — they measure isolated function performance
in-process with no network overhead.

The scripts in `tests/load/` are **end-to-end load tests** that exercise the
full HTTP/WebSocket stack against a live server. Use both:

- Microbenchmarks → diagnose where CPU time goes, catch algorithm regressions
- Load tests → measure real-world throughput, connection limits, rate-limiting behaviour
