//! Server performance benchmarks for Accord
//!
//! These benchmarks measure server-side operations that don't require
//! a live network connection. For full WebSocket load testing, see
//! scripts/load-test.sh and the load-test binary.
//!
//! Benchmarked:
//! - State initialization (in-memory DB)
//! - User registration throughput
//! - Authentication throughput
//! - Token validation
//! - Node creation and joining
//! - Channel creation and message storage
//! - Broadcast to connected users (simulated)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::Arc;
use tokio::runtime::Runtime;

use accord_server::state::AppState;

fn rt() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

// ─── State initialization ────────────────────────────────────────────────────

fn bench_state_init(c: &mut Criterion) {
    let rt = rt();
    c.bench_function("state/init_in_memory", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(AppState::new_in_memory().await.unwrap());
        });
    });
}

// ─── User registration ──────────────────────────────────────────────────────

fn bench_user_registration(c: &mut Criterion) {
    let rt = rt();
    c.bench_function("user/register", |b| {
        let state = rt.block_on(AppState::new_in_memory()).unwrap();
        let mut counter = 0u64;
        b.to_async(&rt).iter(|| {
            counter += 1;
            let username = format!("user_{}", counter);
            let state_ref = &state;
            async move {
                black_box(
                    state_ref
                        .register_user(username, "pubkey123".into(), "password".into())
                        .await,
                );
            }
        });
    });
}

// ─── Authentication ──────────────────────────────────────────────────────────

fn bench_authentication(c: &mut Criterion) {
    let rt = rt();
    let state = rt.block_on(AppState::new_in_memory()).unwrap();
    rt.block_on(state.register_user(
        "bench_user".into(),
        "pubkey".into(),
        "bench_password".into(),
    ))
    .unwrap();

    c.bench_function("user/authenticate", |b| {
        b.to_async(&rt).iter(|| {
            let state_ref = &state;
            async move {
                black_box(
                    state_ref
                        .authenticate_user("bench_user".into(), "bench_password".into())
                        .await,
                );
            }
        });
    });
}

// ─── Token validation ────────────────────────────────────────────────────────

fn bench_token_validation(c: &mut Criterion) {
    let rt = rt();
    let state = rt.block_on(AppState::new_in_memory()).unwrap();
    rt.block_on(state.register_user("tv_user".into(), "pk".into(), "pw".into()))
        .unwrap();
    let auth = rt
        .block_on(state.authenticate_user("tv_user".into(), "pw".into()))
        .unwrap();
    let token = auth.token.clone();

    c.bench_function("user/validate_token", |b| {
        b.to_async(&rt).iter(|| {
            let state_ref = &state;
            let t = &token;
            async move {
                black_box(state_ref.validate_token(t).await);
            }
        });
    });
}

// ─── Node operations ─────────────────────────────────────────────────────────

fn bench_node_operations(c: &mut Criterion) {
    let rt = rt();
    let state = rt.block_on(AppState::new_in_memory()).unwrap();
    let owner = rt
        .block_on(state.register_user("owner".into(), "pk".into(), "pw".into()))
        .unwrap();

    let mut group = c.benchmark_group("node");

    group.bench_function("create", |b| {
        let mut counter = 0u64;
        b.to_async(&rt).iter(|| {
            counter += 1;
            let name = format!("node_{}", counter);
            let state_ref = &state;
            async move {
                black_box(state_ref.create_node(name, owner, None).await.unwrap());
            }
        });
    });

    // Pre-create a node for join benchmarks
    let node = rt
        .block_on(state.create_node("join_node".into(), owner, None))
        .unwrap();

    group.bench_function("join", |b| {
        let mut counter = 0u64;
        b.to_async(&rt).iter(|| {
            counter += 1;
            let username = format!("joiner_{}", counter);
            let state_ref = &state;
            let node_id = node.id;
            async move {
                let uid = state_ref
                    .register_user(username, "pk".into(), "".into())
                    .await
                    .unwrap();
                black_box(state_ref.join_node(uid, node_id).await.unwrap());
            }
        });
    });

    group.finish();
}

// ─── Message storage ─────────────────────────────────────────────────────────

fn bench_message_storage(c: &mut Criterion) {
    let rt = rt();
    let state = rt.block_on(AppState::new_in_memory()).unwrap();
    let owner = rt
        .block_on(state.register_user("msg_owner".into(), "pk".into(), "pw".into()))
        .unwrap();
    let node = rt
        .block_on(state.create_node("msg_node".into(), owner, None))
        .unwrap();
    let channel = rt
        .block_on(state.create_channel("bench_ch".into(), node.id, owner))
        .unwrap();

    let mut group = c.benchmark_group("message");

    for size in [64, 256, 1024, 4096] {
        let payload = vec![0xABu8; size];
        group.bench_with_input(BenchmarkId::new("store", size), &payload, |b, payload| {
            b.to_async(&rt).iter(|| {
                let state_ref = &state;
                let ch_id = channel.id;
                async move {
                    black_box(
                        state_ref
                            .store_message(ch_id, owner, black_box(payload))
                            .await
                            .unwrap(),
                    );
                }
            });
        });
    }

    group.finish();
}

// ─── Broadcast simulation ────────────────────────────────────────────────────

fn bench_broadcast(c: &mut Criterion) {
    let rt = rt();

    let mut group = c.benchmark_group("broadcast");

    for num_recipients in [10, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::new("send_to_channel", num_recipients),
            &num_recipients,
            |b, &n| {
                let state = rt.block_on(AppState::new_in_memory()).unwrap();
                let state = Arc::new(state);
                let owner = rt
                    .block_on(state.register_user("bc_owner".into(), "pk".into(), "".into()))
                    .unwrap();
                let node = rt
                    .block_on(state.create_node("bc_node".into(), owner, None))
                    .unwrap();
                let channel = rt
                    .block_on(state.create_channel("bc_ch".into(), node.id, owner))
                    .unwrap();

                // Register users and add WebSocket connections (broadcast senders)
                for i in 0..n {
                    let uid = rt
                        .block_on(state.register_user(format!("bc_u{}", i), "pk".into(), "".into()))
                        .unwrap();
                    rt.block_on(state.join_node(uid, node.id)).unwrap();
                    rt.block_on(state.join_channel(uid, channel.id)).unwrap();
                    let (tx, _rx) = tokio::sync::broadcast::channel(16);
                    rt.block_on(state.add_connection(uid, tx));
                }

                let msg = r#"{"type":"message","content":"benchmark"}"#.to_string();

                b.to_async(&rt).iter(|| {
                    let state_ref = state.clone();
                    let m = msg.clone();
                    let ch_id = channel.id;
                    async move {
                        black_box(state_ref.send_to_channel(ch_id, m).await.unwrap());
                    }
                });
            },
        );
    }

    group.finish();
}

// ─── Groups ──────────────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_state_init,
    bench_user_registration,
    bench_authentication,
    bench_token_validation,
    bench_node_operations,
    bench_message_storage,
    bench_broadcast,
);
criterion_main!(benches);
