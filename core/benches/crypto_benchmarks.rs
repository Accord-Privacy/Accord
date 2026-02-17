//! Crypto benchmarks for Accord core
//!
//! Benchmarks: Double Ratchet, X3DH, SRTP encrypt/decrypt

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use accord_core::double_ratchet::{
    x3dh_initiate, x3dh_respond, DoubleRatchetSession, IdentityKeyPair, OneTimePreKeyPair,
    PreKeyBundle, SignedPreKeyPair,
};
use accord_core::srtp::{VoiceDecryptor, VoiceEncryptor, VoiceSessionKey};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn setup_double_ratchet_sessions() -> (DoubleRatchetSession, DoubleRatchetSession) {
    let alice_ik = IdentityKeyPair::generate();
    let bob_ik = IdentityKeyPair::generate();
    let bob_spk = SignedPreKeyPair::generate();
    let bob_opk = OneTimePreKeyPair::generate();

    let bundle = PreKeyBundle {
        identity_key: bob_ik.public.to_bytes(),
        signed_prekey: bob_spk.public.to_bytes(),
        one_time_prekey: Some(bob_opk.public.to_bytes()),
    };

    let x3dh_out = x3dh_initiate(&alice_ik, &bundle).unwrap();
    let bob_sk = x3dh_respond(
        &bob_ik,
        &bob_spk,
        Some(&bob_opk),
        alice_ik.public.to_bytes(),
        x3dh_out.ephemeral_public.to_bytes(),
    )
    .unwrap();

    let alice = DoubleRatchetSession::init_alice(x3dh_out.shared_secret, bob_spk.public.to_bytes())
        .unwrap();
    let bob = DoubleRatchetSession::init_bob(bob_sk, bob_spk.secret.clone());

    (alice, bob)
}

fn voice_key() -> VoiceSessionKey {
    VoiceSessionKey::derive(&[42u8; 32], &[1u8; 16])
}

// ─── Double Ratchet benchmarks ───────────────────────────────────────────────

fn bench_double_ratchet_encrypt_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("double_ratchet");

    for size in [64, 256, 1024, 4096] {
        let payload = vec![0xABu8; size];

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("encrypt", size), &payload, |b, payload| {
            let (mut alice, _bob) = setup_double_ratchet_sessions();
            b.iter(|| {
                black_box(alice.encrypt(black_box(payload)).unwrap());
            });
        });

        group.bench_with_input(
            BenchmarkId::new("encrypt_decrypt_cycle", size),
            &payload,
            |b, payload| {
                let (mut alice, mut bob) = setup_double_ratchet_sessions();
                b.iter(|| {
                    let msg = alice.encrypt(black_box(payload)).unwrap();
                    black_box(bob.decrypt(&msg).unwrap());
                });
            },
        );
    }

    group.finish();
}

fn bench_double_ratchet_with_dh_ratchet(c: &mut Criterion) {
    c.bench_function("double_ratchet/alternating_messages", |b| {
        let (mut alice, mut bob) = setup_double_ratchet_sessions();
        let payload = vec![0xABu8; 256];
        b.iter(|| {
            // Each iteration: Alice→Bob then Bob→Alice (triggers DH ratchet)
            let msg = alice.encrypt(black_box(&payload)).unwrap();
            bob.decrypt(&msg).unwrap();
            let reply = bob.encrypt(black_box(&payload)).unwrap();
            alice.decrypt(&reply).unwrap();
        });
    });
}

// ─── X3DH benchmarks ────────────────────────────────────────────────────────

fn bench_x3dh(c: &mut Criterion) {
    let mut group = c.benchmark_group("x3dh");

    group.bench_function("initiate", |b| {
        let alice_ik = IdentityKeyPair::generate();
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKeyPair::generate();
        let bob_opk = OneTimePreKeyPair::generate();

        let bundle = PreKeyBundle {
            identity_key: bob_ik.public.to_bytes(),
            signed_prekey: bob_spk.public.to_bytes(),
            one_time_prekey: Some(bob_opk.public.to_bytes()),
        };

        b.iter(|| {
            black_box(x3dh_initiate(&alice_ik, &bundle).unwrap());
        });
    });

    group.bench_function("respond", |b| {
        let alice_ik = IdentityKeyPair::generate();
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKeyPair::generate();
        let bob_opk = OneTimePreKeyPair::generate();

        let bundle = PreKeyBundle {
            identity_key: bob_ik.public.to_bytes(),
            signed_prekey: bob_spk.public.to_bytes(),
            one_time_prekey: Some(bob_opk.public.to_bytes()),
        };

        let x3dh_out = x3dh_initiate(&alice_ik, &bundle).unwrap();
        let eph_pub = x3dh_out.ephemeral_public.to_bytes();
        let alice_pub = alice_ik.public.to_bytes();

        b.iter(|| {
            black_box(x3dh_respond(&bob_ik, &bob_spk, Some(&bob_opk), alice_pub, eph_pub).unwrap());
        });
    });

    group.bench_function("full_handshake", |b| {
        b.iter(|| {
            let alice_ik = IdentityKeyPair::generate();
            let bob_ik = IdentityKeyPair::generate();
            let bob_spk = SignedPreKeyPair::generate();
            let bob_opk = OneTimePreKeyPair::generate();

            let bundle = PreKeyBundle {
                identity_key: bob_ik.public.to_bytes(),
                signed_prekey: bob_spk.public.to_bytes(),
                one_time_prekey: Some(bob_opk.public.to_bytes()),
            };

            let x3dh_out = x3dh_initiate(&alice_ik, &bundle).unwrap();
            black_box(
                x3dh_respond(
                    &bob_ik,
                    &bob_spk,
                    Some(&bob_opk),
                    alice_ik.public.to_bytes(),
                    x3dh_out.ephemeral_public.to_bytes(),
                )
                .unwrap(),
            );
        });
    });

    group.finish();
}

// ─── SRTP benchmarks ─────────────────────────────────────────────────────────

fn bench_srtp(c: &mut Criterion) {
    let mut group = c.benchmark_group("srtp");

    // Typical Opus frame sizes at different bitrates
    for size in [80, 160, 320, 640] {
        let payload = vec![0xCDu8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("encrypt_packet", size),
            &payload,
            |b, payload| {
                let vk = voice_key();
                let mut enc = VoiceEncryptor::new(12345, vk);
                b.iter(|| {
                    black_box(enc.encrypt_packet(black_box(payload)).unwrap());
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("encrypt_decrypt_cycle", size),
            &payload,
            |b, payload| {
                let vk = voice_key();
                let mut enc = VoiceEncryptor::new(12345, vk.clone());
                let mut dec = VoiceDecryptor::new(12345, vk);
                b.iter(|| {
                    let pkt = enc.encrypt_packet(black_box(payload)).unwrap();
                    black_box(dec.decrypt_packet(&pkt).unwrap());
                });
            },
        );
    }

    group.finish();
}

fn bench_srtp_key_derivation(c: &mut Criterion) {
    c.bench_function("srtp/voice_key_derivation", |b| {
        let session_key = [42u8; 32];
        let channel_id = [1u8; 16];
        b.iter(|| {
            black_box(VoiceSessionKey::derive(
                black_box(&session_key),
                black_box(&channel_id),
            ));
        });
    });

    c.bench_function("srtp/srtp_key_derivation", |b| {
        let vk = voice_key();
        b.iter(|| {
            black_box(vk.derive_srtp_keys(black_box(0)));
        });
    });
}

// ─── Groups ──────────────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_double_ratchet_encrypt_decrypt,
    bench_double_ratchet_with_dh_ratchet,
    bench_x3dh,
    bench_srtp,
    bench_srtp_key_derivation,
);
criterion_main!(benches);
