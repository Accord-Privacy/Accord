//! SPEC-02 section 6.7: the accord-core reference implementation against the
//! shared vector files, which the TypeScript client reads too (T-2, T-3, T-9,
//! T-45). `attachments-v1.json` holds the Padmé table and TV1 to TV5;
//! `typed-plaintext-v1.json` holds V1 to V26 and the further cases of T-9.
//!
//! The fixed-key sealer exists only under the `test-vectors` feature, which
//! the crate's dev-dependency on itself turns on for test builds.

use accord_core::attachment::{
    accepted_paths, blob_length, classify_plaintext, open, padme, read_envelope_v1, record_count,
    seal_with_fixed_key_for_vectors, Classified, OpenParams, RECORD_SIZE,
};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn vectors(name: &str) -> Value {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).expect("vector file")).expect("vector JSON")
}

fn hex32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn plaintext_of(p: &Value) -> Vec<u8> {
    match p["kind"].as_str().unwrap() {
        "hex" => hex::decode(p["hex"].as_str().unwrap()).unwrap(),
        "repeat" => vec![p["byte"].as_u64().unwrap() as u8; p["length"].as_u64().unwrap() as usize],
        "mod251" => (0..p["length"].as_u64().unwrap() as usize)
            .map(|i| (i % 251) as u8)
            .collect(),
        other => panic!("unknown plaintext kind {other}"),
    }
}

#[test]
fn gcm_primitive_matches_mcgrew_viega_13_and_14() {
    let v = vectors("attachments-v1.json");
    for tc in v["gcm_primitive_checks"].as_array().unwrap() {
        let key = hex32(&tc["key_hex"]);
        let nonce = hex::decode(tc["nonce_hex"].as_str().unwrap()).unwrap();
        let pt = hex::decode(tc["plaintext_hex"].as_str().unwrap()).unwrap();
        let out = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(Nonce::from_slice(&nonce), pt.as_slice())
            .unwrap();
        let expected = format!(
            "{}{}",
            tc["ciphertext_hex"].as_str().unwrap(),
            tc["tag_hex"].as_str().unwrap()
        );
        assert_eq!(hex::encode(out), expected, "{}", tc["id"]);
    }
}

#[test]
fn padme_table() {
    let v = vectors("attachments-v1.json");
    let table = v["padme"].as_array().unwrap();
    assert_eq!(table.len(), 18);
    for row in table {
        assert_eq!(
            padme(row["size"].as_u64().unwrap()),
            row["padded_size"].as_u64().unwrap(),
            "padme({})",
            row["size"]
        );
    }
}

#[test]
fn blob_vectors_tv1_to_tv5() {
    let v = vectors("attachments-v1.json");
    let key = hex32(&v["key_hex"]);
    let prefix: [u8; 7] = hex::decode(v["nonce_prefix_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let blobs = v["blobs"].as_array().unwrap();
    assert_eq!(blobs.len(), 5);
    for b in blobs {
        let id = b["id"].as_str().unwrap();
        let plain = plaintext_of(&b["plaintext"]);
        let sealed = seal_with_fixed_key_for_vectors(&plain, &key, &prefix).unwrap();
        assert_eq!(sealed.size, b["size"].as_u64().unwrap(), "{id}");
        assert_eq!(
            sealed.padded_size,
            b["padded_size"].as_u64().unwrap(),
            "{id}"
        );
        assert_eq!(
            record_count(sealed.padded_size),
            b["records"].as_u64().unwrap(),
            "{id}"
        );
        assert_eq!(
            sealed.blob.len() as u64,
            b["blob_length"].as_u64().unwrap(),
            "{id}"
        );
        assert_eq!(
            blob_length(sealed.padded_size),
            sealed.blob.len() as u64,
            "{id}"
        );
        // Record tags: the last 16 bytes of each record output.
        let n = record_count(sealed.padded_size);
        let mut off = 0usize;
        let mut tags = Vec::new();
        for i in 0..n {
            let plen = if i < n - 1 {
                RECORD_SIZE
            } else {
                sealed.padded_size - (n - 1) * RECORD_SIZE
            } as usize;
            off += plen + 16;
            tags.push(hex::encode(&sealed.blob[off - 16..off]));
        }
        let expected_tags: Vec<String> = b["record_tags_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(tags, expected_tags, "{id}");
        assert_eq!(
            hex::encode(sealed.sha256),
            b["sha256_hex"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&sealed.blob)),
            b["sha256_hex"].as_str().unwrap()
        );
        if let Some(full) = b.get("blob_hex") {
            assert_eq!(hex::encode(&sealed.blob), full.as_str().unwrap(), "{id}");
        }
        let opened = open(
            &sealed.blob,
            OpenParams {
                key: &key,
                nonce_prefix: &prefix,
                sha256: &sealed.sha256,
                size: sealed.size,
                padded_size: sealed.padded_size,
            },
        )
        .unwrap();
        assert_eq!(opened, plain, "{id}");
    }
}

/// The class name only: a failure message never prints the plaintext.
fn class_name(c: &Classified) -> &'static str {
    match c {
        Classified::Control(_) => "control",
        Classified::EnvelopeInvalid(_)
        | Classified::EnvelopeNewer(_)
        | Classified::EnvelopeV1(_) => "envelope",
        Classified::LegacyText { .. } => "legacy_text",
    }
}

fn path_codes(c: &Classified) -> Vec<String> {
    accepted_paths(c)
        .iter()
        .map(|p| p.code().to_owned())
        .collect()
}

#[test]
fn typed_plaintext_vectors() {
    let v = vectors("typed-plaintext-v1.json");
    let list = v["vectors"].as_array().unwrap();
    for i in 1..=26 {
        assert!(
            list.iter().any(|x| x["id"] == format!("V{i}")),
            "V{i} missing"
        );
    }
    for x in list {
        let id = x["id"].as_str().unwrap();
        let e = &x["expect"];
        let bytes = hex::decode(x["plaintext_hex"].as_str().unwrap()).unwrap();
        let c = classify_plaintext(&bytes);
        let accepted: Vec<String> = e["accepted_by"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(path_codes(&c), accepted, "{id}: accepted_by");
        match (e["class"].as_str().unwrap(), &c) {
            ("control", Classified::Control(Ok(valid))) => {
                assert_eq!(e["valid"], true, "{id}");
                assert_eq!(valid.tag, e["tag"].as_str().unwrap(), "{id}");
                assert_eq!(valid.type_, e["type"].as_str().unwrap(), "{id}");
            }
            ("control", Classified::Control(Err(f))) => {
                assert_eq!(e["valid"], false, "{id}");
                assert_eq!(f.code(), e["reason"].as_str().unwrap(), "{id}");
            }
            ("envelope", Classified::EnvelopeInvalid(f)) => {
                assert_eq!(e["result"], "invalid", "{id}");
                assert_eq!(f.code(), e["reason"].as_str().unwrap(), "{id}");
            }
            ("envelope", Classified::EnvelopeNewer(_)) => {
                assert_eq!(e["result"], "newer_version", "{id}");
            }
            ("envelope", Classified::EnvelopeV1(o)) => match read_envelope_v1(o) {
                accord_core::attachment::EnvelopeRead::Valid(env) => {
                    assert_eq!(e["result"], "valid", "{id}");
                    assert_eq!(env.channel_id, e["channel_id"].as_str().unwrap(), "{id}");
                    assert_eq!(env.body, e["body"].as_str().unwrap(), "{id}");
                    assert_eq!(
                        env.attachments.len() as u64,
                        e["attachments"].as_u64().unwrap(),
                        "{id}"
                    );
                    let unusable = env.attachments.iter().filter(|a| a.is_none()).count() as u64;
                    assert_eq!(unusable, e["unusable"].as_u64().unwrap(), "{id}");
                }
                accord_core::attachment::EnvelopeRead::Invalid(f) => {
                    assert_eq!(e["result"], "invalid", "{id}");
                    assert_eq!(f.code(), e["reason"].as_str().unwrap(), "{id}");
                }
                accord_core::attachment::EnvelopeRead::NewerVersion => {
                    panic!("{id}: read_envelope_v1 never reports a newer version")
                }
            },
            ("legacy_text", Classified::LegacyText { legacy_key_json }) => {
                assert_eq!(
                    *legacy_key_json,
                    e["legacy_key_json"].as_bool().unwrap(),
                    "{id}"
                );
            }
            (expected, got) => panic!(
                "{id}: expected class {expected}, got {} accepted by {:?}",
                class_name(got),
                path_codes(got)
            ),
        }
    }
}
