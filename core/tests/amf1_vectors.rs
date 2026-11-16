//! SPEC-03 section 6.11: an independent reader of the shared AMF1 vector file
//! `vectors/amf1-v1.json`, which the TypeScript client checks too
//! (`desktop/frontend/src/voice/mediaFrame.test.ts`, `vp8.test.ts`); both must
//! agree on every entry (T-14).
//!
//! The Accord media frame v1 is reimplemented here from section 6.2 with the
//! crate's existing `hkdf`, `sha2` and `aes-gcm` dependencies: the SFrame
//! header (RFC 9605 section 4.3), the key schedule of RFC 9605 section 4.4.2
//! for suite 0x0005 and the screen base key of section 6.2.4, the 50-byte
//! metadata, the receive checks of sections 6.2.6 and 6.2.8, the fragment
//! header of section 6.2.7, the call payload body rules of section 6.3 (after
//! SPEC-02's classifier), the binary relay messages of section 6.12.2 and the
//! VP8 checks of section 6.2.9.

use accord_core::attachment::{classify_plaintext, Classified, JsonValue};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use hkdf::Hkdf;
use serde_json::Value;
use sha2::Sha512;

const VECTORS: &str = include_str!("vectors/amf1-v1.json");

const SUITE: u16 = 0x0005;
const AUDIO: u8 = 0x01;
const VIDEO: u8 = 0x02;
const KID_LIMIT: u64 = 1 << 32;
const CTR_LIMIT: u64 = 1 << 48;
const TAG_LEN: usize = 16;
const FRAG_HDR: usize = 18;
const FRAG_PAYLOAD: usize = 16_000;

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("amf1-v1.json is JSON")
}

fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("hex")
}

fn int(v: &Value) -> u64 {
    v.as_u64().expect("integer")
}

fn arr<'a>(v: &'a Value, name: &str) -> &'a Vec<Value> {
    v[name]
        .as_array()
        .unwrap_or_else(|| panic!("section {name}"))
}

// ---------------------------------------------------------------------------
// SFrame header
// ---------------------------------------------------------------------------

fn minimal_be(v: u64) -> Vec<u8> {
    let b = v.to_be_bytes();
    let first = b.iter().position(|&x| x != 0).unwrap_or(8);
    b[first..].to_vec()
}

/// RFC 9605 section 4.3 encoding with minimal lengths (any u64).
fn encode_header(kid: u64, ctr: u64) -> Vec<u8> {
    let kb = if kid < 8 { vec![] } else { minimal_be(kid) };
    let cb = if ctr < 8 { vec![] } else { minimal_be(ctr) };
    let x = u8::from(kid >= 8);
    let k = if kid < 8 {
        kid as u8
    } else {
        (kb.len() - 1) as u8
    };
    let y = u8::from(ctr >= 8);
    let c = if ctr < 8 {
        ctr as u8
    } else {
        (cb.len() - 1) as u8
    };
    let mut out = vec![(x << 7) | (k << 4) | (y << 3) | c];
    out.extend(kb);
    out.extend(cb);
    out
}

fn read_extended(b: &[u8]) -> Option<u64> {
    if b.len() > 1 && b[0] == 0 {
        return None; // leading zero byte
    }
    let v = b.iter().fold(0u64, |acc, &x| (acc << 8) | u64::from(x));
    if v < 8 {
        return None; // belongs in the config byte
    }
    Some(v)
}

/// Decode with the minimal-encoding rule; `(kid, ctr, header length)`.
fn decode_header(b: &[u8]) -> Option<(u64, u64, usize)> {
    let cfg = *b.first()?;
    let (x, k, y, c) = (cfg >> 7, (cfg >> 4) & 7, (cfg >> 3) & 1, cfg & 7);
    let kid_len = if x == 1 { usize::from(k) + 1 } else { 0 };
    let ctr_len = if y == 1 { usize::from(c) + 1 } else { 0 };
    let len = 1 + kid_len + ctr_len;
    if b.len() < len {
        return None;
    }
    let kid = if x == 1 {
        read_extended(&b[1..1 + kid_len])?
    } else {
        u64::from(k)
    };
    let ctr = if y == 1 {
        read_extended(&b[1 + kid_len..len])?
    } else {
        u64::from(c)
    };
    Some((kid, ctr, len))
}

/// The AMF1 v1 decoder: additionally KID < 2^32 and CTR < 2^48.
fn decode_header_v1(b: &[u8]) -> Option<(u64, u64, usize)> {
    decode_header(b).filter(|&(kid, ctr, _)| kid < KID_LIMIT && ctr < CTR_LIMIT)
}

// ---------------------------------------------------------------------------
// Key schedule, metadata, AEAD
// ---------------------------------------------------------------------------

fn label(prefix: &[u8], kid: u64) -> Vec<u8> {
    let mut info = prefix.to_vec();
    info.extend(kid.to_be_bytes());
    info.extend(SUITE.to_be_bytes());
    info
}

/// deriveEpochKeys of section 6.2.4 (RFC 9605 section 4.4.2, suite 5).
fn derive(base_key: &[u8], kid: u64) -> ([u8; 32], [u8; 12]) {
    let hk = Hkdf::<Sha512>::new(Some(&[]), base_key);
    let mut key = [0u8; 32];
    let mut salt = [0u8; 12];
    hk.expand(&label(b"SFrame 1.0 Secret key ", kid), &mut key)
        .unwrap();
    hk.expand(&label(b"SFrame 1.0 Secret salt ", kid), &mut salt)
        .unwrap();
    (key, salt)
}

/// screenBase of section 6.2.4.
fn screen_base(secret: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha512>::new(Some(&[]), secret)
        .expand(b"Accord AMF1 screen base key", &mut out)
        .unwrap();
    out
}

fn keys_for(kind: u8, secret: &[u8], kid: u64) -> ([u8; 32], [u8; 12]) {
    match kind {
        AUDIO => derive(secret, kid),
        VIDEO => derive(&screen_base(secret), kid),
        _ => panic!("unknown media kind"),
    }
}

fn uuid_bytes(s: &str) -> Vec<u8> {
    hex::decode(s.replace('-', "")).expect("uuid")
}

struct Ctx {
    channel: Vec<u8>,
    sender: Vec<u8>,
    inst: Vec<u8>,
}

fn ctx_of(v: &Value) -> Ctx {
    Ctx {
        channel: uuid_bytes(v["channel_id"].as_str().unwrap()),
        sender: uuid_bytes(v["sender_id"].as_str().unwrap()),
        inst: unhex(&v["inst"]),
    }
}

fn metadata(format: u8, kind: u8, ctx: &Ctx) -> Vec<u8> {
    let mut out = vec![format, kind];
    out.extend(&ctx.channel);
    out.extend(&ctx.sender);
    out.extend(&ctx.inst);
    assert_eq!(out.len(), 50);
    out
}

fn nonce(salt: &[u8; 12], ctr: u64) -> [u8; 12] {
    let mut n = *salt;
    let c = ctr.to_be_bytes();
    for i in 0..8 {
        n[4 + i] ^= c[i];
    }
    n
}

fn sframe_encrypt(
    key: &[u8; 32],
    salt: &[u8; 12],
    kid: u64,
    ctr: u64,
    md: &[u8],
    pt: &[u8],
) -> Vec<u8> {
    let header = encode_header(kid, ctr);
    let mut aad = header.clone();
    aad.extend(md);
    let ct = Aes256Gcm::new_from_slice(key)
        .unwrap()
        .encrypt(
            Nonce::from_slice(&nonce(salt, ctr)),
            Payload { msg: pt, aad: &aad },
        )
        .unwrap();
    let mut out = header;
    out.extend(ct);
    out
}

fn sframe_decrypt(
    key: &[u8; 32],
    salt: &[u8; 12],
    header: &[u8],
    ctr: u64,
    md: &[u8],
    ct: &[u8],
) -> Option<Vec<u8>> {
    let mut aad = header.to_vec();
    aad.extend(md);
    Aes256Gcm::new_from_slice(key)
        .unwrap()
        .decrypt(
            Nonce::from_slice(&nonce(salt, ctr)),
            Payload { msg: ct, aad: &aad },
        )
        .ok()
}

/// sealFrame of section 6.2.5.
fn seal(kind: u8, secret: &[u8], kid: u64, ctr: u64, ctx: &Ctx, pt: &[u8]) -> Vec<u8> {
    let (key, salt) = keys_for(kind, secret, kid);
    let mut out = vec![0x01, kind];
    out.extend(sframe_encrypt(
        &key,
        &salt,
        kid,
        ctr,
        &metadata(0x01, kind, ctx),
        pt,
    ));
    out
}

// ---------------------------------------------------------------------------
// Fragment header (section 6.2.7)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
struct FragHeader {
    vcodec: u8,
    flags: u8,
    share_seq: u32,
    frame_no: u32,
    frag_index: u16,
    frag_count: u16,
    width: u16,
    height: u16,
}

fn within_caps(w: u64, h: u64) -> bool {
    (16..=1920).contains(&w) && (16..=1920).contains(&h) && w * h <= 2_073_600
}

fn parse_fragment(pt: &[u8]) -> Option<(FragHeader, &[u8])> {
    if pt.len() < FRAG_HDR + 1 {
        return None;
    }
    let u16_at = |i: usize| u16::from_be_bytes([pt[i], pt[i + 1]]);
    let u32_at = |i: usize| u32::from_be_bytes([pt[i], pt[i + 1], pt[i + 2], pt[i + 3]]);
    let h = FragHeader {
        vcodec: pt[0],
        flags: pt[1],
        share_seq: u32_at(2),
        frame_no: u32_at(6),
        frag_index: u16_at(10),
        frag_count: u16_at(12),
        width: u16_at(14),
        height: u16_at(16),
    };
    let payload = &pt[FRAG_HDR..];
    let ok = h.vcodec == 0x01
        && h.flags & !0x01 == 0
        && h.share_seq >= 1
        && (1..=64).contains(&h.frag_count)
        && h.frag_index < h.frag_count
        && within_caps(u64::from(h.width), u64::from(h.height))
        && !payload.is_empty()
        && payload.len() <= FRAG_PAYLOAD
        && (h.frag_index == h.frag_count - 1 || payload.len() == FRAG_PAYLOAD);
    ok.then_some((h, payload))
}

fn encode_fragment(h: &Value, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![int(&h["vcodec"]) as u8, int(&h["flags"]) as u8];
    out.extend((int(&h["share_seq"]) as u32).to_be_bytes());
    out.extend((int(&h["frame_no"]) as u32).to_be_bytes());
    for f in ["frag_index", "frag_count", "width", "height"] {
        out.extend((int(&h[f]) as u16).to_be_bytes());
    }
    out.extend(payload);
    out
}

// ---------------------------------------------------------------------------
// The receiver of sections 6.2.6 and 6.2.8 (steps 2 to 4, AEAD, step 10)
// ---------------------------------------------------------------------------

fn receive(bytes: &[u8], kind: u8, secret: &[u8], ctx: &Ctx) -> Result<Vec<u8>, &'static str> {
    let max = if kind == AUDIO { 4096 } else { 16_384 };
    if bytes.len() < 20 || bytes.len() > max {
        return Err("length");
    }
    if bytes[0] != 0x01 {
        return Err("format");
    }
    if bytes[1] != kind {
        return Err("kind");
    }
    let (kid, ctr, hlen) = decode_header_v1(&bytes[2..]).ok_or("header")?;
    if bytes.len() - 2 - hlen < TAG_LEN {
        return Err("header");
    }
    let (key, salt) = keys_for(kind, secret, kid);
    let header = &bytes[2..2 + hlen];
    let pt = sframe_decrypt(
        &key,
        &salt,
        header,
        ctr,
        &metadata(0x01, kind, ctx),
        &bytes[2 + hlen..],
    )
    .ok_or("aead")?;
    if kind == VIDEO && parse_fragment(&pt).is_none() {
        return Err("fragment");
    }
    Ok(pt)
}

// ---------------------------------------------------------------------------
// Call payloads (section 6.3, after SPEC-02's classifier)
// ---------------------------------------------------------------------------

fn is_canonical_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
}

fn string<'a>(body: &'a JsonValue, name: &str) -> Option<&'a str> {
    match body.get(name) {
        Some(JsonValue::String(s)) => Some(s),
        _ => None,
    }
}

fn integer(body: &JsonValue, name: &str) -> Option<u64> {
    match body.get(name) {
        Some(JsonValue::Int(n)) => Some(*n),
        _ => None,
    }
}

/// Standard base64 with padding, canonical, of exactly `len` bytes.
fn b64_bytes(s: &str, len: usize) -> Option<Vec<u8>> {
    let engine = base64::engine::general_purpose::STANDARD;
    let b = engine.decode(s).ok()?;
    (b.len() == len && engine.encode(&b) == s).then_some(b)
}

/// The type of an accepted call payload from `from` in channel `ch`.
fn call_payload(pt: &[u8], from: &str, ch: &str) -> Option<String> {
    let valid = match classify_plaintext(pt) {
        Classified::Control(Ok(v)) if v.tag == "accord-call" => v,
        _ => return None,
    };
    let body = &valid.body;
    if valid.v != 1 || integer(body, "v") != Some(1) {
        return None;
    }
    let uuid_ok = |name: &str, expected: &str| {
        string(body, name).is_some_and(|s| is_canonical_uuid(s) && s == expected)
    };
    if !uuid_ok("from", from) || !uuid_ok("ch", ch) {
        return None;
    }
    string(body, "inst").and_then(|s| b64_bytes(s, 16))?;
    let to_inst = match body.get("to_inst")? {
        JsonValue::Null => None,
        JsonValue::String(s) => Some(b64_bytes(s, 16)?),
        _ => return None,
    };
    let epoch_ok = || integer(body, "epoch").is_some_and(|e| e < KID_LIMIT);
    let ty = string(body, "type")?;
    let ok = match ty {
        "call_hello" => true,
        "call_key" => {
            to_inst.is_some()
                && integer(body, "suite") == Some(u64::from(SUITE))
                && epoch_ok()
                && string(body, "key").and_then(|s| b64_bytes(s, 32)).is_some()
        }
        "call_key_ack" => to_inst.is_some() && epoch_ok(),
        _ => false,
    };
    ok.then(|| ty.to_string())
}

// ---------------------------------------------------------------------------
// Binary relay messages (section 6.12.2) and VP8 checks (section 6.2.9)
// ---------------------------------------------------------------------------

fn uuid_string(b: &[u8]) -> String {
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// `(channel, from, fragment length)` of a well-formed message.
fn screen_wire(direction: &str, b: &[u8]) -> Option<(String, Option<String>, usize)> {
    match direction {
        "up" if (37..=16_401).contains(&b.len()) && b[0] == 0x01 => {
            Some((uuid_string(&b[1..17]), None, b.len() - 17))
        }
        "down" if (53..=16_417).contains(&b.len()) && b[0] == 0x02 => Some((
            uuid_string(&b[1..17]),
            Some(uuid_string(&b[17..33])),
            b.len() - 33,
        )),
        "up" | "down" => None,
        _ => panic!("direction"),
    }
}

fn vp8_tag_ok(d: &[u8], key: bool) -> bool {
    if d.len() < 3 {
        return false;
    }
    let tag = u32::from(d[0]) | (u32::from(d[1]) << 8) | (u32::from(d[2]) << 16);
    let is_key = tag & 1 == 0;
    let version = (tag >> 1) & 7;
    let first_part = ((tag >> 5) & 0x7FFFF) as usize;
    is_key == key && version <= 3 && d.len() > first_part + if key { 10 } else { 3 }
}

fn vp8_key_size(d: &[u8]) -> Option<(u64, u64)> {
    if d.len() < 10 || d[3..6] != [0x9d, 0x01, 0x2a] {
        return None;
    }
    let w = u64::from(u16::from_le_bytes([d[6], d[7]]) & 0x3FFF);
    let h = u64::from(u16::from_le_bytes([d[8], d[9]]) & 0x3FFF);
    Some((w, h))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn file_shape() {
    let v = vectors();
    assert_eq!(int(&v["version"]), 1);
    assert_eq!(int(&v["suite"]), 5);
    for s in [
        "headers",
        "key_schedule",
        "metadata",
        "frames",
        "negative",
        "call_payloads",
        "screen_base",
        "video_key_schedule",
        "video_fragments",
        "video_negative",
        "screen_wire",
        "vp8_headers",
    ] {
        assert!(!arr(&v, s).is_empty(), "{s}");
    }
}

#[test]
fn headers_encode_and_decode() {
    let v = vectors();
    for h in arr(&v, "headers") {
        let (kid, ctr) = (int(&h["kid"]), int(&h["ctr"]));
        let bytes = unhex(&h["hex"]);
        assert_eq!(encode_header(kid, ctr), bytes, "{kid}/{ctr}");
        assert_eq!(
            decode_header_v1(&bytes),
            Some((kid, ctr, bytes.len())),
            "{kid}/{ctr}"
        );
    }
    assert_eq!(hex::encode(encode_header(0x123, 0x4567)), "9901234567");
}

#[test]
fn rfc9605_c1_headers_outside_v1_limits() {
    let v = vectors();
    let out = arr(&v, "headers_out_of_range");
    assert!(out.len() > 100);
    let in_range = arr(&v, "headers")
        .iter()
        .filter(|h| h["source"] == "rfc9605-c1")
        .count();
    assert_eq!(in_range + out.len(), 289, "all of RFC 9605 Appendix C.1");
    for h in out {
        let kid = u64::from_str_radix(h["kid"].as_str().unwrap(), 16).unwrap();
        let ctr = u64::from_str_radix(h["ctr"].as_str().unwrap(), 16).unwrap();
        let bytes = unhex(&h["hex"]);
        // The generic RFC 9605 codec reproduces the RFC; AMF1 v1 rejects it.
        assert_eq!(encode_header(kid, ctr), bytes);
        assert_eq!(decode_header(&bytes), Some((kid, ctr, bytes.len())));
        assert_eq!(decode_header_v1(&bytes), None);
    }
}

#[test]
fn rfc9605_c3_suite_5() {
    let v = vectors();
    let c3 = &v["rfc9605_c3"];
    let base = unhex(&c3["base_key"]);
    assert_eq!(base.len(), 16);
    let (kid, ctr) = (int(&c3["kid"]), int(&c3["ctr"]));
    let (key, salt) = derive(&base, kid);
    assert_eq!(key.to_vec(), unhex(&c3["key"]));
    assert_eq!(salt.to_vec(), unhex(&c3["salt"]));
    assert_eq!(nonce(&salt, ctr).to_vec(), unhex(&c3["nonce"]));
    let md = unhex(&c3["metadata"]);
    let ct = sframe_encrypt(&key, &salt, kid, ctr, &md, &unhex(&c3["pt"]));
    assert_eq!(ct, unhex(&c3["ct"]));
    let mut aad = encode_header(kid, ctr);
    aad.extend(&md);
    assert_eq!(aad, unhex(&c3["aad"]));
    let hlen = decode_header(&ct).unwrap().2;
    assert_eq!(
        sframe_decrypt(&key, &salt, &ct[..hlen], ctr, &md, &ct[hlen..]),
        Some(unhex(&c3["pt"]))
    );
}

#[test]
fn key_schedule() {
    let v = vectors();
    for k in arr(&v, "key_schedule") {
        let (key, salt) = derive(&unhex(&k["base_key"]), int(&k["kid"]));
        assert_eq!(key.to_vec(), unhex(&k["key"]), "{}", k["kid"]);
        assert_eq!(salt.to_vec(), unhex(&k["salt"]), "{}", k["kid"]);
    }
}

#[test]
fn metadata_layout() {
    let v = vectors();
    for m in arr(&v, "metadata") {
        let md = metadata(int(&m["format"]) as u8, int(&m["kind"]) as u8, &ctx_of(m));
        assert_eq!(md, unhex(&m["hex"]));
    }
}

#[test]
fn audio_frames() {
    let v = vectors();
    for f in arr(&v, "frames") {
        let ctx = ctx_of(f);
        let secret = unhex(&f["base_key"]);
        let frame = seal(
            AUDIO,
            &secret,
            int(&f["kid"]),
            int(&f["ctr"]),
            &ctx,
            &unhex(&f["plaintext"]),
        );
        assert_eq!(frame, unhex(&f["frame"]), "{}/{}", f["kid"], f["ctr"]);
        assert_eq!(
            receive(&frame, AUDIO, &secret, &ctx),
            Ok(unhex(&f["plaintext"]))
        );
    }
}

#[test]
fn audio_negative_vectors() {
    let v = vectors();
    for n in arr(&v, "negative") {
        let c = &n["context"];
        let got = receive(
            &unhex(&n["frame"]),
            int(&c["kind"]) as u8,
            &unhex(&c["base_key"]),
            &ctx_of(c),
        );
        assert_eq!(got, Err(n["stage"].as_str().unwrap()), "{}", n["name"]);
    }
}

#[test]
fn call_payloads() {
    let v = vectors();
    let from = v["fixed"]["sender_id"].as_str().unwrap();
    let ch = v["fixed"]["channel_id"].as_str().unwrap();
    for p in arr(&v, "call_payloads") {
        let got = call_payload(&unhex(&p["plaintext"]), from, ch);
        match p["expect"].as_str().unwrap() {
            "accept" => assert_eq!(got.as_deref(), p["type"].as_str(), "{}", p["name"]),
            _ => assert_eq!(got, None, "{}", p["name"]),
        }
    }
}

#[test]
fn screen_base_and_video_keys() {
    let v = vectors();
    for s in arr(&v, "screen_base") {
        assert_eq!(
            screen_base(&unhex(&s["epoch_secret"])).to_vec(),
            unhex(&s["screen_base"])
        );
    }
    for k in arr(&v, "video_key_schedule") {
        let secret = unhex(&k["epoch_secret"]);
        let kid = int(&k["kid"]);
        let (vk, vs) = keys_for(VIDEO, &secret, kid);
        let (ak, as_) = keys_for(AUDIO, &secret, kid);
        assert_eq!(vk.to_vec(), unhex(&k["key"]));
        assert_eq!(vs.to_vec(), unhex(&k["salt"]));
        assert_eq!(ak.to_vec(), unhex(&k["audio_key"]));
        assert_eq!(as_.to_vec(), unhex(&k["audio_salt"]));
        assert_ne!(vk, ak);
        assert_ne!(vs, as_);
    }
}

#[test]
fn video_fragments() {
    let v = vectors();
    for f in arr(&v, "video_fragments") {
        let ctx = ctx_of(f);
        let secret = unhex(&f["epoch_secret"]);
        let payload = unhex(&f["payload"]);
        let pt = encode_fragment(&f["header"], &payload);
        let fragment = seal(VIDEO, &secret, int(&f["kid"]), int(&f["vctr"]), &ctx, &pt);
        assert_eq!(
            fragment,
            unhex(&f["fragment"]),
            "{}/{}",
            f["kid"],
            f["vctr"]
        );
        let opened = receive(&fragment, VIDEO, &secret, &ctx).expect("fragment accepted");
        let (h, p) = parse_fragment(&opened).unwrap();
        assert_eq!(p, payload.as_slice());
        assert_eq!(u64::from(h.share_seq), int(&f["header"]["share_seq"]));
        assert_eq!(u64::from(h.frame_no), int(&f["header"]["frame_no"]));
        assert_eq!(u64::from(h.frag_index), int(&f["header"]["frag_index"]));
        assert_eq!(u64::from(h.frag_count), int(&f["header"]["frag_count"]));
        // Sealed with the audio key, the same fragment does not open.
        assert_eq!(
            receive(
                &seal(AUDIO, &secret, int(&f["kid"]), int(&f["vctr"]), &ctx, &pt)[..],
                VIDEO,
                &secret,
                &ctx
            ),
            Err("kind")
        );
    }
}

#[test]
fn video_negative_vectors() {
    let v = vectors();
    for n in arr(&v, "video_negative") {
        let c = &n["context"];
        let got = receive(
            &unhex(&n["fragment"]),
            int(&c["kind"]) as u8,
            &unhex(&c["epoch_secret"]),
            &ctx_of(c),
        );
        assert_eq!(got, Err(n["stage"].as_str().unwrap()), "{}", n["name"]);
    }
}

#[test]
fn screen_wire_messages() {
    let v = vectors();
    for w in arr(&v, "screen_wire") {
        let got = screen_wire(w["direction"].as_str().unwrap(), &unhex(&w["bytes"]));
        match w["expect"].as_str().unwrap() {
            "accept" => {
                let (ch, from, len) = got.unwrap_or_else(|| panic!("{} accepted", w["name"]));
                assert_eq!(ch, w["channel_id"].as_str().unwrap());
                assert_eq!(from.as_deref(), w["from"].as_str());
                assert_eq!(len as u64, int(&w["fragment_length"]));
            }
            _ => assert_eq!(got, None, "{}", w["name"]),
        }
    }
}

#[test]
fn vp8_headers() {
    let v = vectors();
    for f in arr(&v, "vp8_headers") {
        let d = unhex(&f["frame"]);
        let key = f["key"].as_bool().unwrap();
        let ok = vp8_tag_ok(&d, key)
            && (!key
                || vp8_key_size(&d).is_some_and(|(w, h)| {
                    Some(w) == f["width"].as_u64()
                        && Some(h) == f["height"].as_u64()
                        && within_caps(w, h)
                }));
        assert_eq!(ok, f["expect"] == "accept", "{}", f["name"]);
    }
}
