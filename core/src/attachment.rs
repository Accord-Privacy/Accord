//! # Attachment reference implementation (SPEC-02)
//!
//! A second, independent implementation of SPEC-02's attachment formats,
//! kept unwired (owner decision OD-41) so that two implementations pin the
//! known-answer vectors of SPEC-02 section 6.7, and as the base for mobile
//! clients, which must implement SPEC-02 before they offer attachments
//! (REQ-45).
//!
//! It covers:
//! - the blob format `A256GCM-STREAM64K` of section 6.3: Padmé padding,
//!   64 KiB AES-256-GCM records with the nonce `prefix ‖ u32be(i) ‖ final`,
//!   and `open` with every check of REQ-5;
//! - the typed-plaintext classification of section 6.1 (control payload,
//!   content envelope, legacy text), the strict JSON pass of section 6.2
//!   rules 1 to 4, and the consumer paths of REQ-53;
//! - the content envelope v1 and attachment descriptor v1 of sections 6.2.1
//!   and 6.2.2 (rules 5 and 6);
//! - file-name sanitization (REQ-23) and the final extension of section 6.8,
//!   which the desktop shell applies again before saving.
//!
//! The TypeScript client (`desktop/frontend/src/e2ee/plaintext.ts` and
//! `desktop/frontend/src/attachments/`) must give the same result on every
//! vector in `core/tests/vectors/`.
//!
//! Nothing here logs plaintext, keys or names.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine as _;
use icu_normalizer::ComposingNormalizerBorrowed;
use icu_properties::props::{DefaultIgnorableCodePoint, GeneralCategory, WhiteSpace};
use icu_properties::{CodePointMapData, CodePointSetData};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Constants (SPEC-02 sections 6.1 to 6.3 and 6.8)
// ---------------------------------------------------------------------------

/// The only blob scheme of descriptor v1.
pub const SCHEME: &str = "A256GCM-STREAM64K";
/// Record plaintext size R.
pub const RECORD_SIZE: u64 = 65_536;
/// AES-GCM tag size.
pub const TAG_SIZE: u64 = 16;
/// Per-file key size.
pub const KEY_SIZE: usize = 32;
/// Nonce prefix size.
pub const NONCE_PREFIX_SIZE: usize = 7;
/// SHA-256 output size.
pub const SHA256_SIZE: usize = 32;
/// Largest blob a client creates or accepts.
pub const CLIENT_MAX_BLOB_BYTES: u64 = 104_857_600;
/// At most this many attachments per message.
pub const MAX_ATTACHMENTS_PER_MESSAGE: usize = 10;
/// Largest serialized content envelope, in UTF-8 bytes.
pub const MAX_ENVELOPE_BYTES: usize = 16_384;
/// Largest envelope body, in UTF-8 bytes.
pub const MAX_BODY_BYTES: usize = 8_192;
/// Largest envelope notice, in UTF-8 bytes.
pub const MAX_NOTICE_BYTES: usize = 256;
/// Largest descriptor name (and sanitized file name), in UTF-8 bytes.
pub const MAX_NAME_BYTES: usize = 255;
/// Largest descriptor MIME type, in bytes.
pub const MAX_MIME_BYTES: usize = 255;
/// Deepest nesting of arrays and objects; the outer value is level 1.
pub const MAX_NESTING_DEPTH: usize = 8;
/// Largest control payload, in bytes.
pub const MAX_CONTROL_PAYLOAD_BYTES: usize = 65_536;
/// Largest number token value, 2^53 - 1.
pub const MAX_JSON_INTEGER: u64 = (1 << 53) - 1;
/// The 24-byte envelope prefix of section 6.1.
pub const ENVELOPE_PREFIX: &[u8] = b"{\"type\":\"accord.content\"";
/// The control-payload separator, U+001E.
pub const CONTROL_SEPARATOR: u8 = 0x1e;
/// Used when sanitization leaves nothing (REQ-23 step 7).
pub const FALLBACK_NAME: &str = "attachment";
/// At most this many code points follow the dot of a final extension.
pub const MAX_EXTENSION_CODE_POINTS: usize = 16;

const MAX_TAG_BYTES: usize = 32;

// ---------------------------------------------------------------------------
// Padding and layout (section 6.3.1, 6.3.2)
// ---------------------------------------------------------------------------

/// Number of binary digits of `x` (0 for 0).
fn bit_length(x: u64) -> u32 {
    64 - x.leading_zeros()
}

/// Padmé: the padded size for a plaintext of `len` bytes.
pub fn padme(len: u64) -> u64 {
    if len < 2 {
        return len;
    }
    let e = bit_length(len) - 1;
    let s = bit_length(u64::from(e));
    let unit = 1u64 << (e - s);
    len.div_ceil(unit) * unit
}

/// Number of records for a padded size: `max(1, ceil(P / R))`.
pub fn record_count(padded_size: u64) -> u64 {
    padded_size.div_ceil(RECORD_SIZE).max(1)
}

/// `blob_length(P) = P + 16 * max(1, ceil(P / R))`.
pub fn blob_length(padded_size: u64) -> u64 {
    padded_size + TAG_SIZE * record_count(padded_size)
}

/// The 12-byte nonce of record `index`: `prefix ‖ u32be(index) ‖ final flag`.
pub fn record_nonce(prefix: &[u8; NONCE_PREFIX_SIZE], index: u32, last: bool) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..NONCE_PREFIX_SIZE].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_SIZE..11].copy_from_slice(&index.to_be_bytes());
    nonce[11] = u8::from(last);
    nonce
}

/// Plaintext length of record `index` among `n` records of a padded size.
fn record_plain_len(padded_size: u64, index: u64, n: u64) -> u64 {
    if index < n - 1 {
        RECORD_SIZE
    } else {
        padded_size - (n - 1) * RECORD_SIZE
    }
}

// ---------------------------------------------------------------------------
// Seal and open (section 6.3.2, REQ-1 to REQ-5)
// ---------------------------------------------------------------------------

/// Why sealing failed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SealError {
    /// The blob would exceed [`CLIENT_MAX_BLOB_BYTES`].
    #[error("attachment exceeds the client blob limit")]
    TooLarge,
    /// The AEAD primitive failed.
    #[error("attachment encryption failed")]
    Cipher,
}

/// Which check of REQ-5 a blob failed. Carries no received or decrypted bytes.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityError {
    /// The descriptor parameters are out of range (REQ-3).
    #[error("attachment parameters are invalid")]
    Params,
    /// The blob length differs from `blob_length(padded_size)`.
    #[error("attachment has the wrong length")]
    Length,
    /// SHA-256 of the blob differs from the descriptor.
    #[error("attachment hash does not match")]
    Hash,
    /// A record failed authentication.
    #[error("attachment failed authentication")]
    Aead,
    /// A padding byte is not zero.
    #[error("attachment padding is not zero")]
    Padding,
}

/// One sealed attachment: the blob and the descriptor values.
pub struct SealedAttachment {
    /// The concatenated record outputs; the upload body.
    pub blob: Vec<u8>,
    /// The per-file key, wiped on drop.
    pub key: Zeroizing<[u8; KEY_SIZE]>,
    /// The nonce prefix.
    pub nonce_prefix: [u8; NONCE_PREFIX_SIZE],
    /// SHA-256 of the complete blob (REQ-4).
    pub sha256: [u8; SHA256_SIZE],
    /// Plaintext length.
    pub size: u64,
    /// `padme(size)`.
    pub padded_size: u64,
}

/// Encrypt one attachment with a fresh key and nonce prefix from the OS
/// generator (REQ-1, REQ-2). In a normal build this is the only sealer.
pub fn seal(plain: &[u8]) -> Result<SealedAttachment, SealError> {
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    let mut prefix = [0u8; NONCE_PREFIX_SIZE];
    OsRng.fill_bytes(key.as_mut());
    OsRng.fill_bytes(&mut prefix);
    seal_records(plain, &key, &prefix)
}

/// Encrypt under the fixed key and nonce prefix of the known-answer vectors
/// (section 6.7). Compiled only for this crate's tests and the `test-vectors`
/// feature, which only the vector tests enable: sealing two files under one
/// key and prefix reuses AES-GCM nonces, which REQ-1 forbids.
#[cfg(any(test, feature = "test-vectors"))]
pub fn seal_with_fixed_key_for_vectors(
    plain: &[u8],
    key: &[u8; KEY_SIZE],
    nonce_prefix: &[u8; NONCE_PREFIX_SIZE],
) -> Result<SealedAttachment, SealError> {
    seal_records(plain, key, nonce_prefix)
}

fn seal_records(
    plain: &[u8],
    key: &[u8; KEY_SIZE],
    nonce_prefix: &[u8; NONCE_PREFIX_SIZE],
) -> Result<SealedAttachment, SealError> {
    let size = plain.len() as u64;
    let padded_size = padme(size);
    if blob_length(padded_size) > CLIENT_MAX_BLOB_BYTES {
        return Err(SealError::TooLarge);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| SealError::Cipher)?;
    let n = record_count(padded_size);
    let mut blob = Vec::with_capacity(blob_length(padded_size) as usize);
    let mut record = Vec::with_capacity(RECORD_SIZE as usize);
    for i in 0..n {
        let start = (i * RECORD_SIZE) as usize;
        let plen = record_plain_len(padded_size, i, n) as usize;
        record.clear();
        if start < plain.len() {
            let end = (start + plen).min(plain.len());
            record.extend_from_slice(&plain[start..end]);
        }
        record.resize(plen, 0);
        let nonce = record_nonce(nonce_prefix, i as u32, i == n - 1);
        let out = cipher
            .encrypt(Nonce::from_slice(&nonce), record.as_slice())
            .map_err(|_| SealError::Cipher)?;
        blob.extend_from_slice(&out);
    }
    record.zeroize();
    let sha256: [u8; SHA256_SIZE] = Sha256::digest(&blob).into();
    Ok(SealedAttachment {
        blob,
        key: Zeroizing::new(*key),
        nonce_prefix: *nonce_prefix,
        sha256,
        size,
        padded_size,
    })
}

/// The descriptor values `open` needs.
#[derive(Clone, Copy)]
pub struct OpenParams<'a> {
    /// Per-file key.
    pub key: &'a [u8; KEY_SIZE],
    /// Nonce prefix.
    pub nonce_prefix: &'a [u8; NONCE_PREFIX_SIZE],
    /// SHA-256 of the blob.
    pub sha256: &'a [u8; SHA256_SIZE],
    /// Plaintext length.
    pub size: u64,
    /// Padded length.
    pub padded_size: u64,
}

/// True when the parameters satisfy REQ-3 on the receiving side.
pub fn valid_open_params(size: u64, padded_size: u64) -> bool {
    size <= padded_size
        && padded_size <= MAX_JSON_INTEGER
        && blob_length(padded_size) <= CLIENT_MAX_BLOB_BYTES
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Decrypt and verify a blob (REQ-5). Returns the plaintext only after the
/// length, the SHA-256, every record (with the final flag on the last
/// expected record only) and the zero padding have all been checked; on any
/// failure every decrypted byte is wiped.
pub fn open(blob: &[u8], params: OpenParams<'_>) -> Result<Vec<u8>, IntegrityError> {
    if !valid_open_params(params.size, params.padded_size) {
        return Err(IntegrityError::Params);
    }
    if blob.len() as u64 != blob_length(params.padded_size) {
        return Err(IntegrityError::Length);
    }
    let digest: [u8; SHA256_SIZE] = Sha256::digest(blob).into();
    if !constant_time_eq(&digest, params.sha256) {
        return Err(IntegrityError::Hash);
    }
    let cipher = Aes256Gcm::new_from_slice(params.key).map_err(|_| IntegrityError::Params)?;
    let n = record_count(params.padded_size);
    let mut out = Zeroizing::new(Vec::with_capacity(params.padded_size as usize));
    let mut off = 0usize;
    for i in 0..n {
        let plen = record_plain_len(params.padded_size, i, n) as usize;
        let sealed = &blob[off..off + plen + TAG_SIZE as usize];
        let nonce = record_nonce(params.nonce_prefix, i as u32, i == n - 1);
        let mut plain = Zeroizing::new(
            cipher
                .decrypt(Nonce::from_slice(&nonce), sealed)
                .map_err(|_| IntegrityError::Aead)?,
        );
        if plain.len() != plen {
            return Err(IntegrityError::Aead);
        }
        out.extend_from_slice(&plain);
        plain.zeroize();
        off += plen + TAG_SIZE as usize;
    }
    if out[params.size as usize..].iter().any(|&b| b != 0) {
        return Err(IntegrityError::Padding);
    }
    out.truncate(params.size as usize);
    Ok(std::mem::take(&mut *out))
}

// ---------------------------------------------------------------------------
// Strict JSON (section 6.2 rules 1 to 4)
// ---------------------------------------------------------------------------

/// A strictly parsed JSON value. Every number is an integer of at most
/// 2^53 - 1 (rule 3); object members keep their order and are unique.
///
/// `Debug` prints the shape only, never a string, number or member name.
#[derive(Clone, PartialEq, Eq)]
pub enum JsonValue {
    /// `null`
    Null,
    /// `true` or `false`
    Bool(bool),
    /// A number token of the form `0|[1-9][0-9]*`.
    Int(u64),
    /// A string without lone surrogates.
    String(String),
    /// An array.
    Array(Vec<JsonValue>),
    /// An object, members in order.
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    /// The member `name` of an object.
    pub fn get(&self, name: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(members) => members.iter().find(|(k, _)| k == name).map(|(_, v)| v),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(s) => Some(s),
            _ => None,
        }
    }

    fn as_int(&self) -> Option<u64> {
        match self {
            JsonValue::Int(n) => Some(*n),
            _ => None,
        }
    }
}

// `Debug` for the plaintext types of this module (REQ-11, REQ-53). Strings,
// numbers and member names of a plaintext can hold descriptor keys, nonce
// prefixes, hashes, file names, message bodies or control-payload secrets, so
// no `Debug` output here contains any of them: only the class, tag,
// registered `type`, reason code, channel id and lengths.

impl std::fmt::Debug for JsonValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsonValue::Null => f.write_str("Null"),
            JsonValue::Bool(_) => f.write_str("Bool"),
            JsonValue::Int(_) => f.write_str("Int"),
            JsonValue::String(s) => write!(f, "String(<{} bytes>)", s.len()),
            JsonValue::Array(items) => write!(f, "Array(<{} items>)", items.len()),
            JsonValue::Object(members) => write!(f, "Object(<{} members>)", members.len()),
        }
    }
}

/// The rule a text broke. Never derived from the text itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictParseError {
    /// Not JSON.
    Syntax,
    /// Two members with the same name after unescaping (rule 1).
    Duplicate,
    /// A lone surrogate (rule 2).
    Surrogate,
    /// A number token that is not a plain integer up to 2^53 - 1 (rule 3).
    Number,
    /// Nesting deeper than allowed (rule 4).
    Depth,
}

impl StrictParseError {
    /// The reason code shared with the TypeScript reader and the vectors.
    pub fn code(self) -> &'static str {
        match self {
            StrictParseError::Syntax => "syntax",
            StrictParseError::Duplicate => "duplicate",
            StrictParseError::Surrogate => "surrogate",
            StrictParseError::Number => "number",
            StrictParseError::Depth => "depth",
        }
    }
}

struct Parser<'a> {
    text: &'a str,
    s: &'a [u8],
    pos: usize,
    max_depth: usize,
    /// Accept every RFC 8259 number token instead of rule 3. Only legacy-key
    /// JSON detection sets it; such a number's value is never read.
    any_number: bool,
}

fn is_json_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

fn hex_value(b: u8) -> Option<u16> {
    match b {
        b'0'..=b'9' => Some(u16::from(b - b'0')),
        b'a'..=b'f' => Some(u16::from(b - b'a' + 10)),
        b'A'..=b'F' => Some(u16::from(b - b'A' + 10)),
        _ => None,
    }
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while self.peek().is_some_and(is_json_ws) {
            self.pos += 1;
        }
    }

    fn document(&mut self) -> Result<JsonValue, StrictParseError> {
        self.skip_ws();
        let value = self.value(0)?;
        self.skip_ws();
        if self.pos != self.s.len() {
            return Err(StrictParseError::Syntax);
        }
        Ok(value)
    }

    fn value(&mut self, depth: usize) -> Result<JsonValue, StrictParseError> {
        match self.peek() {
            None => Err(StrictParseError::Syntax),
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string().map(JsonValue::String),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => {
                let rest = &self.s[self.pos..];
                if rest.starts_with(b"true") {
                    self.pos += 4;
                    Ok(JsonValue::Bool(true))
                } else if rest.starts_with(b"false") {
                    self.pos += 5;
                    Ok(JsonValue::Bool(false))
                } else if rest.starts_with(b"null") {
                    self.pos += 4;
                    Ok(JsonValue::Null)
                } else {
                    Err(StrictParseError::Syntax)
                }
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<JsonValue, StrictParseError> {
        if depth > self.max_depth {
            return Err(StrictParseError::Depth);
        }
        self.pos += 1; // {
        let mut members: Vec<(String, JsonValue)> = Vec::new();
        let mut names: HashSet<String> = HashSet::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(StrictParseError::Syntax);
            }
            let name = self.string()?;
            if !names.insert(name.clone()) {
                return Err(StrictParseError::Duplicate);
            }
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(StrictParseError::Syntax);
            }
            self.pos += 1;
            self.skip_ws();
            let value = self.value(depth)?;
            members.push((name, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(members));
                }
                _ => return Err(StrictParseError::Syntax),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<JsonValue, StrictParseError> {
        if depth > self.max_depth {
            return Err(StrictParseError::Depth);
        }
        self.pos += 1; // [
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonValue::Array(items));
                }
                _ => return Err(StrictParseError::Syntax),
            }
        }
    }

    /// Rule 2: the unescaped string, as UTF-16 code units, must contain no
    /// lone surrogate. Checked once the whole string has been read, as the
    /// TypeScript reader does, so both report the same first failure.
    fn string(&mut self) -> Result<String, StrictParseError> {
        self.pos += 1; // opening quote
        let mut units: Vec<u16> = Vec::new();
        loop {
            let c = self.peek().ok_or(StrictParseError::Syntax)?;
            if c == b'"' {
                self.pos += 1;
                break;
            }
            if c < 0x20 {
                return Err(StrictParseError::Syntax);
            }
            if c != b'\\' {
                // The text is valid UTF-8, so this is the start of a char.
                let ch = self.text[self.pos..]
                    .chars()
                    .next()
                    .ok_or(StrictParseError::Syntax)?;
                let mut buf = [0u16; 2];
                units.extend_from_slice(ch.encode_utf16(&mut buf));
                self.pos += ch.len_utf8();
                continue;
            }
            self.pos += 1;
            let e = self.peek().ok_or(StrictParseError::Syntax)?;
            self.pos += 1;
            let unit = match e {
                b'"' => 0x22,
                b'\\' => 0x5c,
                b'/' => 0x2f,
                b'b' => 0x08,
                b'f' => 0x0c,
                b'n' => 0x0a,
                b'r' => 0x0d,
                b't' => 0x09,
                b'u' => {
                    let mut v: u16 = 0;
                    for _ in 0..4 {
                        let h = self
                            .peek()
                            .and_then(hex_value)
                            .ok_or(StrictParseError::Syntax)?;
                        v = v * 16 + h;
                        self.pos += 1;
                    }
                    v
                }
                _ => return Err(StrictParseError::Syntax),
            };
            units.push(unit);
        }
        String::from_utf16(&units).map_err(|_| StrictParseError::Surrogate)
    }

    /// Rule 3: only `0|[1-9][0-9]*`, at most 2^53 - 1. With `any_number`,
    /// any RFC 8259 number token; one that rule 3 rejects reads as `Null`.
    fn number(&mut self) -> Result<JsonValue, StrictParseError> {
        let start = self.pos;
        while self
            .peek()
            .is_some_and(|b| b.is_ascii_digit() || matches!(b, b'-' | b'+' | b'.' | b'e' | b'E'))
        {
            self.pos += 1;
        }
        let token = &self.s[start..self.pos];
        if let Some(n) = strict_integer(token) {
            return Ok(JsonValue::Int(n));
        }
        if self.any_number && is_rfc8259_number(token) {
            return Ok(JsonValue::Null);
        }
        Err(StrictParseError::Number)
    }
}

/// The value of a rule-3 number token: `0|[1-9][0-9]*`, at most 2^53 - 1.
fn strict_integer(token: &[u8]) -> Option<u64> {
    let plain = token == b"0"
        || (matches!(token.first(), Some(b'1'..=b'9')) && token.iter().all(u8::is_ascii_digit));
    if !plain || token.len() > 16 {
        return None;
    }
    let n = token
        .iter()
        .fold(0u64, |n, &d| n * 10 + u64::from(d - b'0'));
    (n <= MAX_JSON_INTEGER).then_some(n)
}

/// True for an RFC 8259 number token:
/// `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`, of any magnitude.
fn is_rfc8259_number(t: &[u8]) -> bool {
    fn digits(t: &[u8], i: &mut usize) -> usize {
        let start = *i;
        while t.get(*i).is_some_and(u8::is_ascii_digit) {
            *i += 1;
        }
        *i - start
    }
    let mut i = 0;
    if t.first() == Some(&b'-') {
        i += 1;
    }
    match t.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            digits(t, &mut i);
        }
        _ => return false,
    }
    if t.get(i) == Some(&b'.') {
        i += 1;
        if digits(t, &mut i) == 0 {
            return false;
        }
    }
    if matches!(t.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(t.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        if digits(t, &mut i) == 0 {
            return false;
        }
    }
    i == t.len()
}

/// Parse a JSON text under section 6.2 rules 1 to 4, returning the first
/// rule it breaks in reading order.
pub fn parse_strict_json(text: &str, max_depth: usize) -> Result<JsonValue, StrictParseError> {
    Parser {
        text,
        s: text.as_bytes(),
        pos: 0,
        max_depth,
        any_number: false,
    }
    .document()
}

// ---------------------------------------------------------------------------
// Classification (section 6.1) and consumer paths (REQ-53)
// ---------------------------------------------------------------------------

/// The consumer paths of REQ-53.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumerPath {
    /// Message display paths.
    Display,
    /// The voice path (SPEC-03).
    Voice,
    /// The key-distribution path.
    KeyDistribution,
    /// The control-queue path (SPEC-04 REQ-41).
    ControlQueue,
}

impl ConsumerPath {
    /// The name used in the vector files.
    pub fn code(self) -> &'static str {
        match self {
            ConsumerPath::Display => "display",
            ConsumerPath::Voice => "voice",
            ConsumerPath::KeyDistribution => "key_distribution",
            ConsumerPath::ControlQueue => "control_queue",
        }
    }
}

/// One registered control-payload tag.
pub struct ControlRegistration {
    /// The tag between the two separators.
    pub tag: &'static str,
    /// The registered `type` values.
    pub types: &'static [&'static str],
    /// The registered `v`.
    pub v: u64,
    /// The one path that accepts it.
    pub path: ConsumerPath,
}

/// The registry of section 6.1.
pub const CONTROL_REGISTRY: &[ControlRegistration] = &[
    ControlRegistration {
        tag: "accord-call",
        types: &["call_hello", "call_key", "call_key_ack"],
        v: 1,
        path: ConsumerPath::Voice,
    },
    ControlRegistration {
        tag: "accord-keys",
        types: &["skdm", "nmk"],
        v: 2,
        path: ConsumerPath::KeyDistribution,
    },
    ControlRegistration {
        tag: "accord-ctl",
        types: &["session_reset", "identity"],
        v: 1,
        path: ConsumerPath::ControlQueue,
    },
];

/// Legacy key JSON (untagged `skdm` or `nmk` objects) is accepted by the
/// key-distribution path of clients that do not implement SPEC-05.
pub const LEGACY_KEY_JSON_ACCEPTED: bool = true;

/// Why a control payload is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlFailure {
    /// No second separator within 33 bytes.
    Framing,
    /// The tag is empty or has bytes outside `[a-z0-9-]`.
    Tag,
    /// The tag, `type` or `v` is not registered.
    Unregistered,
    /// Longer than 65,536 bytes.
    Size,
    /// The body is not valid UTF-8.
    Utf8,
    /// The body breaks a strict JSON rule.
    Parse(StrictParseError),
    /// The body is not an object with a string `type` and an integer `v`.
    Shape,
}

impl ControlFailure {
    /// The reason code shared with the TypeScript reader and the vectors.
    pub fn code(self) -> &'static str {
        match self {
            ControlFailure::Framing => "framing",
            ControlFailure::Tag => "tag",
            ControlFailure::Unregistered => "unregistered",
            ControlFailure::Size => "size",
            ControlFailure::Utf8 => "utf8",
            ControlFailure::Parse(e) => e.code(),
            ControlFailure::Shape => "shape",
        }
    }
}

/// Why a content envelope is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeFailure {
    /// Longer than 16,384 bytes.
    Size,
    /// Not valid UTF-8.
    Utf8,
    /// Breaks a strict JSON rule.
    Parse(StrictParseError),
    /// `v` is not an integer of at least 1.
    Version,
    /// A member of section 6.2.1 is missing or out of range (rule 5).
    Shape,
}

impl EnvelopeFailure {
    /// The reason code shared with the TypeScript reader and the vectors.
    pub fn code(self) -> &'static str {
        match self {
            EnvelopeFailure::Size => "size",
            EnvelopeFailure::Utf8 => "utf8",
            EnvelopeFailure::Parse(e) => e.code(),
            EnvelopeFailure::Version => "version",
            EnvelopeFailure::Shape => "shape",
        }
    }
}

/// A valid control payload. `Debug` never prints the body.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidControl {
    /// The registered tag.
    pub tag: &'static str,
    /// The registered `type`.
    pub type_: String,
    /// The registered `v`.
    pub v: u64,
    /// The JSON body after the strict pass.
    pub body: JsonValue,
}

impl std::fmt::Debug for ValidControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Tag, type and v are registry values; the body is shown as its shape.
        f.debug_struct("ValidControl")
            .field("tag", &self.tag)
            .field("type_", &self.type_)
            .field("v", &self.v)
            .field("body", &self.body)
            .finish()
    }
}

/// The class of a plaintext, decided from its leading bytes. `Debug` prints
/// the class, tag, type and reason code only.
#[derive(Clone, PartialEq, Eq)]
pub enum Classified {
    /// A control payload (first byte 0x1E). Never displayed.
    Control(Result<ValidControl, ControlFailure>),
    /// A content envelope that is invalid (shown as "invalid message format").
    EnvelopeInvalid(EnvelopeFailure),
    /// A content envelope with `v` > 1 (newer-version placeholder).
    EnvelopeNewer(u64),
    /// A content envelope whose rules 1 to 4 hold and whose `v` is 1.
    EnvelopeV1(JsonValue),
    /// Anything else. `legacy_key_json` marks an untagged `skdm` or `nmk` object.
    LegacyText {
        /// Accepted only by the key-distribution path of pre-SPEC-05 clients.
        legacy_key_json: bool,
    },
}

impl std::fmt::Debug for Classified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Classified::Control(Ok(valid)) => f.debug_tuple("Control").field(valid).finish(),
            Classified::Control(Err(e)) => write!(f, "Control(Err({}))", e.code()),
            Classified::EnvelopeInvalid(e) => write!(f, "EnvelopeInvalid({})", e.code()),
            Classified::EnvelopeNewer(v) => write!(f, "EnvelopeNewer({v})"),
            Classified::EnvelopeV1(o) => f.debug_tuple("EnvelopeV1").field(o).finish(),
            Classified::LegacyText { legacy_key_json } => f
                .debug_struct("LegacyText")
                .field("legacy_key_json", legacy_key_json)
                .finish(),
        }
    }
}

fn is_tag_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'
}

fn classify_control(bytes: &[u8]) -> Result<ValidControl, ControlFailure> {
    let sep = (1..=MAX_TAG_BYTES + 1)
        .take_while(|&i| i < bytes.len())
        .find(|&i| bytes[i] == CONTROL_SEPARATOR)
        .ok_or(ControlFailure::Framing)?;
    if sep == 1 || !bytes[1..sep].iter().copied().all(is_tag_byte) {
        return Err(ControlFailure::Tag);
    }
    let tag = &bytes[1..sep];
    let reg = CONTROL_REGISTRY
        .iter()
        .find(|r| r.tag.as_bytes() == tag)
        .ok_or(ControlFailure::Unregistered)?;
    if bytes.len() > MAX_CONTROL_PAYLOAD_BYTES {
        return Err(ControlFailure::Size);
    }
    let text = std::str::from_utf8(&bytes[sep + 1..]).map_err(|_| ControlFailure::Utf8)?;
    let body = parse_strict_json(text, MAX_NESTING_DEPTH).map_err(ControlFailure::Parse)?;
    if !matches!(body, JsonValue::Object(_)) {
        return Err(ControlFailure::Shape);
    }
    let type_ = body
        .get("type")
        .and_then(JsonValue::as_str)
        .ok_or(ControlFailure::Shape)?
        .to_owned();
    let v = body
        .get("v")
        .and_then(JsonValue::as_int)
        .ok_or(ControlFailure::Shape)?;
    if !reg.types.contains(&type_.as_str()) || v != reg.v {
        return Err(ControlFailure::Unregistered);
    }
    Ok(ValidControl {
        tag: reg.tag,
        type_,
        v,
        body,
    })
}

fn classify_envelope(bytes: &[u8]) -> Classified {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Classified::EnvelopeInvalid(EnvelopeFailure::Size);
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Classified::EnvelopeInvalid(EnvelopeFailure::Utf8);
    };
    let object = match parse_strict_json(text, MAX_NESTING_DEPTH) {
        Ok(v) => v,
        Err(e) => return Classified::EnvelopeInvalid(EnvelopeFailure::Parse(e)),
    };
    match object.get("v").and_then(JsonValue::as_int) {
        Some(1) => Classified::EnvelopeV1(object),
        Some(v) if v > 1 => Classified::EnvelopeNewer(v),
        _ => Classified::EnvelopeInvalid(EnvelopeFailure::Version),
    }
}

/// Legacy key JSON (the last row of the section 6.1 registry): legacy text
/// that parses as an object whose `type` is `skdm` or `nmk`. "Parses" has one
/// definition, shared with the TypeScript classifier: the text, with invalid
/// UTF-8 replaced by U+FFFD, passes rules 1, 2 and 4 of section 6.2 (depth at
/// most [`MAX_NESTING_DEPTH`]), and any RFC 8259 number token is allowed in
/// place of rule 3, because today's clients write these objects with
/// `JSON.stringify`. A general-purpose parser is not used: serde_json and
/// `JSON.parse` disagree on lone surrogates, out-of-range numbers and deep
/// nesting, and two clients would then show the same plaintext differently.
fn is_legacy_key_json(bytes: &[u8]) -> bool {
    let start = bytes.iter().position(|&b| !is_json_ws(b));
    if start.map(|i| bytes[i]) != Some(b'{') {
        return false;
    }
    let text = String::from_utf8_lossy(bytes);
    let parsed = Parser {
        text: &text,
        s: text.as_bytes(),
        pos: 0,
        max_depth: MAX_NESTING_DEPTH,
        any_number: true,
    }
    .document();
    matches!(
        parsed.as_ref().ok().and_then(|o| o.get("type")),
        Some(JsonValue::String(t)) if t == "skdm" || t == "nmk"
    )
}

/// Classify a plaintext (section 6.1), from its UTF-8 bytes.
pub fn classify_plaintext(bytes: &[u8]) -> Classified {
    if bytes.first() == Some(&CONTROL_SEPARATOR) {
        return Classified::Control(classify_control(bytes));
    }
    let start = bytes
        .iter()
        .position(|&b| !is_json_ws(b))
        .unwrap_or(bytes.len());
    if bytes[start..].starts_with(ENVELOPE_PREFIX) {
        return classify_envelope(bytes);
    }
    Classified::LegacyText {
        legacy_key_json: is_legacy_key_json(bytes),
    }
}

/// The paths that act on a classified plaintext (REQ-53). Every other path
/// discards it silently.
pub fn accepted_paths(c: &Classified) -> Vec<ConsumerPath> {
    match c {
        Classified::Control(Ok(valid)) => CONTROL_REGISTRY
            .iter()
            .filter(|r| r.tag == valid.tag)
            .map(|r| r.path)
            .collect(),
        Classified::Control(Err(_)) => Vec::new(),
        Classified::EnvelopeInvalid(_)
        | Classified::EnvelopeNewer(_)
        | Classified::EnvelopeV1(_) => {
            vec![ConsumerPath::Display]
        }
        Classified::LegacyText {
            legacy_key_json: true,
        } => {
            if LEGACY_KEY_JSON_ACCEPTED {
                vec![ConsumerPath::KeyDistribution]
            } else {
                Vec::new()
            }
        }
        Classified::LegacyText {
            legacy_key_json: false,
        } => vec![ConsumerPath::Display],
    }
}

/// True when user text must be sent in a REQ-10 escape envelope.
pub fn needs_envelope_escape(text: &str) -> bool {
    let b = text.as_bytes();
    let start = b.iter().position(|&x| !is_json_ws(x)).unwrap_or(b.len());
    b.first() == Some(&CONTROL_SEPARATOR) || b[start..].starts_with(ENVELOPE_PREFIX)
}

// ---------------------------------------------------------------------------
// Content envelope v1 and descriptor v1 (sections 6.2.1, 6.2.2)
// ---------------------------------------------------------------------------

/// A descriptor that passed section 6.2.2.
#[derive(Clone, PartialEq, Eq)]
pub struct Descriptor {
    /// Lowercase canonical UUID.
    pub blob_id: String,
    /// Per-file key.
    pub key: Zeroizing<[u8; KEY_SIZE]>,
    /// Nonce prefix.
    pub nonce_prefix: [u8; NONCE_PREFIX_SIZE],
    /// SHA-256 of the blob.
    pub sha256: [u8; SHA256_SIZE],
    /// Plaintext length.
    pub size: u64,
    /// Padded length.
    pub padded_size: u64,
    /// The name as sent; sanitize it before any use (REQ-23).
    pub name: String,
    /// Lowercase `type/subtype`.
    pub mime: String,
}

impl std::fmt::Debug for Descriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print keys or names.
        f.debug_struct("Descriptor")
            .field("blob_id", &self.blob_id)
            .field("size", &self.size)
            .field("padded_size", &self.padded_size)
            .finish_non_exhaustive()
    }
}

impl Descriptor {
    /// The values `open` needs.
    pub fn open_params(&self) -> OpenParams<'_> {
        OpenParams {
            key: &self.key,
            nonce_prefix: &self.nonce_prefix,
            sha256: &self.sha256,
            size: self.size,
            padded_size: self.padded_size,
        }
    }
}

/// A valid content envelope v1. `Debug` prints the channel id and lengths,
/// never the body or a descriptor.
#[derive(Clone, PartialEq, Eq)]
pub struct EnvelopeV1 {
    /// The channel the sender encrypted it for.
    pub channel_id: String,
    /// The body; empty when absent.
    pub body: String,
    /// Whether an `attachments` member exists at all (REQ-50).
    pub has_attachments_member: bool,
    /// One entry per descriptor; `None` is an unusable attachment (REQ-9).
    pub attachments: Vec<Option<Descriptor>>,
}

impl std::fmt::Debug for EnvelopeV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvelopeV1")
            .field("channel_id", &self.channel_id)
            .field("body", &format_args!("<{} bytes>", self.body.len()))
            .field("has_attachments_member", &self.has_attachments_member)
            .field("attachments", &self.attachments.len())
            .finish()
    }
}

/// The result of reading a content envelope. `Debug` never prints the body
/// or a descriptor.
#[derive(Clone, PartialEq, Eq)]
pub enum EnvelopeRead {
    /// Rules 1 to 6 hold.
    Valid(EnvelopeV1),
    /// Shown as "invalid message format".
    Invalid(EnvelopeFailure),
    /// Shown as "requires a newer version of Accord".
    NewerVersion,
}

impl std::fmt::Debug for EnvelopeRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeRead::Valid(e) => f.debug_tuple("Valid").field(e).finish(),
            EnvelopeRead::Invalid(e) => write!(f, "Invalid({})", e.code()),
            EnvelopeRead::NewerVersion => f.write_str("NewerVersion"),
        }
    }
}

/// True for a lowercase canonical UUID (8-4-4-4-12 hex digits).
pub fn is_canonical_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
}

fn is_mime_part(p: &[u8]) -> bool {
    let first_ok = p
        .first()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    first_ok
        && p.len() <= 127
        && p.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"!#$&-^_.+".contains(&c))
}

/// True for a MIME type allowed in a descriptor: lowercase `type/subtype`,
/// each an RFC 6838 restricted-name, no parameters.
pub fn is_valid_mime(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() > MAX_MIME_BYTES {
        return false;
    }
    let mut parts = b.split(|&c| c == b'/');
    matches!((parts.next(), parts.next(), parts.next()), (Some(t), Some(st), None) if is_mime_part(t) && is_mime_part(st))
}

/// Decode canonical base64 of exactly `N` bytes: padded, no whitespace, and
/// re-encoding gives back the input.
fn decode_canonical<const N: usize>(s: &str) -> Option<[u8; N]> {
    let engine = base64::engine::general_purpose::STANDARD;
    let bytes = engine.decode(s).ok()?;
    if engine.encode(&bytes) != s {
        return None;
    }
    bytes.try_into().ok()
}

/// Apply section 6.2.2 to one descriptor object; `None` is unusable.
pub fn read_descriptor(o: &JsonValue) -> Option<Descriptor> {
    if o.get("v")?.as_int()? != 1 || o.get("scheme")?.as_str()? != SCHEME {
        return None;
    }
    let blob_id = o.get("blob_id")?.as_str()?;
    if !is_canonical_uuid(blob_id) {
        return None;
    }
    let key = Zeroizing::new(decode_canonical::<KEY_SIZE>(o.get("key")?.as_str()?)?);
    let nonce_prefix = decode_canonical::<NONCE_PREFIX_SIZE>(o.get("nonce_prefix")?.as_str()?)?;
    let sha256 = decode_canonical::<SHA256_SIZE>(o.get("sha256")?.as_str()?)?;
    let size = o.get("size")?.as_int()?;
    let padded_size = o.get("padded_size")?.as_int()?;
    if !valid_open_params(size, padded_size) {
        return None;
    }
    let name = o.get("name")?.as_str()?;
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return None;
    }
    let mime = o.get("mime")?.as_str()?;
    if !is_valid_mime(mime) {
        return None;
    }
    Some(Descriptor {
        blob_id: blob_id.to_owned(),
        key,
        nonce_prefix,
        sha256,
        size,
        padded_size,
        name: name.to_owned(),
        mime: mime.to_owned(),
    })
}

/// Apply rules 5 and 6 and section 6.2.1 to an envelope object whose `v` is 1.
pub fn read_envelope_v1(o: &JsonValue) -> EnvelopeRead {
    let invalid = EnvelopeRead::Invalid(EnvelopeFailure::Shape);
    if o.get("type").and_then(JsonValue::as_str) != Some("accord.content")
        || o.get("v").and_then(JsonValue::as_int) != Some(1)
    {
        return invalid;
    }
    let Some(channel_id) = o.get("channel_id").and_then(JsonValue::as_str) else {
        return invalid;
    };
    if !is_canonical_uuid(channel_id) {
        return invalid;
    }
    if let Some(notice) = o.get("notice") {
        if !notice.as_str().is_some_and(|n| n.len() <= MAX_NOTICE_BYTES) {
            return invalid;
        }
    }
    let body = match o.get("body") {
        None => String::new(),
        Some(JsonValue::String(b)) if b.len() <= MAX_BODY_BYTES => b.clone(),
        Some(_) => return invalid,
    };
    let mut attachments = Vec::new();
    let has_attachments_member = o.get("attachments").is_some();
    if let Some(list) = o.get("attachments") {
        let JsonValue::Array(items) = list else {
            return invalid;
        };
        if items.len() > MAX_ATTACHMENTS_PER_MESSAGE {
            return invalid;
        }
        let mut seen = HashSet::new();
        for item in items {
            if !matches!(item, JsonValue::Object(_)) {
                return invalid;
            }
            if let Some(id) = item.get("blob_id").and_then(JsonValue::as_str) {
                if !seen.insert(id) {
                    return invalid;
                }
            }
        }
        attachments = items.iter().map(read_descriptor).collect();
    }
    EnvelopeRead::Valid(EnvelopeV1 {
        channel_id: channel_id.to_owned(),
        body,
        has_attachments_member,
        attachments,
    })
}

/// Classify a plaintext and, when it is a content envelope, read it.
/// `None` when the plaintext is not a content envelope.
pub fn read_envelope(plaintext: &[u8]) -> Option<EnvelopeRead> {
    match classify_plaintext(plaintext) {
        Classified::EnvelopeInvalid(f) => Some(EnvelopeRead::Invalid(f)),
        Classified::EnvelopeNewer(_) => Some(EnvelopeRead::NewerVersion),
        Classified::EnvelopeV1(o) => Some(read_envelope_v1(&o)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// File names (REQ-23, section 6.8)
// ---------------------------------------------------------------------------

fn is_removed(c: char) -> bool {
    let gc = CodePointMapData::<GeneralCategory>::new().get(c);
    matches!(
        gc,
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::Surrogate
            | GeneralCategory::PrivateUse
            | GeneralCategory::Unassigned
    ) || CodePointSetData::new::<DefaultIgnorableCodePoint>().contains(c)
}

/// The final extension of a sanitized name: its last `.` and everything
/// after it, when that dot is not the first character and at most 16 code
/// points follow it.
pub fn final_extension(name: &str) -> Option<&str> {
    let dot = name.rfind('.')?;
    if dot == 0 || name[dot + 1..].chars().count() > MAX_EXTENSION_CODE_POINTS {
        return None;
    }
    Some(&name[dot..])
}

fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    let mut end = 0;
    for (i, c) in s.char_indices() {
        if i + c.len_utf8() > max_bytes {
            break;
        }
        end = i + c.len_utf8();
    }
    &s[..end]
}

/// Sanitize a sender-chosen file name (REQ-23, steps 1 to 7 in order). Rust
/// strings hold no lone surrogates, so step 1 reduces to NFC.
pub fn sanitize_file_name(input: &str) -> String {
    // 1. NFC.
    let nfc = ComposingNormalizerBorrowed::new_nfc().normalize(input);
    let white = CodePointSetData::new::<WhiteSpace>();
    let mut s = String::with_capacity(nfc.len());
    for c in nfc.chars() {
        // 2. White_Space to U+0020.
        if white.contains(c) {
            s.push(' ');
            continue;
        }
        // 3. Remove Cc, Cf, Cs, Co, Cn and Default_Ignorable_Code_Point.
        if is_removed(c) {
            continue;
        }
        // 4. Reserved path and shell characters.
        s.push(
            if matches!(c, '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*') {
                '_'
            } else {
                c
            },
        );
    }
    // 5. Collapse runs of U+0020, then trim U+0020 and dots at both ends.
    let mut collapsed = String::with_capacity(s.len());
    for c in s.chars() {
        if c == ' ' && collapsed.ends_with(' ') {
            continue;
        }
        collapsed.push(c);
    }
    let trimmed = collapsed.trim_matches(|c| c == ' ' || c == '.');
    // 6. At most 255 UTF-8 bytes, keeping the final extension.
    let mut out = if trimmed.len() > MAX_NAME_BYTES {
        match final_extension(trimmed) {
            Some(ext) => {
                let stem = &trimmed[..trimmed.len() - ext.len()];
                format!("{}{}", truncate_utf8(stem, MAX_NAME_BYTES - ext.len()), ext)
            }
            None => truncate_utf8(trimmed, MAX_NAME_BYTES).to_owned(),
        }
    } else {
        trimmed.to_owned()
    };
    // 7. Fallback.
    if out.is_empty() {
        out.push_str(FALLBACK_NAME);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    const PREFIX: [u8; 7] = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6];

    fn mod251(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    fn params<'a>(blob: &[u8], sha: &'a mut [u8; 32], size: u64, padded: u64) -> OpenParams<'a> {
        *sha = Sha256::digest(blob).into();
        OpenParams {
            key: &KEY,
            nonce_prefix: &PREFIX,
            sha256: sha,
            size,
            padded_size: padded,
        }
    }

    /// Seal an already padded buffer record by record, with chosen final flags.
    fn seal_raw(padded: &[u8], last: impl Fn(u64, u64) -> bool) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(&KEY).unwrap();
        let n = record_count(padded.len() as u64);
        let mut out = Vec::new();
        for i in 0..n {
            let start = (i * RECORD_SIZE) as usize;
            let end = (start + RECORD_SIZE as usize).min(padded.len());
            let nonce = record_nonce(&PREFIX, i as u32, last(i, n));
            out.extend(
                cipher
                    .encrypt(Nonce::from_slice(&nonce), &padded[start..end])
                    .unwrap(),
            );
        }
        out
    }

    #[test]
    fn padme_is_exact_for_large_values() {
        assert_eq!(padme((1 << 52) + 1), (1 << 52) + (1 << 46));
        assert_eq!(padme((1 << 53) - 1), 1 << 53);
        assert_eq!(padme(u64::MAX >> 1), 1 << 63);
    }

    #[test]
    fn seal_draws_fresh_keys_and_prefixes() {
        let a = seal(&[7u8; 2048]).unwrap();
        let b = seal(&[7u8; 2048]).unwrap();
        assert_ne!(*a.key, *b.key);
        assert_ne!(a.nonce_prefix, b.nonce_prefix);
        assert_ne!(a.sha256, b.sha256);
        assert_eq!(a.padded_size, padme(2048));
        assert_eq!(
            seal(&vec![0u8; 104_857_601]).err(),
            Some(SealError::TooLarge)
        );
    }

    #[test]
    fn open_accepts_unpadded_and_padme_sizes() {
        let plain = vec![0x61u8; 1000];
        for padded in [1000u64, 1024] {
            let mut buf = plain.clone();
            buf.resize(padded as usize, 0);
            let blob = seal_raw(&buf, |i, n| i == n - 1);
            let mut sha = [0u8; 32];
            assert_eq!(
                open(&blob, params(&blob, &mut sha, 1000, padded)).unwrap(),
                plain
            );
        }
        let blob = seal_raw(&[0u8; 10], |i, n| i == n - 1);
        let mut sha = [0u8; 32];
        assert_eq!(
            open(&blob, params(&blob, &mut sha, 11, 10)),
            Err(IntegrityError::Params)
        );
        assert_eq!(blob_length(104_832_000), CLIENT_MAX_BLOB_BYTES);
        assert_eq!(
            open(&blob, params(&blob, &mut sha, 10, 104_832_001)),
            Err(IntegrityError::Params)
        );
    }

    #[test]
    fn tamper_matrix_on_tv4() {
        let plain = mod251(140_000);
        let padded_size = padme(140_000);
        let mut padded = plain.clone();
        padded.resize(padded_size as usize, 0);
        let good = seal_raw(&padded, |i, n| i == n - 1);
        let rec = |i: usize| i * (RECORD_SIZE as usize + 16);
        let mut cases: Vec<(&str, Vec<u8>, bool, IntegrityError)> = Vec::new();
        for i in 0..3 {
            let mut body = good.clone();
            body[rec(i) + 5] ^= 1;
            cases.push(("body", body.clone(), true, IntegrityError::Aead));
            cases.push(("body, hash kept", body, false, IntegrityError::Hash));
            let mut tag = good.clone();
            let end = if i < 2 { rec(i + 1) } else { good.len() };
            tag[end - 3] ^= 1;
            cases.push(("tag", tag, true, IntegrityError::Aead));
        }
        cases.push((
            "final record removed",
            good[..rec(2)].to_vec(),
            true,
            IntegrityError::Length,
        ));
        cases.push((
            "last byte removed",
            good[..good.len() - 1].to_vec(),
            true,
            IntegrityError::Length,
        ));
        let mut appended = good.clone();
        appended.extend([0u8; 16]);
        cases.push(("16 bytes appended", appended, true, IntegrityError::Length));
        let mut swapped = good[rec(1)..rec(2)].to_vec();
        swapped.extend_from_slice(&good[..rec(1)]);
        swapped.extend_from_slice(&good[rec(2)..]);
        cases.push(("records swapped", swapped, true, IntegrityError::Aead));
        cases.push((
            "no final flag",
            seal_raw(&padded, |_, _| false),
            true,
            IntegrityError::Aead,
        ));
        cases.push((
            "early final flag",
            seal_raw(&padded, |i, n| i == 1 || i == n - 1),
            true,
            IntegrityError::Aead,
        ));
        let mut other = padded.clone();
        other[0] ^= 0xff;
        cases.push((
            "other plaintext",
            seal_raw(&other, |i, n| i == n - 1),
            false,
            IntegrityError::Hash,
        ));
        let mut bad_padding = padded.clone();
        *bad_padding.last_mut().unwrap() = 1;
        cases.push((
            "non-zero padding",
            seal_raw(&bad_padding, |i, n| i == n - 1),
            true,
            IntegrityError::Padding,
        ));
        for (name, blob, rehash, expected) in cases {
            let sha: [u8; 32] = Sha256::digest(if rehash { &blob } else { &good }).into();
            let p = OpenParams {
                key: &KEY,
                nonce_prefix: &PREFIX,
                sha256: &sha,
                size: 140_000,
                padded_size,
            };
            assert_eq!(open(&blob, p), Err(expected), "{name}");
        }
        let mut sha = [0u8; 32];
        assert_eq!(
            open(&good, params(&good, &mut sha, 140_000, padded_size)).unwrap(),
            plain
        );
    }

    #[test]
    fn strict_json_rules() {
        let err = |t: &str| parse_strict_json(t, MAX_NESTING_DEPTH).err();
        assert_eq!(err(r#"{"a":1,"a":2}"#), Some(StrictParseError::Duplicate));
        assert_eq!(err(r#"{"a":1,"a":2}"#), Some(StrictParseError::Duplicate));
        assert_eq!(err(r#"{"a":1,"a":1.5}"#), Some(StrictParseError::Duplicate));
        for bad in [
            "[-1]",
            "[1.0]",
            "[1e0]",
            "[01]",
            "[-0]",
            "[9007199254740992]",
            "[1-2]",
        ] {
            assert_eq!(err(bad), Some(StrictParseError::Number), "{bad}");
        }
        assert_eq!(err("[9007199254740991]"), None);
        assert_eq!(err(r#"["\ud800"]"#), Some(StrictParseError::Surrogate));
        assert_eq!(err(r#"["\ud800\x"]"#), Some(StrictParseError::Syntax));
        assert_eq!(err(r#"["😀"]"#), None);
        assert_eq!(err("[[[[[[[[0]]]]]]]]"), None);
        assert_eq!(err("[[[[[[[[[0]]]]]]]]]"), Some(StrictParseError::Depth));
        for bad in [
            "",
            "{",
            "{\"a\":1,}",
            "[1,]",
            "{\"a\"}",
            "[tru]",
            "\"\u{1}\"",
            "[+1]",
            "[.5]",
            "{} x",
        ] {
            assert_eq!(err(bad), Some(StrictParseError::Syntax), "{bad:?}");
        }
        assert_eq!(
            parse_strict_json(" {\"é\":[true,false,null,\"a\\n\"]} ", 8),
            Ok(JsonValue::Object(vec![(
                "é".into(),
                JsonValue::Array(vec![
                    JsonValue::Bool(true),
                    JsonValue::Bool(false),
                    JsonValue::Null,
                    JsonValue::String("a\n".into())
                ])
            )]))
        );
    }

    #[test]
    fn mime_and_uuid_rules() {
        assert!(is_valid_mime("text/plain"));
        assert!(is_valid_mime("image/svg+xml"));
        assert!(is_valid_mime(&format!(
            "{}/{}",
            "a".repeat(127),
            "b".repeat(127)
        )));
        for bad in [
            "Text/plain",
            "text/plain;charset=utf-8",
            "text",
            "/x",
            "x/",
            "-a/b",
            "a/b/c",
            "a b/c",
        ] {
            assert!(!is_valid_mime(bad), "{bad}");
        }
        assert!(!is_valid_mime(&format!("{}/b", "a".repeat(128))));
        assert!(is_canonical_uuid("6f1c2b7e-0d4a-4f53-9b8e-2a6d3c1e9f04"));
        assert!(!is_canonical_uuid("6F1C2B7E-0D4A-4F53-9B8E-2A6D3C1E9F04"));
        assert!(!is_canonical_uuid("6f1c2b7e0d4a4f539b8e2a6d3c1e9f04"));
    }

    #[test]
    fn escape_detection() {
        assert!(needs_envelope_escape(
            "{\"type\":\"accord.content\",\"v\":1}"
        ));
        assert!(needs_envelope_escape("\n {\"type\":\"accord.content\""));
        assert!(needs_envelope_escape("\u{1e}accord-call\u{1e}{}"));
        assert!(!needs_envelope_escape(" \u{1e}accord-call\u{1e}{}"));
        assert!(!needs_envelope_escape("hello"));
    }

    #[test]
    fn fixed_key_sealer_matches_seal_layout() {
        let a = seal_with_fixed_key_for_vectors(&[7u8; 100], &KEY, &PREFIX).unwrap();
        let b = seal_with_fixed_key_for_vectors(&[7u8; 100], &KEY, &PREFIX).unwrap();
        // Same key and prefix, same output: why only tests may fix them (REQ-1).
        assert_eq!(a.blob, b.blob);
        assert_eq!(*a.key, KEY);
        assert_eq!(a.nonce_prefix, PREFIX);
        assert_eq!(a.blob.len() as u64, blob_length(padme(100)));
    }

    #[test]
    fn debug_output_never_contains_plaintext() {
        let d = r#"{"v":1,"blob_id":"6f1c2b7e-0d4a-4f53-9b8e-2a6d3c1e9f04","scheme":"A256GCM-STREAM64K","key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","nonce_prefix":"oKGio6Slpg==","sha256":"H9Qnji+ygnF5jFXngB7ZXX9XtcFvQX6HznTu0N/XGqY=","size":5,"padded_size":5,"name":"hello.txt","mime":"text/plain"}"#;
        let env = format!(
            r#"{{"type":"accord.content","v":1,"channel_id":"7c9e6679-7425-40de-944b-e07fc1f90ae7","body":"secret body","attachments":[{d}]}}"#
        );
        let c = classify_plaintext(env.as_bytes());
        let Classified::EnvelopeV1(o) = &c else {
            panic!("not an envelope");
        };
        let read = read_envelope_v1(o);
        assert!(
            matches!(&read, EnvelopeRead::Valid(e) if e.attachments.len() == 1 && e.attachments[0].is_some())
        );
        let control = classify_plaintext(
            b"\x1eaccord-keys\x1e{\"type\":\"skdm\",\"v\":2,\"ck\":\"SECRETCK\"}",
        );
        assert!(matches!(control, Classified::Control(Ok(_))));
        let outputs = [
            format!("{c:?}"),
            format!("{c:#?}"),
            format!("{read:?}"),
            format!("{read:#?}"),
            format!("{control:?}"),
            format!("{:?}", parse_strict_json(&env, MAX_NESTING_DEPTH)),
            format!("{:?}", read_envelope(env.as_bytes())),
        ];
        for out in &outputs {
            for secret in [
                "AAECAw",
                "oKGio6",
                "H9Qnji",
                "hello",
                "text/plain",
                "secret",
                "SECRETCK",
                "accord.content",
            ] {
                assert!(!out.contains(secret), "{secret} printed");
            }
        }
        assert_eq!(outputs[0], "EnvelopeV1(Object(<5 members>))");
        assert_eq!(
            outputs[2],
            "Valid(EnvelopeV1 { channel_id: \"7c9e6679-7425-40de-944b-e07fc1f90ae7\", body: <11 bytes>, has_attachments_member: true, attachments: 1 })"
        );
        assert_eq!(
            outputs[4],
            "Control(ValidControl { tag: \"accord-keys\", type_: \"skdm\", v: 2, body: Object(<3 members>) })"
        );
    }

    #[test]
    fn legacy_key_json_has_one_definition() {
        let legacy = |s: &str| {
            matches!(
                classify_plaintext(s.as_bytes()),
                Classified::LegacyText {
                    legacy_key_json: true
                }
            )
        };
        assert!(legacy(
            r#"{"type":"skdm","ch":"c","skid":"k","ck":"AA==","spk":"AA==","iter":0,"rep":null}"#
        ));
        assert!(legacy(r#" {"type":"nmk","node":"n","key":"AA=="}"#));
        // Any RFC 8259 number token, of any magnitude.
        for n in [
            "1e400",
            "-0.5E-3",
            "-0",
            "1.25",
            "18446744073709551616",
            "2E+2",
        ] {
            assert!(legacy(&format!(r#"{{"type":"nmk","x":{n}}}"#)), "{n}");
        }
        // Rules 1, 2 and 4 still hold, and the grammar is RFC 8259.
        for bad in [
            r#"{"type":"skdm","x":"\ud800"}"#,
            r#"{"type":"skdm","type":"skdm"}"#,
            r#"{"type":"skdm","x":[[[[[[[[0]]]]]]]]}"#,
            r#"{"type":"skdm","x":01}"#,
            r#"{"type":"skdm","x":1.}"#,
            r#"{"type":"skdm","x":.5}"#,
            r#"{"type":"skdm","x":+1}"#,
            r#"{"type":"skdm","x":1e}"#,
            r#"{"type":"skdm","x":--1}"#,
            r#"{"type":"skdm"} x"#,
            r#"{"type":"skdmx"}"#,
            r#"["skdm"]"#,
        ] {
            assert!(!legacy(bad), "{bad}");
        }
        assert!(legacy(r#"{"type":"skdm","x":[[[[[[0]]]]]]}"#));
        // Rule 3 is relaxed for legacy key JSON only.
        assert_eq!(
            parse_strict_json("[1e400]", MAX_NESTING_DEPTH),
            Err(StrictParseError::Number)
        );
    }

    #[test]
    fn sanitize_t23() {
        assert_eq!(
            sanitize_file_name("invoice\u{202e}fdp.exe"),
            "invoicefdp.exe"
        );
        assert_eq!(
            sanitize_file_name("invoice.pdf\u{2028}.exe"),
            "invoice.pdf .exe"
        );
        assert_eq!(final_extension("invoice.pdf .exe"), Some(".exe"));
        assert_eq!(
            sanitize_file_name("report\u{feff}\u{200b}.pdf"),
            "report.pdf"
        );
        assert_eq!(sanitize_file_name("\u{3164}.pdf"), "pdf");
        assert_eq!(sanitize_file_name("a/b\\c:d<e>f?.txt"), "a_b_c_d_e_f_.txt");
        assert_eq!(sanitize_file_name("..."), "attachment");
        assert_eq!(sanitize_file_name(""), "attachment");
        let long = sanitize_file_name(&format!("{}.pdf", "\u{e9}".repeat(300)));
        assert!(long.len() <= 255);
        assert_eq!(long, format!("{}.pdf", "\u{e9}".repeat(125)));
        assert_eq!(sanitize_file_name("a\u{0}b\u{85}c.txt"), "ab c.txt");
        assert_eq!(
            sanitize_file_name("e\u{301}te\u{301}.txt"),
            "\u{e9}t\u{e9}.txt"
        );
        assert_eq!(
            sanitize_file_name("a\u{1f600}".repeat(60).as_str()).len(),
            255
        );
        for cp in [
            0x061c, 0x200b, 0x200f, 0x202a, 0x202e, 0x2060, 0x2064, 0x2066, 0x206f, 0xfeff, 0xfff9,
            0xfffb, 0xe0000, 0xe0041, 0xe007f, 0xfe00, 0xfe0f, 0xe0100, 0x115f, 0x1160, 0x3164,
            0xffa0, 0x1, 0x7f, 0x9f, 0xe000, 0xf8ff, 0xf0000, 0x10ffff, 0xfdd0, 0xffff,
        ] {
            let c = char::from_u32(cp).unwrap();
            assert_eq!(sanitize_file_name(&format!("a{c}b")), "ab", "U+{cp:04X}");
        }
        for cp in [
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x85, 0xa0, 0x1680, 0x2000, 0x200a, 0x2028, 0x2029,
            0x202f, 0x205f, 0x3000,
        ] {
            let c = char::from_u32(cp).unwrap();
            assert_eq!(
                sanitize_file_name(&format!("a{c}{c}b")),
                "a b",
                "U+{cp:04X}"
            );
        }
        assert_eq!(sanitize_file_name("holiday photo.jpg"), "holiday photo.jpg");
        assert_eq!(final_extension(".bashrc"), None);
        assert_eq!(final_extension(&format!("a.{}", "x".repeat(17))), None);
    }
}
