/**
 * @module plaintext
 * Typed E2EE plaintext (SPEC-02 §6.1, §6.2 rules 1 to 4) and the batch-wide
 * consumer rule (SPEC-02 REQ-53).
 *
 * This is the single classifier for every plaintext produced by a Double
 * Ratchet decryption, a Sender Keys decryption or a cache record. Every
 * consumer path imports it: the message display paths (through
 * `attachments/decode.ts`), the voice path (SPEC-03), the key-distribution
 * path (SPEC-05, SPEC-06) and the control queue (SPEC-04). No other module may
 * classify plaintext or reimplement the strict JSON pass.
 *
 * Classes, decided from the leading bytes before any JSON parsing:
 *   - control payload: first byte 0x1E, then `tag`, 0x1E and a JSON object;
 *     never displayed;
 *   - content envelope: after optional JSON whitespace, the 24-byte envelope
 *     prefix `{"type":"accord.content"`;
 *   - legacy text: anything else.
 *
 * Nothing in this module logs, and no failure carries text derived from the
 * plaintext: callers get a fixed reason code at most (REQ-53).
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** The 24-byte envelope prefix of SPEC-02 §6.1. */
export const ENVELOPE_PREFIX = '{"type":"accord.content"';
/** The control-payload separator, U+001E (ASCII record separator). */
export const CONTROL_SEPARATOR = '\u001e';
/** Largest serialized content envelope, in UTF-8 bytes (SPEC-02 §6.2.1). */
export const MAX_ENVELOPE_BYTES = 16_384;
/** Largest control payload, in bytes (SPEC-02 §6.1). */
export const MAX_CONTROL_PAYLOAD_BYTES = 65_536;
/** Deepest nesting of arrays and objects; the outer object is level 1. */
export const MAX_NESTING_DEPTH = 8;
/** Largest number token value, 2^53 - 1 (SPEC-02 §6.2 rule 3). */
export const MAX_JSON_INTEGER = Number.MAX_SAFE_INTEGER;

const MAX_TAG_BYTES = 32;
const MAX_JSON_INTEGER_DIGITS = '9007199254740991';

const ENVELOPE_PREFIX_BYTES = new TextEncoder().encode(ENVELOPE_PREFIX);

// ---------------------------------------------------------------------------
// Registry (SPEC-02 §6.1)
// ---------------------------------------------------------------------------

/** The consumer paths of REQ-53. */
export type ConsumerPath = 'display' | 'voice' | 'key_distribution' | 'control_queue';

export type ControlTag = 'accord-call' | 'accord-keys' | 'accord-ctl';

interface ControlRegistration {
  readonly types: readonly string[];
  readonly v: number;
  readonly path: ConsumerPath;
}

/**
 * Registered control-payload tags, their `type` values and `v`, and the one
 * path that accepts each. New payload types are added here and nowhere else.
 */
export const CONTROL_REGISTRY: Readonly<Record<ControlTag, ControlRegistration>> = Object.freeze({
  // SPEC-03 §6.3
  'accord-call': Object.freeze({ types: Object.freeze(['call_hello', 'call_key', 'call_key_ack']), v: 1, path: 'voice' as const }),
  // SPEC-05 §6.9; fields added by SPEC-06 §6.8
  'accord-keys': Object.freeze({ types: Object.freeze(['skdm', 'nmk']), v: 2, path: 'key_distribution' as const }),
  // SPEC-04 §6.9 (session_reset), SPEC-05 §6.17 (identity)
  'accord-ctl': Object.freeze({ types: Object.freeze(['session_reset', 'identity']), v: 1, path: 'control_queue' as const }),
});

/**
 * Legacy key JSON (untagged objects whose `type` is `skdm` or `nmk`) is
 * accepted by the key-distribution path of clients that do not implement
 * SPEC-05. SPEC-05 clients never accept it (SPEC-05 REQ-48); the SPEC-05
 * change sets this to false.
 */
export const LEGACY_KEY_JSON_ACCEPTED = true;

const LEGACY_KEY_JSON_TYPES: ReadonlySet<string> = new Set(['skdm', 'nmk']);

/** An RFC 8259 number token, of any magnitude (legacy key JSON only). */
const RFC8259_NUMBER = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/;

function isRegisteredTag(tag: string): tag is ControlTag {
  return Object.prototype.hasOwnProperty.call(CONTROL_REGISTRY, tag);
}

// ---------------------------------------------------------------------------
// Strict JSON (SPEC-02 §6.2 rules 1 to 4)
// ---------------------------------------------------------------------------

/**
 * A parsed JSON object. Members keep their order; names are unique by
 * construction (rule 1), so the map cannot hide a duplicate.
 */
export class StrictObject {
  readonly members: ReadonlyMap<string, StrictValue>;
  constructor(members: ReadonlyMap<string, StrictValue>) {
    this.members = members;
  }
  get(name: string): StrictValue | undefined {
    return this.members.get(name);
  }
  has(name: string): boolean {
    return this.members.has(name);
  }
}

/**
 * A strictly parsed JSON value. Every number is a non-negative integer of at
 * most 2^53 - 1 (rule 3), so it is exact as a JavaScript number.
 */
export type StrictValue = null | boolean | number | string | StrictValue[] | StrictObject;

/** Why the strict pass rejected a text. Never derived from the text itself. */
export type StrictParseFailure = 'syntax' | 'duplicate' | 'surrogate' | 'number' | 'depth';

export type StrictParseResult =
  | { ok: true; value: StrictValue }
  | { ok: false; reason: StrictParseFailure };

class StrictParseError {
  readonly reason: StrictParseFailure;
  constructor(reason: StrictParseFailure) {
    this.reason = reason;
  }
}

function isJsonWhitespace(c: number): boolean {
  return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;
}

function isDigit(c: number): boolean {
  return c >= 0x30 && c <= 0x39;
}

function hexValue(c: number): number {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x61 && c <= 0x66) return c - 0x57;
  if (c >= 0x41 && c <= 0x46) return c - 0x37;
  return -1;
}

/** True when the UTF-16 string contains no lone surrogate. */
export function isWellFormedUtf16(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (d >= 0xdc00 && d <= 0xdfff) {
        i++;
        continue;
      }
      return false;
    }
    if (c >= 0xdc00 && c <= 0xdfff) return false;
  }
  return true;
}

/** UTF-8 length of a string; a lone surrogate counts as its 3-byte replacement. */
export function utf8ByteLength(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        n += 4;
        i++;
      } else n += 3;
    } else n += 3;
  }
  return n;
}

class StrictParser {
  private pos = 0;
  private readonly s: string;
  private readonly maxDepth: number;
  /**
   * Accept every RFC 8259 number token instead of rule 3. Only legacy key
   * JSON detection sets it; such a number's value is never read.
   */
  private readonly anyNumber: boolean;

  constructor(s: string, maxDepth: number, anyNumber = false) {
    this.s = s;
    this.maxDepth = maxDepth;
    this.anyNumber = anyNumber;
  }

  parseDocument(): StrictValue {
    this.skipWs();
    const value = this.parseValue(0);
    this.skipWs();
    if (this.pos !== this.s.length) throw new StrictParseError('syntax');
    return value;
  }

  private skipWs(): void {
    while (this.pos < this.s.length && isJsonWhitespace(this.s.charCodeAt(this.pos))) this.pos++;
  }

  private parseValue(depth: number): StrictValue {
    if (this.pos >= this.s.length) throw new StrictParseError('syntax');
    const c = this.s.charCodeAt(this.pos);
    if (c === 0x7b /* { */) return this.parseObject(depth + 1);
    if (c === 0x5b /* [ */) return this.parseArray(depth + 1);
    if (c === 0x22 /* " */) return this.parseString();
    if (c === 0x2d /* - */ || isDigit(c)) return this.parseNumber();
    if (this.s.startsWith('true', this.pos)) {
      this.pos += 4;
      return true;
    }
    if (this.s.startsWith('false', this.pos)) {
      this.pos += 5;
      return false;
    }
    if (this.s.startsWith('null', this.pos)) {
      this.pos += 4;
      return null;
    }
    throw new StrictParseError('syntax');
  }

  private parseObject(depth: number): StrictObject {
    if (depth > this.maxDepth) throw new StrictParseError('depth');
    this.pos++; // {
    const members = new Map<string, StrictValue>();
    this.skipWs();
    if (this.s.charCodeAt(this.pos) === 0x7d /* } */) {
      this.pos++;
      return new StrictObject(members);
    }
    for (;;) {
      this.skipWs();
      if (this.s.charCodeAt(this.pos) !== 0x22) throw new StrictParseError('syntax');
      const name = this.parseString();
      if (members.has(name)) throw new StrictParseError('duplicate');
      this.skipWs();
      if (this.s.charCodeAt(this.pos) !== 0x3a /* : */) throw new StrictParseError('syntax');
      this.pos++;
      this.skipWs();
      members.set(name, this.parseValue(depth));
      this.skipWs();
      const c = this.s.charCodeAt(this.pos);
      if (c === 0x2c /* , */) {
        this.pos++;
        continue;
      }
      if (c === 0x7d /* } */) {
        this.pos++;
        return new StrictObject(members);
      }
      throw new StrictParseError('syntax');
    }
  }

  private parseArray(depth: number): StrictValue[] {
    if (depth > this.maxDepth) throw new StrictParseError('depth');
    this.pos++; // [
    const items: StrictValue[] = [];
    this.skipWs();
    if (this.s.charCodeAt(this.pos) === 0x5d /* ] */) {
      this.pos++;
      return items;
    }
    for (;;) {
      this.skipWs();
      items.push(this.parseValue(depth));
      this.skipWs();
      const c = this.s.charCodeAt(this.pos);
      if (c === 0x2c) {
        this.pos++;
        continue;
      }
      if (c === 0x5d) {
        this.pos++;
        return items;
      }
      throw new StrictParseError('syntax');
    }
  }

  /** Rule 2: the unescaped string must contain no lone surrogate. */
  private parseString(): string {
    this.pos++; // opening quote
    const units: number[] = [];
    for (;;) {
      if (this.pos >= this.s.length) throw new StrictParseError('syntax');
      const c = this.s.charCodeAt(this.pos++);
      if (c === 0x22) break;
      if (c < 0x20) throw new StrictParseError('syntax');
      if (c !== 0x5c /* \ */) {
        units.push(c);
        continue;
      }
      if (this.pos >= this.s.length) throw new StrictParseError('syntax');
      const e = this.s.charCodeAt(this.pos++);
      switch (e) {
        case 0x22: units.push(0x22); break;
        case 0x5c: units.push(0x5c); break;
        case 0x2f: units.push(0x2f); break;
        case 0x62: units.push(0x08); break;
        case 0x66: units.push(0x0c); break;
        case 0x6e: units.push(0x0a); break;
        case 0x72: units.push(0x0d); break;
        case 0x74: units.push(0x09); break;
        case 0x75: {
          let v = 0;
          for (let k = 0; k < 4; k++) {
            const h = this.pos < this.s.length ? hexValue(this.s.charCodeAt(this.pos)) : -1;
            if (h < 0) throw new StrictParseError('syntax');
            v = v * 16 + h;
            this.pos++;
          }
          units.push(v);
          break;
        }
        default:
          throw new StrictParseError('syntax');
      }
    }
    let out = '';
    for (let i = 0; i < units.length; i += 4096) {
      out += String.fromCharCode(...units.slice(i, i + 4096));
    }
    if (!isWellFormedUtf16(out)) throw new StrictParseError('surrogate');
    return out;
  }

  /**
   * Rule 3: only `0|[1-9][0-9]*`, at most 2^53 - 1. With `anyNumber`, any
   * RFC 8259 number token; one that rule 3 rejects reads as `null`, as in the
   * accord-core reference.
   */
  private parseNumber(): number | null {
    const start = this.pos;
    while (this.pos < this.s.length) {
      const c = this.s.charCodeAt(this.pos);
      if (isDigit(c) || c === 0x2d || c === 0x2b || c === 0x2e || c === 0x65 || c === 0x45) this.pos++;
      else break;
    }
    const token = this.s.slice(start, this.pos);
    if (isStrictInteger(token)) return Number(token);
    if (this.anyNumber && RFC8259_NUMBER.test(token)) return null;
    throw new StrictParseError('number');
  }
}

/** True for a rule-3 number token: `0|[1-9][0-9]*`, at most 2^53 - 1. */
function isStrictInteger(token: string): boolean {
  if (!/^(0|[1-9][0-9]*)$/.test(token)) return false;
  return token.length < MAX_JSON_INTEGER_DIGITS.length
    || (token.length === MAX_JSON_INTEGER_DIGITS.length && token <= MAX_JSON_INTEGER_DIGITS);
}

/**
 * Parse a JSON text under SPEC-02 §6.2 rules 1 to 4: no duplicate member
 * names at any depth (after unescaping), no lone surrogates, integer number
 * tokens only (at most 2^53 - 1), nesting depth at most `maxDepth`. Returns
 * the first rule the text breaks, in reading order.
 */
export function parseStrictJson(text: string, maxDepth: number = MAX_NESTING_DEPTH): StrictParseResult {
  try {
    return { ok: true, value: new StrictParser(text, maxDepth).parseDocument() };
  } catch (e) {
    if (e instanceof StrictParseError) return { ok: false, reason: e.reason };
    // Only a stack overflow can land here, and depth is bounded; fail closed.
    return { ok: false, reason: 'syntax' };
  }
}

/**
 * Copy a strict value into fresh plain objects (SPEC-02 §6.2: "receivers copy
 * known members into fresh objects"). Member names such as `__proto__` become
 * own data properties, never prototypes.
 */
export function strictToPlain(value: StrictValue): unknown {
  if (value instanceof StrictObject) {
    return Object.fromEntries([...value.members].map(([k, v]) => [k, strictToPlain(v)]));
  }
  if (Array.isArray(value)) return value.map(strictToPlain);
  return value;
}

// ---------------------------------------------------------------------------
// Classification (SPEC-02 §6.1)
// ---------------------------------------------------------------------------

export type ControlFailure = 'framing' | 'tag' | 'unregistered' | 'size' | 'utf8' | StrictParseFailure | 'shape';
export type EnvelopeFailure = 'size' | 'utf8' | StrictParseFailure | 'version';

export type ValidControl = {
  readonly class: 'control';
  readonly valid: true;
  readonly tag: ControlTag;
  readonly type: string;
  readonly v: number;
  /** The JSON object after the strict pass. */
  readonly body: StrictObject;
};

export type InvalidControl = { readonly class: 'control'; readonly valid: false; readonly reason: ControlFailure };

export type EnvelopeClassification =
  | { readonly class: 'envelope'; readonly status: 'invalid'; readonly reason: EnvelopeFailure }
  | { readonly class: 'envelope'; readonly status: 'newer_version'; readonly v: number }
  /** Rules 1 to 4 hold and `v` is 1; `attachments/envelope.ts` applies rules 5 and 6. */
  | { readonly class: 'envelope'; readonly status: 'v1'; readonly object: StrictObject };

export type LegacyText = {
  readonly class: 'legacy_text';
  readonly text: string;
  /** An object whose `type` is `skdm` or `nmk`: key-distribution path only. */
  readonly legacyKeyJson: boolean;
};

export type Classified = ValidControl | InvalidControl | EnvelopeClassification | LegacyText;

const utf8Encoder = new TextEncoder();

function decodeUtf8Fatal(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
}

function skipWsBytes(bytes: Uint8Array): number {
  let i = 0;
  while (i < bytes.length && isJsonWhitespace(bytes[i])) i++;
  return i;
}

function startsWithAt(bytes: Uint8Array, at: number, prefix: Uint8Array): boolean {
  if (bytes.length - at < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) if (bytes[at + i] !== prefix[i]) return false;
  return true;
}

function isTagByte(b: number): boolean {
  return (b >= 0x61 && b <= 0x7a) || (b >= 0x30 && b <= 0x39) || b === 0x2d;
}

function classifyControl(bytes: Uint8Array, wellFormed: boolean): ValidControl | InvalidControl {
  const fail = (reason: ControlFailure): InvalidControl => ({ class: 'control', valid: false, reason });
  let sep = -1;
  for (let i = 1; i <= MAX_TAG_BYTES + 1 && i < bytes.length; i++) {
    if (bytes[i] === 0x1e) {
      sep = i;
      break;
    }
  }
  if (sep < 0) return fail('framing');
  if (sep === 1) return fail('tag');
  for (let i = 1; i < sep; i++) if (!isTagByte(bytes[i])) return fail('tag');
  let tag = '';
  for (let i = 1; i < sep; i++) tag += String.fromCharCode(bytes[i]);
  if (!isRegisteredTag(tag)) return fail('unregistered');
  if (bytes.length > MAX_CONTROL_PAYLOAD_BYTES) return fail('size');
  const text = wellFormed ? decodeUtf8Fatal(bytes.subarray(sep + 1)) : null;
  if (text === null) return fail('utf8');
  const parsed = parseStrictJson(text);
  if (!parsed.ok) return fail(parsed.reason);
  const body = parsed.value;
  if (!(body instanceof StrictObject)) return fail('shape');
  const type = body.get('type');
  const v = body.get('v');
  if (typeof type !== 'string' || typeof v !== 'number') return fail('shape');
  const reg = CONTROL_REGISTRY[tag];
  if (!reg.types.includes(type) || v !== reg.v) return fail('unregistered');
  return { class: 'control', valid: true, tag, type, v, body };
}

function classifyEnvelope(bytes: Uint8Array, wellFormed: boolean): EnvelopeClassification {
  if (bytes.length > MAX_ENVELOPE_BYTES) return { class: 'envelope', status: 'invalid', reason: 'size' };
  const text = wellFormed ? decodeUtf8Fatal(bytes) : null;
  if (text === null) return { class: 'envelope', status: 'invalid', reason: 'utf8' };
  const parsed = parseStrictJson(text);
  if (!parsed.ok) return { class: 'envelope', status: 'invalid', reason: parsed.reason };
  const object = parsed.value;
  // The prefix guarantees an object whose first member is "type".
  if (!(object instanceof StrictObject)) return { class: 'envelope', status: 'invalid', reason: 'syntax' };
  const v = object.get('v');
  if (typeof v !== 'number') return { class: 'envelope', status: 'invalid', reason: 'version' };
  if (v === 1) return { class: 'envelope', status: 'v1', object };
  if (v > 1) return { class: 'envelope', status: 'newer_version', v };
  return { class: 'envelope', status: 'invalid', reason: 'version' };
}

/**
 * Legacy key JSON (the last row of the §6.1 registry): legacy text that
 * parses as an object whose `type` is `skdm` or `nmk`. "Parses" has one
 * definition, shared with the accord-core reference: the text, with invalid
 * UTF-8 replaced by U+FFFD, passes rules 1, 2 and 4 of §6.2 (depth at most
 * MAX_NESTING_DEPTH), and any RFC 8259 number token is allowed in place of
 * rule 3, because today's clients write these objects with `JSON.stringify`.
 * `JSON.parse` is not used: it and serde_json disagree on lone surrogates,
 * out-of-range numbers and deep nesting, and two clients would then show the
 * same plaintext differently (vectors X57 to X65).
 */
function isLegacyKeyJson(text: string): boolean {
  let i = 0;
  while (i < text.length && isJsonWhitespace(text.charCodeAt(i))) i++;
  if (text.charCodeAt(i) !== 0x7b) return false;
  let parsed: StrictValue;
  try {
    parsed = new StrictParser(text, MAX_NESTING_DEPTH, true).parseDocument();
  } catch {
    return false;
  }
  if (!(parsed instanceof StrictObject)) return false;
  const type = parsed.get('type');
  return typeof type === 'string' && LEGACY_KEY_JSON_TYPES.has(type);
}

/**
 * Classify a plaintext (SPEC-02 §6.1). Accepts the decrypted string or its
 * UTF-8 bytes. A string that is not well-formed UTF-16 cannot be valid UTF-8,
 * so as a control payload or envelope it is invalid (reason `utf8`).
 */
export function classifyPlaintext(input: string | Uint8Array): Classified {
  let bytes: Uint8Array;
  let wellFormed = true;
  if (typeof input === 'string') {
    wellFormed = isWellFormedUtf16(input);
    bytes = utf8Encoder.encode(input);
  } else {
    bytes = input;
  }
  if (bytes.length > 0 && bytes[0] === 0x1e) return classifyControl(bytes, wellFormed);
  if (startsWithAt(bytes, skipWsBytes(bytes), ENVELOPE_PREFIX_BYTES)) return classifyEnvelope(bytes, wellFormed);
  const lossy = typeof input === 'string' && wellFormed ? input : new TextDecoder('utf-8', { ignoreBOM: true }).decode(bytes);
  const text = typeof input === 'string' ? input : lossy;
  // A lone surrogate in a decrypted string is examined as its UTF-8 encoding
  // (U+FFFD), exactly as the accord-core reference sees the same bytes.
  return { class: 'legacy_text', text, legacyKeyJson: isLegacyKeyJson(lossy) };
}

// ---------------------------------------------------------------------------
// Consumer rule (REQ-53)
// ---------------------------------------------------------------------------

/** The paths that act on a classified plaintext, per the §6.1 registry. */
export function acceptedPaths(c: Classified): ConsumerPath[] {
  switch (c.class) {
    case 'control':
      return c.valid ? [CONTROL_REGISTRY[c.tag].path] : [];
    case 'envelope':
      // The display path shows invalid and newer envelopes as placeholders.
      return ['display'];
    case 'legacy_text':
      if (c.legacyKeyJson) return LEGACY_KEY_JSON_ACCEPTED ? ['key_distribution'] : [];
      return ['display'];
  }
}

/** True when `path` may act on `c`. Anything else MUST be discarded silently. */
export function acceptsOn(path: ConsumerPath, c: Classified): boolean {
  return acceptedPaths(c).includes(path);
}

/**
 * Classify and apply the consumer rule in one step. Returns null when the
 * path does not accept the plaintext: the caller then discards it silently
 * (no rendering, caching, persisting, applying or logging; REQ-53).
 */
export function classifyFor(path: ConsumerPath, input: string | Uint8Array): Classified | null {
  const c = classifyPlaintext(input);
  return acceptsOn(path, c) ? c : null;
}

/**
 * What the key-distribution path (`sender_key_distribution`,
 * `pending_sender_keys`) may act on, after classification.
 */
export type KeyDistributionPlaintext =
  /** Legacy key JSON (`skdm`, `nmk`) of clients that predate SPEC-05. */
  | { readonly kind: 'legacy'; readonly message: Readonly<Record<string, unknown>> }
  /** A valid `accord-keys` control payload (SPEC-05 §6.9 bodies). */
  | { readonly kind: 'v2'; readonly type: string; readonly body: StrictObject };

/**
 * The key-distribution path's consumer rule (REQ-53): classify a decrypted
 * key-distribution plaintext and return what the path may act on, or null
 * when it must be discarded silently (not applied, persisted or logged; the
 * queued item may still be acknowledged). Only legacy key JSON (while
 * `LEGACY_KEY_JSON_ACCEPTED`) and `accord-keys` control payloads pass; content
 * envelopes, legacy text, other control tags and invalid control payloads
 * never do.
 */
export function readKeyDistribution(plaintext: string): KeyDistributionPlaintext | null {
  const c = classifyFor('key_distribution', plaintext);
  if (!c) return null;
  if (c.class === 'control') return c.valid ? { kind: 'v2', type: c.type, body: c.body } : null;
  if (c.class !== 'legacy_text' || !c.legacyKeyJson) return null;
  // Classification has checked rules 1, 2 and 4, so this reads the same
  // members every implementation sees.
  try {
    const v: unknown = JSON.parse(c.text);
    if (v === null || typeof v !== 'object' || Array.isArray(v)) return null;
    return { kind: 'legacy', message: v as Record<string, unknown> };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Producing control payloads
// ---------------------------------------------------------------------------

/** A JSON value a control payload body may carry (§6.2 rules 1 to 4). */
export type ControlJson =
  | null
  | boolean
  | number
  | string
  | readonly ControlJson[]
  | { readonly [name: string]: ControlJson };

/** The body of a control payload: a registered `type`, its `v`, and the type's fields. */
export type ControlBody = { readonly type: string; readonly v: number } & { readonly [name: string]: ControlJson };

function checkControlJson(v: ControlJson, depth: number): void {
  if (depth > MAX_NESTING_DEPTH) throw new TypeError('control payload: nesting too deep');
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) throw new TypeError('control payload: integers only');
  } else if (typeof v === 'string') {
    if (!isWellFormedUtf16(v)) throw new TypeError('control payload: lone surrogate');
  } else if (Array.isArray(v)) {
    for (const x of v as readonly ControlJson[]) checkControlJson(x, depth + 1);
  } else if (v !== null && typeof v === 'object') {
    for (const [k, x] of Object.entries(v)) {
      if (!isWellFormedUtf16(k)) throw new TypeError('control payload: lone surrogate');
      checkControlJson(x as ControlJson, depth + 1);
    }
  }
}

/**
 * Frame a control payload for the one tag that `path` accepts (§6.1):
 * `0x1E ‖ tag ‖ 0x1E ‖ UTF-8 JSON object`. Producers name the consumer path,
 * not the tag, so the framing and the registry stay in this module only.
 *
 * `body.type` must be registered for that tag and `body.v` must be its
 * version; numbers must be safe integers and nesting at most 8 levels (rules
 * 1 to 4). The result is checked with the classifier before it is returned,
 * so a producer can never emit a payload its own consumer would discard.
 * Throws a TypeError on any violation (a programming error); the message
 * never contains the body.
 */
export function encodeControlPayloadFor(path: ConsumerPath, body: ControlBody): string {
  const tags = (Object.keys(CONTROL_REGISTRY) as ControlTag[]).filter(t => CONTROL_REGISTRY[t].path === path);
  if (tags.length !== 1) throw new TypeError('control payload: no single tag for this path');
  const reg = CONTROL_REGISTRY[tags[0]];
  if (!reg.types.includes(body.type) || body.v !== reg.v) throw new TypeError('control payload: unregistered type or version');
  checkControlJson(body as ControlJson, 1);
  const out = CONTROL_SEPARATOR + tags[0] + CONTROL_SEPARATOR + JSON.stringify(body);
  const c = classifyFor(path, out);
  if (!c || c.class !== 'control' || !c.valid) throw new TypeError('control payload: rejected by the classifier');
  return out;
}

// ---------------------------------------------------------------------------
// Sender escape (REQ-10)
// ---------------------------------------------------------------------------

/** True when `text` begins, after JSON whitespace, with the envelope prefix. */
export function startsWithEnvelopePrefix(text: string): boolean {
  let i = 0;
  while (i < text.length && isJsonWhitespace(text.charCodeAt(i))) i++;
  return text.startsWith(ENVELOPE_PREFIX, i);
}

/**
 * True when user text could be taken for a typed payload and must be sent
 * inside an escape envelope (REQ-10): it begins with U+001E, or with the
 * envelope prefix after JSON whitespace.
 */
export function needsEnvelopeEscape(text: string): boolean {
  return text.startsWith(CONTROL_SEPARATOR) || startsWithEnvelopePrefix(text);
}
