/**
 * @module voice/callPayload
 * The bodies of call messages (SPEC-03 §6.3.2 to §6.3.5): `call_hello`,
 * `call_key` and `call_key_ack`, and the after-decryption checks of REQ-12
 * that do not need call state.
 *
 * Whether a plaintext is a call payload at all is decided by SPEC-02's
 * classifier (`e2ee/plaintext.ts`, consumer path `voice`): this module calls
 * it first and never parses anything the classifier did not accept for the
 * voice path, so DM text, content envelopes and key-distribution or control
 * payloads of other tags are never read as call messages (REQ-13, SPEC-02
 * REQ-53). Nothing here logs; a rejection carries no text derived from the
 * plaintext.
 */

import { classifyFor, StrictObject, type StrictValue } from '../e2ee/plaintext';
import { decodeCanonicalBase64 } from '../attachments/base64';
import { isCanonicalUuid } from '../attachments/envelope';
import { CALL_SUITE, INST_LEN, KID_LIMIT, SECRET_LEN } from './mediaFrame';

/** `v` of every call payload of this spec. */
export const CALL_PAYLOAD_VERSION = 1;

interface CallCommon {
  /** Sender user id, equal to the relay-stamped sender. */
  readonly from: string;
  /** The active channel. */
  readonly ch: string;
  /** The sender's 16-byte instance. */
  readonly inst: Uint8Array;
}

export interface CallHello extends CallCommon {
  readonly type: 'call_hello';
  /** The recipient's instance, or null when the sender does not know it. */
  readonly toInst: Uint8Array | null;
  /** SPEC-06 head claim (final rule only); not validated here. */
  readonly gh?: StrictValue;
}

export interface CallKey extends CallCommon {
  readonly type: 'call_key';
  readonly toInst: Uint8Array;
  readonly epoch: number;
  /**
   * The 32-byte epoch secret. The caller imports it and zero-fills this
   * buffer at once (REQ-27).
   */
  readonly key: Uint8Array;
  readonly gh?: StrictValue;
}

export interface CallKeyAck extends CallCommon {
  readonly type: 'call_key_ack';
  readonly toInst: Uint8Array;
  readonly epoch: number;
}

export type CallPayload = CallHello | CallKey | CallKeyAck;

/** The receiver's view of the message: the relay-stamped sender and C. */
export interface CallPayloadContext {
  readonly from: string;
  readonly ch: string;
}

function str(o: StrictObject, name: string): string | null {
  const v = o.get(name);
  return typeof v === 'string' ? v : null;
}

function uuidField(o: StrictObject, name: string, expected: string): string | null {
  const v = str(o, name);
  if (v === null || !isCanonicalUuid(v) || v !== expected.toLowerCase()) return null;
  return v;
}

function bytesField(o: StrictObject, name: string, length: number): Uint8Array | null {
  const v = str(o, name);
  return v === null ? null : decodeCanonicalBase64(v, length);
}

function epochField(o: StrictObject): number | null {
  const v = o.get('epoch');
  return typeof v === 'number' && Number.isInteger(v) && v >= 0 && v < KID_LIMIT ? v : null;
}

/**
 * Validate a decrypted call message (§6.3, REQ-12 after decryption, REQ-26,
 * REQ-33 (c)'s format rules). Returns the payload, or null when any of these
 * fails, in which case the caller discards the message silently:
 *
 * - SPEC-02's classifier accepts the plaintext on the voice path (the call
 *   tag, SPEC-02 §6.2 rules 1 to 4, a registered `type` and `v` = 1);
 * - `from` equals the relay-stamped sender and `ch` equals C, both lowercase
 *   canonical UUIDs;
 * - `inst` is standard base64 (with padding, canonical) of 16 bytes, and so is
 *   `to_inst`, which may be null in a `call_hello` only;
 * - `call_key`: `suite` = 5, `epoch` an integer in [0, 2^32 − 1], `key` 32 bytes;
 * - `call_key_ack`: `epoch` an integer in [0, 2^32 − 1].
 *
 * Unknown members are ignored once the classifier's strict pass accepted them.
 * The SPEC-05 session checks of REQ-12 are the caller's.
 */
export function parseCallPayload(plaintext: string | Uint8Array, ctx: CallPayloadContext): CallPayload | null {
  const c = classifyFor('voice', plaintext);
  if (!c || c.class !== 'control' || !c.valid) return null;
  const body = c.body;
  if (body.get('v') !== CALL_PAYLOAD_VERSION) return null;
  const from = uuidField(body, 'from', ctx.from);
  const ch = uuidField(body, 'ch', ctx.ch);
  const inst = bytesField(body, 'inst', INST_LEN);
  if (from === null || ch === null || inst === null) return null;
  if (!body.has('to_inst')) return null;
  const toInst = body.get('to_inst') === null ? null : bytesField(body, 'to_inst', INST_LEN);
  if (toInst === null && body.get('to_inst') !== null) return null;
  const gh = body.get('gh');
  switch (body.get('type')) {
    case 'call_hello':
      return { type: 'call_hello', from, ch, inst, toInst, ...(gh === undefined ? {} : { gh }) };
    case 'call_key': {
      if (toInst === null || body.get('suite') !== CALL_SUITE) return null;
      // Every other check comes first: the secret is decoded last, so no
      // rejection leaves a decoded key behind (REQ-27). Any check added
      // after the decode must zero-fill `key` before returning null.
      const epoch = epochField(body);
      if (epoch === null) return null;
      const key = bytesField(body, 'key', SECRET_LEN);
      if (key === null) return null;
      return { type: 'call_key', from, ch, inst, toInst, epoch, key, ...(gh === undefined ? {} : { gh }) };
    }
    case 'call_key_ack': {
      const epoch = epochField(body);
      if (toInst === null || epoch === null) return null;
      return { type: 'call_key_ack', from, ch, inst, toInst, epoch };
    }
    default:
      return null;
  }
}
