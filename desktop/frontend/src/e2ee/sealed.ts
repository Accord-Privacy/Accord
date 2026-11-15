/**
 * @module e2ee/sealed
 * The sealed wire payload of SPEC-02 REQ-48.
 *
 * `ws.sendChannelMessage`, `ws.sendEditMessage` and `api.editMessage` accept a
 * message payload only as a `SealedPayload`. Only the sealing functions below
 * produce one, and only from a successful encryption: the Double Ratchet for
 * DMs, Sender Keys for node channels and, for text only, the legacy channel-key
 * opt-in. Its constructor is private to this module, so no plaintext, body or
 * envelope can reach a send function, on the first send or on any resend.
 *
 * The type carries a brand that no object literal or string has, and a
 * run-time registry backs it up (`isSealedPayload`), so the send functions also
 * refuse a forged object at run time.
 *
 * Nothing here logs a plaintext or an error derived from one.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { decodeWireBase64, encodeBase64 } from '../attachments/base64';
import { classifyPlaintext } from './plaintext';
import { readEnvelope } from '../attachments/envelope';
import { encryptChannelMessage, type SenderKeyStore } from './senderKeys';
import type { PreKeyBundle } from './keys';

declare const sealedBrand: unique symbol;

/** How a payload was sealed. */
export type SealScheme = 'dr' | 'sk' | 'legacy';

/** An encrypted message payload exactly as it goes on the wire (REQ-48). */
export interface SealedPayload {
  readonly [sealedBrand]: true;
  /** Base64, as `encrypted_data` carries it. */
  readonly wire: string;
  readonly scheme: SealScheme;
  /** Base64 of SHA-256 over the base64-decoded wire bytes (REQ-49, §6.2.4). */
  readonly wireSha256: string;
}

const minted = new WeakSet<object>();

function mintSealed(wire: string, scheme: SealScheme): SealedPayload {
  const bytes = decodeWireBase64(wire);
  if (bytes === null) throw new Error('sealing produced a payload that is not base64');
  const payload = Object.freeze({ wire, scheme, wireSha256: encodeBase64(sha256(bytes)) }) as unknown as SealedPayload;
  minted.add(payload);
  return payload;
}

/** True only for payloads produced by the sealing functions of this module. */
export function isSealedPayload(x: unknown): x is SealedPayload {
  return typeof x === 'object' && x !== null && minted.has(x);
}

/** The part of `E2EEManager` the Double Ratchet sealer needs. */
export interface DoubleRatchetSealer {
  encryptEnvelope(peerId: string, plaintext: string, peerBundle?: PreKeyBundle): string;
}

/**
 * Seal a DM plaintext with the Double Ratchet (REQ-7). The envelope is the
 * manager's self-describing JSON (`x3dh` on first contact, then `dr`), base64
 * encoded for the wire. Throws when no session exists and no bundle is given,
 * or when encryption fails.
 */
export function sealForDm(manager: DoubleRatchetSealer, peerId: string, plaintext: string, peerBundle?: PreKeyBundle): SealedPayload {
  const envelopeJson = manager.encryptEnvelope(peerId, plaintext, peerBundle);
  return mintSealed(encodeBase64(new TextEncoder().encode(envelopeJson)), 'dr');
}

/**
 * Seal a node-channel plaintext with this user's sender key for the channel
 * (REQ-7). Throws when encryption fails.
 */
export function sealForChannel(store: SenderKeyStore, channelId: string, plaintext: string): SealedPayload {
  return mintSealed(encryptChannelMessage(store, channelId).encryptFn(plaintext), 'sk');
}

/**
 * Seal text with the legacy channel key, the explicit compatibility opt-in
 * (`accord_legacy_channel_crypto`). The relay can derive that key, so this is
 * not end-to-end encryption, and it is refused for anything but text: a
 * control payload, an invalid or newer envelope, or an envelope with an
 * `attachments` member never goes out under it (REQ-7). The REQ-10 escape
 * envelope, which carries only a body, is text.
 */
export async function sealLegacyText(
  encrypt: (plaintext: string) => Promise<string>,
  plaintext: string,
): Promise<SealedPayload> {
  const c = classifyPlaintext(plaintext);
  if (c.class === 'control') throw new Error('the legacy channel key seals text only');
  if (c.class === 'envelope') {
    const read = readEnvelope(c);
    if (read.status !== 'valid' || read.envelope.hasAttachmentsMember) {
      throw new Error('the legacy channel key seals text only');
    }
  }
  return mintSealed(await encrypt(plaintext), 'legacy');
}
