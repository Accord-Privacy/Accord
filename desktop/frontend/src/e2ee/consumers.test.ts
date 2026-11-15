/**
 * SPEC-02 T-53 (REQ-53): every consumer path of decrypted plaintext acts only
 * on the classes and tags the §6.1 registry gives it.
 *
 * Every vector of `core/tests/vectors/typed-plaintext-v1.json` (V1 to V26 and
 * the extra cases) is encrypted on a real session (the Double Ratchet between
 * two E2EE managers, or Sender Keys) and fed to each path that exists in this
 * client, through the code the app runs:
 *
 * - message display: a live DM frame (Double Ratchet) and a channel history
 *   item (Sender Keys) through the decode function; notifications, Copy Text,
 *   bookmarks and link previews read only what the decode function displays
 *   (App.tsx returns before them for a hidden message, checked statically);
 * - edits: a Sender Keys `message_edit` through `decodeEdit`;
 * - the key-distribution path (`sender_key_distribution`,
 *   `pending_sender_keys`): `readKeyDistribution`, which both App.tsx
 *   handlers call before anything else;
 * - pins, threads and search: no Double Ratchet or Sender Keys decryption
 *   happens there in stage 1 (their content is relay JSON, REQ-51); the
 *   search overlay's legacy decryption shows legacy text only.
 *
 * The voice path (SPEC-03) and the control queue (SPEC-04) do not exist in
 * this client yet; a static check makes sure nothing outside the classifier
 * parses the control framing, so whichever spec adds them must call it.
 *
 * Discarded plaintexts leave no rendered content, cache record, store entry,
 * applied key, console output or storage write containing them.
 */

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { E2EEManager } from './index';
import { SenderKeyStore, buildDistributionMessage, decryptChannelMessage, isSenderKeyEnvelope, parseDistributionMessage } from './senderKeys';
import { sealForChannel } from './sealed';
import { readKeyDistribution, type ConsumerPath } from './plaintext';
import { decodeEdit, decodeMessage, type Decryptors } from '../attachments/decode';
import { AttachmentStore } from '../attachments/store';

const REPO_ROOT = join(process.cwd(), '..', '..');
const SRC = join(process.cwd(), 'src');

interface Vector {
  id: string;
  plaintext_hex: string;
  expect: { class: string; accepted_by: ConsumerPath[] };
}

const vectors = (JSON.parse(readFileSync(join(REPO_ROOT, 'core/tests/vectors/typed-plaintext-v1.json'), 'utf8')) as { vectors: Vector[] }).vectors;

function utf8(hex: string): string | null {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null; // a session hands over strings; invalid UTF-8 is covered by plaintext.test.ts
  }
}

const usable = vectors.flatMap(v => {
  const text = utf8(v.plaintext_hex);
  return text === null ? [] : [{ ...v, text }];
});

const ORIGIN = 'https://relay.example';
const X = '7c9e6679-7425-40de-944b-e07fc1f90ae7';
const D = '0b1c2d3e-4f50-4a61-8b72-9c8d7e6f5a4b';
const ALICE = '11111111-2222-4333-8444-555555555555';
const BOB = '66666666-7777-4888-8999-aaaaaaaaaaaa';

const toWire = (s: string) => btoa(String.fromCharCode(...new TextEncoder().encode(s)));
const fromWire = (s: string) => new TextDecoder().decode(Uint8Array.from(atob(s), c => c.charCodeAt(0)));

describe('T-53 (REQ-53): every consumer path acts only on what the registry gives it', () => {
  const alice = new E2EEManager();
  const bob = new E2EEManager();
  const aliceKeys = new SenderKeyStore();
  const bobKeys = new SenderKeyStore();
  let bundle: ReturnType<E2EEManager['initialize']>;
  const logged: string[] = [];
  const stored: string[] = [];

  beforeAll(() => {
    alice.initialize();
    bundle = bob.initialize();
    const sk = aliceKeys.getOrCreateMyKey(X);
    bobKeys.setPeerKey(X, ALICE, parseDistributionMessage(buildDistributionMessage(X, sk)).state);
    for (const level of ['log', 'info', 'warn', 'error', 'debug'] as const) {
      vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
        logged.push(args.map(a => (a instanceof Error ? `${a.message} ${a.stack}` : typeof a === 'string' ? a : JSON.stringify(a))).join(' '));
      });
    }
    const setItem = Storage.prototype.setItem;
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(function (this: Storage, k: string, v: string) {
      stored.push(`${k}=${v}`);
      setItem.call(this, k, v);
    });
  });

  afterAll(() => {
    vi.restoreAllMocks();
  });

  /** Alice → Bob over the Double Ratchet, as the wire carries it. */
  const drWire = (text: string) => toWire(alice.encryptEnvelope(BOB, text, bundle));
  const drDecryptor: Decryptors = {
    doubleRatchet: (sender, payload) => bob.decryptEnvelope(sender, fromWire(payload)),
    senderKeys: () => null,
  };
  const skDecryptor: Decryptors = {
    senderKeys: (channel, sender, payload) => (isSenderKeyEnvelope(payload) ? decryptChannelMessage(bobKeys, channel, sender, payload) : null),
  };

  for (const v of usable) {
    const accepts = (p: ConsumerPath) => v.expect.accepted_by.includes(p);

    it(`${v.id}: display paths (live DM, channel history) ${accepts('display') ? 'show it' : 'discard it'}`, async () => {
      for (const [channel, payload, decryptors] of [
        [D, drWire(v.text), drDecryptor],
        [X, sealForChannel(aliceKeys, X, v.text).wire, skDecryptor],
      ] as const) {
        const store = new AttachmentStore();
        const cache = new Map<string, unknown>();
        const id = `${v.id}-${channel}`;
        const decoded = await decodeMessage(
          { origin: ORIGIN, renderedChannelId: channel, ownUserId: BOB },
          { channelId: channel, messageId: id, senderId: ALICE, payload, editedAt: null },
          { decryptors, store, cache: { get: k => cache.get(k), put: r => void cache.set(r.message_id, r) } },
        );
        if (accepts('display')) {
          expect(decoded.verified, `${v.id} decrypted`).toBe(true);
          expect(decoded.display).not.toBe('hidden');
        } else {
          expect(decoded.display).toBe('hidden');
          expect(decoded.body).toBe('');
          expect(cache.size).toBe(0);
          expect(store.listChannel(ORIGIN, channel)).toEqual([]);
        }
      }
    });

    it(`${v.id}: the edit path ${accepts('display') ? 'may apply it' : 'drops it'}`, async () => {
      const store = new AttachmentStore();
      const decision = await decodeEdit(
        { origin: ORIGIN, renderedChannelId: X, ownUserId: BOB },
        { channelId: X, messageId: 'target', senderId: ALICE, payload: sealForChannel(aliceKeys, X, v.text).wire },
        { channelId: X, messageId: 'target', senderId: ALICE },
        { decryptors: skDecryptor, store },
      );
      if (!accepts('display')) expect(decision.action).toBe('drop');
      expect(store.listChannel(ORIGIN, X)).toEqual([]);
    });

    it(`${v.id}: the key-distribution path ${accepts('key_distribution') ? 'accepts it' : 'discards it'}`, () => {
      const decrypted = bob.decryptEnvelope(ALICE, fromWire(drWire(v.text)));
      expect(decrypted).toBe(v.text);
      const read = readKeyDistribution(decrypted);
      if (accepts('key_distribution')) {
        expect(read).not.toBeNull();
        expect(read!.kind).toBe(v.expect.class === 'control' ? 'v2' : 'legacy');
      } else {
        expect(read).toBeNull();
      }
    });
  }

  it('no console output or storage write contains a discarded plaintext', () => {
    const discarded = usable.filter(v => !v.expect.accepted_by.includes('display') && v.text.length >= 8);
    expect(discarded.length).toBeGreaterThan(0);
    for (const v of discarded) {
      const body = v.text.replace(/^\u001e[^\u001e]*\u001e/, '');
      for (const line of [...logged, ...stored]) {
        expect(line.includes(v.text), `${v.id} in output`).toBe(false);
        if (body.length >= 8) expect(line.includes(body), `${v.id} body in output`).toBe(false);
      }
    }
  });
});

describe('T-53 static: one classifier, used by every consumer', () => {
  function sources(dir: string): string[] {
    return readdirSync(dir, { withFileTypes: true }).flatMap(e => {
      const p = join(dir, e.name);
      if (e.isDirectory()) return e.name === '__integration__' ? [] : sources(p);
      return /\.(ts|tsx)$/.test(e.name) && !/\.test\.tsx?$/.test(e.name) ? [p] : [];
    });
  }
  const files = sources(SRC);

  it('only e2ee/plaintext.ts knows the control framing or classifies', () => {
    const offenders = files
      .filter(f => relative(SRC, f) !== join('e2ee', 'plaintext.ts'))
      .filter(f => {
        const text = readFileSync(f, 'utf8');
        return /0x1e|\\u001e|\\x1e|accord-call|accord-keys|accord-ctl/i.test(text) || /function\s+classify[A-Z]\w*\s*\(/.test(text);
      })
      .map(f => relative(SRC, f));
    expect(offenders).toEqual([]);
  });

  it('every path that consumes decrypted plaintext imports the classifier', () => {
    for (const rel of ['attachments/decode.ts', 'attachments/envelope.ts', 'e2ee/sealed.ts', 'App.tsx', 'SearchOverlay.tsx']) {
      expect(readFileSync(join(SRC, rel), 'utf8'), rel).toMatch(/from ['"](?:\.\.?\/)+(?:e2ee\/)?plaintext['"]|from ['"]\.\/e2ee\/plaintext['"]|from ['"]\.\/plaintext['"]/);
    }
  });

  it('App.tsx: both key-distribution handlers classify before parsing, and a hidden message stops before notifications', () => {
    const app = readFileSync(join(SRC, 'App.tsx'), 'utf8');
    for (const event of ['sender_key_distribution', 'pending_sender_keys']) {
      const start = app.indexOf(`socket.on('${event}'`);
      const next = app.indexOf('socket.on(', start + 10);
      const handler = app.slice(start, next > start ? next : start + 2500);
      expect(handler, event).toMatch(/readKeyDistribution\(decrypted\)/);
      expect(handler, event).not.toMatch(/JSON\.parse\(decrypted\)/);
      expect(handler, event).not.toMatch(/console\.\w+\([^)]*err/);
    }
    const live = app.slice(app.indexOf("socket.on('channel_message'"));
    const hidden = live.indexOf("decoded.display === 'hidden') return");
    expect(hidden).toBeGreaterThan(0);
    expect(hidden).toBeLessThan(live.indexOf('notificationManager.addMessage'));
  });
});
