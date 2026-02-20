import { describe, it, expect } from 'vitest';
import {
  generateSenderKey,
  senderKeyFingerprint,
  senderKeyToPublic,
  createSenderKeyState,
  senderKeyEncrypt,
  senderKeyDecrypt,
  buildDistributionMessage,
  parseDistributionMessage,
  isSenderKeyEnvelope,
  parseSenderKeyEnvelope,
  SenderKeyStore,
  encryptChannelMessage,
  decryptChannelMessage,
  type SenderKeyEnvelope,
} from './senderKeys';

describe('Sender Keys', () => {
  describe('generateSenderKey', () => {
    it('generates a valid sender key', () => {
      const sk = generateSenderKey();
      expect(sk.chainKey).toHaveLength(32);
      expect(sk.signingKey).toHaveLength(32);
      expect(sk.signingPubKey).toHaveLength(32);
      expect(sk.iteration).toBe(0);
    });

    it('generates unique keys each time', () => {
      const sk1 = generateSenderKey();
      const sk2 = generateSenderKey();
      expect(sk1.chainKey).not.toEqual(sk2.chainKey);
      expect(sk1.signingKey).not.toEqual(sk2.signingKey);
    });
  });

  describe('senderKeyFingerprint', () => {
    it('returns a 16-char hex string', () => {
      const sk = generateSenderKey();
      const fp = senderKeyFingerprint(sk.signingPubKey);
      expect(fp).toMatch(/^[0-9a-f]{16}$/);
    });

    it('is deterministic', () => {
      const sk = generateSenderKey();
      expect(senderKeyFingerprint(sk.signingPubKey))
        .toBe(senderKeyFingerprint(sk.signingPubKey));
    });
  });

  describe('encrypt / decrypt', () => {
    it('round-trips a message', () => {
      const sk = generateSenderKey();
      const plaintext = new TextEncoder().encode('Hello, Sender Keys!');
      const { envelope, updatedKey } = senderKeyEncrypt(sk, plaintext);

      expect(envelope.v).toBe(1);
      expect(envelope.i).toBe(0);
      expect(updatedKey.iteration).toBe(1);

      const pub = senderKeyToPublic(sk);
      const state = createSenderKeyState(pub);
      const { plaintext: decrypted, updatedState } = senderKeyDecrypt(state, envelope);

      expect(new TextDecoder().decode(decrypted)).toBe('Hello, Sender Keys!');
      expect(updatedState.currentIteration).toBe(1);
    });

    it('handles multiple messages in sequence', () => {
      let sk = generateSenderKey();
      const pub = senderKeyToPublic(sk);
      let state = createSenderKeyState(pub);

      for (let i = 0; i < 10; i++) {
        const msg = `Message ${i}`;
        const { envelope, updatedKey } = senderKeyEncrypt(sk, new TextEncoder().encode(msg));
        sk = updatedKey;

        const { plaintext, updatedState } = senderKeyDecrypt(state, envelope);
        state = updatedState;
        expect(new TextDecoder().decode(plaintext)).toBe(msg);
      }

      expect(sk.iteration).toBe(10);
      expect(state.currentIteration).toBe(10);
    });

    it('handles out-of-order messages', () => {
      let sk = generateSenderKey();
      const pub = senderKeyToPublic(sk);
      let state = createSenderKeyState(pub);

      // Encrypt 3 messages
      const envelopes: SenderKeyEnvelope[] = [];
      for (let i = 0; i < 3; i++) {
        const { envelope, updatedKey } = senderKeyEncrypt(sk, new TextEncoder().encode(`msg${i}`));
        envelopes.push(envelope);
        sk = updatedKey;
      }

      // Decrypt in reverse order: msg2, msg0, msg1
      const { plaintext: p2, updatedState: s1 } = senderKeyDecrypt(state, envelopes[2]);
      expect(new TextDecoder().decode(p2)).toBe('msg2');

      const { plaintext: p0, updatedState: s2 } = senderKeyDecrypt(s1, envelopes[0]);
      expect(new TextDecoder().decode(p0)).toBe('msg0');

      const { plaintext: p1 } = senderKeyDecrypt(s2, envelopes[1]);
      expect(new TextDecoder().decode(p1)).toBe('msg1');
    });

    it('rejects tampered ciphertext (signature fails)', () => {
      const sk = generateSenderKey();
      const { envelope } = senderKeyEncrypt(sk, new TextEncoder().encode('secret'));

      // Tamper with ciphertext
      const tampered = { ...envelope, ct: btoa('tampered') };

      const pub = senderKeyToPublic(sk);
      const state = createSenderKeyState(pub);
      expect(() => senderKeyDecrypt(state, tampered)).toThrow('signature verification failed');
    });

    it('rejects too many skipped messages', () => {
      let sk = generateSenderKey();
      const pub = senderKeyToPublic(sk);
      const state = createSenderKeyState(pub);

      // Skip way ahead
      for (let i = 0; i < 2001; i++) {
        const { updatedKey } = senderKeyEncrypt(sk, new TextEncoder().encode('x'));
        sk = updatedKey;
      }

      const { envelope } = senderKeyEncrypt(sk, new TextEncoder().encode('late'));
      expect(() => senderKeyDecrypt(state, envelope)).toThrow('Too many skipped');
    });
  });

  describe('distribution messages', () => {
    it('round-trips a distribution message', () => {
      const sk = generateSenderKey();
      const dist = buildDistributionMessage('channel-123', sk);

      expect(dist.type).toBe('skdm');
      expect(dist.ch).toBe('channel-123');
      expect(dist.iter).toBe(0);
      expect(dist.rep).toBeNull();

      const { pub, state } = parseDistributionMessage(dist);
      expect(pub.senderKeyId).toBe(senderKeyFingerprint(sk.signingPubKey));
      expect(state.currentIteration).toBe(0);

      // Can decrypt messages with parsed key
      const plaintext = new TextEncoder().encode('test');
      const { envelope } = senderKeyEncrypt(sk, plaintext);
      const { plaintext: decrypted } = senderKeyDecrypt(state, envelope);
      expect(new TextDecoder().decode(decrypted)).toBe('test');
    });

    it('supports rotation (replacesKeyId)', () => {
      const sk = generateSenderKey();
      const dist = buildDistributionMessage('ch-1', sk, 'old-key-id');
      expect(dist.rep).toBe('old-key-id');
    });
  });

  describe('envelope detection', () => {
    it('detects sender key envelopes', () => {
      const sk = generateSenderKey();
      const { envelope } = senderKeyEncrypt(sk, new TextEncoder().encode('test'));
      const json = JSON.stringify(envelope);
      expect(isSenderKeyEnvelope(json)).toBe(true);
    });

    it('rejects non-envelope strings', () => {
      expect(isSenderKeyEnvelope('not json')).toBe(false);
      expect(isSenderKeyEnvelope('{"foo":"bar"}')).toBe(false);
      expect(isSenderKeyEnvelope(btoa('encrypted'))).toBe(false);
    });

    it('parses envelope from JSON', () => {
      const sk = generateSenderKey();
      const { envelope } = senderKeyEncrypt(sk, new TextEncoder().encode('test'));
      const parsed = parseSenderKeyEnvelope(JSON.stringify(envelope));
      expect(parsed.v).toBe(1);
      expect(parsed.sk).toBe(envelope.sk);
    });
  });

  describe('SenderKeyStore', () => {
    it('creates and retrieves keys', () => {
      const store = new SenderKeyStore();
      const sk = store.getOrCreateMyKey('ch-1');
      expect(sk.chainKey).toHaveLength(32);
      // Returns same key on second call
      expect(store.getOrCreateMyKey('ch-1')).toBe(sk);
    });

    it('manages peer keys', () => {
      const store = new SenderKeyStore();
      const sk = generateSenderKey();
      const pub = senderKeyToPublic(sk);
      const state = createSenderKeyState(pub);

      store.setPeerKey('ch-1', 'user-a', state);
      expect(store.hasPeerKey('ch-1', 'user-a')).toBe(true);
      expect(store.hasPeerKey('ch-1', 'user-b')).toBe(false);
      expect(store.getPeerKey('ch-1', 'user-a')).toBe(state);
    });

    it('rotates keys', () => {
      const store = new SenderKeyStore();
      const old = store.getOrCreateMyKey('ch-1');
      const rotated = store.rotateMyKey('ch-1');
      expect(rotated.chainKey).not.toEqual(old.chainKey);
      expect(store.getMyKey('ch-1')).toBe(rotated);
    });

    it('removes peer keys', () => {
      const store = new SenderKeyStore();
      const sk = generateSenderKey();
      store.setPeerKey('ch-1', 'user-a', createSenderKeyState(senderKeyToPublic(sk)));
      store.removePeerKey('ch-1', 'user-a');
      expect(store.hasPeerKey('ch-1', 'user-a')).toBe(false);
    });

    it('serializes and deserializes', () => {
      const store = new SenderKeyStore();
      store.getOrCreateMyKey('ch-1');
      const sk = generateSenderKey();
      store.setPeerKey('ch-1', 'user-a', createSenderKeyState(senderKeyToPublic(sk)));

      const exported = store.exportStore();
      const store2 = new SenderKeyStore();
      store2.importStore(exported);

      expect(store2.hasChannelKeys('ch-1')).toBe(true);
      expect(store2.hasPeerKey('ch-1', 'user-a')).toBe(true);
    });
  });

  describe('high-level encrypt/decrypt', () => {
    it('encrypts and decrypts channel messages via store', () => {
      const aliceStore = new SenderKeyStore();
      const bobStore = new SenderKeyStore();

      // Alice sets up her key for channel
      const aliceSk = aliceStore.getOrCreateMyKey('ch-1');

      // Bob gets Alice's public key (simulating distribution)
      const alicePub = senderKeyToPublic(aliceSk);
      bobStore.setPeerKey('ch-1', 'alice', createSenderKeyState(alicePub));

      // Alice encrypts
      const { encryptFn } = encryptChannelMessage(aliceStore, 'ch-1');
      const ciphertext = encryptFn('Hello from Alice!');

      // Bob decrypts
      const plaintext = decryptChannelMessage(bobStore, 'ch-1', 'alice', ciphertext);
      expect(plaintext).toBe('Hello from Alice!');
    });

    it('falls through with error if peer key missing', () => {
      const store = new SenderKeyStore();
      const sk = generateSenderKey();
      const { envelope } = senderKeyEncrypt(sk, new TextEncoder().encode('test'));

      expect(() => decryptChannelMessage(store, 'ch-1', 'unknown', JSON.stringify(envelope)))
        .toThrow('No sender key');
    });
  });
});
