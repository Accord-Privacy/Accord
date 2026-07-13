import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  initStorageMasterKey,
  clearStorageMasterKey,
  hasStorageMasterKey,
  deriveAtRestKey,
} from './storageKey';
import { saveNmkStore, loadNmkStore, NodeMetadataKey } from './metadata';
import { saveOwnMessages, loadOwnMessages } from './persistence';

// Simulate the Tauri keyring by mocking window.__TAURI__.core.invoke to return
// a fixed base64 SMK, so the v2 (SMK/HKDF) at-rest path can be exercised in
// jsdom — where the real OS keyring is unavailable.
const FIXED_SMK_B64 = btoa(String.fromCharCode(...new Uint8Array(32).fill(7)));

function installFakeKeyring() {
  (window as any).__TAURI__ = {
    core: {
      invoke: vi.fn(async (cmd: string) => {
        if (cmd === 'get_or_create_smk') return FIXED_SMK_B64;
        return null;
      }),
    },
  };
}

describe('storageKey — two-factor at-rest key', () => {
  beforeEach(() => {
    localStorage.clear();
    clearStorageMasterKey();
    delete (window as any).__TAURI__;
  });
  afterEach(() => {
    clearStorageMasterKey();
    delete (window as any).__TAURI__;
  });

  it('deriveAtRestKey is deterministic and password/domain-dependent', () => {
    const a = deriveAtRestKey('pw', 'domain-a');
    const b = deriveAtRestKey('pw', 'domain-a');
    const c = deriveAtRestKey('pw', 'domain-b');
    const d = deriveAtRestKey('pw2', 'domain-a');
    expect(Array.from(a)).toEqual(Array.from(b));
    expect(Array.from(a)).not.toEqual(Array.from(c));
    expect(Array.from(a)).not.toEqual(Array.from(d));
    expect(a.length).toBe(32);
  });

  it('SMK changes the derived key (salt actually mixes in)', async () => {
    const legacy = deriveAtRestKey('pw', 'd');
    installFakeKeyring();
    await initStorageMasterKey('user1');
    expect(hasStorageMasterKey()).toBe(true);
    const withSmk = deriveAtRestKey('pw', 'd');
    expect(Array.from(withSmk)).not.toEqual(Array.from(legacy));
  });

  it('web build (no keyring) leaves SMK unavailable', async () => {
    await initStorageMasterKey('user1');
    expect(hasStorageMasterKey()).toBe(false);
  });

  it('v2 store roundtrips with the SMK present', async () => {
    installFakeKeyring();
    await initStorageMasterKey('user1');
    const msgs = new Map([['m1', 'hello'], ['m2', 'world']]);
    saveOwnMessages('user1', msgs, 'pw');
    // The stored blob must be v2-tagged (first byte 0x02).
    const raw = localStorage.getItem('accord_e2ee_ownmsgs_user1')!;
    expect(atob(raw).charCodeAt(0)).toBe(0x02);
    const loaded = loadOwnMessages('user1', 'pw');
    expect(loaded.get('m1')).toBe('hello');
    expect(loaded.get('m2')).toBe('world');
  });

  it('a v2 blob cannot be read without the SMK (device-bound)', async () => {
    installFakeKeyring();
    await initStorageMasterKey('user1');
    saveOwnMessages('user1', new Map([['m', 'secret']]), 'pw');
    // Drop the SMK as if on a different device / after keyring loss.
    clearStorageMasterKey();
    const loaded = loadOwnMessages('user1', 'pw');
    expect(loaded.size).toBe(0); // undecryptable → empty, not the plaintext
  });

  it('legacy (pre-SMK) blobs still read, then migrate to v2 on next save', async () => {
    // Write legacy (no SMK).
    saveOwnMessages('user1', new Map([['m', 'legacy-data']]), 'pw');
    const legacyRaw = localStorage.getItem('accord_e2ee_ownmsgs_user1')!;
    expect(atob(legacyRaw).charCodeAt(0)).not.toBe(0x02); // untagged

    // Now the SMK becomes available; legacy data must still load.
    installFakeKeyring();
    await initStorageMasterKey('user1');
    const loaded = loadOwnMessages('user1', 'pw');
    expect(loaded.get('m')).toBe('legacy-data');

    // Re-save migrates to v2.
    saveOwnMessages('user1', loaded, 'pw');
    const migratedRaw = localStorage.getItem('accord_e2ee_ownmsgs_user1')!;
    expect(atob(migratedRaw).charCodeAt(0)).toBe(0x02);
    expect(loadOwnMessages('user1', 'pw').get('m')).toBe('legacy-data');
  });

  it('NMK store roundtrips under v2 and migrates from legacy', async () => {
    const nmk = NodeMetadataKey.fromBytes(new Uint8Array(32).fill(9));
    // legacy write
    saveNmkStore('user1', new Map([['node1', nmk]]), 'pw');
    installFakeKeyring();
    await initStorageMasterKey('user1');
    const loaded = loadNmkStore('user1', 'pw');
    expect(loaded).not.toBeNull();
    expect(Array.from(loaded!.get('node1')!.asBytes())).toEqual(Array.from(nmk.asBytes()));
    // migrate
    saveNmkStore('user1', loaded!, 'pw');
    expect(atob(localStorage.getItem('accord_e2ee_nmk_user1')!).charCodeAt(0)).toBe(0x02);
  });
});
