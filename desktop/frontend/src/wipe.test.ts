import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { wipeLocalData } from './wipe';

describe('wipeLocalData', () => {
  const invoke = vi.fn(async (cmd: string, _args?: Record<string, unknown>) => {
    if (cmd === 'list_identities') return ['hashA', 'hashB'];
    return null;
  });

  beforeEach(() => {
    localStorage.clear();
    invoke.mockClear();
    (window as any).__TAURI__ = { core: { invoke } };
  });
  afterEach(() => {
    delete (window as any).__TAURI__;
  });

  it('removes every accord_* / accord-* key from localStorage, leaving others', async () => {
    localStorage.setItem('accord_user_id', 'u1');
    localStorage.setItem('accord_e2ee_identity_u1', 'blob');
    localStorage.setItem('accord_e2ee_ownmsgs_u1', 'blob');
    localStorage.setItem('accord-nodes', 'x');
    localStorage.setItem('accord_private_key', 'k');
    localStorage.setItem('unrelated_key', 'keep-me');

    await wipeLocalData('u1', { allIdentities: true });

    expect(localStorage.getItem('accord_user_id')).toBeNull();
    expect(localStorage.getItem('accord_e2ee_identity_u1')).toBeNull();
    expect(localStorage.getItem('accord_e2ee_ownmsgs_u1')).toBeNull();
    expect(localStorage.getItem('accord-nodes')).toBeNull();
    expect(localStorage.getItem('accord_private_key')).toBeNull();
    // Non-Accord keys are untouched.
    expect(localStorage.getItem('unrelated_key')).toBe('keep-me');
  });

  it('destroys the keyring SMK, token, and (panic) all identities', async () => {
    await wipeLocalData('u1', { allIdentities: true });
    const calls = invoke.mock.calls.map((c) => c[0]);
    expect(calls).toContain('delete_smk');        // storage master key
    expect(calls).toContain('delete_token');      // auth token
    expect(calls).toContain('list_identities');   // enumerate to delete all
    expect(calls).toContain('delete_identity');   // each identity
    // Both listed identities deleted.
    const idArgs = invoke.mock.calls
      .filter((c) => c[0] === 'delete_identity')
      .map((c) => (c[1] as any).keyHash);
    expect(idArgs).toEqual(expect.arrayContaining(['hashA', 'hashB']));
  });

  it('duress mode deletes only the active identity, not all', async () => {
    await wipeLocalData('u1', { allIdentities: false, activeKeyHash: 'realHash' });
    const calls = invoke.mock.calls.map((c) => c[0]);
    expect(calls).toContain('delete_smk');
    expect(calls).not.toContain('list_identities'); // does not enumerate/erase others
    const idArgs = invoke.mock.calls
      .filter((c) => c[0] === 'delete_identity')
      .map((c) => (c[1] as any).keyHash);
    expect(idArgs).toEqual(['realHash']);
  });

  it('destroys the SMK before erasing blobs (fail-closed ordering)', async () => {
    localStorage.setItem('accord_e2ee_identity_u1', 'blob');
    const order: string[] = [];
    invoke.mockImplementation(async (cmd: string) => {
      order.push(`invoke:${cmd}`);
      if (cmd === 'list_identities') return [];
      return null;
    });
    const origRemove = localStorage.removeItem.bind(localStorage);
    vi.spyOn(Storage.prototype, 'removeItem').mockImplementation((k: string) => {
      order.push(`removeItem:${k}`);
      origRemove(k);
    });
    await wipeLocalData('u1', { allIdentities: true });
    const smkIdx = order.findIndex((o) => o === 'invoke:delete_smk');
    const firstRemoveIdx = order.findIndex((o) => o.startsWith('removeItem:'));
    expect(smkIdx).toBeGreaterThanOrEqual(0);
    expect(firstRemoveIdx).toBeGreaterThan(smkIdx);
    vi.restoreAllMocks();
  });
});
