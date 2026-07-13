/**
 * @module wipe
 * Irreversible local-account destruction, shared by the panic button and the
 * duress password.
 *
 * The goal is that after a wipe nothing on this device can recover the account:
 * no key material, no encrypted stores, no plaintext caches. Order matters —
 * we destroy the OS-keyring Storage Master Key FIRST, which alone renders every
 * at-rest store cryptographically undecryptable, before erasing the blobs
 * themselves. If the process is interrupted between those steps, what remains
 * is still unreadable.
 */

import { destroyStorageMasterKey } from './e2ee/storageKey';
import { deleteIdentity, listIdentities } from './identityStorage';

function isTauri(): boolean {
  return typeof window !== 'undefined' && !!(window as any).__TAURI__;
}

async function invoke(cmd: string, args?: Record<string, unknown>): Promise<void> {
  if (!isTauri()) return;
  try {
    await (window as any).__TAURI__.core.invoke(cmd, args);
  } catch (e) {
    console.warn(`[wipe] ${cmd} failed:`, e);
  }
}

/** Remove every Accord key from localStorage. */
function clearLocalStorage(): void {
  const toRemove: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    if (k && (k.startsWith('accord_') || k.startsWith('accord-'))) toRemove.push(k);
  }
  for (const k of toRemove) localStorage.removeItem(k);
}

/**
 * Irreversibly destroy all local data for the account(s) on this device.
 *
 * @param userId  the logged-in user id (for the keyring SMK); optional.
 * @param opts.allIdentities  when true (panic wipe), also delete every stored
 *   identity from the keyring, not just the active one. The duress path passes
 *   false so it only nukes the real account it just unlocked.
 */
export async function wipeLocalData(
  userId: string | null,
  opts: { allIdentities?: boolean; activeKeyHash?: string | null } = {},
): Promise<void> {
  // 1. Destroy the keyring storage master key first — this alone makes every
  //    at-rest store undecryptable, so an interrupted wipe still fails closed.
  if (userId) {
    await destroyStorageMasterKey(userId);
  }

  // 2. Delete identity keypair(s) from the OS keyring.
  try {
    if (opts.allIdentities) {
      const hashes = await listIdentities().catch(() => [] as string[]);
      for (const h of hashes) await deleteIdentity(h).catch(() => {});
    } else if (opts.activeKeyHash) {
      await deleteIdentity(opts.activeKeyHash).catch(() => {});
    }
  } catch (e) {
    console.warn('[wipe] identity deletion failed:', e);
  }

  // 3. Delete the auth token from the keyring.
  await invoke('delete_token');

  // 4. Erase all Accord localStorage (encrypted blobs, prefs, session slots).
  clearLocalStorage();
}
