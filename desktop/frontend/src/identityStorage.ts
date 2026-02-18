// Identity storage abstraction: uses Tauri keyring when available, falls back to localStorage.
//
// When running inside Tauri, identity keys are persisted in the OS credential store
// (macOS Keychain, Windows Credential Manager, Linux Secret Service) so they survive
// app-data clears. In a plain browser the existing localStorage path is used.

// ---------------------------------------------------------------------------
// Tauri detection & invoke helper
// ---------------------------------------------------------------------------

declare global {
  interface Window {
    __TAURI__?: {
      core?: {
        invoke: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
      };
    };
  }
}

interface IdentityData {
  encrypted_private_key: string;
  public_key: string;
}

function isTauri(): boolean {
  return typeof window !== 'undefined' && !!window.__TAURI__?.core?.invoke;
}

async function tauriInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return window.__TAURI__!.core!.invoke<T>(cmd, args);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Save an identity (encrypted private key + public key) keyed by public-key hash.
 */
export async function saveIdentity(
  keyHash: string,
  encryptedPrivateKey: string,
  publicKey: string,
): Promise<void> {
  if (isTauri()) {
    await tauriInvoke('save_identity', {
      keyHash,
      encryptedPrivateKey,
      publicKey,
    });
    return;
  }
  // localStorage fallback
  const prefix = `accord_id_${keyHash.slice(0, 16)}`;
  localStorage.setItem(`${prefix}_priv`, encryptedPrivateKey);
  localStorage.setItem(`${prefix}_pub`, publicKey);
  // Maintain an index
  const idx = getLocalIdentityIndex();
  if (!idx.includes(keyHash)) {
    idx.push(keyHash);
    localStorage.setItem('accord_identity_index', JSON.stringify(idx));
  }
}

/**
 * Load an identity from storage. Returns null if not found.
 */
export async function loadIdentity(keyHash: string): Promise<IdentityData | null> {
  if (isTauri()) {
    const data = await tauriInvoke<IdentityData | null>('load_identity', { keyHash });
    return data;
  }
  const prefix = `accord_id_${keyHash.slice(0, 16)}`;
  const priv = localStorage.getItem(`${prefix}_priv`);
  const pub_ = localStorage.getItem(`${prefix}_pub`);
  if (!priv || !pub_) return null;
  return { encrypted_private_key: priv, public_key: pub_ };
}

/**
 * Delete an identity from storage.
 */
export async function deleteIdentity(keyHash: string): Promise<void> {
  if (isTauri()) {
    await tauriInvoke('delete_identity', { keyHash });
    return;
  }
  const prefix = `accord_id_${keyHash.slice(0, 16)}`;
  localStorage.removeItem(`${prefix}_priv`);
  localStorage.removeItem(`${prefix}_pub`);
  const idx = getLocalIdentityIndex().filter((h) => h !== keyHash);
  localStorage.setItem('accord_identity_index', JSON.stringify(idx));
}

/**
 * List all stored identity key hashes.
 */
export async function listIdentities(): Promise<string[]> {
  if (isTauri()) {
    return tauriInvoke<string[]>('list_identities');
  }
  return getLocalIdentityIndex();
}

// ---------------------------------------------------------------------------
// Migration: localStorage → keyring (runs once on first Tauri launch)
// ---------------------------------------------------------------------------

const MIGRATION_FLAG = 'accord_keyring_migrated';

/**
 * Migrate identities from localStorage to the Tauri keyring.
 * Call this early in app startup when running in Tauri.
 * Safe to call multiple times — it's a no-op after the first migration.
 */
export async function migrateToKeyring(): Promise<void> {
  if (!isTauri()) return;
  if (localStorage.getItem(MIGRATION_FLAG)) return;

  // Collect identity data from localStorage (both legacy and namespaced keys)
  const migrated: string[] = [];

  // Scan localStorage for accord_private_key* entries
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (!key) continue;

    // Match namespaced keys: accord_private_key_<hash16>
    const nsMatch = key.match(/^accord_private_key_([a-f0-9]{16})$/);
    if (nsMatch) {
      const hashPrefix = nsMatch[1];
      const priv = localStorage.getItem(key);
      const pub_ = localStorage.getItem(`accord_public_key_${hashPrefix}`);
      if (priv && pub_) {
        // We only have the prefix; use it as the key hash for migration
        const fullHash = hashPrefix;
        try {
          await tauriInvoke('save_identity', {
            keyHash: fullHash,
            encryptedPrivateKey: priv,
            publicKey: pub_,
          });
          migrated.push(fullHash);
        } catch (e) {
          console.warn('Failed to migrate identity to keyring:', e);
        }
      }
    }

    // Also migrate legacy un-namespaced key
    if (key === 'accord_private_key') {
      const priv = localStorage.getItem('accord_private_key');
      const pub_ = localStorage.getItem('accord_public_key');
      if (priv && pub_) {
        try {
          await tauriInvoke('save_identity', {
            keyHash: '_legacy',
            encryptedPrivateKey: priv,
            publicKey: pub_,
          });
          migrated.push('_legacy');
        } catch (e) {
          console.warn('Failed to migrate legacy identity to keyring:', e);
        }
      }
    }
  }

  if (migrated.length > 0) {
    console.log(`Migrated ${migrated.length} identity/identities to OS keyring`);
  }
  localStorage.setItem(MIGRATION_FLAG, '1');
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getLocalIdentityIndex(): string[] {
  try {
    const raw = localStorage.getItem('accord_identity_index');
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}
