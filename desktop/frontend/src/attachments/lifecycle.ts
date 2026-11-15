/**
 * @module attachments/lifecycle
 * SPEC-02 REQ-24: when a message is deleted (`message_delete`), purged
 * (`messages_purged`) or expires locally (expiry sweep, read-gate countdown),
 * the client drops its attachment-store entry, which revokes its `blob:` URLs,
 * aborts its downloads and drops its decrypted bytes (`attachments/view.ts`
 * listens), and removes its record from the encrypted plaintext cache.
 */

import type { AttachmentStore } from './store';

export interface ForgetDeps {
  readonly store: AttachmentStore;
  /** The relay origin that keys the store. */
  readonly origin: string;
  /** The plaintext cache (relay message id → §6.2.4 record or legacy string). */
  readonly cache: Map<string, unknown>;
  /** Other per-message bookkeeping to clear, if any. */
  readonly extra?: { delete(id: string): unknown };
  /** Re-persist the encrypted cache; called once when anything was removed. */
  persist(): void;
}

/** Forget every trace of the given messages (REQ-24). */
export function forgetMessages(ids: Iterable<string>, deps: ForgetDeps): void {
  let changed = false;
  for (const id of ids) {
    deps.store.removeMessage(deps.origin, id);
    deps.extra?.delete(id);
    if (deps.cache.delete(id)) changed = true;
  }
  if (changed) deps.persist();
}
