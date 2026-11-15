/**
 * @module attachments/sealer
 * The application's `ConversationSealer` (SPEC-02 REQ-7, REQ-12): the only
 * encryption a message or edit can go out under. DMs use the Double Ratchet,
 * node channels Sender Keys; neither depends on the legacy `keyPair` or
 * `encryptionEnabled` (D26). Text alone may fall back to the explicit legacy
 * channel-key opt-in; an envelope with attachments never does.
 */

import type { PreKeyBundle } from '../e2ee/keys';
import type { SenderKeyStore } from '../e2ee/senderKeys';
import { sealForChannel, sealForDm, sealLegacyText, type DoubleRatchetSealer, type SealedPayload } from '../e2ee/sealed';
import type { Conversation, ConversationSealer } from './send';

/** The part of `E2EEManager` the sealer needs. */
export interface SealerE2EE extends DoubleRatchetSealer {
  readonly isInitialized: boolean;
  hasSession(peerId: string): boolean;
}

export interface SealerDeps {
  /** The initialized E2EE manager, or null. */
  e2ee(): SealerE2EE | null;
  senderKeys(): SenderKeyStore;
  /** Create and distribute an own sender key for the channel; false when impossible. */
  bootstrapSenderKey(channelId: string): boolean;
  /** Fetch (and cache) a peer's prekey bundle; undefined when unavailable. */
  fetchBundle(peerId: string): Promise<PreKeyBundle | undefined>;
  /** Persist the sender key store after its chain advanced. */
  persistSenderKeys(): void;
  /**
   * The legacy channel-key opt-in (`accord_legacy_channel_crypto`), or null
   * when it is off or unusable. Text only.
   */
  legacyText(): ((channelId: string, text: string) => Promise<string>) | null;
}

export function createConversationSealer(deps: SealerDeps): ConversationSealer {
  return {
    async ready(conv: Conversation): Promise<boolean> {
      if (conv.kind === 'dm') {
        const mgr = deps.e2ee();
        if (!mgr?.isInitialized) return false;
        if (mgr.hasSession(conv.peerId)) return true;
        return !!(await deps.fetchBundle(conv.peerId));
      }
      const store = deps.senderKeys();
      if (store.hasChannelKeys(conv.channelId)) return true;
      return deps.bootstrapSenderKey(conv.channelId) && store.hasChannelKeys(conv.channelId);
    },

    async seal(conv: Conversation, plaintext: string, kind: 'text' | 'attachments'): Promise<SealedPayload> {
      const mgr = deps.e2ee();
      if (conv.kind === 'dm') {
        if (!mgr?.isInitialized) throw new Error('E2EE unavailable');
        const bundle = mgr.hasSession(conv.peerId) ? undefined : await deps.fetchBundle(conv.peerId);
        return sealForDm(mgr, conv.peerId, plaintext, bundle);
      }
      const store = deps.senderKeys();
      if (store.hasChannelKeys(conv.channelId)) {
        try {
          const sealed = sealForChannel(store, conv.channelId, plaintext);
          deps.persistSenderKeys();
          return sealed;
        } catch {
          // fall through to the text-only opt-in, if any
        }
      }
      const legacy = kind === 'text' ? deps.legacyText() : null;
      if (legacy) return sealLegacyText(text => legacy(conv.channelId, text), plaintext);
      throw new Error('E2EE unavailable');
    },
  };
}
