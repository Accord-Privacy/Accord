/**
 * @module voice/callKeyBridge
 * The E2EE bridge of SPEC-03 §6.10: the only way the voice code reaches
 * E2EE state (Double Ratchet sessions, membership, identities).
 *
 * `CallKeyManager` (`voice/callKeys.ts`) depends on this interface only, so
 * it runs against the real implementation (`voice/callKeyBridgeImpl.ts`,
 * over `E2EEManager`, the API client and the channel directory) and against
 * test fakes alike. SPEC-05 and SPEC-06 replace the implementation, never
 * the interface.
 *
 * Nothing that crosses this interface is logged or stored by the voice code
 * (REQ-13, REQ-27).
 */

/** A lowercase canonical UUID. */
export type Uuid = string;

export type SessionVersion = 'legacy' | 'v2';

/** The session that decrypted a message. `isk` is null on legacy sessions. */
export interface SessionIdentity {
  isk: Uint8Array | null;
  ik: Uint8Array;
}

export type DecryptResult =
  | {
    ok: true;
    plaintext: string;
    /** A stored skipped message key produced the plaintext (REQ-32: discard). */
    usedSkippedKey: boolean;
    sessionVersion: SessionVersion;
    peer: SessionIdentity;
  }
  | { ok: false; error: 'no_session' | 'decrypt_failed' | 'handshake_rejected' | 'identity_changed' | 'store_locked' };

export type EncryptResult =
  | { ok: true; envelope: string }
  | { ok: false; error: 'chain_limit' | 'await_peer' | 'bundle_unavailable' | 'identity_blocked' | 'store_locked' };

export type Ineligible =
  | 'not_in_view'
  | 'membership_unknown'
  | 'not_member'
  | 'channel_not_in_node'
  | 'node_unverified'
  | 'not_in_audience'
  | 'no_pin'
  | 'identity_changed';

export type Eligibility = { eligible: true } | { eligible: false; reason: Ineligible };

/** SPEC-06 §6.14 head claim, with its relay receipt. */
export type HeadClaim = { seq: number; hash: string; prev: string; rcpt: string };

export type MembershipCause = 'call_start' | 'timer' | 'event' | 'on_demand';

export interface IdentityLabel {
  /** The first 8 hex digits of the user id (REQ-11). */
  shortId: string;
  /** The first group of the SPEC-05 fingerprint, under the final rule. */
  fingerprintGroup?: string;
  /** SPEC-05 verified. Always false before SPEC-05. */
  verified: boolean;
}

export interface CallKeyBridge {
  /** The E2EE manager is initialized and unlocked (REQ-23). */
  isReady(): boolean;
  selfId(): Uuid;
  rule(): 'interim' | 'final';
  /** True once SPEC-05 is implemented in the client (§5.1). */
  pinnedSessionsOnly(): boolean;
  /** A usable session as §5.1 defines it. */
  hasUsableSession(peer: Uuid): boolean;
  /** Messages of any kind in the current sending chain toward `peer`, or null without a session. */
  sendingChainLength(peer: Uuid): number | null;
  encryptFor(peer: Uuid, plaintext: string, useCredit: boolean): Promise<EncryptResult>;
  /**
   * Call before any other await, in the WebSocket handler: the call fixes the
   * message's place in the peer's Double Ratchet order, and results resolve
   * in arrival order.
   */
  decryptFrom(peer: Uuid, envelope: string): Promise<DecryptResult>;
  /** REQ-9 (b) or REQ-8 (b). 'unknown' while a fetch that may list `peer` is pending. */
  membership(node: Uuid, channel: Uuid, peer: Uuid): 'member' | 'not_member' | 'unknown';
  eligibility(node: Uuid, channel: Uuid, peer: Uuid): Eligibility;
  refreshMembership(node: Uuid, cause: MembershipCause): Promise<void>;
  /** Final rule: the local head claim to put in `gh`. */
  governanceHead(node: Uuid): HeadClaim | null;
  /** SPEC-06 REQ-7. */
  offerHead(node: Uuid, from: Uuid, head: HeadClaim): void;
  identityLabel(peer: Uuid): IdentityLabel;
  onEligibilityChange(listener: (node: Uuid) => void): () => void;
  onSessionUsable(listener: (peer: Uuid) => void): () => void;

  // Additions to §6.10, needed by checks that SPEC-03 states but whose inputs
  // the listed methods do not expose. Before SPEC-05 and SPEC-06 they return
  // null and false.

  /** SPEC-05: the peer's pinned ISK (REQ-12 `pin(S)`), or null without a pin. */
  pinnedIsk(peer: Uuid): Uint8Array | null;
  /** SPEC-06: the ISK that roster(peer) names (REQ-8, REQ-12), or null. */
  rosterIsk(node: Uuid, peer: Uuid): Uint8Array | null;
  /** SPEC-06 REQ-17's `withheld` flag for the node (REQ-8: R may only shrink). */
  audienceWithheld(node: Uuid): boolean;
}

/** The clock of the voice key code (§6.5); tests inject a manual one. */
export interface CallClock {
  /** Milliseconds. */
  now(): number;
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

export const systemCallClock: CallClock = {
  now: () => Date.now(),
  setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms),
  clearTimeout: h => globalThis.clearTimeout(h as Parameters<typeof globalThis.clearTimeout>[0]),
};

/** `CALL_CHAIN_LIMIT` (REQ-21; OD-58): messages in the current sending chain. */
export const CALL_CHAIN_LIMIT = 32;

/** The REQ-11 short id: the first 8 hex digits of a user id. */
export function shortIdOf(userId: string): string {
  return userId.toLowerCase().replace(/-/g, '').slice(0, 8);
}
