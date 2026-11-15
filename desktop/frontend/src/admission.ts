/**
 * Desktop side of relay admission (SPEC-01 REQ-43).
 *
 * - The relay advertises `admission/1` in the `features` of its `hello` frame
 *   and of `GET /health` (SPEC-01 §6.8). Clients test membership only, and a
 *   missing token means a legacy relay.
 * - Invite creation sends `expires_in_seconds` to relays with `admission/1`,
 *   and otherwise integer `expires_in_hours` (30 minutes round up to 1 hour).
 * - Every invite redemption sends a node-scoped device fingerprint (§6.9),
 *   learning the node id from the invite preview first.
 * - `node_joined`, a join success and `already_member` are hints for the user
 *   interface only. They may reload the node list and never by themselves send
 *   a sender key or a node metadata key.
 * - Each refusal `reason` maps to the messages of SPEC-01 §8.
 *
 * This module imports nothing from `./api` at run time, so it keeps working
 * where tests replace the API module with a mock.
 */
import { errorReason, errorRetryAfter, errorStatus, errorText } from './apiError';
import { nodeDeviceFingerprint } from './nodeFingerprint';

/** The capability token of relay admission (SPEC-01 REQ-42). */
export const ADMISSION_FEATURE = 'admission/1';

/** Does the relay's `features` array list `token`? Membership only. */
export function hasRelayFeature(
  features: readonly string[] | null | undefined,
  token: string,
): boolean {
  return Array.isArray(features) && features.includes(token);
}

// ── Invite creation ──────────────────────────────────────────────────────

/**
 * Seconds for a lifetime given in hours, as the relay converts them: the
 * smallest integer not below hours × 3600 after rounding that product to 3
 * decimal places (SPEC-01 REQ-37).
 */
export function hoursToSeconds(hours: number): number {
  return Math.ceil(Math.round(hours * 3600 * 1000) / 1000);
}

/**
 * The body of `POST /nodes/:id/invites` (SPEC-01 §6.2). `expiresHours`
 * undefined means "never"; `maxUses` undefined means unlimited.
 */
export function inviteCreateBody(
  maxUses: number | undefined,
  expiresHours: number | undefined,
  features: readonly string[] | null | undefined,
): Record<string, number> {
  const body: Record<string, number> = {};
  if (maxUses !== undefined && Number.isFinite(maxUses)) body.max_uses = maxUses;
  if (expiresHours !== undefined && Number.isFinite(expiresHours)) {
    if (hasRelayFeature(features, ADMISSION_FEATURE)) {
      body.expires_in_seconds = hoursToSeconds(expiresHours);
    } else {
      // A legacy relay accepts only whole hours, under this field name.
      body.expires_in_hours = Math.max(1, Math.ceil(expiresHours));
    }
  }
  return body;
}

/** The message for a failed invite creation (SPEC-01 §8). */
export function inviteCreateErrorMessage(err: unknown): string {
  switch (errorReason(err)) {
    case 'invalid_request':
      return `Couldn't create invite: ${errorText(err, 'invalid request')}`;
    case 'unavailable':
      return "Couldn't create invite. Try again.";
    case 'rate_limited':
      return admissionMessage('rate_limited', { retryAfter: errorRetryAfter(err) });
    default:
      return errorText(err, "Couldn't create invite");
  }
}

// ── Messages ─────────────────────────────────────────────────────────────

/** The user-facing messages of SPEC-01 §8, by `reason`. */
const ADMISSION_MESSAGES: Record<string, string> = {
  invite_invalid: 'This invite link is invalid or was revoked',
  invite_expired: 'This invite has expired',
  invite_exhausted: 'This invite has reached its use limit',
  banned: "You can't join this node",
  device_banned: "You can't join this node",
  fingerprint_required: 'This node needs a device check. Update Accord and try again.',
  device_limit: 'Too many accounts from this device have joined this node',
  build_not_allowed: 'This node only accepts specific app builds',
  invite_required: 'This node requires an invite link',
  join_requests_full: "This node isn't accepting requests right now",
  pending_approval: 'Request sent. A moderator must approve it.',
  join_request_denied: 'Your request to join was not approved',
  owner_cannot_leave: 'Transfer or delete the node instead',
  unavailable: 'The server is busy. Try again.',
};

/**
 * The message for an admission `reason`. Unknown or absent reasons (older
 * relays) fall back to the relay's own `error` text.
 */
export function admissionMessage(
  reason: string | undefined,
  opts: { retryAfter?: number; fallback?: string } = {},
): string {
  if (reason === 'rate_limited') {
    return opts.retryAfter !== undefined
      ? `Too many attempts. Try again in ${Math.max(1, Math.ceil(opts.retryAfter))} seconds.`
      : 'Too many attempts. Try again later.';
  }
  if (reason && ADMISSION_MESSAGES[reason]) return ADMISSION_MESSAGES[reason];
  return opts.fallback ?? 'Failed to join node';
}

/**
 * The message for a failed membership action (join, leave or kick), from an
 * API error or a WS failure frame: the §8 text for its `reason`, else the
 * relay's `error` text, else `fallback`.
 */
export function admissionErrorMessage(err: unknown, fallback: string): string {
  return admissionMessage(errorReason(err), {
    retryAfter: errorRetryAfter(err),
    fallback: errorText(err, fallback),
  });
}

/** The message for a failed join, from an API error or a `join_failed` frame. */
export function joinErrorMessage(err: unknown, fallback = 'Failed to join node'): string {
  return admissionErrorMessage(err, fallback);
}

/** The text a relay without `admission/1` sends, with no `reason`, for a re-join. */
const LEGACY_ALREADY_MEMBER_TEXT = 'Already a member of this node';

/**
 * Is this the relay's `already_member` answer? It is a success hint (§8).
 * A legacy relay answers a re-join with 400 and only the `error` text
 * (section 7.2: a new desktop on an old relay), which counts too.
 */
export function isAlreadyMember(err: unknown): boolean {
  const reason = errorReason(err);
  if (reason === 'already_member') return true;
  return reason === undefined && errorText(err, '') === LEGACY_ALREADY_MEMBER_TEXT;
}

/**
 * Should the welcome card still offer Join after this preview failure?
 * Yes for `rate_limited` and for network errors (no HTTP answer at all), so
 * the pasted code can be redeemed directly (REQ-43).
 */
export function isPreviewUnavailable(err: unknown): boolean {
  if (errorReason(err) === 'rate_limited' || errorStatus(err) === 429) return true;
  return errorStatus(err) === undefined;
}

// ── Redemption ───────────────────────────────────────────────────────────

/** The answer of a successful join (SPEC-01 §6.2). */
export interface JoinResult {
  status?: string;
  node_id?: string;
  node_name?: string;
  expires_at?: number;
  /** Some older relays answered with a node object. */
  id?: string;
  name?: string;
}

/** What {@link redeemInvite} needs from an API client. */
export interface InviteRedeemer {
  previewInviteHere?(inviteCode: string): Promise<{ node_id?: string } | null | undefined>;
  joinNodeByInvite(
    inviteCode: string,
    token: string,
    opts?: { deviceFingerprintHash?: string },
  ): Promise<JoinResult | null | undefined | void>;
}

export type RedeemOutcome =
  | { status: 'joined'; nodeId?: string; nodeName?: string }
  | { status: 'already_member'; nodeId?: string };

/**
 * Redeem an invite through `POST /invites/:code/join` with this
 * installation's fingerprint for the invite's node. The node id comes from
 * `opts.nodeId` or from the invite preview (unless `opts.preview` is false,
 * for example because the preview just failed); if neither is available the
 * join goes without a fingerprint. `already_member` counts as success. Any
 * other refusal is thrown; show it with {@link joinErrorMessage}.
 */
export async function redeemInvite(
  client: InviteRedeemer,
  inviteCode: string,
  token: string,
  opts: { nodeId?: string; preview?: boolean } = {},
): Promise<RedeemOutcome> {
  let nodeId = opts.nodeId;
  if (!nodeId && opts.preview !== false && client.previewInviteHere) {
    try {
      nodeId = (await client.previewInviteHere(inviteCode))?.node_id || undefined;
    } catch {
      // Preview unavailable (rate limited, network, invalid): redeem anyway;
      // the redemption gives the authoritative answer.
    }
  }
  const fingerprint = nodeId ? await nodeDeviceFingerprint(nodeId) : undefined;
  try {
    const result = await client.joinNodeByInvite(
      inviteCode,
      token,
      fingerprint ? { deviceFingerprintHash: fingerprint } : undefined,
    );
    const joined = (result || {}) as JoinResult;
    return {
      status: 'joined',
      nodeId: joined.node_id ?? joined.id ?? nodeId,
      nodeName: joined.node_name ?? joined.name,
    };
  } catch (err) {
    if (isAlreadyMember(err)) return { status: 'already_member', nodeId };
    throw err;
  }
}

// ── WebSocket events ─────────────────────────────────────────────────────

/** The part of the socket this module listens on. */
export interface AdmissionEventSource {
  on(event: any, listener: (data: any) => void): void;
}

/**
 * Register the admission WS handlers. `node_joined` (a join answer, or an
 * approval pushed by the relay) only reloads the node list: it is a hint and
 * never sends a sender key or a node metadata key by itself (REQ-43).
 * `join_request_denied` reports the §8 message.
 */
export function registerAdmissionHandlers(
  socket: AdmissionEventSource,
  handlers: { reloadNodes: () => void; onNotice?: (message: string) => void },
): void {
  socket.on('node_joined', () => {
    handlers.reloadNodes();
  });
  socket.on('join_request_denied', () => {
    handlers.onNotice?.(admissionMessage('join_request_denied'));
  });
}
