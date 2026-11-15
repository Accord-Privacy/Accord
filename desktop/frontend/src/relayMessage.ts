/**
 * @module relayMessage
 * The one place where relay message JSON (history items, pins, thread
 * replies) is turned into `Message` fields (SPEC-02 REQ-51). Search results
 * have their own explicit copy (`searchResultFromRelay` in SearchOverlay.tsx).
 *
 * It copies an explicit list of fields, each checked for its type, and never
 * spreads the relay object. In particular it never copies `files`,
 * `attachments` or `attachment_ids`: attachment state comes only from the
 * decode function (`attachments/decode.ts`), never from relay JSON.
 */

import type { Message, MessageReaction, RepliedMessage } from './types';

/** The relay-supplied fields a `Message` may take over. */
export interface RelayMessageFields {
  id: string;
  channel_id?: string;
  sender_id?: string;
  sender_public_key_hash?: string;
  display_name?: string;
  edited_at?: number;
  pinned_at?: number;
  pinned_by?: string;
  expires_at?: number;
  read_gated?: boolean;
  gate_ttl_secs?: number;
  reply_to?: string;
  replied_message?: RepliedMessage;
  reply_count?: number;
  reactions?: MessageReaction[];
}

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

function num(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}

function bool(v: unknown): boolean | undefined {
  return typeof v === 'boolean' ? v : undefined;
}

/** A field that may be a string or a number on the wire (ids, some timestamps). */
function idString(v: unknown): string | undefined {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' && Number.isFinite(v)) return String(v);
  return undefined;
}

function repliedMessage(v: unknown): RepliedMessage | undefined {
  if (!isObj(v)) return undefined;
  const id = idString(v.id);
  if (id === undefined) return undefined;
  return {
    id,
    sender_id: idString(v.sender_id) ?? '',
    sender_public_key_hash: str(v.sender_public_key_hash) ?? '',
    encrypted_payload: str(v.encrypted_payload) ?? '',
    created_at: num(v.created_at) ?? 0,
    content: str(v.content),
  };
}

function reactions(v: unknown): MessageReaction[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: MessageReaction[] = [];
  for (const r of v) {
    if (!isObj(r) || typeof r.emoji !== 'string') continue;
    out.push({
      emoji: r.emoji,
      count: num(r.count) ?? 0,
      users: Array.isArray(r.users) ? r.users.filter((u): u is string => typeof u === 'string') : [],
      created_at: num(r.created_at) ?? 0,
    });
  }
  return out;
}

/**
 * Copy the known fields of a relay message object. Unknown members, and
 * members of the wrong type, are left out. Absent and null values become
 * `undefined`.
 */
export function relayMessageFields(raw: unknown): RelayMessageFields {
  const m: Obj = isObj(raw) ? raw : {};
  return {
    id: idString(m.id) ?? '',
    channel_id: idString(m.channel_id),
    sender_id: idString(m.sender_id),
    sender_public_key_hash: str(m.sender_public_key_hash),
    display_name: str(m.display_name),
    edited_at: num(m.edited_at),
    pinned_at: num(m.pinned_at),
    pinned_by: idString(m.pinned_by),
    expires_at: num(m.expires_at),
    read_gated: bool(m.read_gated),
    gate_ttl_secs: num(m.gate_ttl_secs),
    reply_to: idString(m.reply_to),
    replied_message: repliedMessage(m.replied_message),
    reply_count: num(m.reply_count),
    reactions: reactions(m.reactions),
  };
}

/**
 * A pinned message (`GET /channels/{id}/pins`) as the pinned panel shows it.
 * Pins are not decoded in stage 1 (REQ-51): the relay's `content` string is
 * shown as text, and the result carries no attachment count or ref, so it
 * shows no attachment UI (`attachments/render.ts`).
 */
export function pinnedMessageFromRelay(raw: unknown, fingerprint: (hash: string) => string): Message {
  const m: Obj = isObj(raw) ? raw : {};
  const fields = relayMessageFields(m);
  const createdAt = num(m.created_at) ?? 0;
  const pinnedAt = num(m.pinned_at);
  return {
    ...fields,
    author: str(m.author) || fields.display_name || fingerprint(fields.sender_public_key_hash || fields.sender_id || '') || 'Unknown',
    content: str(m.content) ?? '',
    time: new Date(createdAt * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    pinned_at: pinnedAt === undefined ? undefined : pinnedAt * 1000, // milliseconds
    timestamp: createdAt * 1000,
  };
}

/**
 * A thread reply (`GET /messages/{id}/thread`) as the thread panel shows it.
 * Like pins, thread replies are not decoded in stage 1 and show no
 * attachment UI (REQ-51).
 */
export function threadMessageFromRelay(raw: unknown): Message {
  const m: Obj = isObj(raw) ? raw : {};
  const fields = relayMessageFields(m);
  const seconds = num(m.created_at) || num(m.timestamp) || 0;
  return {
    ...fields,
    content: str(m.content) ?? '',
    time: new Date(seconds * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    timestamp: seconds * 1000,
    author: str(m.author) || fields.display_name || fields.sender_id?.substring(0, 8) || 'Unknown',
  };
}
