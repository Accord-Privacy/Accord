/**
 * Shared assertions and small helpers of the SPEC-03 integration tests.
 */

import { binaryNeedles, findLeaks, textNeedles, type Needle } from '../../src/__integration__/scan';
import { HC, classifyWire, sleep, waitFor, type OutgoingCall } from './hc';
import { clientBody, typeOf, type HrpConn, type HrpMessage, type HostileRelayProxy } from './hrp';

export { sleep, waitFor };

/** Every encoding of every call secret any of `hcs` received (keys of the call, §5.1). */
export function secretNeedles(hcs: readonly HC[]): Needle[] {
  const seen = new Set<string>();
  const out: Needle[] = [];
  for (const hc of hcs) {
    for (const k of hc.receivedKeys) {
      const id = Buffer.from(k.secret).toString('hex');
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(...binaryNeedles(`epoch secret ${k.from.slice(0, 8)}/${k.epoch}`, k.secret));
    }
  }
  return out;
}

/** The secrets' labels found in `chunks` (empty when nothing leaked). */
export function leaks(chunks: readonly Buffer[], needles: readonly Needle[]): string[] {
  return findLeaks(chunks, needles);
}

export { binaryNeedles, textNeedles, findLeaks };

/** The client call messages (`VoiceKeyExchange`) HRP saw from `from` (any connection), classified. */
export function callMessagesFrom(hrp: HostileRelayProxy, from: HC, since = 0): Array<{ msg: HrpMessage; body: Record<string, any>; call: OutgoingCall | undefined }> {
  return hrp.messages({ dir: 'c2s', user: from.userId, type: 'VoiceKeyExchange', since }).map(msg => {
    const body = clientBody(msg)!;
    return { msg, body, call: classifyWire(body.wrapped_key) };
  });
}

/** Relay messages of `type` delivered to `to` since `since`. */
export function relayMessagesTo(hrp: HostileRelayProxy, to: HC, type: string, since = 0): HrpMessage[] {
  return hrp.messages({ dir: 's2c', user: to.userId, type, since });
}

/** Client messages of `type` that `from` sent since `since`. */
export function clientMessagesFrom(hrp: HostileRelayProxy, from: HC, type: string, since = 0): HrpMessage[] {
  return hrp.messages({ dir: 'c2s', user: from.userId, type, since });
}

/** The current (newest live) proxy connection of `hc`. */
export function connOf(hrp: HostileRelayProxy, hc: HC): HrpConn {
  const conns = hrp.connsOf(hc.userId);
  const c = conns[conns.length - 1];
  if (!c) throw new Error(`${hc.name} has no live connection`);
  return c;
}

/** True when the message is a relay message to `to` about channel `channelId`. */
export function isTo(m: HrpMessage, to: HC): boolean {
  return m.conn.userId === to.userId;
}

export function typeIs(m: HrpMessage, type: string): boolean {
  return typeOf(m) === type;
}

/** Order clients so that `lower` has the lower user id (REQ-10's initiator). */
export function byId(a: HC, b: HC): [lower: HC, higher: HC] {
  return a.userId < b.userId ? [a, b] : [b, a];
}

/** Count of `played` markers from `from` at `at` in [t0, t1). */
export function playedBetween(hc: HC, from: HC, t0: number, t1: number): number {
  return hc.played.filter(p => p.from === from.userId && p.at >= t0 && p.at < t1).length;
}

/** Frame numbers played more than once at `hc` from `from` (a frame plays at most once, G2). */
export function duplicatesPlayed(hc: HC, from: HC): number[] {
  const seen = new Map<number, number>();
  for (const p of hc.played) {
    if (p.from !== from.userId || p.tag !== from.options.tag) continue;
    seen.set(p.n, (seen.get(p.n) ?? 0) + 1);
  }
  return [...seen].filter(([, c]) => c > 1).map(([n]) => n);
}

/** Make `a` and `b` friends and give them a DM channel, as SPEC-02's harness does. */
export async function dmChannel(a: HC, b: HC, nodeId: string): Promise<string> {
  const fr = await a.client.api.sendFriendRequest(b.userId, nodeId);
  await b.client.api.acceptFriendRequest(fr.request_id);
  const id = (await a.client.api.createDmChannel(b.userId, a.client.token)).id;
  a.client.dmChannels.add(id);
  b.client.dmChannels.add(id);
  return id;
}

/**
 * Times at which `hc` processed relay events of `type` matching `pred`. The
 * listener is added after the voice connection's own, so when it runs the
 * connection has already handled the event.
 */
export function eventTimes(hc: HC, type: string, pred: (data: Record<string, any>) => boolean = () => true): number[] {
  const times: number[] = [];
  hc.ws.on(type as never, ((data: Record<string, any>) => {
    if (pred(data ?? {})) times.push(Date.now());
  }) as never);
  return times;
}

/**
 * Emulate a relay that keeps forwarding to `to` what it forwards to `via`
 * from `from` (audio frames, and fragments with `screen`): the non-evicting
 * relay of RG-C112 and RG-SCR-9.
 */
export function copyMediaTo(hrp: HostileRelayProxy, from: HC, via: HC, to: HC, opts: { screen?: boolean } = {}): () => void {
  return hrp.addRule('s2c', m => {
    if (m.conn.userId !== via.userId) return undefined;
    const t = typeOf(m);
    if (t === 'srtp_voice_packet' && m.json?.from === from.userId) hrp.inject(to.userId, 's2c', m.json);
    if (opts.screen && t === 'SCREEN_DOWN' && m.data.length > 33 && Buffer.from(m.data.subarray(17, 33)).equals(Buffer.from(from.userId.replace(/-/g, ''), 'hex'))) {
      hrp.inject(to.userId, 's2c', m.data);
    }
    return undefined;
  });
}

/** POST /nodes/:id/bans for `target`, as `by` (the relay hashes the account's public key string). */
export async function ban(baseUrl: string, by: HC, nodeId: string, target: HC): Promise<number> {
  const { createHash } = await import('node:crypto');
  const hash = createHash('sha256').update(target.client.publicKey, 'utf8').digest('hex');
  const r = await fetch(`${baseUrl}/nodes/${nodeId}/bans`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${by.client.token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ public_key_hash: hash }),
  });
  await r.text();
  return r.status;
}

/** A DM each way, so that a Double Ratchet session exists in both directions before a call. */
export async function establishSession(a: HC, b: HC, dm: string): Promise<void> {
  const nb = b.client.received.length;
  await a.client.send({ kind: 'dm', channelId: dm, peerId: b.userId }, 'session a');
  await b.client.waitForMessage(r => b.client.received.indexOf(r) >= nb && r.channelId === dm);
  const na = a.client.received.length;
  await b.client.send({ kind: 'dm', channelId: dm, peerId: a.userId }, 'session b');
  await a.client.waitForMessage(r => a.client.received.indexOf(r) >= na && r.channelId === dm);
}

/** The epochs whose keys `holder`'s call holds for `from`'s current instance (§6.7 RemoteSender). */
export function heldEpochs(holder: HC, from: HC): number[] {
  const r = holder.conn?.callKeys?.retainedRecord(from.userId);
  return r ? [...new Set(r.keys.map(k => k.kid))].sort((a, b) => a - b) : [];
}

/** The retained record `holder` keeps for `from` (REQ-34). */
export function recordOf(holder: HC, from: HC) {
  return holder.conn?.callKeys?.retainedRecord(from.userId) ?? null;
}
