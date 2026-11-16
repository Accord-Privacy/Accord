/**
 * The relay, the hostile relay proxy and the headless clients of one SPEC-03
 * integration scenario (§10.1).
 *
 * - The relay is SPEC-02's `RelayProcess` (`ACCORD_SERVER_BIN`, or `cargo
 *   run` when cargo is on the PATH), started once per test file with
 *   `--disable-rate-limits`, which turns off only the start, stop and watch
 *   counters of §6.12.5 (the byte bucket, queues and other bounds stay on).
 *   It picks its port by binding 127.0.0.1:0, and a failed start is retried
 *   once on a new port.
 * - Each scenario gets a new proxy and new accounts: the first client owns
 *   a new node with one voice channel; the others join it by invite. Every
 *   client subscribes to the node's text channel, as App.tsx does when the
 *   channel is selected, so the relay's rotation events reach it.
 */

import { readFileSync } from 'node:fs';
import { RelayProcess, RELAY_AVAILABLE } from '../../src/__integration__/relay';
import { HostileRelayProxy } from './hrp';
import { HC, type HcOptions, waitFor } from './hc';

export { RELAY_AVAILABLE };

/** The 64 KiB receive buffers of §10.1 (on HRP's sockets). */
export const SMALL_SOCKET_BUFFER = 65_536;

/**
 * `RELAY_NOTSENT_LOWAT` (SPEC-03 A2, §14.2): the relay sets `TCP_NOTSENT_LOWAT`
 * to this on every client connection (`server/src/socket_opts.rs`), so its
 * kernel holds about this much unsent data per connection.
 */
export const RELAY_NOTSENT_LOWAT = 32_768;

/**
 * The smallest `net.ipv4.tcp_wmem` maximum the CI voice job leaves in place
 * (it sets 4 MiB). Send buffers stay large on purpose: the relay's kernel
 * send buffer on a loopback connection then grows to megabytes, so only the
 * relay's TCP_NOTSENT_LOWAT keeps its unsent data near RELAY_NOTSENT_LOWAT,
 * and the byte and time bounds of T-51 and RG-SCR-8 fail without it.
 */
export const LARGE_SEND_BUFFER = 1 << 20;

function tcpMemMax(file: string): number {
  try {
    return Number(readFileSync(file, 'utf8').trim().split(/\s+/)[2]);
  } catch {
    return NaN;
  }
}

/**
 * True when the kernel caps TCP receive buffers at 64 KiB (the
 * `net.ipv4.tcp_rmem` maximum is at most 65,536): the §10.1 condition, 64
 * KiB receive buffers on HRP's sockets, for the queue-fill tests (T-47,
 * T-51, RG-SCR-8).
 *
 * Node cannot set `SO_RCVBUF` on a TCP socket, so the CI voice job sets the
 * cap for the whole runner with `sysctl` before `npm run test:voice`; locally
 * the same holds inside a user and network namespace (`unshare -rn`, then
 * write the file). Send buffers are not capped (see `LARGE_SEND_BUFFER`).
 * Without the cap, loopback receive buffers absorb megabytes before a slow
 * link pushes back, and those tests run their fallback forms.
 */
export function kernelReceiveBuffersCapped(limit = SMALL_SOCKET_BUFFER): boolean {
  const r = tcpMemMax('/proc/sys/net/ipv4/tcp_rmem');
  return Number.isFinite(r) && r <= limit;
}

/** True when the kernel lets TCP send buffers grow to at least `min` bytes (`net.ipv4.tcp_wmem` maximum). */
export function kernelSendBuffersLarge(min = LARGE_SEND_BUFFER): boolean {
  const w = tcpMemMax('/proc/sys/net/ipv4/tcp_wmem');
  return Number.isFinite(w) && w >= min;
}

// CI sets ACCORD_VOICE_TCP_CAP=required: the queue-fill tests must then run
// in their §10.1 form, never in the fallback, with send buffers large enough
// that they check the relay's TCP_NOTSENT_LOWAT (A2, §14.2).
if (process.env.ACCORD_VOICE_TCP_CAP === 'required') {
  if (!kernelReceiveBuffersCapped()) {
    throw new Error('SPEC-03 §10.1: ACCORD_VOICE_TCP_CAP=required, but the net.ipv4.tcp_rmem maximum is not capped at 64 KiB');
  }
  if (!kernelSendBuffersLarge()) {
    throw new Error(`SPEC-03 A2: ACCORD_VOICE_TCP_CAP=required, but the net.ipv4.tcp_wmem maximum is below ${LARGE_SEND_BUFFER} bytes, so the relay's TCP_NOTSENT_LOWAT would not be exercised`);
  }
}

export async function startRelay(extraArgs: readonly string[] = []): Promise<RelayProcess> {
  const args = ['--disable-rate-limits', ...extraArgs];
  try {
    return await RelayProcess.start(args);
  } catch {
    // One retry on a new port (§10.1), for example when the port was taken meanwhile.
    return RelayProcess.start(args);
  }
}

export interface VoiceWorld {
  readonly relay: RelayProcess;
  readonly hrp: HostileRelayProxy;
  readonly hcs: HC[];
  readonly nodeId: string;
  readonly voiceChannel: string;
  readonly textChannel: string;
  /** Clients by name. */
  readonly by: Record<string, HC>;
}

export interface WorldOptions {
  /** Options per client; `tag` defaults to the client's position plus 1. */
  readonly client?: (name: string, index: number) => Partial<HcOptions>;
  /** Clients that do not join the node (outsider accounts). */
  readonly outsiders?: readonly string[];
}

let worldCount = 0;

export async function buildWorld(relay: RelayProcess, names: readonly string[], opts: WorldOptions = {}): Promise<VoiceWorld> {
  const hrp = new HostileRelayProxy(relay.port);
  await hrp.start();
  const hcs: HC[] = [];
  for (const [i, name] of names.entries()) {
    const o = opts.client?.(name, i) ?? {};
    hcs.push(await HC.create(name, hrp.baseUrl, { tag: i + 1, ...o }));
  }
  const owner = hcs[0];
  const node = await owner.client.api.createNode(`spec03-voice-${++worldCount}`, owner.client.token);
  const voice = await owner.client.api.createChannel(node.id, 'call', 'voice', owner.client.token);
  const channels = await owner.client.api.getNodeChannels(node.id, owner.client.token);
  const text = channels.find(c => (c as { channel_type?: string }).channel_type !== 'voice' && c.id !== voice.id) ?? channels[0];
  const outsiders = new Set(opts.outsiders ?? []);
  for (const hc of hcs.slice(1)) {
    if (outsiders.has(hc.name)) continue;
    const invite = await owner.client.api.createInvite(node.id, owner.client.token);
    await hc.client.api.joinNodeByInvite(invite.invite_code, hc.client.token);
  }
  for (const hc of hcs) {
    await hc.connect();
    if (!outsiders.has(hc.name)) await hc.subscribe(text.id);
  }
  const by: Record<string, HC> = {};
  for (const hc of hcs) by[hc.name] = hc;
  return { relay, hrp, hcs, nodeId: node.id, voiceChannel: voice.id, textChannel: text.id, by };
}

export async function disposeWorld(w: VoiceWorld | undefined): Promise<void> {
  if (!w) return;
  for (const hc of w.hcs) await hc.dispose();
  await w.hrp.close();
}

/** Join every listed client to the world's voice channel, in order, `gapMs` apart. */
export async function joinAll(w: VoiceWorld, hcs: readonly HC[], gapMs = 0): Promise<void> {
  for (const [i, hc] of hcs.entries()) {
    if (i > 0 && gapMs > 0) await new Promise(r => setTimeout(r, gapMs));
    await hc.joinVoice(w.voiceChannel, w.nodeId);
  }
}

/** Wait until every ordered pair of the listed clients is Secure (§8.2 row 4). */
export async function allSecure(hcs: readonly HC[], timeoutMs = 30_000): Promise<void> {
  await waitFor('every pair secure', () => {
    for (const a of hcs) {
      for (const b of hcs) {
        if (a === b) continue;
        if (a.participant(b)?.label !== 'secure') return false;
      }
    }
    return true;
  }, timeoutMs);
}
