/**
 * Setup of the SPEC-03 voice integration harness (§10.1), run before every
 * file of `npm run test:voice`, in Vitest's `node` environment.
 *
 * - SPEC-02's integration setup supplies XMLHttpRequest on top of fetch.
 * - `localStorage` is an in-memory store that records every write, so tests
 *   can scan what the E2EE layer persisted (T-13, T-27). Node runs every
 *   headless client in one process, so the clients share this one store;
 *   the E2EE layer namespaces its keys by identity, and the scans read all
 *   writes.
 * - `navigator.onLine` is true: Node 22 has a `navigator` without it, which
 *   `ws.ts` would read as offline and so wait 30 s before every reconnect.
 * - `RTCPeerConnection` and `RTCSessionDescription` are stubs that count
 *   constructions (REQ-39, T-39 I, RG-C003-1, RG-SCR-10): the expected
 *   count is always 0.
 */
import '../../src/__integration__/setup';

import type { StorageWrite } from './spies';

class RecordingStorage {
  private map = new Map<string, string>();
  readonly writes: StorageWrite[] = [];
  get length(): number {
    return this.map.size;
  }
  key(i: number): string | null {
    return [...this.map.keys()][i] ?? null;
  }
  getItem(k: string): string | null {
    return this.map.get(k) ?? null;
  }
  setItem(k: string, v: string): void {
    const value = String(v);
    this.map.set(k, value);
    this.writes.push({ key: k, value, at: Date.now() });
  }
  removeItem(k: string): void {
    this.map.delete(k);
  }
  clear(): void {
    this.map.clear();
  }
}

interface HarnessGlobals {
  storage: RecordingStorage;
  session: RecordingStorage;
  peerConnections: { constructions: number };
}
const g = globalThis as unknown as { __accordVoiceHarness?: HarnessGlobals };
const harness: HarnessGlobals = g.__accordVoiceHarness ?? { storage: new RecordingStorage(), session: new RecordingStorage(), peerConnections: { constructions: 0 } };
g.__accordVoiceHarness = harness;
Object.defineProperty(globalThis, 'localStorage', { value: harness.storage, configurable: true, writable: true });
Object.defineProperty(globalThis, 'sessionStorage', { value: harness.session, configurable: true, writable: true });

const nav = (globalThis as { navigator?: object }).navigator;
if (nav && (nav as { onLine?: unknown }).onLine === undefined) {
  Object.defineProperty(nav, 'onLine', { value: true, configurable: true });
} else if (!nav) {
  Object.defineProperty(globalThis, 'navigator', { value: { onLine: true }, configurable: true });
}

class CountingPeerConnection {
  constructor() {
    harness.peerConnections.constructions++;
    throw new Error('SPEC-03 REQ-39: no peer connection may be created');
  }
}
for (const name of ['RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCSessionDescription', 'RTCIceCandidate']) {
  Object.defineProperty(globalThis, name, { value: CountingPeerConnection, configurable: true, writable: true });
}
