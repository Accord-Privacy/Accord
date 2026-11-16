/**
 * Read access to the spies that `setup.ts` installs (the recording storage
 * and the WebRTC constructor counter), through one object on `globalThis`
 * so that every module of a test file sees the same instances.
 */

export interface StorageWrite {
  readonly key: string;
  readonly value: string;
  readonly at: number;
}

interface HarnessGlobals {
  storage: { writes: StorageWrite[] };
  session: { writes: StorageWrite[] };
  peerConnections: { constructions: number };
}

function harness(): HarnessGlobals {
  const h = (globalThis as unknown as { __accordVoiceHarness?: HarnessGlobals }).__accordVoiceHarness;
  if (!h) throw new Error('tests/voice/setup.ts did not run');
  return h;
}

/** Every `localStorage` and `sessionStorage` write so far. */
export function storageWrites(): StorageWrite[] {
  const h = harness();
  return [...h.storage.writes, ...h.session.writes];
}

/** Constructions of `RTCPeerConnection` (or any WebRTC object) so far; always expected to be 0. */
export function peerConnectionConstructions(): number {
  return harness().peerConnections.constructions;
}
