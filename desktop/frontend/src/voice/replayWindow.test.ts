// @vitest-environment node
/**
 * SPEC-03 T-15 (REQ-15): the replay window of §6.5, for audio (W = 128) and,
 * with A1, for video (W = 1024), including the rule that only authenticated
 * frames move it.
 */

import { describe, expect, it } from 'vitest';
import { REPLAY_WINDOW_AUDIO, REPLAY_WINDOW_VIDEO, ReplayWindow } from './replayWindow';
import { CTR_LIMIT, MEDIA_KIND_AUDIO, MEDIA_KIND_VIDEO, deriveEpochKeys, frameContext, importHkdfKey, openFrame, parseFrame, sealFrame, type MediaKind } from './mediaFrame';

/** Accept a counter the way §6.2.6 steps 6 to 8 do (check, authenticate, commit). */
function accept(w: ReplayWindow, ctr: number, authenticates = true): boolean {
  if (!w.check(ctr)) return false;
  if (!authenticates) return false;
  return w.commit(ctr);
}

for (const [label, W] of [['audio', REPLAY_WINDOW_AUDIO], ['video', REPLAY_WINDOW_VIDEO]] as const) {
  describe(`replay window, ${label} (W = ${W})`, () => {
    it('drops a duplicate', () => {
      const w = new ReplayWindow(W);
      expect(accept(w, 5)).toBe(true);
      expect(accept(w, 5)).toBe(false);
      expect(w.check(5)).toBe(false);
    });

    it('accepts a frame out of order within the window exactly once', () => {
      const w = new ReplayWindow(W);
      for (const c of [10, 12, 11, 9]) expect(accept(w, c), `${c}`).toBe(true);
      for (const c of [9, 10, 11, 12]) expect(accept(w, c), `${c} again`).toBe(false);
    });

    it(`accepts W − 1 behind once and drops W behind`, () => {
      const w = new ReplayWindow(W);
      expect(accept(w, 5000)).toBe(true);
      expect(accept(w, 5000 - (W - 1))).toBe(true);
      expect(accept(w, 5000 - (W - 1))).toBe(false);
      expect(accept(w, 5000 - W)).toBe(false);
      expect(w.highest).toBe(5000);
    });

    it('a forged frame with a high counter and a bad tag leaves the window unchanged', () => {
      const w = new ReplayWindow(W);
      for (let c = 0; c < 20; c++) accept(w, c);
      expect(accept(w, 2 ** 40, false)).toBe(false);
      expect(w.highest).toBe(19);
      expect(accept(w, 20)).toBe(true);
      expect(accept(w, 3)).toBe(false);
    });

    it('forgets counters as the window moves, across large jumps', () => {
      const w = new ReplayWindow(W);
      expect(accept(w, 1)).toBe(true);
      expect(accept(w, 1 + 3 * W)).toBe(true);
      expect(accept(w, 1 + 3 * W - 1)).toBe(true);
      expect(accept(w, 1 + 2 * W)).toBe(false); // W behind
      expect(accept(w, 2 + 2 * W)).toBe(true); // W − 1 behind, never seen
    });

    it('agrees with a set-based model on random sequences', () => {
      let seed = W;
      const rand = () => {
        seed = (seed * 1103515245 + 12345) % 2 ** 31;
        return seed / 2 ** 31;
      };
      const mismatches: string[] = [];
      for (let run = 0; run < 20; run++) {
        const w = new ReplayWindow(W);
        const seen = new Set<number>();
        let highest = -1;
        for (let i = 0; i < 2000; i++) {
          const ctr = Math.max(0, Math.floor(highest + (rand() - 0.7) * 3 * W));
          const authenticates = rand() > 0.1;
          const expected = (ctr > highest || (highest - ctr < W && !seen.has(ctr))) && authenticates;
          if (accept(w, ctr, authenticates) !== expected) mismatches.push(`run ${run} step ${i} ctr ${ctr}`);
          if (expected) {
            seen.add(ctr);
            highest = Math.max(highest, ctr);
          }
        }
      }
      expect(mismatches).toEqual([]);
    });
  });
}

describe('replay window: inputs and commits', () => {
  it('rejects counters outside [0, 2^48) and non-integers', () => {
    const w = new ReplayWindow(REPLAY_WINDOW_AUDIO);
    for (const c of [-1, CTR_LIMIT, 1.5, Number.NaN, Infinity]) {
      expect(w.check(c)).toBe(false);
      expect(w.commit(c)).toBe(false);
    }
    expect(accept(w, CTR_LIMIT - 1)).toBe(true);
  });

  it('a second commit of a counter decrypted twice in parallel is refused', () => {
    const w = new ReplayWindow(REPLAY_WINDOW_VIDEO);
    expect(w.check(77) && w.check(77)).toBe(true); // both copies pass the pre-check
    expect(w.commit(77)).toBe(true);
    expect(w.commit(77)).toBe(false);
  });

  it('refuses window sizes that are not positive integers', () => {
    for (const s of [0, -1, 1.5, 2 ** 20]) expect(() => new ReplayWindow(s)).toThrow(RangeError);
    expect(new ReplayWindow(REPLAY_WINDOW_VIDEO).size).toBe(1024);
  });

  it('A1: the audio and video windows of an instance are independent', () => {
    const audio = new ReplayWindow(REPLAY_WINDOW_AUDIO);
    const video = new ReplayWindow(REPLAY_WINDOW_VIDEO);
    expect(accept(video, 500)).toBe(true);
    expect(audio.check(500)).toBe(true);
    expect(accept(audio, 500)).toBe(true);
    expect(accept(video, 500)).toBe(false);
  });
});

describe('replay window with real frames (§6.2.6 steps 6 to 8)', () => {
  it('only authenticated frames commit; duplicates and forgeries never move the window', async () => {
    const secret = await importHkdfKey(new Uint8Array(32).fill(0x42));
    const tx = await deriveEpochKeys(secret, 4, 'encrypt');
    const rx = await deriveEpochKeys(secret, 4, 'decrypt');
    const ctx = frameContext('00000000-0000-4000-8000-0000000000c1', '00000000-0000-4000-8000-0000000000a1', new Uint8Array(16).fill(1));
    for (const kind of [MEDIA_KIND_AUDIO, MEDIA_KIND_VIDEO] as MediaKind[]) {
      const w = new ReplayWindow(kind === MEDIA_KIND_AUDIO ? REPLAY_WINDOW_AUDIO : REPLAY_WINDOW_VIDEO);
      const pt = kind === MEDIA_KIND_AUDIO ? Uint8Array.of(1, 2, 3, 4) : (() => {
        const b = new Uint8Array(30);
        b.set([1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 2, 128, 1, 104]); // vcodec 1, key, share 1, frame 0, 1/1, 640 × 360
        return b;
      })();
      const receive = async (frame: Uint8Array): Promise<boolean> => {
        const p = parseFrame(frame, kind);
        if (!p.ok || !w.check(p.ctr)) return false;
        const out = await openFrame(p, rx, ctx);
        return out !== null && w.commit(p.ctr);
      };
      const f10 = await sealFrame(kind, tx, 10, ctx, pt);
      expect(await receive(f10)).toBe(true);
      expect(await receive(f10)).toBe(false); // duplicate
      const forged = await sealFrame(kind, tx, 2 ** 47, ctx, pt);
      forged[forged.length - 1] ^= 1;
      expect(await receive(forged)).toBe(false);
      expect(w.highest).toBe(10);
      expect(await receive(await sealFrame(kind, tx, 11, ctx, pt))).toBe(true);
      expect(await receive(await sealFrame(kind, tx, 9, ctx, pt))).toBe(true); // out of order, once
    }
  });
});
