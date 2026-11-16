// @vitest-environment node
/**
 * U tests of the bounded jitter buffer (`voice/jitterBuffer.ts`) that relay
 * mode feeds with authenticated CTRs (SPEC-03 REQ-15, §6.2.6 step 9, G2).
 */
import { describe, expect, it } from 'vitest';
import { JitterBuffer } from './jitterBuffer';

/** A one-sample payload carrying its sequence number. */
function frame(seq: number): ArrayBuffer {
  return Int32Array.of(seq).buffer;
}

function seqOf(payload: ArrayBuffer | null): number | null {
  return payload ? new Int32Array(payload)[0] : null;
}

/** A buffer on a manual clock, as relay mode builds it (no concealment). */
function buffer() {
  let t = 1000;
  const jb = new JitterBuffer({ maxConcealment: 0, now: () => t });
  return {
    jb,
    tick(ms = 20) {
      t += ms;
    },
  };
}

describe('JitterBuffer bounds (SPEC-03 REQ-15)', () => {
  it('never holds more than maxDelay (20) frames, whatever counters a sender chooses', () => {
    const { jb, tick } = buffer();
    for (let i = 0; i < 5000; i++) {
      jb.push(1_000_000 + i * 1000, frame(i));
      expect(jb.buffered).toBeLessThanOrEqual(20);
      tick();
    }
    expect(jb.getStats().packetsOverflow).toBe(5000 - 20);
    const played: number[] = [];
    for (let i = 0; i < 25; i++) {
      const p = seqOf(jb.pull());
      if (p !== null) played.push(p);
    }
    expect(played).toEqual(Array.from({ length: 20 }, (_, k) => 4980 + k));
  });

  it('skips a gap at once: playout latency after it is the same as before it', () => {
    const { jb, tick } = buffer();
    const playedAt = new Map<number, number>();
    for (let tickNo = 0; tickNo < 310; tickNo++) {
      if (tickNo < 50 || (tickNo >= 150 && tickNo < 300)) jb.push(tickNo, frame(tickNo)); // 100 frames lost
      const p = seqOf(jb.pull());
      if (p !== null) playedAt.set(p, tickNo);
      tick();
    }
    const delay = (s: number) => playedAt.get(s)! - s;
    expect(delay(150)).toBeLessThanOrEqual(delay(40) + 2);
    expect(delay(299)).toBe(delay(40));
    for (let s = 50; s < 150; s++) expect(playedAt.has(s)).toBe(false);
    expect(jb.getStats().framesSkipped).toBe(100);
  });

  it('a duplicate or an older sequence never plays, and nothing plays twice', () => {
    const { jb, tick } = buffer();
    const played: number[] = [];
    const pull = () => {
      const p = seqOf(jb.pull());
      if (p !== null) played.push(p);
      tick();
    };
    jb.push(0, frame(0));
    jb.push(1, frame(1));
    jb.push(1, frame(1)); // duplicate while buffered
    pull();
    pull();
    jb.push(0, frame(0)); // already played
    jb.push(1, frame(1));
    jb.push(10, frame(10));
    jb.push(11, frame(11));
    pull();
    jb.push(5, frame(5)); // inside the skipped gap
    jb.push(10, frame(10));
    for (let i = 0; i < 5; i++) pull();
    expect(played).toEqual([0, 1, 10, 11]);
    expect(jb.getStats().packetsLate).toBe(5);
  });

  it('plays a lone frame after targetDelay ticks, and the rest of a spurt one per tick', () => {
    const { jb, tick } = buffer();
    jb.push(0, frame(0));
    expect(jb.pull()).toBeNull();
    expect(jb.pull()).toBeNull();
    expect(seqOf(jb.pull())).toBe(0);
    expect(jb.pull()).toBeNull();
    // A spurt: once playing, the buffer drains to the last frame.
    for (let s = 1; s <= 4; s++) {
      jb.push(s, frame(s));
      tick();
    }
    const out = [jb.pull(), jb.pull(), jb.pull(), jb.pull(), jb.pull()].map(seqOf);
    expect(out).toEqual([1, 2, 3, 4, null]);
    expect(jb.buffered).toBe(0);
  });

  it('a gap does not inflate the jitter estimate (the sequence is the media clock)', () => {
    const { jb, tick } = buffer();
    for (let s = 0; s < 50; s++) {
      jb.push(s, frame(s));
      tick();
    }
    tick(20 * 100);
    for (let s = 150; s < 160; s++) {
      jb.push(s, frame(s));
      tick();
    }
    expect(jb.getStats().jitterMs).toBe(0);
    expect(jb.getStats().currentDelayFrames).toBe(2);
  });

  it('A2: highestReceived is the highest sequence pushed since the last reset, late and duplicate pushes included', () => {
    const { jb } = buffer();
    expect(jb.highestReceived).toBe(-1);
    jb.push(10, frame(10));
    jb.push(2 ** 47, frame(11));
    jb.push(12, frame(12)); // late, never played
    expect(jb.highestReceived).toBe(2 ** 47);
    jb.reset();
    expect(jb.highestReceived).toBe(-1);
    jb.push(5, frame(5));
    expect(jb.highestReceived).toBe(5);
    expect(seqOf(jb.pull()) ?? seqOf(jb.pull()) ?? seqOf(jb.pull())).toBe(5);
  });
});
