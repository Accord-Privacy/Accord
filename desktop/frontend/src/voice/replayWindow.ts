/**
 * @module voice/replayWindow
 * The anti-replay window of SPEC-03 §6.5 (REQ-15), one per remote sender
 * instance, media kind and epoch (KID; amendment A2, §14.1): 128 counters
 * for audio CTR, 1024 for video VCTR.
 *
 * Keep `highest` (−1 at first) and a W-bit map of the accepted counters at or
 * below it:
 * - `check(ctr)`: a counter above `highest` passes; one W or more below fails;
 *   otherwise it passes only if its bit is clear. Nothing changes.
 * - `commit(ctr)`, only after AEAD succeeded: above `highest`, shift the map
 *   by `ctr − highest`, set bit 0 and raise `highest`; otherwise set its bit.
 *
 * `CallKeyManager` keeps an epoch's windows while its key is installed, and
 * the highest accepted epoch's while REQ-33 (c) may still reinstall it
 * (REQ-34 as amended by A2), so a frame authenticates at most once per
 * instance, kind and epoch. A frame under one epoch never moves another
 * epoch's window: a holder of an older epoch's key cannot push the window
 * past the sender's counters under a newer one.
 */

import { CTR_LIMIT } from './mediaFrame';

/** `REPLAY_WINDOW`: audio counters (RFC 3711 §3.3.2 asks for at least 64). */
export const REPLAY_WINDOW_AUDIO = 128;
/** `REPLAY_WINDOW_VIDEO` (A1). */
export const REPLAY_WINDOW_VIDEO = 1024;

const MAX_WINDOW = 1 << 16;

export class ReplayWindow {
  /** W, the number of counters the map covers. */
  readonly size: number;
  private top = -1;
  /** Ring map: slot `ctr mod W` marks `ctr` while `top − ctr < W`. */
  private readonly seen: Uint8Array;

  constructor(size: number) {
    if (!Number.isInteger(size) || size < 1 || size > MAX_WINDOW) throw new RangeError('replay window size');
    this.size = size;
    this.seen = new Uint8Array(size);
  }

  /** The highest committed counter, or −1. */
  get highest(): number {
    return this.top;
  }

  /** The replay check: true when `ctr` may still be accepted. Changes nothing. */
  check(ctr: number): boolean {
    if (!Number.isSafeInteger(ctr) || ctr < 0 || ctr >= CTR_LIMIT) return false;
    if (ctr > this.top) return true;
    if (this.top - ctr >= this.size) return false;
    return this.seen[ctr % this.size] === 0;
  }

  /**
   * Record an authenticated counter. Returns false, changing nothing, when the
   * counter no longer passes `check` (for example a duplicate whose twin was
   * committed while both were being decrypted); the caller then drops it.
   */
  commit(ctr: number): boolean {
    if (!this.check(ctr)) return false;
    if (ctr > this.top) {
      const shift = ctr - this.top;
      if (shift >= this.size) {
        this.seen.fill(0);
      } else {
        // Counters top+1 … ctr reuse the slots of counters that leave the window.
        for (let c = this.top + 1; c <= ctr; c++) this.seen[c % this.size] = 0;
      }
      this.top = ctr;
    }
    this.seen[ctr % this.size] = 1;
    return true;
  }
}
