/**
 * Adaptive jitter buffer for voice playback.
 *
 * TypeScript port of core/src/jitter_buffer.rs concepts.
 * Buffers incoming packets, reorders them, and adapts delay
 * based on measured jitter (RFC 3550 exponential moving average).
 *
 * The buffer is bounded (SPEC-03 REQ-15, §6.2.6 step 9: relay mode feeds it
 * the authenticated CTR of every frame, which any participant chooses for
 * its own frames):
 * - it never holds more than `maxDelay` frames; on overflow the oldest are
 *   dropped and the playout sequence moves past them;
 * - a gap before the oldest buffered frame is skipped in one step instead of
 *   one sequence number per tick, so a gap (frames the relay dropped, frames
 *   discarded at a rotation, a sender jumping its counter) never adds its
 *   length to the playout latency;
 * - it buffers `targetDelay` frames only when playout starts (at the first
 *   frame, and after an underrun), and for at most `targetDelay` ticks; once
 *   playing it plays one frame per tick until it runs empty, so the end of a
 *   talk spurt is not held until the next spurt arrives;
 * - the jitter estimate uses the sequence number as the media timestamp, so
 *   a gap is not mistaken for jitter.
 *
 * Every rule only moves the playout sequence forward: a duplicate, or a
 * frame older than the last one played, never plays (SPEC-03 §3.2 G2).
 */

const DEFAULT_FRAME_DURATION_MS = 20;
const DEFAULT_MIN_DELAY = 2;   // frames
const DEFAULT_MAX_DELAY = 20;  // 400ms at 20ms frames
const DEFAULT_MAX_CONCEALMENT = 5;
const JITTER_ALPHA = 1 / 16;   // RFC 3550
const JITTER_FACTOR = 2.0;     // standard deviations of jitter to buffer

interface BufferedPacket {
  sequence: number;
  payload: ArrayBuffer;
}

export interface JitterBufferStats {
  packetsReceived: number;
  packetsPlayed: number;
  /** Older than the playout sequence, or a duplicate: never played. */
  packetsLate: number;
  /** Dropped, oldest first, because the buffer already held `maxDelay` frames. */
  packetsOverflow: number;
  /** Sequence numbers skipped over a gap. */
  framesSkipped: number;
  framesConcealedCount: number;
  jitterMs: number;
  currentDelayFrames: number;
}

export class JitterBuffer {
  /** Ascending by sequence, without duplicates, every entry ≥ `nextPlaySeq`. */
  private buffer: BufferedPacket[] = [];
  private nextPlaySeq = -1;
  /** The highest sequence pushed since the last reset, or −1. */
  private highestPushed = -1;
  private lastPayload: ArrayBuffer | null = null;
  private concealedCount = 0;
  /** Playing: one frame per tick until the buffer runs empty (an underrun). */
  private playing = false;
  /** Ticks spent (re)buffering, waiting for `targetDelay` frames. */
  private waitTicks = 0;

  // Adaptive delay
  private jitterEstimate = 0;
  private haveTransit = false;
  private lastTransit = 0;
  private targetDelay: number;

  // Stats
  private stats: JitterBufferStats = {
    packetsReceived: 0,
    packetsPlayed: 0,
    packetsLate: 0,
    packetsOverflow: 0,
    framesSkipped: 0,
    framesConcealedCount: 0,
    jitterMs: 0,
    currentDelayFrames: DEFAULT_MIN_DELAY,
  };

  private frameDurationMs: number;
  private minDelay: number;
  private maxDelay: number;
  private maxConcealment: number;
  private now: () => number;

  constructor(opts?: {
    frameDurationMs?: number;
    minDelay?: number;
    maxDelay?: number;
    maxConcealment?: number;
    /** Arrival clock in milliseconds (default `performance.now`). */
    now?: () => number;
  }) {
    this.frameDurationMs = opts?.frameDurationMs ?? DEFAULT_FRAME_DURATION_MS;
    this.minDelay = opts?.minDelay ?? DEFAULT_MIN_DELAY;
    this.maxDelay = Math.max(this.minDelay, opts?.maxDelay ?? DEFAULT_MAX_DELAY);
    this.maxConcealment = opts?.maxConcealment ?? DEFAULT_MAX_CONCEALMENT;
    this.now = opts?.now ?? (() => performance.now());
    this.targetDelay = this.minDelay;
  }

  /** Push an incoming packet into the buffer. */
  push(sequence: number, payload: ArrayBuffer): void {
    const now = this.now();
    this.stats.packetsReceived++;
    if (sequence > this.highestPushed) this.highestPushed = sequence;

    // Update jitter estimate (RFC 3550 §6.4.1, A.8), with the sequence
    // number as the media timestamp: frames lost in a gap are not jitter.
    const transit = now - sequence * this.frameDurationMs;
    if (this.haveTransit) {
      const d = Math.abs(transit - this.lastTransit);
      this.jitterEstimate += JITTER_ALPHA * (d - this.jitterEstimate);
    }
    this.lastTransit = transit;
    this.haveTransit = true;

    // Initialize playout sequence
    if (this.nextPlaySeq < 0) {
      this.nextPlaySeq = sequence;
    }

    // Discard late packets
    if (sequence < this.nextPlaySeq) {
      this.stats.packetsLate++;
      return;
    }

    // Insert in order (searching from the newest end: in-order arrivals cost
    // one comparison), dropping duplicates.
    let idx = this.buffer.length;
    while (idx > 0 && this.buffer[idx - 1].sequence > sequence) idx--;
    if (idx > 0 && this.buffer[idx - 1].sequence === sequence) {
      this.stats.packetsLate++;
      return;
    }
    this.buffer.splice(idx, 0, { sequence, payload });

    // Bound: at most `maxDelay` frames; the oldest go, and the playout
    // sequence moves past them (forward only).
    if (this.buffer.length > this.maxDelay) {
      const excess = this.buffer.length - this.maxDelay;
      this.buffer.splice(0, excess);
      this.stats.packetsOverflow += excess;
      this.nextPlaySeq = this.buffer[0].sequence;
    }

    // Update target delay
    this.updateTargetDelay();
  }

  /**
   * Pull next frame for playout.
   * Call this every frameDurationMs (20ms).
   * Returns the audio payload, or null if concealment/silence should be output.
   */
  pull(): ArrayBuffer | null {
    const head = this.buffer[0];

    // Underrun: nothing buffered; playout re-buffers. The playout sequence
    // stays where it is, so a frame that is merely late still plays.
    if (!head) {
      this.playing = false;
      this.waitTicks = 0;
      if (this.lastPayload && this.concealedCount < this.maxConcealment) {
        // Repeat last frame (simple PLC)
        this.concealedCount++;
        this.stats.framesConcealedCount++;
        return this.lastPayload;
      }
      return null;
    }

    // (Re)buffering: wait for `targetDelay` frames, but for at most
    // `targetDelay` ticks.
    if (!this.playing) {
      if (this.buffer.length < this.targetDelay && this.waitTicks < this.targetDelay) {
        this.waitTicks++;
        return null;
      }
      this.playing = true;
      this.waitTicks = 0;
    }

    // A gap before the oldest buffered frame is skipped at once.
    if (head.sequence > this.nextPlaySeq) {
      this.stats.framesSkipped += head.sequence - this.nextPlaySeq;
    }
    this.buffer.shift();
    this.nextPlaySeq = head.sequence + 1;
    this.lastPayload = head.payload;
    this.concealedCount = 0;
    this.stats.packetsPlayed++;
    return head.payload;
  }

  /** Frames waiting for playout. */
  get buffered(): number {
    return this.buffer.length;
  }

  /**
   * The highest sequence received since the last reset, or −1 (SPEC-03
   * REQ-15 as amended by A2: the caller resets the buffer when the first
   * frame under a sender's newer epoch is not above it).
   */
  get highestReceived(): number {
    return this.highestPushed;
  }

  /** Reset buffer state (e.g., on re-join). */
  reset(): void {
    this.buffer = [];
    this.nextPlaySeq = -1;
    this.highestPushed = -1;
    this.lastPayload = null;
    this.concealedCount = 0;
    this.playing = false;
    this.waitTicks = 0;
    this.jitterEstimate = 0;
    this.haveTransit = false;
    this.lastTransit = 0;
    this.targetDelay = this.minDelay;
  }

  getStats(): JitterBufferStats {
    return {
      ...this.stats,
      jitterMs: this.jitterEstimate,
      currentDelayFrames: this.targetDelay,
    };
  }

  private updateTargetDelay(): void {
    const jitterFrames = this.jitterEstimate / this.frameDurationMs;
    const raw = this.minDelay + JITTER_FACTOR * jitterFrames;
    // Smooth transition (alpha = 0.1)
    this.targetDelay = Math.round(
      Math.min(this.maxDelay, Math.max(this.minDelay, this.targetDelay * 0.9 + raw * 0.1))
    );
  }
}
