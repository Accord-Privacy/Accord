/**
 * Adaptive jitter buffer for voice playback.
 *
 * TypeScript port of core/src/jitter_buffer.rs concepts.
 * Buffers incoming packets, reorders them, and adapts delay
 * based on measured jitter (RFC 3550 exponential moving average).
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
  arrivalMs: number;
}

export interface JitterBufferStats {
  packetsReceived: number;
  packetsPlayed: number;
  packetsLate: number;
  framesConcealedCount: number;
  jitterMs: number;
  currentDelayFrames: number;
}

export class JitterBuffer {
  private buffer: BufferedPacket[] = [];
  private nextPlaySeq = -1;
  private lastPayload: ArrayBuffer | null = null;
  private concealedCount = 0;

  // Adaptive delay
  private jitterEstimate = 0;
  private lastArrivalMs = 0;
  private lastTransit = 0;
  private targetDelay: number;

  // Stats
  private stats: JitterBufferStats = {
    packetsReceived: 0,
    packetsPlayed: 0,
    packetsLate: 0,
    framesConcealedCount: 0,
    jitterMs: 0,
    currentDelayFrames: DEFAULT_MIN_DELAY,
  };

  private frameDurationMs: number;
  private minDelay: number;
  private maxDelay: number;
  private maxConcealment: number;

  constructor(opts?: {
    frameDurationMs?: number;
    minDelay?: number;
    maxDelay?: number;
    maxConcealment?: number;
  }) {
    this.frameDurationMs = opts?.frameDurationMs ?? DEFAULT_FRAME_DURATION_MS;
    this.minDelay = opts?.minDelay ?? DEFAULT_MIN_DELAY;
    this.maxDelay = opts?.maxDelay ?? DEFAULT_MAX_DELAY;
    this.maxConcealment = opts?.maxConcealment ?? DEFAULT_MAX_CONCEALMENT;
    this.targetDelay = this.minDelay;
  }

  /** Push an incoming packet into the buffer. */
  push(sequence: number, payload: ArrayBuffer): void {
    const now = performance.now();
    this.stats.packetsReceived++;

    // Update jitter estimate (RFC 3550 §6.4.1)
    if (this.lastArrivalMs > 0) {
      const arrival = now - this.lastArrivalMs;
      const transit = arrival - this.frameDurationMs;
      const d = Math.abs(transit - this.lastTransit);
      this.jitterEstimate += JITTER_ALPHA * (d - this.jitterEstimate);
      this.lastTransit = transit;
    }
    this.lastArrivalMs = now;

    // Initialize playout sequence
    if (this.nextPlaySeq < 0) {
      this.nextPlaySeq = sequence;
    }

    // Discard late packets
    if (sequence < this.nextPlaySeq) {
      this.stats.packetsLate++;
      return;
    }

    // Insert in order
    const idx = this.buffer.findIndex(p => p.sequence > sequence);
    const packet: BufferedPacket = { sequence, payload, arrivalMs: now };
    if (idx === -1) {
      this.buffer.push(packet);
    } else {
      // Deduplicate
      if (this.buffer[idx]?.sequence === sequence) return;
      this.buffer.splice(idx, 0, packet);
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
    // Wait until we've buffered enough
    if (this.buffer.length < this.targetDelay && this.nextPlaySeq <= (this.buffer[0]?.sequence ?? 0)) {
      return null;
    }

    // Look for the expected sequence
    const idx = this.buffer.findIndex(p => p.sequence === this.nextPlaySeq);

    if (idx >= 0) {
      // Found the expected packet
      const packet = this.buffer.splice(idx, 1)[0];
      this.lastPayload = packet.payload;
      this.concealedCount = 0;
      this.nextPlaySeq++;
      this.stats.packetsPlayed++;
      return packet.payload;
    }

    // Packet missing — concealment
    this.concealedCount++;
    this.stats.framesConcealedCount++;
    this.nextPlaySeq++;

    if (this.concealedCount <= this.maxConcealment && this.lastPayload) {
      // Repeat last frame (simple PLC)
      return this.lastPayload;
    }

    // Too many consecutive losses — output silence
    return null;
  }

  /** Reset buffer state (e.g., on re-join). */
  reset(): void {
    this.buffer = [];
    this.nextPlaySeq = -1;
    this.lastPayload = null;
    this.concealedCount = 0;
    this.jitterEstimate = 0;
    this.lastArrivalMs = 0;
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
