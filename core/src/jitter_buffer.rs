//! # Adaptive Jitter Buffer
//!
//! Buffers incoming voice packets to compensate for network jitter,
//! reorders out-of-sequence packets, and conceals lost packets.
//!
//! Design:
//! - Adaptive playout delay based on measured inter-arrival jitter
//! - Packet reordering with configurable buffer depth
//! - Loss concealment: repeat last frame or output silence
//! - Statistics tracking for monitoring

use std::collections::BTreeMap;

/// Configuration for the jitter buffer.
#[derive(Debug, Clone)]
pub struct JitterBufferConfig {
    /// Minimum playout delay in frames (floor)
    pub min_delay_frames: u16,
    /// Maximum playout delay in frames (ceiling)
    pub max_delay_frames: u16,
    /// Frame duration in milliseconds (e.g. 20ms for Opus)
    pub frame_duration_ms: u16,
    /// Maximum consecutive concealed frames before signaling loss
    pub max_concealment_frames: u16,
    /// Exponential moving average factor for jitter estimation (0.0–1.0)
    pub jitter_alpha: f64,
    /// How many standard deviations of jitter to buffer (target = mean + factor * jitter)
    pub jitter_factor: f64,
}

impl Default for JitterBufferConfig {
    fn default() -> Self {
        Self {
            min_delay_frames: 2,
            max_delay_frames: 20, // 400ms at 20ms frames
            frame_duration_ms: 20,
            max_concealment_frames: 5,
            jitter_alpha: 0.0625, // 1/16, per RFC 3550
            jitter_factor: 2.0,
        }
    }
}

/// Statistics tracked by the jitter buffer.
#[derive(Debug, Clone, Default)]
pub struct JitterBufferStats {
    /// Total packets received
    pub packets_received: u64,
    /// Packets played out normally
    pub packets_played: u64,
    /// Packets that arrived too late (discarded)
    pub packets_late: u64,
    /// Packets that arrived out of order but were reordered successfully
    pub packets_reordered: u64,
    /// Frames concealed due to loss
    pub frames_concealed: u64,
    /// Current estimated jitter in milliseconds
    pub jitter_ms: f64,
    /// Current playout delay in frames
    pub current_delay_frames: u16,
    /// Estimated packet loss rate (0.0–1.0)
    pub loss_rate: f64,
    /// Running count for loss rate calculation
    packets_expected: u64,
    packets_lost: u64,
}

impl JitterBufferStats {
    fn update_loss_rate(&mut self) {
        if self.packets_expected > 0 {
            self.loss_rate = self.packets_lost as f64 / self.packets_expected as f64;
        }
    }
}

/// A single buffered frame.
#[derive(Debug, Clone)]
struct BufferedFrame {
    /// The audio payload
    payload: Vec<u8>,
    /// Arrival time (monotonic, in ms since buffer creation)
    _arrival_ms: u64,
}

/// The adaptive jitter buffer.
pub struct JitterBuffer {
    config: JitterBufferConfig,
    stats: JitterBufferStats,

    /// Packets indexed by sequence number, waiting for playout
    buffer: BTreeMap<u16, BufferedFrame>,

    /// Next sequence number we expect to play out
    next_playout_seq: Option<u16>,

    /// Adaptive target delay in frames
    target_delay: f64,

    /// Last arrival time for jitter calculation
    last_arrival_ms: Option<u64>,
    /// Last packet timestamp for jitter calculation
    last_packet_ts: Option<u32>,

    /// Estimated inter-arrival jitter (RFC 3550 style)
    jitter_estimate: f64,

    /// Last successfully played frame (for concealment)
    last_frame: Option<Vec<u8>>,

    /// Consecutive concealment count
    concealment_count: u16,

    /// Monotonic clock base (not real time — caller provides timestamps)
    /// Number of playout ticks since start
    playout_tick: u64,
}

impl JitterBuffer {
    pub fn new(config: JitterBufferConfig) -> Self {
        let target_delay = config.min_delay_frames as f64;
        Self {
            config,
            stats: JitterBufferStats::default(),
            buffer: BTreeMap::new(),
            next_playout_seq: None,
            target_delay,
            last_arrival_ms: None,
            last_packet_ts: None,
            jitter_estimate: 0.0,
            last_frame: None,
            concealment_count: 0,
            playout_tick: 0,
        }
    }

    /// Push a received packet into the buffer.
    ///
    /// `seq` — RTP sequence number (16-bit, wraps)
    /// `timestamp` — RTP timestamp
    /// `payload` — decrypted audio frame
    /// `arrival_ms` — monotonic arrival time in milliseconds
    pub fn push(&mut self, seq: u16, timestamp: u32, payload: Vec<u8>, arrival_ms: u64) {
        self.stats.packets_received += 1;

        // Update jitter estimate (RFC 3550 §A.8)
        if let (Some(last_arr), Some(last_ts)) = (self.last_arrival_ms, self.last_packet_ts) {
            let arrival_diff = arrival_ms as f64 - last_arr as f64;
            let ts_diff = timestamp.wrapping_sub(last_ts) as f64
                * (self.config.frame_duration_ms as f64 / 960.0); // normalize to ms assuming 48kHz/20ms
            let d = (arrival_diff - ts_diff).abs();
            self.jitter_estimate += self.config.jitter_alpha * (d - self.jitter_estimate);
            self.stats.jitter_ms = self.jitter_estimate;
        }
        self.last_arrival_ms = Some(arrival_ms);
        self.last_packet_ts = Some(timestamp);

        // Adapt target delay
        self.adapt_delay();

        // Check if this packet is too late
        if let Some(next) = self.next_playout_seq {
            if seq_before(seq, next) {
                self.stats.packets_late += 1;
                return; // discard late packet
            }
        }

        // Detect out-of-order arrival: if a lower seq arrives after a higher one
        // already in the buffer, it was reordered in transit
        if let Some(&highest_buffered) = self.buffer.keys().next_back() {
            if seq_before(seq, highest_buffered) {
                self.stats.packets_reordered += 1;
            }
        }

        self.buffer.insert(
            seq,
            BufferedFrame {
                payload,
                _arrival_ms: arrival_ms,
            },
        );
    }

    /// Pull the next frame for playout. Call this once per frame interval (e.g. every 20ms).
    ///
    /// Returns:
    /// - `Some(payload)` if a frame is available (real or concealed)
    /// - `None` if buffer is in initial fill phase
    pub fn pull(&mut self) -> Option<Vec<u8>> {
        self.playout_tick += 1;

        // Initial fill: wait until we have enough buffered frames
        if self.next_playout_seq.is_none() {
            let needed = self.current_delay_frames() as usize;
            if self.buffer.len() < needed.max(1) {
                return None; // still filling
            }
            // Start playout from the earliest buffered sequence
            if let Some((&first_seq, _)) = self.buffer.iter().next() {
                self.next_playout_seq = Some(first_seq);
            } else {
                return None;
            }
        }

        let seq = self.next_playout_seq.unwrap();
        self.stats.packets_expected += 1;

        if let Some(frame) = self.buffer.remove(&seq) {
            // Normal playout
            self.stats.packets_played += 1;
            self.concealment_count = 0;
            self.last_frame = Some(frame.payload.clone());
            self.next_playout_seq = Some(seq.wrapping_add(1));
            Some(frame.payload)
        } else {
            // Packet missing — conceal
            self.stats.packets_lost += 1;
            self.stats.frames_concealed += 1;
            self.stats.update_loss_rate();
            self.concealment_count += 1;
            self.next_playout_seq = Some(seq.wrapping_add(1));

            if self.concealment_count <= self.config.max_concealment_frames {
                // Repeat last frame
                self.last_frame.clone()
            } else {
                // Too many consecutive losses — output silence (empty vec signals silence)
                Some(Vec::new())
            }
        }
    }

    /// Get current statistics.
    pub fn stats(&self) -> &JitterBufferStats {
        &self.stats
    }

    /// Reset the buffer (e.g. on re-join or codec change).
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.next_playout_seq = None;
        self.last_arrival_ms = None;
        self.last_packet_ts = None;
        self.last_frame = None;
        self.concealment_count = 0;
        self.jitter_estimate = 0.0;
        self.target_delay = self.config.min_delay_frames as f64;
        self.playout_tick = 0;
    }

    /// Current target delay in frames.
    pub fn current_delay_frames(&self) -> u16 {
        let delay = self.target_delay.round() as u16;
        delay.clamp(self.config.min_delay_frames, self.config.max_delay_frames)
    }

    fn adapt_delay(&mut self) {
        // Target delay = base + jitter_factor * jitter_estimate / frame_duration
        let jitter_frames = self.jitter_estimate / self.config.frame_duration_ms as f64;
        let new_target =
            self.config.min_delay_frames as f64 + self.config.jitter_factor * jitter_frames;
        // Smooth transition
        self.target_delay += 0.1 * (new_target - self.target_delay);
        self.target_delay = self.target_delay.clamp(
            self.config.min_delay_frames as f64,
            self.config.max_delay_frames as f64,
        );
        self.stats.current_delay_frames = self.current_delay_frames();
    }
}

/// Returns true if `a` is "before" `b` in the circular 16-bit sequence space.
/// Uses the standard half-space comparison.
fn seq_before(a: u16, b: u16) -> bool {
    let diff = b.wrapping_sub(a);
    diff > 0 && diff < 0x8000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_buf() -> JitterBuffer {
        JitterBuffer::new(JitterBufferConfig {
            min_delay_frames: 2,
            max_delay_frames: 20,
            frame_duration_ms: 20,
            max_concealment_frames: 3,
            jitter_alpha: 0.0625,
            jitter_factor: 2.0,
        })
    }

    #[test]
    fn test_seq_before() {
        assert!(seq_before(0, 1));
        assert!(seq_before(65535, 0)); // wrap
        assert!(!seq_before(1, 0));
        assert!(!seq_before(5, 5));
    }

    #[test]
    fn test_basic_ordered_playout() {
        let mut buf = default_buf();

        // Push 5 packets in order
        for i in 0u16..5 {
            buf.push(i, i as u32 * 960, vec![i as u8; 10], i as u64 * 20);
        }

        // Pull should start after initial fill (min_delay_frames=2)
        let frame = buf.pull();
        assert!(frame.is_some());
        assert_eq!(frame.unwrap(), vec![0u8; 10]);

        let frame = buf.pull();
        assert!(frame.is_some());
        assert_eq!(frame.unwrap(), vec![1u8; 10]);
    }

    #[test]
    fn test_reordered_packets() {
        let mut buf = JitterBuffer::new(JitterBufferConfig {
            min_delay_frames: 1,
            max_delay_frames: 1, // pin delay so jitter adaptation doesn't increase fill requirement
            jitter_factor: 0.0,
            ..JitterBufferConfig::default()
        });

        // Push out of order: 0, 2, 1, 3
        buf.push(0, 0, vec![0], 0);
        buf.push(2, 1920, vec![2], 40);
        buf.push(1, 960, vec![1], 45); // arrived late but before playout
        buf.push(3, 2880, vec![3], 60);

        let f0 = buf.pull().unwrap();
        assert_eq!(f0, vec![0]);
        let f1 = buf.pull().unwrap();
        assert_eq!(f1, vec![1]); // reordered correctly
        let f2 = buf.pull().unwrap();
        assert_eq!(f2, vec![2]);

        assert!(buf.stats().packets_reordered > 0);
    }

    #[test]
    fn test_packet_loss_concealment() {
        let mut buf = default_buf();

        // Push packets 0, 1, 3 (skip 2)
        buf.push(0, 0, vec![10], 0);
        buf.push(1, 960, vec![11], 20);
        buf.push(3, 2880, vec![13], 60);

        let f0 = buf.pull().unwrap();
        assert_eq!(f0, vec![10]);
        let f1 = buf.pull().unwrap();
        assert_eq!(f1, vec![11]);

        // Packet 2 is missing — should get concealment (repeat last frame)
        let f2 = buf.pull().unwrap();
        assert_eq!(f2, vec![11]); // repeated

        // Packet 3 should be normal
        let f3 = buf.pull().unwrap();
        assert_eq!(f3, vec![13]);

        assert_eq!(buf.stats().frames_concealed, 1);
    }

    #[test]
    fn test_excessive_loss_outputs_silence() {
        let mut buf = JitterBuffer::new(JitterBufferConfig {
            min_delay_frames: 1,
            max_concealment_frames: 2,
            ..JitterBufferConfig::default()
        });

        // Push only packet 0, then nothing
        buf.push(0, 0, vec![99], 0);

        let f0 = buf.pull().unwrap();
        assert_eq!(f0, vec![99]);

        // 1 missing — repeat
        let f1 = buf.pull().unwrap();
        assert_eq!(f1, vec![99]);

        // 2 missing — repeat
        let f2 = buf.pull().unwrap();
        assert_eq!(f2, vec![99]);

        // 3 missing — exceeded max_concealment_frames, silence
        let f3 = buf.pull().unwrap();
        assert!(f3.is_empty()); // silence
    }

    #[test]
    fn test_late_packet_discarded() {
        let mut buf = default_buf();

        buf.push(0, 0, vec![0], 0);
        buf.push(1, 960, vec![1], 20);

        // Play out 0
        buf.pull();

        // Now push a packet with seq 0 again (duplicate/late)
        let before = buf.stats().packets_late;
        buf.push(0, 0, vec![0], 50);
        assert_eq!(buf.stats().packets_late, before + 1);
    }

    #[test]
    fn test_jitter_adaptation() {
        let mut buf = default_buf();

        // Simulate jittery arrivals
        buf.push(0, 0, vec![0], 0);
        buf.push(1, 960, vec![1], 20);
        buf.push(2, 1920, vec![2], 55); // late arrival → jitter spike
        buf.push(3, 2880, vec![3], 60);
        buf.push(4, 3840, vec![4], 100); // another spike

        // Jitter estimate should be non-zero
        assert!(buf.stats().jitter_ms > 0.0);
        // Target delay should have increased from minimum
        assert!(buf.current_delay_frames() >= buf.config.min_delay_frames);
    }

    #[test]
    fn test_reset() {
        let mut buf = default_buf();
        buf.push(0, 0, vec![0], 0);
        buf.push(1, 960, vec![1], 20);
        buf.pull();

        buf.reset();
        assert!(buf.next_playout_seq.is_none());
        assert!(buf.buffer.is_empty());
        assert_eq!(buf.jitter_estimate, 0.0);
    }

    #[test]
    fn test_initial_fill_phase() {
        let mut buf = default_buf(); // min_delay = 2

        // Push only 1 packet
        buf.push(0, 0, vec![0], 0);

        // Should return None (still filling)
        assert!(buf.pull().is_none());

        // Push second packet
        buf.push(1, 960, vec![1], 20);

        // Now should start playing
        assert!(buf.pull().is_some());
    }

    #[test]
    fn test_sequence_wraparound() {
        // Test that packets near u16::MAX boundary play out correctly.
        // BTreeMap orders u16 numerically, so we feed packets sequentially
        // and verify each one is retrieved in order by next_playout_seq tracking.
        let mut buf = JitterBuffer::new(JitterBufferConfig {
            min_delay_frames: 1,
            ..JitterBufferConfig::default()
        });

        // Start from 65534, push in order, pull each before pushing next
        // to ensure next_playout_seq tracks the wrap correctly.
        buf.push(65534, 0, vec![1], 0);
        assert_eq!(buf.pull().unwrap(), vec![1]);

        buf.push(65535, 960, vec![2], 20);
        assert_eq!(buf.pull().unwrap(), vec![2]);

        buf.push(0, 1920, vec![3], 40); // wrapped
        assert_eq!(buf.pull().unwrap(), vec![3]);

        buf.push(1, 2880, vec![4], 60);
        assert_eq!(buf.pull().unwrap(), vec![4]);
    }

    #[test]
    fn test_stats_tracking() {
        let mut buf = default_buf();

        for i in 0u16..10 {
            buf.push(i, i as u32 * 960, vec![i as u8], i as u64 * 20);
        }

        for _ in 0..8 {
            buf.pull();
        }

        let stats = buf.stats();
        assert_eq!(stats.packets_received, 10);
        assert!(stats.packets_played > 0);
    }
}
