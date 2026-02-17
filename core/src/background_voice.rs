//! # Background Voice Session
//!
//! Manages voice call state across mobile app lifecycle events (foreground/background).
//!
//! When a mobile app is backgrounded during a voice call, this module:
//! - Transitions the session through a state machine (Active → Backgrounded → Reconnecting → Active)
//! - Continues receiving audio packets, buffering them for playback on resume
//! - Sends periodic STUN keepalive pings to prevent NAT binding timeout
//! - Optionally mutes the microphone while backgrounded
//! - Tracks statistics (time backgrounded, packets received, reconnections)
//!
//! Platform-specific integration (iOS `AVAudioSession`, Android foreground services)
//! is handled by the native app layer; this module provides the core Rust logic
//! exposed via FFI/JNI.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

// ─── Constants ───────────────────────────────────────────────────────────────

/// STUN keepalive interval to prevent NAT timeout (RFC 8445 recommends ≤15s)
pub const KEEPALIVE_INTERVAL_MS: u64 = 10_000;

/// Maximum time to stay backgrounded before giving up (5 minutes)
pub const MAX_BACKGROUND_DURATION_MS: u64 = 300_000;

/// Maximum buffered audio frames while backgrounded (avoid OOM)
pub const MAX_BACKGROUND_BUFFER_FRAMES: usize = 500;

/// Reconnection timeout after network change (ms)
pub const RECONNECT_TIMEOUT_MS: u64 = 10_000;

/// Maximum reconnection attempts before declaring failure
pub const MAX_RECONNECT_ATTEMPTS: u32 = 5;

// ─── State Machine ───────────────────────────────────────────────────────────

/// Voice session lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoiceLifecycleState {
    /// App is in foreground, full audio I/O active.
    Active,
    /// App has been backgrounded. Receiving continues; mic may be muted.
    Backgrounded,
    /// Network connectivity changed while backgrounded; attempting reconnection.
    Reconnecting,
    /// Session has been suspended (exceeded max background duration or failed reconnection).
    Suspended,
}

// ─── Configuration ───────────────────────────────────────────────────────────

/// Configuration for background voice behavior.
#[derive(Debug, Clone)]
pub struct BackgroundVoiceConfig {
    /// Mute microphone when app is backgrounded.
    pub mute_on_background: bool,
    /// STUN keepalive interval in milliseconds.
    pub keepalive_interval_ms: u64,
    /// Maximum time to remain backgrounded before suspending (ms).
    pub max_background_duration_ms: u64,
    /// Maximum audio frames to buffer while backgrounded.
    pub max_buffer_frames: usize,
    /// Maximum reconnection attempts.
    pub max_reconnect_attempts: u32,
}

impl Default for BackgroundVoiceConfig {
    fn default() -> Self {
        Self {
            mute_on_background: true,
            keepalive_interval_ms: KEEPALIVE_INTERVAL_MS,
            max_background_duration_ms: MAX_BACKGROUND_DURATION_MS,
            max_buffer_frames: MAX_BACKGROUND_BUFFER_FRAMES,
            max_reconnect_attempts: MAX_RECONNECT_ATTEMPTS,
        }
    }
}

// ─── Statistics ──────────────────────────────────────────────────────────────

/// Statistics for the background voice session.
#[derive(Debug, Clone, Default)]
pub struct BackgroundVoiceStats {
    /// Total time spent in background state (ms).
    pub total_background_ms: u64,
    /// Number of packets received while backgrounded.
    pub packets_received_in_background: u64,
    /// Number of keepalive pings sent.
    pub keepalives_sent: u64,
    /// Number of successful reconnections.
    pub reconnection_count: u32,
    /// Number of failed reconnection attempts.
    pub failed_reconnections: u32,
    /// Number of audio frames dropped due to buffer overflow.
    pub frames_dropped: u64,
    /// Current state.
    pub current_state: Option<VoiceLifecycleState>,
}

// ─── Background Voice Session ────────────────────────────────────────────────

/// Manages voice state that persists across app lifecycle events.
///
/// Thread-safe: the inner state is behind a Mutex, and the `mic_muted` flag
/// is an AtomicBool for lock-free reads from the audio thread.
pub struct BackgroundVoiceSession {
    inner: Mutex<SessionInner>,
    /// Atomic mic-muted flag readable from the audio render thread without locking.
    mic_muted: AtomicBool,
}

struct SessionInner {
    state: VoiceLifecycleState,
    config: BackgroundVoiceConfig,
    stats: BackgroundVoiceStats,

    /// Timestamp (monotonic ms) when we entered background.
    background_entered_ms: Option<u64>,
    /// Timestamp of last keepalive sent.
    last_keepalive_ms: Option<u64>,

    /// Audio frames received while backgrounded, queued for playback on resume.
    background_audio_buffer: VecDeque<Vec<u8>>,

    /// Reconnection state.
    reconnect_attempts: u32,
    reconnect_started_ms: Option<u64>,
}

impl BackgroundVoiceSession {
    /// Create a new background voice session with the given configuration.
    pub fn new(config: BackgroundVoiceConfig) -> Self {
        let mic_muted = AtomicBool::new(false);
        Self {
            inner: Mutex::new(SessionInner {
                state: VoiceLifecycleState::Active,
                config,
                stats: BackgroundVoiceStats::default(),
                background_entered_ms: None,
                last_keepalive_ms: None,
                background_audio_buffer: VecDeque::new(),
                reconnect_attempts: 0,
                reconnect_started_ms: None,
            }),
            mic_muted,
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(BackgroundVoiceConfig::default())
    }

    // ── Lifecycle transitions ────────────────────────────────────────────

    /// Transition to backgrounded state. Called when the app enters background.
    ///
    /// Returns the new state, or `None` if the transition is invalid.
    pub fn enter_background(&self, now_ms: u64) -> Option<VoiceLifecycleState> {
        let mut inner = self.inner.lock().unwrap();
        match inner.state {
            VoiceLifecycleState::Active => {
                inner.state = VoiceLifecycleState::Backgrounded;
                inner.background_entered_ms = Some(now_ms);
                inner.last_keepalive_ms = Some(now_ms);
                inner.stats.current_state = Some(VoiceLifecycleState::Backgrounded);

                if inner.config.mute_on_background {
                    self.mic_muted.store(true, Ordering::Release);
                }

                Some(VoiceLifecycleState::Backgrounded)
            }
            _ => None, // Already backgrounded/suspended
        }
    }

    /// Transition back to active state. Called when the app enters foreground.
    ///
    /// Returns the new state, or `None` if the transition is invalid.
    pub fn enter_foreground(&self, now_ms: u64) -> Option<VoiceLifecycleState> {
        let mut inner = self.inner.lock().unwrap();
        match inner.state {
            VoiceLifecycleState::Backgrounded | VoiceLifecycleState::Reconnecting => {
                // Accumulate background time
                if let Some(entered) = inner.background_entered_ms.take() {
                    inner.stats.total_background_ms += now_ms.saturating_sub(entered);
                }

                inner.state = VoiceLifecycleState::Active;
                inner.reconnect_attempts = 0;
                inner.reconnect_started_ms = None;
                inner.stats.current_state = Some(VoiceLifecycleState::Active);

                if inner.config.mute_on_background {
                    self.mic_muted.store(false, Ordering::Release);
                }

                Some(VoiceLifecycleState::Active)
            }
            VoiceLifecycleState::Suspended => {
                // Can resume from suspended if the platform wants
                if let Some(entered) = inner.background_entered_ms.take() {
                    inner.stats.total_background_ms += now_ms.saturating_sub(entered);
                }
                inner.state = VoiceLifecycleState::Active;
                inner.stats.current_state = Some(VoiceLifecycleState::Active);
                self.mic_muted.store(false, Ordering::Release);
                Some(VoiceLifecycleState::Active)
            }
            _ => None,
        }
    }

    /// Signal that a network change was detected while backgrounded.
    /// Transitions to Reconnecting state.
    pub fn on_network_change(&self, now_ms: u64) -> Option<VoiceLifecycleState> {
        let mut inner = self.inner.lock().unwrap();
        if inner.state == VoiceLifecycleState::Backgrounded {
            inner.state = VoiceLifecycleState::Reconnecting;
            inner.reconnect_attempts = 0;
            inner.reconnect_started_ms = Some(now_ms);
            inner.stats.current_state = Some(VoiceLifecycleState::Reconnecting);
            Some(VoiceLifecycleState::Reconnecting)
        } else {
            None
        }
    }

    /// Record a successful reconnection. Returns to Backgrounded state.
    pub fn on_reconnect_success(&self) -> Option<VoiceLifecycleState> {
        let mut inner = self.inner.lock().unwrap();
        if inner.state == VoiceLifecycleState::Reconnecting {
            inner.state = VoiceLifecycleState::Backgrounded;
            inner.stats.reconnection_count += 1;
            inner.reconnect_attempts = 0;
            inner.reconnect_started_ms = None;
            inner.stats.current_state = Some(VoiceLifecycleState::Backgrounded);
            Some(VoiceLifecycleState::Backgrounded)
        } else {
            None
        }
    }

    /// Record a failed reconnection attempt.
    /// Returns `Suspended` if max attempts exceeded.
    pub fn on_reconnect_failure(&self) -> VoiceLifecycleState {
        let mut inner = self.inner.lock().unwrap();
        if inner.state != VoiceLifecycleState::Reconnecting {
            return inner.state;
        }

        inner.reconnect_attempts += 1;
        inner.stats.failed_reconnections += 1;

        if inner.reconnect_attempts >= inner.config.max_reconnect_attempts {
            inner.state = VoiceLifecycleState::Suspended;
            inner.stats.current_state = Some(VoiceLifecycleState::Suspended);
        }
        inner.state
    }

    // ── Keepalive ────────────────────────────────────────────────────────

    /// Check if a keepalive ping should be sent now.
    /// Returns `true` if it's time to send one, and updates the last-sent timestamp.
    pub fn should_send_keepalive(&self, now_ms: u64) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.state != VoiceLifecycleState::Backgrounded {
            return false;
        }

        let interval = inner.config.keepalive_interval_ms;
        let should_send = match inner.last_keepalive_ms {
            Some(last) => now_ms.saturating_sub(last) >= interval,
            None => true,
        };

        if should_send {
            inner.last_keepalive_ms = Some(now_ms);
            inner.stats.keepalives_sent += 1;
        }

        should_send
    }

    // ── Tick / periodic check ────────────────────────────────────────────

    /// Periodic tick called from the platform timer. Checks for timeouts.
    ///
    /// Returns the current state after processing.
    pub fn tick(&self, now_ms: u64) -> VoiceLifecycleState {
        let mut inner = self.inner.lock().unwrap();

        match inner.state {
            VoiceLifecycleState::Backgrounded => {
                // Check max background duration
                if let Some(entered) = inner.background_entered_ms {
                    if now_ms.saturating_sub(entered) >= inner.config.max_background_duration_ms {
                        inner.state = VoiceLifecycleState::Suspended;
                        inner.stats.current_state = Some(VoiceLifecycleState::Suspended);
                    }
                }
            }
            VoiceLifecycleState::Reconnecting => {
                // Check reconnection timeout
                if let Some(started) = inner.reconnect_started_ms {
                    if now_ms.saturating_sub(started) >= RECONNECT_TIMEOUT_MS {
                        inner.reconnect_attempts += 1;
                        inner.stats.failed_reconnections += 1;
                        if inner.reconnect_attempts >= inner.config.max_reconnect_attempts {
                            inner.state = VoiceLifecycleState::Suspended;
                            inner.stats.current_state = Some(VoiceLifecycleState::Suspended);
                        } else {
                            inner.reconnect_started_ms = Some(now_ms);
                        }
                    }
                }
            }
            _ => {}
        }

        inner.state
    }

    // ── Audio buffering ──────────────────────────────────────────────────

    /// Buffer an incoming audio frame received while backgrounded.
    /// Drops oldest frames if the buffer is full.
    pub fn buffer_audio_frame(&self, frame: Vec<u8>) {
        let mut inner = self.inner.lock().unwrap();
        if inner.state != VoiceLifecycleState::Backgrounded
            && inner.state != VoiceLifecycleState::Reconnecting
        {
            return;
        }

        inner.stats.packets_received_in_background += 1;

        if inner.background_audio_buffer.len() >= inner.config.max_buffer_frames {
            inner.background_audio_buffer.pop_front();
            inner.stats.frames_dropped += 1;
        }
        inner.background_audio_buffer.push_back(frame);
    }

    /// Drain all buffered audio frames (called on return to foreground).
    pub fn drain_buffered_audio(&self) -> Vec<Vec<u8>> {
        let mut inner = self.inner.lock().unwrap();
        inner.background_audio_buffer.drain(..).collect()
    }

    // ── Queries ──────────────────────────────────────────────────────────

    /// Get the current lifecycle state.
    pub fn state(&self) -> VoiceLifecycleState {
        self.inner.lock().unwrap().state
    }

    /// Check if the microphone is muted (lock-free for audio thread).
    pub fn is_mic_muted(&self) -> bool {
        self.mic_muted.load(Ordering::Acquire)
    }

    /// Check if the voice session is still active (not suspended).
    pub fn is_active(&self) -> bool {
        let state = self.inner.lock().unwrap().state;
        state != VoiceLifecycleState::Suspended
    }

    /// Get a snapshot of the current statistics.
    pub fn stats(&self) -> BackgroundVoiceStats {
        let inner = self.inner.lock().unwrap();
        let mut stats = inner.stats.clone();
        stats.current_state = Some(inner.state);
        stats
    }

    /// Get the number of buffered audio frames.
    pub fn buffered_frame_count(&self) -> usize {
        self.inner.lock().unwrap().background_audio_buffer.len()
    }
}

// ─── Thread-safe wrapper for FFI ─────────────────────────────────────────────

/// Arc-wrapped session for sharing across FFI boundary.
pub type SharedBackgroundVoiceSession = Arc<BackgroundVoiceSession>;

/// Create a new shared session suitable for FFI use.
pub fn create_shared_session(config: BackgroundVoiceConfig) -> SharedBackgroundVoiceSession {
    Arc::new(BackgroundVoiceSession::new(config))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_session() -> BackgroundVoiceSession {
        BackgroundVoiceSession::with_defaults()
    }

    // ── State transition tests ───────────────────────────────────────────

    #[test]
    fn test_initial_state_is_active() {
        let session = default_session();
        assert_eq!(session.state(), VoiceLifecycleState::Active);
        assert!(session.is_active());
    }

    #[test]
    fn test_enter_background_from_active() {
        let session = default_session();
        let result = session.enter_background(1000);
        assert_eq!(result, Some(VoiceLifecycleState::Backgrounded));
        assert_eq!(session.state(), VoiceLifecycleState::Backgrounded);
    }

    #[test]
    fn test_enter_background_when_already_backgrounded() {
        let session = default_session();
        session.enter_background(1000);
        let result = session.enter_background(2000);
        assert_eq!(result, None); // Invalid transition
    }

    #[test]
    fn test_enter_foreground_from_backgrounded() {
        let session = default_session();
        session.enter_background(1000);
        let result = session.enter_foreground(5000);
        assert_eq!(result, Some(VoiceLifecycleState::Active));
        assert_eq!(session.stats().total_background_ms, 4000);
    }

    #[test]
    fn test_enter_foreground_from_reconnecting() {
        let session = default_session();
        session.enter_background(1000);
        session.on_network_change(2000);
        assert_eq!(session.state(), VoiceLifecycleState::Reconnecting);

        let result = session.enter_foreground(3000);
        assert_eq!(result, Some(VoiceLifecycleState::Active));
    }

    #[test]
    fn test_enter_foreground_from_suspended() {
        let session = default_session();
        session.enter_background(0);
        // Force suspended via max background duration
        let _ = session.tick(MAX_BACKGROUND_DURATION_MS + 1);
        assert_eq!(session.state(), VoiceLifecycleState::Suspended);

        let result = session.enter_foreground(MAX_BACKGROUND_DURATION_MS + 100);
        assert_eq!(result, Some(VoiceLifecycleState::Active));
    }

    #[test]
    fn test_network_change_triggers_reconnecting() {
        let session = default_session();
        session.enter_background(1000);
        let result = session.on_network_change(2000);
        assert_eq!(result, Some(VoiceLifecycleState::Reconnecting));
    }

    #[test]
    fn test_network_change_only_from_backgrounded() {
        let session = default_session();
        // From Active — should be None
        let result = session.on_network_change(1000);
        assert_eq!(result, None);
    }

    #[test]
    fn test_reconnect_success() {
        let session = default_session();
        session.enter_background(1000);
        session.on_network_change(2000);
        let result = session.on_reconnect_success();
        assert_eq!(result, Some(VoiceLifecycleState::Backgrounded));
        assert_eq!(session.stats().reconnection_count, 1);
    }

    #[test]
    fn test_reconnect_failure_exhausts_attempts() {
        let config = BackgroundVoiceConfig {
            max_reconnect_attempts: 3,
            ..Default::default()
        };
        let session = BackgroundVoiceSession::new(config);
        session.enter_background(1000);
        session.on_network_change(2000);

        for i in 0..2 {
            let state = session.on_reconnect_failure();
            assert_eq!(state, VoiceLifecycleState::Reconnecting, "attempt {}", i);
        }

        let state = session.on_reconnect_failure();
        assert_eq!(state, VoiceLifecycleState::Suspended);
        assert!(!session.is_active());
    }

    // ── Mic mute tests ──────────────────────────────────────────────────

    #[test]
    fn test_mic_muted_on_background() {
        let session = default_session();
        assert!(!session.is_mic_muted());
        session.enter_background(1000);
        assert!(session.is_mic_muted());
        session.enter_foreground(2000);
        assert!(!session.is_mic_muted());
    }

    #[test]
    fn test_mic_not_muted_when_config_disabled() {
        let config = BackgroundVoiceConfig {
            mute_on_background: false,
            ..Default::default()
        };
        let session = BackgroundVoiceSession::new(config);
        session.enter_background(1000);
        assert!(!session.is_mic_muted());
    }

    // ── Keepalive tests ─────────────────────────────────────────────────

    #[test]
    fn test_keepalive_timing() {
        let session = default_session();
        session.enter_background(0);

        // Immediately after background, first keepalive was set
        assert!(!session.should_send_keepalive(5000)); // Not yet
        assert!(session.should_send_keepalive(KEEPALIVE_INTERVAL_MS)); // Exactly at interval
        assert!(!session.should_send_keepalive(KEEPALIVE_INTERVAL_MS + 100)); // Just sent
        assert!(session.should_send_keepalive(KEEPALIVE_INTERVAL_MS * 2)); // Next interval
    }

    #[test]
    fn test_keepalive_not_sent_when_active() {
        let session = default_session();
        assert!(!session.should_send_keepalive(KEEPALIVE_INTERVAL_MS * 10));
    }

    #[test]
    fn test_keepalive_stats() {
        let session = default_session();
        session.enter_background(0);
        session.should_send_keepalive(KEEPALIVE_INTERVAL_MS);
        session.should_send_keepalive(KEEPALIVE_INTERVAL_MS * 2);
        assert_eq!(session.stats().keepalives_sent, 2);
    }

    // ── Audio buffer tests ──────────────────────────────────────────────

    #[test]
    fn test_buffer_audio_while_backgrounded() {
        let session = default_session();
        session.enter_background(0);

        session.buffer_audio_frame(vec![1, 2, 3]);
        session.buffer_audio_frame(vec![4, 5, 6]);

        assert_eq!(session.buffered_frame_count(), 2);
        assert_eq!(session.stats().packets_received_in_background, 2);
    }

    #[test]
    fn test_buffer_not_filled_when_active() {
        let session = default_session();
        session.buffer_audio_frame(vec![1, 2, 3]);
        assert_eq!(session.buffered_frame_count(), 0);
    }

    #[test]
    fn test_buffer_overflow_drops_oldest() {
        let config = BackgroundVoiceConfig {
            max_buffer_frames: 3,
            ..Default::default()
        };
        let session = BackgroundVoiceSession::new(config);
        session.enter_background(0);

        for i in 0..5u8 {
            session.buffer_audio_frame(vec![i]);
        }

        assert_eq!(session.buffered_frame_count(), 3);
        assert_eq!(session.stats().frames_dropped, 2);

        let drained = session.drain_buffered_audio();
        assert_eq!(drained, vec![vec![2], vec![3], vec![4]]);
    }

    #[test]
    fn test_drain_buffered_audio() {
        let session = default_session();
        session.enter_background(0);
        session.buffer_audio_frame(vec![10]);
        session.buffer_audio_frame(vec![20]);

        let frames = session.drain_buffered_audio();
        assert_eq!(frames.len(), 2);
        assert_eq!(session.buffered_frame_count(), 0);
    }

    // ── Tick / timeout tests ────────────────────────────────────────────

    #[test]
    fn test_tick_suspends_after_max_duration() {
        let session = default_session();
        session.enter_background(0);

        let state = session.tick(MAX_BACKGROUND_DURATION_MS - 1);
        assert_eq!(state, VoiceLifecycleState::Backgrounded);

        let state = session.tick(MAX_BACKGROUND_DURATION_MS + 1);
        assert_eq!(state, VoiceLifecycleState::Suspended);
    }

    #[test]
    fn test_tick_reconnect_timeout() {
        let config = BackgroundVoiceConfig {
            max_reconnect_attempts: 2,
            ..Default::default()
        };
        let session = BackgroundVoiceSession::new(config);
        session.enter_background(0);
        session.on_network_change(1000);

        // First timeout — retries
        let state = session.tick(1000 + RECONNECT_TIMEOUT_MS + 1);
        assert_eq!(state, VoiceLifecycleState::Reconnecting);

        // Second timeout — suspends
        let state = session.tick(1000 + RECONNECT_TIMEOUT_MS * 2 + 2);
        assert_eq!(state, VoiceLifecycleState::Suspended);
    }

    // ── Stats tests ─────────────────────────────────────────────────────

    #[test]
    fn test_stats_snapshot() {
        let session = default_session();
        session.enter_background(1000);
        session.buffer_audio_frame(vec![1]);
        session.should_send_keepalive(KEEPALIVE_INTERVAL_MS + 1000);

        let stats = session.stats();
        assert_eq!(stats.packets_received_in_background, 1);
        assert_eq!(stats.keepalives_sent, 1);
        assert_eq!(stats.current_state, Some(VoiceLifecycleState::Backgrounded));
    }

    // ── Thread safety ───────────────────────────────────────────────────

    #[test]
    fn test_shared_session() {
        let shared = create_shared_session(BackgroundVoiceConfig::default());
        let clone = Arc::clone(&shared);

        shared.enter_background(0);
        assert_eq!(clone.state(), VoiceLifecycleState::Backgrounded);
    }
}
