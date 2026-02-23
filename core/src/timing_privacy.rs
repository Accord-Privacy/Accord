//! # Timing Privacy
//!
//! Helpers for obfuscating message timing patterns to prevent traffic analysis.
//!
//! - **Jitter delays**: Add random delays to message forwarding so the relay
//!   can't correlate send/receive times precisely.
//! - **Dummy traffic**: Probabilistic generation of cover traffic that is
//!   indistinguishable from real messages at the relay level.

use rand::Rng;
use std::time::{Duration, Instant};

/// Add a random jitter to a base delay.
///
/// Returns `base_ms + uniform_random(0..=max_jitter_ms)`.
pub fn jitter_delay(base_ms: u64, max_jitter_ms: u64) -> u64 {
    if max_jitter_ms == 0 {
        return base_ms;
    }
    let jitter = rand::thread_rng().gen_range(0..=max_jitter_ms);
    base_ms.saturating_add(jitter)
}

/// Probabilistically decide whether to send a dummy message.
///
/// Returns `true` with probability ~5% (1 in 20) by default.
/// Dummy messages should be encrypted identically to real ones so the relay
/// cannot distinguish them.
pub fn should_send_dummy() -> bool {
    rand::thread_rng().gen_ratio(1, 20)
}

/// Configurable dummy traffic scheduler.
///
/// Generates cover traffic at a configurable rate to mask real message patterns.
pub struct DummyTrafficScheduler {
    /// Average interval between dummy messages
    interval: Duration,
    /// Maximum random jitter added to the interval
    jitter: Duration,
    /// Next scheduled dummy send time
    next_send: Instant,
    /// Probability of actually sending when the timer fires (0.0 - 1.0)
    send_probability: f64,
}

impl DummyTrafficScheduler {
    /// Create a new scheduler.
    ///
    /// - `interval`: average time between dummy messages
    /// - `jitter`: max random deviation from the interval
    /// - `send_probability`: chance of actually sending (0.0–1.0)
    pub fn new(interval: Duration, jitter: Duration, send_probability: f64) -> Self {
        let send_probability = send_probability.clamp(0.0, 1.0);
        let mut sched = Self {
            interval,
            jitter,
            next_send: Instant::now(),
            send_probability,
        };
        sched.reschedule();
        sched
    }

    /// Check if it's time to send a dummy message. If so, reschedules and returns `true`.
    pub fn should_send_now(&mut self) -> bool {
        if Instant::now() < self.next_send {
            return false;
        }
        self.reschedule();
        let mut rng = rand::thread_rng();
        rng.gen_bool(self.send_probability)
    }

    /// Get the duration until the next potential dummy send.
    pub fn time_until_next(&self) -> Duration {
        self.next_send.saturating_duration_since(Instant::now())
    }

    /// Force reschedule (e.g., after sending a real message to reset the timer).
    pub fn reschedule(&mut self) {
        let jitter_ms = if self.jitter.as_millis() > 0 {
            rand::thread_rng().gen_range(0..=self.jitter.as_millis() as u64)
        } else {
            0
        };
        self.next_send = Instant::now() + self.interval + Duration::from_millis(jitter_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_delay_no_jitter() {
        assert_eq!(jitter_delay(100, 0), 100);
    }

    #[test]
    fn jitter_delay_in_range() {
        for _ in 0..100 {
            let d = jitter_delay(100, 50);
            assert!((100..=150).contains(&d), "delay {} out of range", d);
        }
    }

    #[test]
    fn jitter_delay_no_overflow() {
        // With base near MAX and jitter up to 100, result should saturate or be close to MAX
        let d = jitter_delay(u64::MAX - 10, 100);
        assert!(d >= u64::MAX - 10, "should be at least base value");
    }

    #[test]
    fn should_send_dummy_returns_bool() {
        // Just make sure it doesn't panic; probabilistic so we can't assert exact value
        let mut any_true = false;
        let mut any_false = false;
        for _ in 0..1000 {
            if should_send_dummy() {
                any_true = true;
            } else {
                any_false = true;
            }
            if any_true && any_false {
                break;
            }
        }
        // With 5% probability over 1000 trials, we should see both
        assert!(
            any_true,
            "should_send_dummy never returned true in 1000 tries"
        );
        assert!(
            any_false,
            "should_send_dummy never returned false in 1000 tries"
        );
    }

    #[test]
    fn scheduler_basic() {
        let mut sched = DummyTrafficScheduler::new(
            Duration::from_millis(0), // fire immediately
            Duration::from_millis(0),
            1.0, // always send
        );
        // With interval=0 and probability=1.0, should_send_now should return true
        assert!(sched.should_send_now());
    }

    #[test]
    fn scheduler_zero_probability_never_sends() {
        let mut sched =
            DummyTrafficScheduler::new(Duration::from_millis(0), Duration::from_millis(0), 0.0);
        for _ in 0..100 {
            assert!(!sched.should_send_now());
        }
    }

    #[test]
    fn scheduler_future_interval_not_ready() {
        let mut sched = DummyTrafficScheduler::new(
            Duration::from_secs(3600), // 1 hour
            Duration::from_millis(0),
            1.0,
        );
        assert!(!sched.should_send_now());
        assert!(sched.time_until_next() > Duration::from_secs(3500));
    }

    #[test]
    fn scheduler_reschedule_resets() {
        let mut sched =
            DummyTrafficScheduler::new(Duration::from_secs(3600), Duration::from_millis(0), 1.0);
        let before = sched.time_until_next();
        sched.reschedule();
        let after = sched.time_until_next();
        // Both should be roughly 1 hour
        assert!(before > Duration::from_secs(3500));
        assert!(after > Duration::from_secs(3500));
    }
}
