//! The encrypted screen-sharing relay path, `screen/1` (SPEC-03 §6.12,
//! REQ-55).
//!
//! The relay never sees keys or plaintext. It learns who shares, who watches
//! whom, keyframe requests, and fragment sizes and timing (§9.3); it reads
//! nothing of a fragment beyond the 17-byte transport header, and logs watch
//! subscriptions and keyframe requests at debug level at most.
//!
//! - **Registrations are per connection** (§6.12.3). A share belongs to the
//!   connection that started it and a watch to the connection that sent
//!   `ScreenWatch`, so fragments come only from the sharing connection and go
//!   only to watching connections, never to a user's other devices.
//! - **Every operation takes the voice participant map**
//!   (`AppState::voice_channels`) as its caller holds it. Callers take that
//!   lock first and this registry's lock second, never the other way round,
//!   so a participation check and the registration it guards cannot be
//!   separated by a leave (the clean-up rule of §6.12.4 runs under the
//!   voice write lock).
//! - **Fragments never enter the control queue.** Each connection has a
//!   [`ScreenQueue`] of at most 256 messages and 1 MiB with head drop and an
//!   age check at dequeue; the connection's outgoing task serves it after the
//!   control queue (`tokio::select!` with `biased`).
//! - **Control frames** (`screen_*`) go through each connection's control
//!   sender, which the registry records when the connection registers.

use serde_json::json;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, Notify};
use uuid::Uuid;

/// Tracing target of the screen path. Nothing above debug level is logged
/// about watches or keyframe requests (REQ-55).
pub const LOG_TARGET: &str = "accord::screen";

// ── Wire format (§6.12.2) ──

/// Type byte of `SCREEN_UP` (client → relay).
pub const SCREEN_UP: u8 = 0x01;
/// Type byte of `SCREEN_DOWN` (relay → client).
pub const SCREEN_DOWN: u8 = 0x02;
/// Shortest `SCREEN_UP`: type, channel id and a 20-byte fragment.
pub const SCREEN_UP_MIN: usize = 37;
/// Longest `SCREEN_UP`: type, channel id and a 16,384-byte fragment.
pub const SCREEN_UP_MAX: usize = 16_401;
/// Shortest `SCREEN_DOWN`.
pub const SCREEN_DOWN_MIN: usize = 53;
/// Longest `SCREEN_DOWN`.
pub const SCREEN_DOWN_MAX: usize = 16_417;
/// Length of the `SCREEN_UP` header: type byte and channel id.
const UP_HEADER: usize = 17;

// ── Limits (§6.12.5) ──

/// Messages one connection's screen queue holds at most.
pub const QUEUE_MAX_MESSAGES: usize = 256;
/// Bytes one connection's screen queue holds at most (1 MiB).
pub const QUEUE_MAX_BYTES: usize = 1 << 20;
/// `SCREEN_QUEUE_MAX_AGE`: a message enqueued longer ago is dropped at
/// dequeue instead of sent.
pub const QUEUE_MAX_AGE: Duration = Duration::from_secs(2);
/// Shares one connection may watch at once.
pub const WATCH_MAX: usize = 2;
/// `ScreenShareStart` and `ScreenShareStop` messages per user per window,
/// counted for both and enforced on starts.
pub const START_STOP_LIMIT: usize = 10;
/// `ScreenWatch` messages with `watch: true` per connection per window.
pub const WATCH_LIMIT: usize = 30;
/// The window of the start-and-stop and watch counters.
pub const RATE_WINDOW: Duration = Duration::from_secs(60);
/// Minimum gap between forwarded keyframe requests of one connection for one
/// share.
pub const KEYFRAME_REQUEST_MIN_GAP: Duration = Duration::from_secs(1);
/// Minimum gap between `screen_watchers` messages for one share.
pub const WATCHERS_MIN_GAP: Duration = Duration::from_secs(1);
/// Binary messages record user activity at most this often per connection.
pub const BINARY_ACTIVITY_MIN_GAP: Duration = Duration::from_secs(10);
/// Oversized or unknown binary messages within [`RATE_WINDOW`] after which
/// the relay closes the connection (a MAY of §6.12.2).
pub const MALFORMED_BINARY_CLOSE: usize = 100;

/// Default number of shares per channel (OD-109, Q14).
pub const DEFAULT_MAX_SHARERS: u8 = 2;
/// Largest configurable number of shares per channel.
pub const MAX_SHARERS_LIMIT: u8 = 8;
/// Default byte rate per share, 4 Mbit/s (OD-109, Q14).
pub const DEFAULT_MAX_BYTES_PER_SECOND: u64 = 500_000;
/// Lowest configurable byte rate per share.
pub const MIN_BYTES_PER_SECOND: u64 = 200_000;
/// Lowest burst of the per-share byte bucket: one 1,024,000-byte keyframe
/// with its framing.
pub const MIN_BURST_BYTES: u64 = 1_100_000;

/// The participant map of voice channels: channel id → user ids.
pub type VoiceMap = HashMap<Uuid, HashSet<Uuid>>;

/// The operator's screen-sharing settings (`--screen-share`,
/// `--screen-max-sharers`, `--screen-max-rate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenConfig {
    /// Screen sharing on (`screen/1` advertised) or off.
    pub enabled: bool,
    /// Shares per channel, 1 to 8 (`max_sharers`).
    pub max_sharers: u8,
    /// Bytes per second per share, at least 200,000
    /// (`max_bytes_per_second`).
    pub max_bytes_per_second: u64,
}

impl Default for ScreenConfig {
    /// On, 2 shares per channel, 500,000 bytes per second (OD-109).
    fn default() -> Self {
        Self {
            enabled: true,
            max_sharers: DEFAULT_MAX_SHARERS,
            max_bytes_per_second: DEFAULT_MAX_BYTES_PER_SECOND,
        }
    }
}

impl ScreenConfig {
    /// Validated settings; the error names the setting.
    pub fn new(enabled: bool, max_sharers: u8, max_bytes_per_second: u64) -> Result<Self, String> {
        if !(1..=MAX_SHARERS_LIMIT).contains(&max_sharers) {
            return Err(format!(
                "--screen-max-sharers must be from 1 to {MAX_SHARERS_LIMIT}, got {max_sharers}"
            ));
        }
        if max_bytes_per_second < MIN_BYTES_PER_SECOND {
            return Err(format!(
                "--screen-max-rate must be at least {MIN_BYTES_PER_SECOND} bytes per second, got {max_bytes_per_second}"
            ));
        }
        Ok(Self {
            enabled,
            max_sharers,
            max_bytes_per_second,
        })
    }

    /// The bucket's burst: 3 × the rate and at least 1,100,000 bytes.
    pub fn burst_bytes(&self) -> u64 {
        self.max_bytes_per_second
            .saturating_mul(3)
            .max(MIN_BURST_BYTES)
    }

    /// `screen_limits` of `hello` and `GET /health`, present only while
    /// screen sharing is on (REQ-55).
    pub fn limits(&self) -> Option<crate::models::ScreenLimits> {
        self.enabled.then_some(crate::models::ScreenLimits {
            max_sharers: self.max_sharers,
            max_bytes_per_second: self.max_bytes_per_second,
        })
    }
}

/// Why a share ended, as `screen_share_stopped` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// The sharing connection sent `ScreenShareStop`, or another connection
    /// of the same user started a share in the channel.
    Stopped,
    /// The user left the call or a connection closed.
    Left,
    /// The user was evicted on removal from the node (REQ-29).
    Removed,
}

impl StopReason {
    pub fn as_str(self) -> &'static str {
        match self {
            StopReason::Stopped => "stopped",
            StopReason::Left => "left",
            StopReason::Removed => "removed",
        }
    }
}

// ── Wire helpers ──

/// The channel id and fragment of a well-formed `SCREEN_UP`: 37 to 16,401
/// bytes with type byte 0x01. Nothing of the fragment is interpreted.
pub fn parse_screen_up(data: &[u8]) -> Option<(Uuid, &[u8])> {
    if !(SCREEN_UP_MIN..=SCREEN_UP_MAX).contains(&data.len()) || data[0] != SCREEN_UP {
        return None;
    }
    let channel = Uuid::from_slice(&data[1..UP_HEADER]).ok()?;
    Some((channel, &data[UP_HEADER..]))
}

/// The channel id, sender and fragment of a well-formed `SCREEN_DOWN`: 53 to
/// 16,417 bytes with type byte 0x02.
pub fn parse_screen_down(data: &[u8]) -> Option<(Uuid, Uuid, &[u8])> {
    if !(SCREEN_DOWN_MIN..=SCREEN_DOWN_MAX).contains(&data.len()) || data[0] != SCREEN_DOWN {
        return None;
    }
    let channel = Uuid::from_slice(&data[1..17]).ok()?;
    let from = Uuid::from_slice(&data[17..33]).ok()?;
    Some((channel, from, &data[33..]))
}

/// `SCREEN_DOWN` for `fragment`, with the relay-stamped sender. UUIDs are
/// written in RFC 9562 byte order.
pub fn build_screen_down(channel: Uuid, from: Uuid, fragment: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(33 + fragment.len());
    message.push(SCREEN_DOWN);
    message.extend_from_slice(channel.as_bytes());
    message.extend_from_slice(from.as_bytes());
    message.extend_from_slice(fragment);
    message
}

// ── Per-connection screen queue (§6.12.3) ──

/// Counters of one screen queue, for diagnostics and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueStats {
    /// Messages queued now.
    pub len: usize,
    /// Bytes queued now.
    pub bytes: usize,
    /// The most messages ever queued at once.
    pub max_len: usize,
    /// The most bytes ever queued at once.
    pub max_bytes: usize,
    /// Messages offered to the queue.
    pub enqueued: u64,
    /// Messages handed to the outgoing task.
    pub sent: u64,
    /// Messages displaced by newer ones (head drop).
    pub dropped_head: u64,
    /// Messages dropped at dequeue for being older than [`QUEUE_MAX_AGE`].
    pub dropped_age: u64,
}

#[derive(Debug, Default)]
struct QueueInner {
    items: VecDeque<(Instant, Arc<[u8]>)>,
    stats: QueueStats,
    closed: bool,
}

impl QueueInner {
    fn remove_front(&mut self) -> Option<(Instant, Arc<[u8]>)> {
        let item = self.items.pop_front()?;
        self.stats.bytes -= item.1.len();
        self.stats.len = self.items.len();
        Some(item)
    }
}

/// The second outbound queue of a connection, for `SCREEN_DOWN` only.
///
/// At most [`QUEUE_MAX_MESSAGES`] messages and [`QUEUE_MAX_BYTES`] bytes. A
/// message that would exceed either bound displaces the oldest queued
/// messages until it fits, so a viewer always receives the newest data. A
/// message enqueued more than [`QUEUE_MAX_AGE`] earlier is dropped at
/// dequeue. The byte counter is decremented on every removal (dequeue, head
/// drop, age drop, close), so it cannot drift.
#[derive(Debug, Default)]
pub struct ScreenQueue {
    inner: Mutex<QueueInner>,
    notify: Notify,
}

impl ScreenQueue {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, QueueInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Offer `message`, enqueued at `now`. Drops only screen messages of
    /// this connection.
    pub fn push(&self, message: Arc<[u8]>, now: Instant) {
        let size = message.len();
        {
            let mut inner = self.lock();
            if inner.closed || size > QUEUE_MAX_BYTES {
                return;
            }
            inner.stats.enqueued += 1;
            while inner.items.len() + 1 > QUEUE_MAX_MESSAGES
                || inner.stats.bytes + size > QUEUE_MAX_BYTES
            {
                if inner.remove_front().is_none() {
                    break;
                }
                inner.stats.dropped_head += 1;
            }
            inner.items.push_back((now, message));
            inner.stats.bytes += size;
            inner.stats.len = inner.items.len();
            inner.stats.max_len = inner.stats.max_len.max(inner.stats.len);
            inner.stats.max_bytes = inner.stats.max_bytes.max(inner.stats.bytes);
        }
        self.notify.notify_one();
    }

    /// The oldest message enqueued at most [`QUEUE_MAX_AGE`] before `now`,
    /// dropping older ones on the way.
    pub fn try_pop(&self, now: Instant) -> Option<Arc<[u8]>> {
        let mut inner = self.lock();
        while let Some((enqueued_at, message)) = inner.remove_front() {
            if now.saturating_duration_since(enqueued_at) > QUEUE_MAX_AGE {
                inner.stats.dropped_age += 1;
                continue;
            }
            inner.stats.sent += 1;
            return Some(message);
        }
        None
    }

    /// Wait for the next message that is fresh when dequeued. Cancel safe:
    /// a message is taken only in the poll that returns it.
    pub async fn pop(&self) -> Arc<[u8]> {
        loop {
            if let Some(message) = self.try_pop(Instant::now()) {
                return message;
            }
            self.notify.notified().await;
        }
    }

    /// Release every queued message and accept no more (connection close).
    pub fn close(&self) {
        let mut inner = self.lock();
        inner.closed = true;
        while inner.remove_front().is_some() {}
    }

    pub fn stats(&self) -> QueueStats {
        self.lock().stats
    }
}

// ── Per-share byte bucket ──

/// Token bucket of one share: `rate` bytes per second with a burst of
/// `burst` bytes. A user's first share in a channel starts with a full
/// bucket; a later one continues the bucket of the user's previous share
/// there until that bucket has refilled (see [`Registry::parked_buckets`]).
#[derive(Debug, Clone)]
struct ByteBucket {
    tokens: f64,
    rate: f64,
    burst: f64,
    last: Instant,
}

impl ByteBucket {
    fn full(config: &ScreenConfig, now: Instant) -> Self {
        let burst = config.burst_bytes() as f64;
        Self {
            tokens: burst,
            rate: config.max_bytes_per_second as f64,
            burst,
            last: now,
        }
    }

    /// Whether the bucket has refilled to its burst by `now`, so that it is
    /// the same as a new full one.
    fn is_full_at(&self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens + elapsed * self.rate >= self.burst
    }

    /// Take `bytes` if the bucket holds them.
    fn take(&mut self, bytes: usize, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now.max(self.last);
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        let bytes = bytes as f64;
        if self.tokens >= bytes {
            self.tokens -= bytes;
            true
        } else {
            false
        }
    }
}

// ── Registry ──

#[derive(Debug)]
struct Watch {
    conn: Uuid,
    user: Uuid,
}

#[derive(Debug)]
struct Share {
    id: u64,
    user: Uuid,
    conn: Uuid,
    bucket: ByteBucket,
    watchers: Vec<Watch>,
    /// connection → when its last keyframe request for this share was
    /// forwarded. Kept apart from the watches, so that unwatching and
    /// watching again does not shorten the gap (§6.12.5); entries older than
    /// [`KEYFRAME_REQUEST_MIN_GAP`] are pruned on every forward.
    keyframe_requests: HashMap<Uuid, Instant>,
    /// The last `screen_watchers` value sent and when.
    watchers_sent: Option<(usize, Instant)>,
    /// A coalesced `screen_watchers` is scheduled.
    watchers_timer: bool,
}

#[derive(Debug)]
struct ConnEntry {
    user: Uuid,
    control: broadcast::Sender<String>,
    queue: Arc<ScreenQueue>,
    /// `ScreenWatch` messages with `watch: true` in the rate window.
    watch_starts: VecDeque<Instant>,
    /// Oversized or unknown binary messages in the rate window.
    malformed: VecDeque<Instant>,
}

#[derive(Debug, Default)]
struct Registry {
    conns: HashMap<Uuid, ConnEntry>,
    /// user → that user's registered connections.
    users: HashMap<Uuid, HashSet<Uuid>>,
    /// channel → its shares, oldest first.
    channels: HashMap<Uuid, Vec<Share>>,
    /// user → `ScreenShareStart` and `ScreenShareStop` messages in the rate
    /// window.
    start_stop: HashMap<Uuid, VecDeque<Instant>>,
    /// (user, channel) → the byte bucket of the user's last ended share in
    /// the channel, until it has refilled to its burst. The user's next
    /// share there continues it, so stopping and starting again (or
    /// starting from another connection, or leaving and rejoining the call)
    /// does not refill a drained bucket at once: the per-share byte rate is
    /// a bandwidth bound and holds whatever flags are set (§6.12.5). A
    /// bucket refills within burst ÷ rate (at most 5.5 s), so an entry
    /// lives at most that long and a share started later starts full.
    parked_buckets: HashMap<(Uuid, Uuid), ByteBucket>,
    next_share_id: u64,
}

/// A coalesced `screen_watchers` to send at `at`.
struct WatchersTimer {
    channel: Uuid,
    share_id: u64,
    at: Instant,
}

/// Work to do after the registry lock is released.
#[derive(Default)]
struct Effects {
    timers: Vec<WatchersTimer>,
}

/// Drop the instants older than [`RATE_WINDOW`] and return how many remain.
fn prune_window(window: &mut VecDeque<Instant>, now: Instant) -> usize {
    while let Some(front) = window.front() {
        if now.saturating_duration_since(*front) > RATE_WINDOW {
            window.pop_front();
        } else {
            break;
        }
    }
    window.len()
}

/// Record `now` in a rate window that only ever needs its newest `limit`
/// entries: the limit is reached exactly when the `limit`-th newest entry is
/// inside the window. Keeping no more bounds the memory of messages that
/// are never refused.
fn record_in_window(window: &mut VecDeque<Instant>, now: Instant, limit: usize) {
    prune_window(window, now);
    window.push_back(now);
    while window.len() > limit {
        window.pop_front();
    }
}

impl Registry {
    fn send_conn(&self, conn: Uuid, message: &str) {
        if let Some(entry) = self.conns.get(&conn) {
            let _ = entry.control.send(message.to_string());
        }
    }

    /// Every registered connection of every user in `participants`.
    fn participant_conns(&self, participants: Option<&HashSet<Uuid>>) -> Vec<Uuid> {
        let mut conns = Vec::new();
        if let Some(participants) = participants {
            for user in participants {
                if let Some(user_conns) = self.users.get(user) {
                    conns.extend(user_conns.iter().copied());
                }
            }
        }
        conns
    }

    /// `screen_share_stopped` to every connection of every remaining
    /// participant of `channel` and to the sharing connection. The copy to
    /// `requester` carries `request_id`.
    fn announce_stopped(
        &self,
        channel: Uuid,
        sharer: Uuid,
        reason: StopReason,
        participants: Option<&HashSet<Uuid>>,
        sharing_conn: Uuid,
        requester: Option<(Uuid, Uuid)>,
    ) {
        let plain = json!({
            "type": "screen_share_stopped",
            "channel_id": channel,
            "user_id": sharer,
            "reason": reason.as_str(),
        });
        let mut targets = self.participant_conns(participants);
        if !targets.contains(&sharing_conn) {
            targets.push(sharing_conn);
        }
        if let Some((conn, _)) = requester {
            if !targets.contains(&conn) {
                targets.push(conn);
            }
        }
        let plain_text = plain.to_string();
        for conn in targets {
            match requester {
                Some((requesting_conn, request_id)) if requesting_conn == conn => {
                    let mut with_request = plain.clone();
                    with_request["request_id"] = json!(request_id);
                    self.send_conn(conn, &with_request.to_string());
                }
                _ => self.send_conn(conn, &plain_text),
            }
        }
    }

    /// [`Registry::announce_stopped`] without a copy to `skip`.
    fn announce_stopped_except(
        &self,
        channel: Uuid,
        sharer: Uuid,
        reason: StopReason,
        participants: Option<&HashSet<Uuid>>,
        sharing_conn: Uuid,
        skip: Uuid,
    ) {
        let frame = json!({
            "type": "screen_share_stopped",
            "channel_id": channel,
            "user_id": sharer,
            "reason": reason.as_str(),
        })
        .to_string();
        let mut targets = self.participant_conns(participants);
        if !targets.contains(&sharing_conn) {
            targets.push(sharing_conn);
        }
        for conn in targets.into_iter().filter(|c| *c != skip) {
            self.send_conn(conn, &frame);
        }
    }

    /// Remove `user`'s share in `channel`, if any.
    fn take_share_of_user(&mut self, channel: Uuid, user: Uuid) -> Option<Share> {
        let shares = self.channels.get_mut(&channel)?;
        let index = shares.iter().position(|s| s.user == user)?;
        Some(self.end_share(channel, index))
    }

    /// Remove the share that `conn` holds in `channel`, if any.
    fn take_share_of_conn(&mut self, channel: Uuid, conn: Uuid) -> Option<Share> {
        let shares = self.channels.get_mut(&channel)?;
        let index = shares.iter().position(|s| s.conn == conn)?;
        Some(self.end_share(channel, index))
    }

    /// Remove the share at `index` of `channel` and park its byte bucket for
    /// the user's next share there. Every way a share ends goes through
    /// here.
    fn end_share(&mut self, channel: Uuid, index: usize) -> Share {
        let shares = self
            .channels
            .get_mut(&channel)
            .expect("the caller found the share");
        let share = shares.remove(index);
        if shares.is_empty() {
            self.channels.remove(&channel);
        }
        let now = Instant::now();
        self.parked_buckets
            .retain(|_, bucket| !bucket.is_full_at(now));
        if !share.bucket.is_full_at(now) {
            self.parked_buckets
                .insert((share.user, channel), share.bucket.clone());
        }
        share
    }

    /// The byte bucket of `user`'s new share in `channel`: the parked bucket
    /// of the user's previous share there while it has not refilled, else a
    /// full one.
    fn bucket_for_new_share(
        &mut self,
        user: Uuid,
        channel: Uuid,
        config: &ScreenConfig,
        now: Instant,
    ) -> ByteBucket {
        self.parked_buckets
            .retain(|_, bucket| !bucket.is_full_at(now));
        self.parked_buckets
            .remove(&(user, channel))
            .unwrap_or_else(|| ByteBucket::full(config, now))
    }

    /// Shares `conn` watches, in every channel.
    fn watch_count(&self, conn: Uuid) -> usize {
        self.channels
            .values()
            .flatten()
            .filter(|share| share.watchers.iter().any(|w| w.conn == conn))
            .count()
    }

    /// Remove the watches of `channel` that `remove` selects, and update the
    /// affected shares' watcher counts.
    fn remove_watches(
        &mut self,
        channel: Uuid,
        remove: impl Fn(&Watch) -> bool,
        now: Instant,
        effects: &mut Effects,
    ) {
        let mut changed = Vec::new();
        if let Some(shares) = self.channels.get_mut(&channel) {
            for share in shares.iter_mut() {
                let before = share.watchers.len();
                share.watchers.retain(|w| !remove(w));
                if share.watchers.len() != before {
                    changed.push(share.id);
                }
            }
        }
        for share_id in changed {
            self.watchers_changed(channel, share_id, now, effects);
        }
    }

    /// The watcher count of a share changed: send `screen_watchers` to the
    /// sharing connection at once, or schedule it so that at most one is
    /// sent per [`WATCHERS_MIN_GAP`] (the latest value wins).
    fn watchers_changed(
        &mut self,
        channel: Uuid,
        share_id: u64,
        now: Instant,
        effects: &mut Effects,
    ) {
        let Some(share) = self
            .channels
            .get_mut(&channel)
            .and_then(|shares| shares.iter_mut().find(|s| s.id == share_id))
        else {
            return;
        };
        let count = share.watchers.len();
        match share.watchers_sent {
            Some((_, sent_at)) if now.saturating_duration_since(sent_at) < WATCHERS_MIN_GAP => {
                if !share.watchers_timer {
                    share.watchers_timer = true;
                    effects.timers.push(WatchersTimer {
                        channel,
                        share_id,
                        at: sent_at + WATCHERS_MIN_GAP,
                    });
                }
            }
            Some((sent, _)) if sent == count => {}
            _ => {
                share.watchers_sent = Some((count, now));
                let conn = share.conn;
                self.send_conn(conn, &watchers_frame(channel, count));
            }
        }
    }

    /// A scheduled `screen_watchers` is due: send the latest value if it
    /// differs from the last one sent.
    fn flush_watchers(&mut self, channel: Uuid, share_id: u64, now: Instant) {
        let Some(share) = self
            .channels
            .get_mut(&channel)
            .and_then(|shares| shares.iter_mut().find(|s| s.id == share_id))
        else {
            return;
        };
        share.watchers_timer = false;
        let count = share.watchers.len();
        if share.watchers_sent.map(|(sent, _)| sent) != Some(count) {
            share.watchers_sent = Some((count, now));
            let conn = share.conn;
            self.send_conn(conn, &watchers_frame(channel, count));
        }
    }

    /// The clean-up rule of §6.12.4 for one channel that `user` has left:
    /// end the user's share there and remove the watches of all of the
    /// user's connections there.
    fn user_left_channel(
        &mut self,
        user: Uuid,
        channel: Uuid,
        reason: StopReason,
        voice: &VoiceMap,
        now: Instant,
        effects: &mut Effects,
    ) {
        let participants = voice.get(&channel);
        if let Some(share) = self.take_share_of_user(channel, user) {
            tracing::debug!(target: LOG_TARGET, "share ended: {}", reason.as_str());
            self.announce_stopped(channel, user, reason, participants, share.conn, None);
        }
        self.remove_watches(channel, |w| w.user == user, now, effects);
        // When the last participant leaves, the channel's screen state goes
        // with it, like `voice_channels`.
        if participants.is_none_or(|p| p.is_empty()) {
            self.channels.remove(&channel);
        }
    }
}

fn watchers_frame(channel: Uuid, count: usize) -> String {
    json!({
        "type": "screen_watchers",
        "channel_id": channel,
        "watchers": count,
    })
    .to_string()
}

fn share_rejected(channel: Uuid, reason: &str, error: &str, request_id: Uuid) -> String {
    json!({
        "type": "screen_share_rejected",
        "channel_id": channel,
        "reason": reason,
        "error": error,
        "request_id": request_id,
    })
    .to_string()
}

fn watch_rejected(
    channel: Uuid,
    sharer: Uuid,
    reason: &str,
    error: &str,
    request_id: Uuid,
) -> String {
    json!({
        "type": "screen_watch_rejected",
        "channel_id": channel,
        "sharer_id": sharer,
        "reason": reason,
        "error": error,
        "request_id": request_id,
    })
    .to_string()
}

const DISABLED_TEXT: &str = "Screen sharing is disabled on this relay";
const NOT_PARTICIPANT_TEXT: &str = "You are not in this voice channel";
const RATE_LIMITED_TEXT: &str = "Rate limit exceeded";
const NOT_SHARING_TEXT: &str = "That user is not sharing a screen in this channel";

/// What became of a binary message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpOutcome {
    /// Offered to this many watching connections' screen queues.
    Forwarded(usize),
    /// Well formed but dropped: no share on this connection, the sender is
    /// not a participant, or the share's byte bucket lacks the bytes.
    Dropped,
    /// Wrong length or type byte. `close` once the connection has sent
    /// [`MALFORMED_BINARY_CLOSE`] of them within [`RATE_WINDOW`].
    Malformed { close: bool },
}

/// The relay's screen-sharing state: operator settings, the share and watch
/// registry, the rate counters and the per-connection screen queues.
#[derive(Debug)]
pub struct ScreenRelay {
    config: ScreenConfig,
    inner: Arc<Mutex<Registry>>,
}

impl Default for ScreenRelay {
    fn default() -> Self {
        Self::new(ScreenConfig::default())
    }
}

impl ScreenRelay {
    pub fn new(config: ScreenConfig) -> Self {
        Self {
            config,
            inner: Arc::new(Mutex::new(Registry::default())),
        }
    }

    pub fn config(&self) -> &ScreenConfig {
        &self.config
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    fn lock(&self) -> MutexGuard<'_, Registry> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Schedule the coalesced `screen_watchers` messages. Needs a tokio
    /// runtime, which every caller in the relay has.
    fn apply(&self, effects: Effects) {
        for timer in effects.timers {
            let inner = Arc::clone(&self.inner);
            tokio::spawn(async move {
                tokio::time::sleep_until(tokio::time::Instant::from_std(timer.at)).await;
                let mut registry = inner.lock().unwrap_or_else(|e| e.into_inner());
                registry.flush_watchers(timer.channel, timer.share_id, Instant::now());
            });
        }
    }

    // ── Connections ──

    /// Register a WebSocket connection and return its screen queue, which
    /// its outgoing task serves after the control queue.
    pub fn register_connection(
        &self,
        conn: Uuid,
        user: Uuid,
        control: broadcast::Sender<String>,
    ) -> Arc<ScreenQueue> {
        let queue = Arc::new(ScreenQueue::new());
        let mut registry = self.lock();
        registry.conns.insert(
            conn,
            ConnEntry {
                user,
                control,
                queue: Arc::clone(&queue),
                watch_starts: VecDeque::new(),
                malformed: VecDeque::new(),
            },
        );
        registry.users.entry(user).or_default().insert(conn);
        queue
    }

    /// A connection closed: its shares end (`left`), its watches are
    /// removed and its screen queue is released (§6.12.4).
    pub fn connection_closed(&self, conn: Uuid, voice: &VoiceMap) {
        let now = Instant::now();
        let mut effects = Effects::default();
        {
            let mut registry = self.lock();
            // Unregister first: nothing more is sent to the closing
            // connection.
            if let Some(entry) = registry.conns.remove(&conn) {
                entry.queue.close();
                if let Some(user_conns) = registry.users.get_mut(&entry.user) {
                    user_conns.remove(&conn);
                    if user_conns.is_empty() {
                        registry.users.remove(&entry.user);
                    }
                }
            }
            let channels: Vec<Uuid> = registry.channels.keys().copied().collect();
            for channel in channels {
                if let Some(share) = registry.take_share_of_conn(channel, conn) {
                    tracing::debug!(target: LOG_TARGET, "share ended: connection closed");
                    registry.announce_stopped(
                        channel,
                        share.user,
                        StopReason::Left,
                        voice.get(&channel),
                        conn,
                        None,
                    );
                }
                registry.remove_watches(channel, |w| w.conn == conn, now, &mut effects);
            }
        }
        self.apply(effects);
    }

    /// The clean-up rule of §6.12.4: `user` was removed from
    /// `voice_channels[C]` for every C in `channels`. `voice` is the
    /// participant map after the removal, held by the caller.
    pub fn users_left_voice(
        &self,
        user: Uuid,
        channels: &[Uuid],
        reason: StopReason,
        voice: &VoiceMap,
    ) {
        if channels.is_empty() {
            return;
        }
        let now = Instant::now();
        let mut effects = Effects::default();
        {
            let mut registry = self.lock();
            for &channel in channels {
                registry.user_left_channel(user, channel, reason, voice, now, &mut effects);
            }
        }
        self.apply(effects);
    }

    /// `screen_sharers` of `voice_channel_joined` and `voice_participants`:
    /// the users with a share in `channel`, oldest first.
    pub fn sharers(&self, channel: Uuid) -> Vec<Uuid> {
        self.lock()
            .channels
            .get(&channel)
            .map(|shares| shares.iter().map(|s| s.user).collect())
            .unwrap_or_default()
    }

    /// The screen queue counters of every registered connection.
    pub fn queue_stats(&self) -> Vec<(Uuid, QueueStats)> {
        self.lock()
            .conns
            .iter()
            .map(|(conn, entry)| (*conn, entry.queue.stats()))
            .collect()
    }

    /// The screen queue counters of every connection of `user`.
    pub fn user_queue_stats(&self, user: Uuid) -> Vec<QueueStats> {
        self.lock()
            .conns
            .values()
            .filter(|entry| entry.user == user)
            .map(|entry| entry.queue.stats())
            .collect()
    }

    // ── JSON arms (§6.12.1) ──

    /// `ScreenShareStart { channel_id }` from `conn` of `user`.
    pub fn share_start(
        &self,
        conn: Uuid,
        user: Uuid,
        channel: Uuid,
        request_id: Uuid,
        rate_limits: bool,
        voice: &VoiceMap,
    ) {
        let now = Instant::now();
        let mut registry = self.lock();
        // (1) Disabled by the operator.
        if !self.config.enabled {
            registry.send_conn(
                conn,
                &share_rejected(channel, "disabled", DISABLED_TEXT, request_id),
            );
            return;
        }
        // (2) Not a participant.
        let participants = voice.get(&channel);
        if !participants.is_some_and(|p| p.contains(&user)) {
            registry.send_conn(
                conn,
                &share_rejected(channel, "not_participant", NOT_PARTICIPANT_TEXT, request_id),
            );
            return;
        }
        // (3) More than 10 start or stop messages from the user in 60 s.
        if rate_limits {
            registry
                .start_stop
                .retain(|_, window| prune_window(window, now) > 0);
            let window = registry.start_stop.entry(user).or_default();
            if window.len() >= START_STOP_LIMIT {
                tracing::debug!(target: LOG_TARGET, "share start refused: rate_limited");
                registry.send_conn(
                    conn,
                    &share_rejected(channel, "rate_limited", RATE_LIMITED_TEXT, request_id),
                );
                return;
            }
            record_in_window(window, now, START_STOP_LIMIT);
        }
        // (4) The connection already shares in C: answer it again.
        if registry
            .channels
            .get(&channel)
            .is_some_and(|shares| shares.iter().any(|s| s.conn == conn))
        {
            registry.send_conn(conn, &started_frame(channel, user, Some(request_id)));
            return;
        }
        // (5) Another connection of the user shares in C: end that share as
        // if it had sent ScreenShareStop, so that a user has at most one
        // share per channel. The requesting connection is left out of that
        // announcement: its own start is answered by the
        // `screen_share_started` below, and a `screen_share_stopped` naming
        // its user without a stop of its own would end its starting share
        // (REQ-52).
        if let Some(previous) = registry.take_share_of_user(channel, user) {
            tracing::debug!(target: LOG_TARGET, "share ended: replaced by another connection");
            registry.announce_stopped_except(
                channel,
                user,
                StopReason::Stopped,
                participants,
                previous.conn,
                conn,
            );
        }
        // (6) The channel's sharer cap.
        let current = registry.channels.get(&channel).map_or(0, Vec::len);
        if current >= usize::from(self.config.max_sharers) {
            let text = format!(
                "{} people are already sharing in this channel",
                self.config.max_sharers
            );
            registry.send_conn(conn, &share_rejected(channel, "limit", &text, request_id));
            return;
        }
        // (7) Record the share and announce it. Its byte bucket is reset to
        // full, except that a bucket the user's previous share in C drained
        // is continued until it has refilled (`Registry::parked_buckets`):
        // a restart must not refill the byte rate at once.
        registry.next_share_id += 1;
        let share_id = registry.next_share_id;
        let bucket = registry.bucket_for_new_share(user, channel, &self.config, now);
        registry.channels.entry(channel).or_default().push(Share {
            id: share_id,
            user,
            conn,
            bucket,
            keyframe_requests: HashMap::new(),
            watchers: Vec::new(),
            watchers_sent: Some((0, now)),
            watchers_timer: false,
        });
        tracing::debug!(target: LOG_TARGET, "share started");
        let plain = started_frame(channel, user, None);
        let mut answered = false;
        for target in registry.participant_conns(participants) {
            if target == conn {
                answered = true;
                registry.send_conn(target, &started_frame(channel, user, Some(request_id)));
            } else {
                registry.send_conn(target, &plain);
            }
        }
        if !answered {
            registry.send_conn(conn, &started_frame(channel, user, Some(request_id)));
        }
        registry.send_conn(conn, &watchers_frame(channel, 0));
    }

    /// `ScreenShareStop { channel_id }` from `conn` of `user`. No participant
    /// check, never refused; counts toward the start-and-stop limit.
    pub fn share_stop(
        &self,
        conn: Uuid,
        user: Uuid,
        channel: Uuid,
        request_id: Uuid,
        rate_limits: bool,
        voice: &VoiceMap,
    ) {
        let now = Instant::now();
        let mut registry = self.lock();
        if rate_limits {
            let window = registry.start_stop.entry(user).or_default();
            record_in_window(window, now, START_STOP_LIMIT);
        }
        if let Some(share) = registry.take_share_of_conn(channel, conn) {
            tracing::debug!(target: LOG_TARGET, "share ended: stopped");
            registry.announce_stopped(
                channel,
                share.user,
                StopReason::Stopped,
                voice.get(&channel),
                conn,
                Some((conn, request_id)),
            );
        }
    }

    /// `ScreenWatch { channel_id, sharer_id, watch }` from `conn` of `user`.
    #[allow(clippy::too_many_arguments)]
    pub fn watch(
        &self,
        conn: Uuid,
        user: Uuid,
        channel: Uuid,
        sharer: Uuid,
        watch: bool,
        request_id: Uuid,
        rate_limits: bool,
        voice: &VoiceMap,
    ) {
        let now = Instant::now();
        let mut effects = Effects::default();
        {
            let mut registry = self.lock();
            if !watch {
                // No participant check, never refused.
                let mut changed = None;
                if let Some(share) = registry
                    .channels
                    .get_mut(&channel)
                    .and_then(|shares| shares.iter_mut().find(|s| s.user == sharer))
                {
                    let before = share.watchers.len();
                    share.watchers.retain(|w| w.conn != conn);
                    if share.watchers.len() != before {
                        changed = Some(share.id);
                    }
                }
                if let Some(share_id) = changed {
                    tracing::debug!(target: LOG_TARGET, "watch removed");
                    registry.watchers_changed(channel, share_id, now, &mut effects);
                }
            } else {
                let reject = |registry: &Registry, reason: &str, text: &str| {
                    registry.send_conn(
                        conn,
                        &watch_rejected(channel, sharer, reason, text, request_id),
                    );
                };
                // (1) Disabled.
                if !self.config.enabled {
                    reject(&registry, "disabled", DISABLED_TEXT);
                    return;
                }
                // (2) Not a participant.
                if !voice.get(&channel).is_some_and(|p| p.contains(&user)) {
                    reject(&registry, "not_participant", NOT_PARTICIPANT_TEXT);
                    return;
                }
                // (3) More than 30 watch requests from the connection in 60 s.
                if rate_limits {
                    let Some(entry) = registry.conns.get_mut(&conn) else {
                        return;
                    };
                    if prune_window(&mut entry.watch_starts, now) >= WATCH_LIMIT {
                        tracing::debug!(target: LOG_TARGET, "watch refused: rate_limited");
                        reject(&registry, "rate_limited", RATE_LIMITED_TEXT);
                        return;
                    }
                    record_in_window(&mut entry.watch_starts, now, WATCH_LIMIT);
                }
                // (4) No such share, or the user's own.
                let share_exists = sharer != user
                    && registry
                        .channels
                        .get(&channel)
                        .is_some_and(|shares| shares.iter().any(|s| s.user == sharer));
                if !share_exists {
                    reject(&registry, "not_sharing", NOT_SHARING_TEXT);
                    return;
                }
                let already = registry.channels.get(&channel).is_some_and(|shares| {
                    shares
                        .iter()
                        .any(|s| s.user == sharer && s.watchers.iter().any(|w| w.conn == conn))
                });
                if already {
                    return;
                }
                // (5) The connection already watches two shares.
                if registry.watch_count(conn) >= WATCH_MAX {
                    let text = format!("You are already watching {WATCH_MAX} screens");
                    reject(&registry, "watch_limit", &text);
                    return;
                }
                // (6) Record the watch.
                let Some(share) = registry
                    .channels
                    .get_mut(&channel)
                    .and_then(|shares| shares.iter_mut().find(|s| s.user == sharer))
                else {
                    return;
                };
                share.watchers.push(Watch { conn, user });
                let share_id = share.id;
                tracing::debug!(target: LOG_TARGET, "watch added");
                registry.watchers_changed(channel, share_id, now, &mut effects);
            }
        }
        self.apply(effects);
    }

    /// `ScreenKeyframeRequest { channel_id, sharer_id }` from `conn` of
    /// `user`: forwarded to the sharing connection only, at most once per
    /// second per connection and share; otherwise dropped silently.
    pub fn keyframe_request(
        &self,
        conn: Uuid,
        user: Uuid,
        channel: Uuid,
        sharer: Uuid,
        voice: &VoiceMap,
    ) {
        if !voice.get(&channel).is_some_and(|p| p.contains(&user)) {
            return;
        }
        let now = Instant::now();
        let mut registry = self.lock();
        let Some(share) = registry
            .channels
            .get_mut(&channel)
            .and_then(|shares| shares.iter_mut().find(|s| s.user == sharer))
        else {
            return;
        };
        if !share.watchers.iter().any(|w| w.conn == conn) {
            return;
        }
        // The gap is per connection and share, not per watch: the last
        // forwarded time outlives an unwatch, so watching again does not
        // reset it.
        share
            .keyframe_requests
            .retain(|_, at| now.saturating_duration_since(*at) < KEYFRAME_REQUEST_MIN_GAP);
        if share.keyframe_requests.contains_key(&conn) {
            return;
        }
        share.keyframe_requests.insert(conn, now);
        let sharing_conn = share.conn;
        let frame = json!({
            "type": "screen_keyframe_request",
            "channel_id": channel,
            "from": user,
        })
        .to_string();
        tracing::debug!(target: LOG_TARGET, "keyframe request forwarded");
        registry.send_conn(sharing_conn, &frame);
    }

    // ── Binary arm (§6.12.2) ──

    /// A binary message from `conn` of `user`: check it in the order of
    /// §6.12.2 and offer `SCREEN_DOWN` to every watching connection whose
    /// user is a current participant other than the sender. The caller holds
    /// the participant map `voice` for the whole call, so nobody is removed
    /// from the call (and evicted) between the check and the hand-off.
    pub fn forward_up(&self, conn: Uuid, user: Uuid, data: &[u8], voice: &VoiceMap) -> UpOutcome {
        let now = Instant::now();
        // (1) Length and type.
        let Some((channel, fragment)) = parse_screen_up(data) else {
            let mut registry = self.lock();
            let Some(entry) = registry.conns.get_mut(&conn) else {
                return UpOutcome::Malformed { close: false };
            };
            record_in_window(&mut entry.malformed, now, MALFORMED_BINARY_CLOSE);
            let close = entry.malformed.len() >= MALFORMED_BINARY_CLOSE;
            return UpOutcome::Malformed { close };
        };
        // (2) The connection holds a share in C and the user is a
        // participant of C.
        let Some(participants) = voice.get(&channel).filter(|p| p.contains(&user)) else {
            return UpOutcome::Dropped;
        };
        let queues: Vec<Arc<ScreenQueue>> = {
            let mut registry = self.lock();
            let Registry {
                channels, conns, ..
            } = &mut *registry;
            let Some(share) = channels
                .get_mut(&channel)
                .and_then(|shares| shares.iter_mut().find(|s| s.conn == conn))
            else {
                return UpOutcome::Dropped;
            };
            // (3) The share's byte bucket, before anything is copied.
            if !share.bucket.take(data.len(), now) {
                return UpOutcome::Dropped;
            }
            // The watching connections whose user is a participant other
            // than the sender. The caller's hold on the participant map
            // keeps them participants until the pushes below are done.
            share
                .watchers
                .iter()
                .filter(|w| w.user != user && participants.contains(&w.user))
                .filter_map(|w| conns.get(&w.conn).map(|e| Arc::clone(&e.queue)))
                .collect()
        };
        // (4) Build SCREEN_DOWN once, outside the registry lock, and offer
        // it to the watchers' screen queues.
        if queues.is_empty() {
            return UpOutcome::Forwarded(0);
        }
        let message: Arc<[u8]> = build_screen_down(channel, user, fragment).into();
        for queue in &queues {
            queue.push(Arc::clone(&message), now);
        }
        UpOutcome::Forwarded(queues.len())
    }
}

fn started_frame(channel: Uuid, user: Uuid, request_id: Option<Uuid>) -> String {
    let mut frame = json!({
        "type": "screen_share_started",
        "channel_id": channel,
        "user_id": user,
    });
    if let Some(request_id) = request_id {
        frame["request_id"] = json!(request_id);
    }
    frame.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(size: usize) -> Arc<[u8]> {
        vec![0u8; size].into()
    }

    #[test]
    fn config_defaults_follow_od_109() {
        let config = ScreenConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_sharers, 2);
        assert_eq!(config.max_bytes_per_second, 500_000);
        assert_eq!(config.burst_bytes(), 1_500_000);
        let limits = config.limits().expect("limits while enabled");
        assert_eq!(limits.max_sharers, 2);
        assert_eq!(limits.max_bytes_per_second, 500_000);
    }

    #[test]
    fn config_validation_and_burst() {
        assert!(ScreenConfig::new(true, 0, 500_000).is_err());
        assert!(ScreenConfig::new(true, 9, 500_000).is_err());
        assert!(ScreenConfig::new(true, 1, 199_999).is_err());
        let low = ScreenConfig::new(true, 8, 200_000).unwrap();
        // 3 × 200,000 is below the floor of one keyframe with framing.
        assert_eq!(low.burst_bytes(), 1_100_000);
        let high = ScreenConfig::new(true, 1, 1_000_000).unwrap();
        assert_eq!(high.burst_bytes(), 3_000_000);
        let off = ScreenConfig::new(false, 2, 500_000).unwrap();
        assert!(off.limits().is_none());
    }

    #[test]
    fn wire_bounds() {
        let channel = Uuid::new_v4();
        let from = Uuid::new_v4();
        for len in [SCREEN_UP_MIN, SCREEN_UP_MAX] {
            let mut up = vec![0xAB; len];
            up[0] = SCREEN_UP;
            up[1..17].copy_from_slice(channel.as_bytes());
            let (parsed, fragment) = parse_screen_up(&up).expect("valid SCREEN_UP");
            assert_eq!(parsed, channel);
            assert_eq!(fragment.len(), len - 17);
            let down = build_screen_down(channel, from, fragment);
            assert_eq!(down.len(), len + 16);
            let (c, f, frag) = parse_screen_down(&down).expect("valid SCREEN_DOWN");
            assert_eq!((c, f), (channel, from));
            assert_eq!(frag, fragment);
        }
        let mut too_short = vec![0u8; SCREEN_UP_MIN - 1];
        too_short[0] = SCREEN_UP;
        assert!(parse_screen_up(&too_short).is_none());
        let mut too_long = vec![0u8; SCREEN_UP_MAX + 1];
        too_long[0] = SCREEN_UP;
        assert!(parse_screen_up(&too_long).is_none());
        let mut wrong_type = vec![0u8; SCREEN_UP_MIN];
        wrong_type[0] = SCREEN_DOWN;
        assert!(parse_screen_up(&wrong_type).is_none());
        assert!(parse_screen_up(&[SCREEN_UP; 16]).is_none());
        let mut down_long = vec![0u8; SCREEN_DOWN_MAX + 1];
        down_long[0] = SCREEN_DOWN;
        assert!(parse_screen_down(&down_long).is_none());
        let mut down_short = vec![0u8; SCREEN_DOWN_MIN - 1];
        down_short[0] = SCREEN_DOWN;
        assert!(parse_screen_down(&down_short).is_none());
    }

    #[test]
    fn queue_head_drop_by_count() {
        let queue = ScreenQueue::new();
        let now = Instant::now();
        for i in 0..300u16 {
            let mut m = vec![0u8; 60];
            m[..2].copy_from_slice(&i.to_be_bytes());
            queue.push(m.into(), now);
        }
        let stats = queue.stats();
        assert_eq!(stats.len, QUEUE_MAX_MESSAGES);
        assert_eq!(stats.max_len, QUEUE_MAX_MESSAGES);
        assert_eq!(stats.dropped_head, 44);
        // The oldest were dropped first: the first left is message 44.
        let first = queue.try_pop(now).unwrap();
        assert_eq!(u16::from_be_bytes([first[0], first[1]]), 44);
    }

    #[test]
    fn queue_head_drop_by_bytes() {
        let queue = ScreenQueue::new();
        let now = Instant::now();
        for _ in 0..100 {
            queue.push(message(SCREEN_DOWN_MAX), now);
        }
        let stats = queue.stats();
        // 63 × 16,417 = 1,034,271 ≤ 1 MiB < 64 × 16,417.
        assert_eq!(stats.len, 63);
        assert_eq!(stats.bytes, 63 * SCREEN_DOWN_MAX);
        assert!(stats.max_bytes <= QUEUE_MAX_BYTES);
        assert_eq!(stats.dropped_head, 37);
    }

    #[test]
    fn queue_age_drop_at_dequeue() {
        let queue = ScreenQueue::new();
        let t0 = Instant::now();
        queue.push(message(100), t0);
        queue.push(message(200), t0 + Duration::from_millis(1500));
        // At t0 + 2.5 s the first is 2.5 s old and the second 1 s old.
        let popped = queue.try_pop(t0 + Duration::from_millis(2500)).unwrap();
        assert_eq!(popped.len(), 200);
        let stats = queue.stats();
        assert_eq!(stats.dropped_age, 1);
        assert_eq!(stats.sent, 1);
        assert_eq!((stats.len, stats.bytes), (0, 0));
        // Exactly 2 s old is still sent.
        queue.push(message(10), t0);
        assert!(queue.try_pop(t0 + QUEUE_MAX_AGE).is_some());
    }

    #[test]
    fn queue_bytes_return_to_zero_on_every_removal() {
        let queue = ScreenQueue::new();
        let t0 = Instant::now();
        for _ in 0..70 {
            queue.push(message(SCREEN_DOWN_MAX), t0);
        }
        assert!(queue.try_pop(t0).is_some());
        assert!(queue.try_pop(t0 + Duration::from_secs(3)).is_none());
        assert_eq!(queue.stats().bytes, 0);
        for _ in 0..5 {
            queue.push(message(1000), t0);
        }
        queue.close();
        let stats = queue.stats();
        assert_eq!((stats.len, stats.bytes), (0, 0));
        // A closed queue accepts nothing.
        queue.push(message(1000), t0);
        assert_eq!(queue.stats().len, 0);
    }

    #[tokio::test]
    async fn queue_pop_waits_for_a_push() {
        let queue = Arc::new(ScreenQueue::new());
        let waiter = {
            let queue = Arc::clone(&queue);
            tokio::spawn(async move { queue.pop().await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        queue.push(message(42), Instant::now());
        let popped = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("pop wakes up")
            .unwrap();
        assert_eq!(popped.len(), 42);
    }

    #[test]
    fn rate_windows_keep_only_what_the_limit_needs() {
        let mut window = VecDeque::new();
        let t0 = Instant::now();
        for i in 0..50 {
            record_in_window(&mut window, t0 + Duration::from_millis(i), START_STOP_LIMIT);
        }
        assert_eq!(window.len(), START_STOP_LIMIT);
        // 61 s later the window is empty again.
        assert_eq!(prune_window(&mut window, t0 + Duration::from_secs(61)), 0);
    }

    #[tokio::test]
    async fn forwards_only_to_watching_participants_and_releases_on_close() {
        let relay = ScreenRelay::default();
        let channel = Uuid::new_v4();
        let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let (a1, a2, b1, c1) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        let mut receivers = Vec::new();
        let mut queues = HashMap::new();
        for (conn, user) in [(a1, a), (a2, a), (b1, b), (c1, c)] {
            let (tx, rx) = broadcast::channel(64);
            receivers.push(rx);
            queues.insert(conn, relay.register_connection(conn, user, tx));
        }
        let mut voice = VoiceMap::new();
        voice.insert(channel, [a, b, c].into_iter().collect());
        relay.share_start(a1, a, channel, Uuid::new_v4(), true, &voice);
        relay.watch(b1, b, channel, a, true, Uuid::new_v4(), true, &voice);
        relay.watch(c1, c, channel, a, true, Uuid::new_v4(), true, &voice);
        assert_eq!(relay.sharers(channel), vec![a]);

        let mut up = vec![SCREEN_UP];
        up.extend_from_slice(channel.as_bytes());
        up.extend_from_slice(&[7u8; 100]);
        assert_eq!(
            relay.forward_up(a1, a, &up, &voice),
            UpOutcome::Forwarded(2)
        );
        // The sharer's other device holds no share.
        assert_eq!(relay.forward_up(a2, a, &up, &voice), UpOutcome::Dropped);
        // A watcher that is no longer a participant gets nothing.
        voice.get_mut(&channel).unwrap().remove(&c);
        assert_eq!(
            relay.forward_up(a1, a, &up, &voice),
            UpOutcome::Forwarded(1)
        );
        assert_eq!(queues[&b1].stats().len, 2);
        assert_eq!(queues[&c1].stats().len, 1);
        assert_eq!(queues[&a1].stats().enqueued, 0);
        assert_eq!(queues[&a2].stats().enqueued, 0);
        let down = queues[&b1].try_pop(Instant::now()).unwrap();
        assert_eq!(&*down, &build_screen_down(channel, a, &[7u8; 100])[..]);

        // Closing a watching connection releases its queue.
        relay.connection_closed(b1, &voice);
        let stats = queues[&b1].stats();
        assert_eq!((stats.len, stats.bytes), (0, 0));
        assert_eq!(
            relay.forward_up(a1, a, &up, &voice),
            UpOutcome::Forwarded(0)
        );
        // Closing the sharing connection ends the share.
        relay.connection_closed(a1, &voice);
        assert!(relay.sharers(channel).is_empty());
        assert!(matches!(
            relay.forward_up(a2, a, &[0u8; 10], &voice),
            UpOutcome::Malformed { close: false }
        ));
    }

    /// The SCREEN_UP of a maximum-size fragment in `channel`.
    fn max_up(channel: Uuid) -> Vec<u8> {
        let mut up = vec![SCREEN_UP];
        up.extend_from_slice(channel.as_bytes());
        up.resize(SCREEN_UP_MAX, 0x33);
        up
    }

    /// How many of `count` maximum-size fragments from `conn` the relay
    /// forwards.
    fn forwarded(
        relay: &ScreenRelay,
        conn: Uuid,
        user: Uuid,
        channel: Uuid,
        voice: &VoiceMap,
        count: usize,
    ) -> usize {
        let up = max_up(channel);
        (0..count)
            .filter(|_| {
                matches!(
                    relay.forward_up(conn, user, &up, voice),
                    UpOutcome::Forwarded(1)
                )
            })
            .count()
    }

    /// A new share does not refill a drained byte bucket: stopping and
    /// starting again, starting from the user's other connection, or leaving
    /// and rejoining the call continues the bucket, with no start-and-stop
    /// counter (`--disable-rate-limits`) to stop the cycle.
    #[tokio::test]
    async fn restarting_a_share_does_not_refill_its_bucket() {
        let relay = ScreenRelay::new(ScreenConfig::new(true, 2, 200_000).unwrap());
        let channel = Uuid::new_v4();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let (a1, a2, b1) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let mut receivers = Vec::new();
        for (conn, user) in [(a1, a), (a2, a), (b1, b)] {
            let (tx, rx) = broadcast::channel(256);
            receivers.push(rx);
            relay.register_connection(conn, user, tx);
        }
        let mut voice = VoiceMap::new();
        voice.insert(channel, [a, b].into_iter().collect());
        let start_and_watch = |conn: Uuid, voice: &VoiceMap| {
            relay.share_start(conn, a, channel, Uuid::new_v4(), false, voice);
            relay.watch(b1, b, channel, a, true, Uuid::new_v4(), false, voice);
        };

        // The first share starts full: 1,100,000 ÷ 16,401 = 67 fragments.
        start_and_watch(a1, &voice);
        let first = forwarded(&relay, a1, a, channel, &voice, 100);
        assert!((67..=68).contains(&first), "{first}");

        // Stop and start again.
        relay.share_stop(a1, a, channel, Uuid::new_v4(), false, &voice);
        start_and_watch(a1, &voice);
        assert!(forwarded(&relay, a1, a, channel, &voice, 100) <= 2);

        // Start from the other connection (ends the first share).
        start_and_watch(a2, &voice);
        assert!(forwarded(&relay, a2, a, channel, &voice, 100) <= 2);

        // Leave and rejoin the call.
        voice.get_mut(&channel).unwrap().remove(&a);
        relay.users_left_voice(a, &[channel], StopReason::Left, &voice);
        voice.get_mut(&channel).unwrap().insert(a);
        start_and_watch(a2, &voice);
        assert!(forwarded(&relay, a2, a, channel, &voice, 100) <= 2);
        assert_eq!(relay.sharers(channel), vec![a]);
    }

    /// A parked bucket is continued until it has refilled to its burst and
    /// then forgotten, so a share started later starts full.
    #[test]
    fn parked_buckets_expire_once_refilled() {
        let config = ScreenConfig::new(true, 2, 200_000).unwrap();
        let t0 = Instant::now();
        let (user, channel) = (Uuid::new_v4(), Uuid::new_v4());
        let mut registry = Registry::default();
        let mut drained = ByteBucket::full(&config, t0);
        assert!(drained.is_full_at(t0));
        assert!(drained.take(1_100_000, t0));
        // 1,100,000 bytes at 200,000 bytes per second: full after 5.5 s.
        assert!(!drained.is_full_at(t0 + Duration::from_millis(5_400)));
        assert!(drained.is_full_at(t0 + Duration::from_millis(5_500)));
        registry.parked_buckets.insert((user, channel), drained);

        // One second later the user's next share continues it.
        let t1 = t0 + Duration::from_secs(1);
        let mut bucket = registry.bucket_for_new_share(user, channel, &config, t1);
        assert!(registry.parked_buckets.is_empty());
        assert!(bucket.take(200_000, t1));
        assert!(!bucket.take(1_000, t1));

        // Once refilled, the entry is pruned and the next share starts full.
        registry.parked_buckets.insert((user, channel), bucket);
        let t2 = t1 + Duration::from_secs(10);
        let other = Uuid::new_v4();
        let mut fresh = registry.bucket_for_new_share(other, channel, &config, t2);
        assert!(registry.parked_buckets.is_empty());
        assert!(fresh.take(1_100_000, t2));
        let mut fresh = registry.bucket_for_new_share(user, channel, &config, t2);
        assert!(fresh.take(1_100_000, t2));
    }

    /// The keyframe-request gap belongs to the connection and the share:
    /// unwatching and watching again does not reset it.
    #[tokio::test]
    async fn keyframe_gap_survives_unwatch_and_rewatch() {
        let relay = ScreenRelay::default();
        let channel = Uuid::new_v4();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let (a1, b1) = (Uuid::new_v4(), Uuid::new_v4());
        let (tx_a, mut rx_a) = broadcast::channel(256);
        let (tx_b, _rx_b) = broadcast::channel(256);
        relay.register_connection(a1, a, tx_a);
        relay.register_connection(b1, b, tx_b);
        let mut voice = VoiceMap::new();
        voice.insert(channel, [a, b].into_iter().collect());
        relay.share_start(a1, a, channel, Uuid::new_v4(), false, &voice);
        relay.watch(b1, b, channel, a, true, Uuid::new_v4(), false, &voice);
        relay.keyframe_request(b1, b, channel, a, &voice);
        for _ in 0..30 {
            relay.watch(b1, b, channel, a, false, Uuid::new_v4(), false, &voice);
            relay.watch(b1, b, channel, a, true, Uuid::new_v4(), false, &voice);
            relay.keyframe_request(b1, b, channel, a, &voice);
        }
        let mut requests = 0;
        while let Ok(frame) = rx_a.try_recv() {
            if frame.contains("\"screen_keyframe_request\"") {
                requests += 1;
            }
        }
        assert_eq!(requests, 1);
    }

    #[test]
    fn bucket_starts_full_and_refills_at_the_rate() {
        let config = ScreenConfig::new(true, 2, 200_000).unwrap();
        let t0 = Instant::now();
        let mut bucket = ByteBucket::full(&config, t0);
        // The burst: 1,100,000 bytes at once, then nothing.
        assert!(bucket.take(1_100_000, t0));
        assert!(!bucket.take(1, t0));
        // After 0.5 s, 100,000 bytes are back.
        let t1 = t0 + Duration::from_millis(500);
        assert!(bucket.take(100_000, t1));
        assert!(!bucket.take(1_000, t1));
        // It never holds more than the burst.
        let t2 = t1 + Duration::from_secs(60);
        assert!(bucket.take(1_100_000, t2));
        assert!(!bucket.take(1_000, t2));
    }
}
