//! SPEC-03 §6.12 (REQ-55): the relay's encrypted screen-sharing path
//! `screen/1`. T-55, the relay side of the A1 regression tests RG-SCR-7 and
//! RG-SCR-8 (and of RG-SCR-5 and RG-SCR-9 where the relay is involved), and
//! T-29 for the voice eviction of REQ-29, whose screen clean-up §6.12.4
//! requires.
//!
//! The tests run with rate limits on unless they say otherwise (§10.1).

use accord_server::rate_limit::RateLimiter;
use accord_server::screen::{self, ScreenConfig, ScreenRelay};
use accord_server::state::AppState;
use accord_server::test_support::{count_frames, LogCapture, TestRelay, WsClient};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

const SHORT: Duration = Duration::from_millis(400);
const WAIT: Duration = Duration::from_secs(5);

// ─────────────────────────────────────────────────────────────────────────
//  Fixture
// ─────────────────────────────────────────────────────────────────────────

async fn state_with(config: ScreenConfig, rate_limits: bool) -> AppState {
    let mut state = AppState::new_in_memory().await.expect("relay state");
    state.screen = ScreenRelay::new(config);
    if !rate_limits {
        // `--disable-rate-limits`.
        state.rate_limiter = RateLimiter::new_disabled();
    }
    state
}

async fn relay_with(config: ScreenConfig) -> TestRelay {
    TestRelay::with_state(Arc::new(state_with(config, true).await)).await
}

struct Account {
    id: Uuid,
    token: String,
    public_key: String,
}

/// A node with one voice channel, owned by `owner`.
struct Fixture {
    relay: TestRelay,
    owner: Account,
    node: Uuid,
    channel: Uuid,
}

impl Fixture {
    async fn new(relay: TestRelay) -> Self {
        let owner = register(&relay, "owner").await;
        let node = relay.create_node(&owner.token, "Screen").await;
        let channel = create_channel(&relay, &owner.token, node, "call").await;
        Self {
            relay,
            owner,
            node,
            channel,
        }
    }

    async fn default() -> Self {
        Self::new(relay_with(ScreenConfig::default()).await).await
    }

    /// A registered account that the owner admitted to the node.
    async fn member(&self, name: &str) -> Account {
        let account = register(&self.relay, name).await;
        self.relay
            .join_with_owner_invite(&account.token, self.node)
            .await;
        account
    }

    async fn connect(&self, account: &Account) -> WsClient {
        WsClient::connect(&self.relay, &account.token).await
    }

    /// A connection of `account` that has joined the voice channel.
    async fn in_call(&self, account: &Account) -> WsClient {
        let mut ws = self.connect(account).await;
        join_voice(&mut ws, self.channel).await;
        ws
    }
}

async fn register(relay: &TestRelay, name: &str) -> Account {
    let public_key = format!("spec03-screen-{name}");
    let (id, token) = relay.register_and_auth(&public_key).await;
    Account {
        id,
        token,
        public_key,
    }
}

async fn create_channel(relay: &TestRelay, token: &str, node: Uuid, name: &str) -> Uuid {
    let response = relay
        .client
        .post(relay.url(&format!("/nodes/{node}/channels")))
        .bearer_auth(token)
        .json(&json!({ "name": name, "channel_type": "voice" }))
        .send()
        .await
        .expect("create channel request");
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.expect("channel body");
    Uuid::parse_str(body["id"].as_str().expect("channel id")).expect("channel uuid")
}

async fn join_voice(ws: &mut WsClient, channel: Uuid) -> Value {
    ws.send(json!({ "JoinVoiceChannel": { "channel_id": channel } }))
        .await;
    ws.wait_for("voice_channel_joined", WAIT)
        .await
        .expect("voice_channel_joined")
}

/// A round trip on `ws`: when the reply arrives, the relay has handled
/// every message this connection sent before (one connection's messages are
/// handled in order). Returns the `voice_participants` reply.
async fn sync(ws: &mut WsClient, channel: Uuid) -> Value {
    ws.send(json!({ "GetVoiceParticipants": { "channel_id": channel } }))
        .await;
    ws.wait_for("voice_participants", WAIT)
        .await
        .expect("voice_participants")
}

async fn start(ws: &mut WsClient, channel: Uuid) -> Uuid {
    ws.send(json!({ "ScreenShareStart": { "channel_id": channel } }))
        .await
}

/// Start a share and wait for its acknowledgement (the
/// `screen_share_started` that carries the request's id; announcements of
/// other shares are skipped) and `screen_watchers 0`.
async fn start_share(ws: &mut WsClient, channel: Uuid) -> Value {
    let request = start(ws, channel).await;
    let started = loop {
        let frame = ws
            .wait_for("screen_share_started", WAIT)
            .await
            .expect("screen_share_started");
        if frame["request_id"] == json!(request) {
            break frame;
        }
    };
    let watchers = ws
        .wait_for("screen_watchers", WAIT)
        .await
        .expect("screen_watchers");
    assert_eq!(watchers["watchers"], 0, "{watchers}");
    started
}

async fn stop(ws: &mut WsClient, channel: Uuid) -> Uuid {
    ws.send(json!({ "ScreenShareStop": { "channel_id": channel } }))
        .await
}

async fn watch(ws: &mut WsClient, channel: Uuid, sharer: Uuid, on: bool) -> Uuid {
    ws.send(json!({
        "ScreenWatch": { "channel_id": channel, "sharer_id": sharer, "watch": on }
    }))
    .await
}

/// Watch `sharer` and wait until the relay has recorded it.
async fn watch_synced(ws: &mut WsClient, channel: Uuid, sharer: Uuid) {
    watch(ws, channel, sharer, true).await;
    sync(ws, channel).await;
}

async fn keyframe_request(ws: &mut WsClient, channel: Uuid, sharer: Uuid) -> Uuid {
    ws.send(json!({
        "ScreenKeyframeRequest": { "channel_id": channel, "sharer_id": sharer }
    }))
    .await
}

/// `SCREEN_UP` for `fragment`.
fn up(channel: Uuid, fragment: &[u8]) -> Vec<u8> {
    let mut message = vec![screen::SCREEN_UP];
    message.extend_from_slice(channel.as_bytes());
    message.extend_from_slice(fragment);
    message
}

/// A fragment of `len` bytes that starts with `seq`.
fn fragment(seq: u32, len: usize) -> Vec<u8> {
    let mut fragment = vec![0x5A; len];
    fragment[..4].copy_from_slice(&seq.to_be_bytes());
    fragment
}

/// The sequence number of a `SCREEN_DOWN` built from [`fragment`].
fn seq_of(down: &[u8]) -> u32 {
    u32::from_be_bytes(down[33..37].try_into().unwrap())
}

/// Assert that `down` is `SCREEN_DOWN` for `fragment` from `from` in
/// `channel`, byte for byte.
fn assert_down(down: &[u8], channel: Uuid, from: Uuid, fragment: &[u8]) {
    assert_eq!(down[0], screen::SCREEN_DOWN);
    assert_eq!(&down[1..17], channel.as_bytes());
    assert_eq!(&down[17..33], from.as_bytes());
    assert_eq!(&down[33..], fragment);
}

fn frames_of<'a>(frames: &'a [Value], frame_type: &str) -> Vec<&'a Value> {
    frames.iter().filter(|f| f["type"] == frame_type).collect()
}

async fn health(relay: &TestRelay) -> Value {
    let response = relay
        .client
        .get(relay.url("/health"))
        .send()
        .await
        .expect("health request");
    assert_eq!(response.status().as_u16(), 200);
    response.json().await.expect("health body")
}

fn has_feature(features: &Value, token: &str) -> bool {
    features
        .as_array()
        .expect("features is an array")
        .iter()
        .any(|t| t == token)
}

/// Assert a rejection frame answers `request` with `reason`.
fn assert_rejection(frame: &Value, frame_type: &str, channel: Uuid, reason: &str, request: Uuid) {
    assert_eq!(frame["type"], frame_type, "{frame}");
    assert_eq!(frame["channel_id"], json!(channel), "{frame}");
    assert_eq!(frame["reason"], reason, "{frame}");
    assert!(
        frame["error"].as_str().is_some_and(|e| !e.is_empty()),
        "{frame}"
    );
    assert_eq!(frame["request_id"], json!(request), "{frame}");
}

// ─────────────────────────────────────────────────────────────────────────
//  T-55: advertisement and configuration
// ─────────────────────────────────────────────────────────────────────────

/// T-55: `hello` and `GET /health` list `screen/1` and `screen_limits` with
/// exactly `max_sharers` and `max_bytes_per_second` (OD-109 defaults, and an
/// operator's values).
#[tokio::test]
async fn t55_hello_and_health_advertise_screen() {
    for (config, expected) in [
        (
            ScreenConfig::default(),
            json!({ "max_sharers": 2, "max_bytes_per_second": 500_000 }),
        ),
        (
            ScreenConfig::new(true, 5, 300_000).unwrap(),
            json!({ "max_sharers": 5, "max_bytes_per_second": 300_000 }),
        ),
    ] {
        let fixture = Fixture::new(relay_with(config).await).await;
        let body = health(&fixture.relay).await;
        assert!(has_feature(&body["features"], "screen/1"), "{body}");
        assert_eq!(body["screen_limits"], expected, "{body}");

        let ws = fixture.connect(&fixture.owner).await;
        assert!(
            has_feature(&ws.hello["features"], "screen/1"),
            "{}",
            ws.hello
        );
        assert!(has_feature(&ws.hello["features"], "admission/1"));
        assert_eq!(ws.hello["screen_limits"], expected, "{}", ws.hello);
    }
}

/// T-55: with `--screen-share off`, `hello` and `GET /health` carry neither
/// `screen/1` nor `screen_limits`, and every screen arm answers `disabled`
/// (the start and the watch with their rejection frames; a stop, an unwatch
/// and a keyframe request have nothing to act on and send nothing).
#[tokio::test]
async fn t55_screen_sharing_off() {
    let config = ScreenConfig::new(false, 2, 500_000).unwrap();
    let fixture = Fixture::new(relay_with(config).await).await;
    let body = health(&fixture.relay).await;
    assert!(!has_feature(&body["features"], "screen/1"), "{body}");
    assert!(has_feature(&body["features"], "admission/1"), "{body}");
    assert!(body.get("screen_limits").is_none(), "{body}");

    let a = fixture.member("off-a").await;
    let b = fixture.member("off-b").await;
    let mut ws_a = fixture.connect(&a).await;
    assert!(!has_feature(&ws_a.hello["features"], "screen/1"));
    assert!(ws_a.hello.get("screen_limits").is_none(), "{}", ws_a.hello);
    let joined = join_voice(&mut ws_a, fixture.channel).await;
    assert!(joined.get("screen_sharers").is_none(), "{joined}");
    let mut ws_b = fixture.in_call(&b).await;

    let request = start(&mut ws_a, fixture.channel).await;
    let frame = ws_a
        .wait_for("screen_share_rejected", WAIT)
        .await
        .expect("rejection");
    assert_rejection(
        &frame,
        "screen_share_rejected",
        fixture.channel,
        "disabled",
        request,
    );

    let request = watch(&mut ws_b, fixture.channel, a.id, true).await;
    let frame = ws_b
        .wait_for("screen_watch_rejected", WAIT)
        .await
        .expect("rejection");
    assert_rejection(
        &frame,
        "screen_watch_rejected",
        fixture.channel,
        "disabled",
        request,
    );
    assert_eq!(frame["sharer_id"], json!(a.id));

    stop(&mut ws_a, fixture.channel).await;
    watch(&mut ws_b, fixture.channel, a.id, false).await;
    keyframe_request(&mut ws_b, fixture.channel, a.id).await;
    ws_a.send_binary(up(fixture.channel, &fragment(1, 100)))
        .await;
    let frames_a = ws_a.frames_for(SHORT).await;
    let frames_b = ws_b.frames_for(SHORT).await;
    for frames in [&frames_a, &frames_b] {
        assert!(
            frames
                .iter()
                .all(|f| !f["type"].as_str().unwrap_or("").starts_with("screen_")
                    && f["type"] != "error"),
            "{frames:?}"
        );
    }
    assert!(ws_b.binaries_for(SHORT).await.is_empty());
    let participants = sync(&mut ws_b, fixture.channel).await;
    assert!(
        participants.get("screen_sharers").is_none(),
        "{participants}"
    );
}

/// T-55: `--screen-max-rate` below 200,000 (and the other out-of-range
/// screen settings) is refused at startup: the relay binary exits with an
/// error before it serves anything.
#[test]
fn t55_invalid_screen_settings_are_refused_at_startup() {
    for (flag, value) in [
        ("--screen-max-rate", "199999"),
        ("--screen-max-sharers", "0"),
        ("--screen-max-sharers", "9"),
        ("--screen-share", "sometimes"),
    ] {
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_accord-server"))
            .args(["--no-tls", "--no-admin", "--port", "0", flag, value])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("run the relay binary");
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.try_wait().expect("wait for the relay") {
                break status;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("{flag} {value}: the relay started");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(!status.success(), "{flag} {value}: exited successfully");
        let mut stderr = String::new();
        use std::io::Read;
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(stderr.contains(flag), "{flag} {value}: {stderr}");
    }
    assert!(ScreenConfig::new(true, 2, 199_999).is_err());
    assert!(ScreenConfig::new(true, 2, 200_000).is_ok());
}

// ─────────────────────────────────────────────────────────────────────────
//  T-55: ScreenShareStart and ScreenShareStop
// ─────────────────────────────────────────────────────────────────────────

/// T-55: `ScreenShareStart` from a non-participant gets `not_participant`;
/// the share is announced to every connection of every participant (the
/// requester's copy with `request_id`) and followed by `screen_watchers 0`;
/// a repeat from the sharing connection answers it alone; a third share
/// gets `limit`; a start from the user's second connection ends the first
/// connection's share (`screen_share_stopped`, then `screen_share_started`)
/// and the first connection's later `SCREEN_UP` messages are dropped.
#[tokio::test]
async fn t55_share_start_checks() {
    let fixture = Fixture::default().await;
    let a = fixture.member("start-a").await;
    let b = fixture.member("start-b").await;
    let c = fixture.member("start-c").await;
    let d = fixture.member("start-d").await;
    let mut a1 = fixture.in_call(&a).await;
    let mut b1 = fixture.in_call(&b).await;
    let mut c1 = fixture.in_call(&c).await;
    let mut d1 = fixture.connect(&d).await; // a member, not in the call

    // A non-participant.
    let request = start(&mut d1, fixture.channel).await;
    let frame = d1
        .wait_for("screen_share_rejected", WAIT)
        .await
        .expect("not_participant");
    assert_rejection(
        &frame,
        "screen_share_rejected",
        fixture.channel,
        "not_participant",
        request,
    );

    // A shares.
    let request = start(&mut a1, fixture.channel).await;
    let frames = a1.frames_for(SHORT).await;
    let started = frames_of(&frames, "screen_share_started");
    assert_eq!(started.len(), 1, "{frames:?}");
    assert_eq!(started[0]["user_id"], json!(a.id));
    assert_eq!(started[0]["channel_id"], json!(fixture.channel));
    assert_eq!(started[0]["request_id"], json!(request));
    let position = |t: &str| frames.iter().position(|f| f["type"] == t).unwrap();
    assert!(position("screen_share_started") < position("screen_watchers"));
    assert_eq!(frames_of(&frames, "screen_watchers")[0]["watchers"], 0);
    for ws in [&mut b1, &mut c1] {
        let started = ws
            .wait_for("screen_share_started", WAIT)
            .await
            .expect("announcement");
        assert_eq!(started["user_id"], json!(a.id));
        assert!(started.get("request_id").is_none(), "{started}");
    }

    // A repeat from the sharing connection: answered to it only.
    let request = start(&mut a1, fixture.channel).await;
    let frames = a1.frames_for(SHORT).await;
    let started = frames_of(&frames, "screen_share_started");
    assert_eq!(started.len(), 1, "{frames:?}");
    assert_eq!(started[0]["request_id"], json!(request));
    assert_eq!(
        count_frames(&b1.frames_for(SHORT).await, "screen_share_started"),
        0
    );

    // B shares (2 of 2), C is refused.
    start_share(&mut b1, fixture.channel).await;
    let request = start(&mut c1, fixture.channel).await;
    let frame = c1
        .wait_for("screen_share_rejected", WAIT)
        .await
        .expect("limit");
    assert_rejection(
        &frame,
        "screen_share_rejected",
        fixture.channel,
        "limit",
        request,
    );

    // A's second connection takes over A's share.
    let mut a2 = fixture.connect(&a).await;
    c1.frames_for(SHORT).await;
    let request = start(&mut a2, fixture.channel).await;
    let frames = a2.frames_for(SHORT).await;
    let started = frames_of(&frames, "screen_share_started");
    assert_eq!(started.len(), 1, "{frames:?}");
    assert_eq!(started[0]["request_id"], json!(request));
    // The requesting connection is not told that its user's other share
    // ended: its own start is answered by `screen_share_started` alone.
    assert_eq!(
        count_frames(&frames, "screen_share_stopped"),
        0,
        "{frames:?}"
    );
    let frames = c1.frames_for(SHORT).await;
    let types: Vec<&str> = frames
        .iter()
        .filter_map(|f| f["type"].as_str())
        .filter(|t| t.starts_with("screen_share"))
        .collect();
    assert_eq!(
        types,
        vec!["screen_share_stopped", "screen_share_started"],
        "{frames:?}"
    );
    assert_eq!(
        frames_of(&frames, "screen_share_stopped")[0]["reason"],
        "stopped"
    );
    assert_eq!(
        frames_of(&frames, "screen_share_stopped")[0]["user_id"],
        json!(a.id)
    );
    let stopped = a1
        .wait_for("screen_share_stopped", WAIT)
        .await
        .expect("the first connection learns its share ended");
    assert!(stopped.get("request_id").is_none(), "{stopped}");

    // C watches A: only the second connection's fragments reach it.
    watch_synced(&mut c1, fixture.channel, a.id).await;
    a1.send_binary(up(fixture.channel, &fragment(1, 64))).await;
    sync(&mut a1, fixture.channel).await;
    a2.send_binary(up(fixture.channel, &fragment(2, 64))).await;
    sync(&mut a2, fixture.channel).await;
    let received = c1.binaries_for(SHORT).await;
    assert_eq!(received.len(), 1);
    assert_down(&received[0], fixture.channel, a.id, &fragment(2, 64));
}

/// T-55: after 10 start or stop messages from U in the last 60 s a
/// `ScreenShareStart` gets `rate_limited`; a `ScreenShareStop` sent then is
/// still honored (with `request_id` on the stopping connection's copy); a
/// stop from a connection without a share changes nothing.
#[tokio::test]
async fn t55_start_stop_rate_limit() {
    let fixture = Fixture::default().await;
    let a = fixture.member("rate-a").await;
    let b = fixture.member("rate-b").await;
    let mut ws_a = fixture.in_call(&a).await;
    let mut ws_b = fixture.in_call(&b).await;

    // 10 messages: S T S T S T S T S S; the share is active after them.
    for i in 0..10 {
        if i % 2 == 0 || i == 9 {
            start(&mut ws_a, fixture.channel).await;
        } else {
            stop(&mut ws_a, fixture.channel).await;
        }
    }
    let frames = ws_a.frames_for(SHORT).await;
    assert_eq!(
        count_frames(&frames, "screen_share_rejected"),
        0,
        "{frames:?}"
    );
    assert_eq!(
        count_frames(&frames, "screen_share_started"),
        6,
        "{frames:?}"
    );

    let request = start(&mut ws_a, fixture.channel).await;
    let frame = ws_a
        .wait_for("screen_share_rejected", WAIT)
        .await
        .expect("rate_limited");
    assert_rejection(
        &frame,
        "screen_share_rejected",
        fixture.channel,
        "rate_limited",
        request,
    );

    ws_b.frames_for(SHORT).await;
    let request = stop(&mut ws_a, fixture.channel).await;
    let stopped = ws_a
        .wait_for("screen_share_stopped", WAIT)
        .await
        .expect("the stop is honored");
    assert_eq!(stopped["request_id"], json!(request));
    assert_eq!(stopped["reason"], "stopped");
    let stopped = ws_b
        .wait_for("screen_share_stopped", WAIT)
        .await
        .expect("participants learn of the stop");
    assert!(stopped.get("request_id").is_none(), "{stopped}");
    assert_eq!(stopped["user_id"], json!(a.id));

    // A stop from a connection without a share: nothing.
    stop(&mut ws_b, fixture.channel).await;
    assert!(ws_a.frames_for(SHORT).await.is_empty());
    assert!(ws_b.frames_for(SHORT).await.is_empty());
}

/// T-55: `ScreenShareStop` and `ScreenWatch` `false` are honored from a
/// connection whose user has already left C, and are never refused for
/// rate: they produce no rejection and no error frame.
#[tokio::test]
async fn t55_stop_and_unwatch_are_never_refused() {
    let fixture = Fixture::default().await;
    let a = fixture.member("never-a").await;
    let b = fixture.member("never-b").await;
    let mut ws_a = fixture.in_call(&a).await;
    let mut ws_b = fixture.in_call(&b).await;
    start_share(&mut ws_a, fixture.channel).await;
    watch_synced(&mut ws_b, fixture.channel, a.id).await;

    // B leaves the call: its watch is gone with it.
    ws_b.send(json!({ "LeaveVoiceChannel": { "channel_id": fixture.channel } }))
        .await;
    ws_b.wait_for("voice_channel_left", WAIT).await.unwrap();
    for _ in 0..40 {
        watch(&mut ws_b, fixture.channel, a.id, false).await;
    }
    // A leaves too, then stops many times.
    ws_a.send(json!({ "LeaveVoiceChannel": { "channel_id": fixture.channel } }))
        .await;
    ws_a.wait_for("voice_channel_left", WAIT).await.unwrap();
    ws_a.frames_for(SHORT).await;
    for _ in 0..15 {
        stop(&mut ws_a, fixture.channel).await;
    }
    for ws in [&mut ws_a, &mut ws_b] {
        let frames = ws.frames_for(SHORT).await;
        assert!(
            frames.iter().all(|f| f["type"] != "error"
                && f["type"] != "screen_share_rejected"
                && f["type"] != "screen_watch_rejected"),
            "{frames:?}"
        );
    }
    assert!(fixture
        .relay
        .state
        .screen
        .sharers(fixture.channel)
        .is_empty());
}

/// T-55: with `--disable-rate-limits` the start, stop and watch counters
/// are off, while the byte bucket and the queue bounds still hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t55_disable_rate_limits_keeps_byte_and_queue_bounds() {
    let config = ScreenConfig::new(true, 2, 200_000).unwrap();
    let relay = TestRelay::with_state(Arc::new(state_with(config, false).await)).await;
    let fixture = Fixture::new(relay).await;
    let a = fixture.member("norate-a").await;
    let b = fixture.member("norate-b").await;
    let mut ws_a = fixture.in_call(&a).await;
    let mut ws_b = fixture.in_call(&b).await;

    for _ in 0..8 {
        start(&mut ws_a, fixture.channel).await;
        stop(&mut ws_a, fixture.channel).await;
    }
    start(&mut ws_a, fixture.channel).await;
    let frames = ws_a.frames_for(SHORT).await;
    assert_eq!(
        count_frames(&frames, "screen_share_rejected"),
        0,
        "{frames:?}"
    );
    assert!(fixture.relay.state.screen.sharers(fixture.channel) == vec![a.id]);

    for i in 0..40 {
        watch(&mut ws_b, fixture.channel, a.id, i % 2 == 0).await;
    }
    watch(&mut ws_b, fixture.channel, a.id, true).await;
    let frames = ws_b.frames_for(SHORT).await;
    assert_eq!(
        count_frames(&frames, "screen_watch_rejected"),
        0,
        "{frames:?}"
    );

    // The byte bucket: 200,000 bytes per second with the 1,100,000-byte
    // burst. 120 maximum-size messages are far more than it holds.
    let started = Instant::now();
    for seq in 0..120u32 {
        ws_a.send_binary(up(fixture.channel, &fragment(seq, 16_384)))
            .await;
    }
    sync(&mut ws_a, fixture.channel).await;
    let elapsed = started.elapsed().as_secs_f64();
    let received = ws_b.binaries_for(Duration::from_secs(1)).await;
    let stats = fixture.relay.state.screen.user_queue_stats(b.id);
    assert_eq!(stats.len(), 1);
    let stats = stats[0];
    let allowed = ((1_100_000.0 + 200_000.0 * elapsed) / 16_401.0).floor() as u64 + 1;
    assert!(stats.enqueued <= allowed, "{stats:?}, allowed {allowed}");
    assert!(stats.enqueued >= 60, "{stats:?}");
    assert!(stats.max_len <= screen::QUEUE_MAX_MESSAGES, "{stats:?}");
    assert!(stats.max_bytes <= screen::QUEUE_MAX_BYTES, "{stats:?}");
    assert_eq!(
        received.len() as u64,
        stats.enqueued - stats.dropped_head - stats.dropped_age,
        "{stats:?}"
    );

    // Stopping and starting again, with no start-and-stop counter to stop
    // it, does not refill the bucket: across four shares the bytes
    // forwarded stay within one burst plus the rate for the time taken.
    // (Before, each new share started with a full 1,100,000-byte bucket, so
    // each burst of 50 messages would have passed whole.)
    let before = stats.enqueued;
    let started = Instant::now();
    for round in 0..4u32 {
        if round > 0 {
            stop(&mut ws_a, fixture.channel).await;
            start_share(&mut ws_a, fixture.channel).await;
            watch_synced(&mut ws_b, fixture.channel, a.id).await;
        }
        for seq in 0..50u32 {
            ws_a.send_binary(up(fixture.channel, &fragment(round * 100 + seq, 16_384)))
                .await;
        }
        sync(&mut ws_a, fixture.channel).await;
    }
    let elapsed = started.elapsed().as_secs_f64();
    ws_b.binaries_for(Duration::from_secs(1)).await;
    let stats = fixture.relay.state.screen.user_queue_stats(b.id)[0];
    let forwarded = stats.enqueued - before;
    let allowed = ((1_100_000.0 + 200_000.0 * elapsed) / 16_401.0).floor() as u64 + 1;
    assert!(
        forwarded <= allowed,
        "forwarded {forwarded} of 200 over {elapsed:.2} s, allowed {allowed}"
    );
    assert!(stats.max_len <= screen::QUEUE_MAX_MESSAGES, "{stats:?}");
    assert!(stats.max_bytes <= screen::QUEUE_MAX_BYTES, "{stats:?}");
}

// ─────────────────────────────────────────────────────────────────────────
//  T-55: ScreenWatch and ScreenKeyframeRequest
// ─────────────────────────────────────────────────────────────────────────

/// T-55: `ScreenWatch` checks in the order of §6.12.1: `not_participant`
/// (before `not_sharing`), `rate_limited` after 30 watch requests of the
/// connection in 60 s (before `not_sharing`), `not_sharing` for a user
/// without a share and for oneself, `watch_limit` for a third watch; a
/// repeated watch is idempotent.
#[tokio::test]
async fn t55_watch_checks_in_order() {
    let config = ScreenConfig::new(true, 3, 500_000).unwrap();
    let fixture = Fixture::new(relay_with(config).await).await;
    let a = fixture.member("watch-a").await;
    let b = fixture.member("watch-b").await;
    let c = fixture.member("watch-c").await;
    let v = fixture.member("watch-v").await;
    let d = fixture.member("watch-d").await;
    let mut ws_a = fixture.in_call(&a).await;
    let mut ws_b = fixture.in_call(&b).await;
    let mut ws_c = fixture.in_call(&c).await;
    let mut ws_v = fixture.in_call(&v).await;
    let mut ws_d = fixture.connect(&d).await; // not in the call

    let expect = |frame: Option<Value>, sharer: Uuid, reason: &str, request: Uuid| {
        let frame = frame.expect("rejection");
        assert_rejection(
            &frame,
            "screen_watch_rejected",
            fixture.channel,
            reason,
            request,
        );
        assert_eq!(frame["sharer_id"], json!(sharer), "{frame}");
    };

    // A has no share yet: the participant check comes first.
    let request = watch(&mut ws_d, fixture.channel, a.id, true).await;
    expect(
        ws_d.wait_for("screen_watch_rejected", WAIT).await,
        a.id,
        "not_participant",
        request,
    );
    let request = watch(&mut ws_v, fixture.channel, a.id, true).await;
    expect(
        ws_v.wait_for("screen_watch_rejected", WAIT).await,
        a.id,
        "not_sharing",
        request,
    );

    // Oneself.
    start_share(&mut ws_v, fixture.channel).await;
    let request = watch(&mut ws_v, fixture.channel, v.id, true).await;
    expect(
        ws_v.wait_for("screen_watch_rejected", WAIT).await,
        v.id,
        "not_sharing",
        request,
    );
    stop(&mut ws_v, fixture.channel).await;
    ws_v.wait_for("screen_share_stopped", WAIT).await.unwrap();

    start_share(&mut ws_a, fixture.channel).await;
    start_share(&mut ws_b, fixture.channel).await;
    start_share(&mut ws_c, fixture.channel).await;
    watch(&mut ws_v, fixture.channel, a.id, true).await;
    watch(&mut ws_v, fixture.channel, a.id, true).await; // idempotent
    watch(&mut ws_v, fixture.channel, b.id, true).await;
    let request = watch(&mut ws_v, fixture.channel, c.id, true).await;
    expect(
        ws_v.wait_for("screen_watch_rejected", WAIT).await,
        c.id,
        "watch_limit",
        request,
    );
    // The repeated watch counted once: A's count settles at 1.
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let counts: Vec<i64> = frames_of(&ws_a.frames_for(SHORT).await, "screen_watchers")
        .iter()
        .map(|f| f["watchers"].as_i64().unwrap())
        .collect();
    assert_eq!(counts.last(), Some(&1), "{counts:?}");
    assert!(counts.iter().all(|&n| n <= 1), "{counts:?}");

    // The rate limit is per connection and precedes `not_sharing`: 30
    // requests for D (who shares nothing) are answered `not_sharing`, the
    // 31st `rate_limited`.
    let mut ws_v2 = fixture.connect(&v).await;
    for _ in 0..30 {
        watch(&mut ws_v2, fixture.channel, d.id, true).await;
    }
    let frames = ws_v2.frames_for(SHORT).await;
    let rejections = frames_of(&frames, "screen_watch_rejected");
    assert_eq!(rejections.len(), 30, "{frames:?}");
    assert!(rejections.iter().all(|f| f["reason"] == "not_sharing"));
    let request = watch(&mut ws_v2, fixture.channel, d.id, true).await;
    expect(
        ws_v2.wait_for("screen_watch_rejected", WAIT).await,
        d.id,
        "rate_limited",
        request,
    );
    // `watch: false` is never counted or refused.
    for _ in 0..5 {
        watch(&mut ws_v2, fixture.channel, a.id, false).await;
    }
    assert_eq!(
        count_frames(&ws_v2.frames_for(SHORT).await, "screen_watch_rejected"),
        0
    );
}

/// T-55 and the relay side of RG-SCR-5: `ScreenKeyframeRequest` is
/// forwarded only from a watching connection, only to the sharing
/// connection, and at most once per second per connection and share.
#[tokio::test]
async fn t55_keyframe_requests() {
    let fixture = Fixture::default().await;
    let a = fixture.member("kfr-a").await;
    let b = fixture.member("kfr-b").await;
    let c = fixture.member("kfr-c").await;
    let mut a1 = fixture.in_call(&a).await;
    let mut a2 = fixture.connect(&a).await;
    let mut b1 = fixture.in_call(&b).await;
    let mut b2 = fixture.connect(&b).await;
    let mut c1 = fixture.in_call(&c).await;
    start_share(&mut a1, fixture.channel).await;
    watch_synced(&mut b1, fixture.channel, a.id).await;
    a1.frames_for(SHORT).await;

    // Not watching: dropped.
    keyframe_request(&mut c1, fixture.channel, a.id).await;
    keyframe_request(&mut b2, fixture.channel, a.id).await;
    // No share: dropped.
    keyframe_request(&mut b1, fixture.channel, c.id).await;
    sync(&mut c1, fixture.channel).await;
    sync(&mut b2, fixture.channel).await;
    sync(&mut b1, fixture.channel).await;
    assert_eq!(
        count_frames(&a1.frames_for(SHORT).await, "screen_keyframe_request"),
        0
    );

    // Watching: forwarded to the sharing connection only, once per second.
    for _ in 0..6 {
        keyframe_request(&mut b1, fixture.channel, a.id).await;
    }
    sync(&mut b1, fixture.channel).await;
    let frames = a1.frames_for(SHORT).await;
    let requests = frames_of(&frames, "screen_keyframe_request");
    assert_eq!(requests.len(), 1, "{frames:?}");
    assert_eq!(
        *requests[0],
        json!({
            "type": "screen_keyframe_request",
            "channel_id": fixture.channel,
            "from": b.id,
        })
    );
    for ws in [&mut a2, &mut b1, &mut b2, &mut c1] {
        assert_eq!(
            count_frames(
                &ws.frames_for(Duration::from_millis(100)).await,
                "screen_keyframe_request"
            ),
            0
        );
    }
    tokio::time::sleep(Duration::from_millis(1100)).await;
    keyframe_request(&mut b1, fixture.channel, a.id).await;
    keyframe_request(&mut b1, fixture.channel, a.id).await;
    let frames = a1.frames_for(SHORT).await;
    assert_eq!(
        count_frames(&frames, "screen_keyframe_request"),
        1,
        "{frames:?}"
    );

    // The gap belongs to the connection and the share, not to the watch:
    // a request, an unwatch, a new watch and another request within 1 s
    // reach the sharer once, however often the cycle repeats.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    keyframe_request(&mut b1, fixture.channel, a.id).await;
    for _ in 0..5 {
        watch(&mut b1, fixture.channel, a.id, false).await;
        watch(&mut b1, fixture.channel, a.id, true).await;
        keyframe_request(&mut b1, fixture.channel, a.id).await;
    }
    sync(&mut b1, fixture.channel).await;
    let frames = a1.frames_for(SHORT).await;
    assert_eq!(
        count_frames(&frames, "screen_keyframe_request"),
        1,
        "{frames:?}"
    );
    assert_eq!(
        count_frames(&b1.frames_for(SHORT).await, "screen_watch_rejected"),
        0
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  T-55: binary messages and forwarding
// ─────────────────────────────────────────────────────────────────────────

/// The shared vector file of §6.11. It is mandatory: T-55 reads its
/// `screen_wire` section, so a missing or renamed file fails the build.
const AMF1_VECTORS: &str = include_str!("../../core/tests/vectors/amf1-v1.json");

/// T-55: the `screen_wire` vectors of the shared vector file (§6.11), which
/// cover what §6.11 lists; each `up` message is accepted or dropped by the
/// relay as the vector expects, and each `down` message parses as the relay
/// builds it.
#[tokio::test]
async fn t55_screen_wire_vectors() {
    let vectors: Value = serde_json::from_str(AMF1_VECTORS).expect("vector file is JSON");
    let entries = vectors["screen_wire"]
        .as_array()
        .expect("the vector file has a screen_wire array");

    // §6.11: valid SCREEN_UP and SCREEN_DOWN messages of minimum and maximum
    // size, an unknown type byte, a 16-byte message, and messages one byte
    // over each maximum.
    let decoded: Vec<(String, bool, Vec<u8>)> = entries
        .iter()
        .map(|entry| {
            let name = entry["name"].as_str().expect("name");
            let direction = entry["direction"]
                .as_str()
                .unwrap_or_else(|| panic!("{name}: direction"));
            assert!(
                direction == "up" || direction == "down",
                "{name}: {direction}"
            );
            let expect = entry["expect"]
                .as_str()
                .unwrap_or_else(|| panic!("{name}: expect"));
            assert!(expect == "accept" || expect == "reject", "{name}: {expect}");
            let bytes = hex::decode(entry["bytes"].as_str().expect("bytes")).expect("hex");
            (direction.to_string(), expect == "accept", bytes)
        })
        .collect();
    let has = |direction: Option<&str>, accept: bool, test: &dyn Fn(&[u8]) -> bool| {
        decoded
            .iter()
            .any(|(d, a, b)| direction.is_none_or(|x| x == d) && *a == accept && test(b))
    };
    let of_len = |len: usize| move |b: &[u8]| b.len() == len;
    let typed = |len: usize, kind: u8| move |b: &[u8]| b.len() == len && b[0] == kind;
    for (direction, accept, len, kind, what) in [
        (
            "up",
            true,
            screen::SCREEN_UP_MIN,
            screen::SCREEN_UP,
            "minimum SCREEN_UP",
        ),
        (
            "up",
            true,
            screen::SCREEN_UP_MAX,
            screen::SCREEN_UP,
            "maximum SCREEN_UP",
        ),
        (
            "down",
            true,
            screen::SCREEN_DOWN_MIN,
            screen::SCREEN_DOWN,
            "minimum SCREEN_DOWN",
        ),
        (
            "down",
            true,
            screen::SCREEN_DOWN_MAX,
            screen::SCREEN_DOWN,
            "maximum SCREEN_DOWN",
        ),
        (
            "up",
            false,
            screen::SCREEN_UP_MAX + 1,
            screen::SCREEN_UP,
            "SCREEN_UP one byte over",
        ),
        (
            "down",
            false,
            screen::SCREEN_DOWN_MAX + 1,
            screen::SCREEN_DOWN,
            "SCREEN_DOWN one byte over",
        ),
    ] {
        assert!(
            has(Some(direction), accept, &typed(len, kind)),
            "no {what} vector"
        );
    }
    assert!(
        has(None, false, &|b: &[u8]| !b.is_empty()
            && b[0] != screen::SCREEN_UP
            && b[0] != screen::SCREEN_DOWN),
        "no unknown-type vector"
    );
    assert!(has(None, false, &of_len(16)), "no 16-byte vector");

    let fixture = Fixture::default().await;
    let a = fixture.member("wire-a").await;
    let b = fixture.member("wire-b").await;
    let mut ws_a = fixture.connect(&a).await;
    let mut ws_b = fixture.connect(&b).await;
    let mut shared: HashSet<Uuid> = HashSet::new();
    for entry in entries {
        let name = entry["name"].as_str().unwrap_or("?");
        let bytes = hex::decode(entry["bytes"].as_str().expect("bytes")).expect("hex");
        let accept = entry["expect"] == "accept";
        match entry["direction"].as_str() {
            Some("up") => {
                assert_eq!(screen::parse_screen_up(&bytes).is_some(), accept, "{name}");
                // Through the relay: the vector's channel gets A and B as
                // participants, A shares there and B watches.
                let channel = if bytes.len() >= 17 {
                    Uuid::from_slice(&bytes[1..17]).unwrap()
                } else {
                    fixture.channel
                };
                if accept && shared.insert(channel) {
                    {
                        let mut voice = fixture.relay.state.voice_channels.write().await;
                        let participants = voice.entry(channel).or_default();
                        participants.insert(a.id);
                        participants.insert(b.id);
                    }
                    start_share(&mut ws_a, channel).await;
                    watch_synced(&mut ws_b, channel, a.id).await;
                }
                ws_a.send_binary(bytes.clone()).await;
                sync(&mut ws_a, fixture.channel).await;
                let received = ws_b.binaries_for(SHORT).await;
                if accept {
                    assert_eq!(received.len(), 1, "{name}");
                    assert_eq!(
                        received[0],
                        screen::build_screen_down(channel, a.id, &bytes[17..]),
                        "{name}"
                    );
                } else {
                    assert!(received.is_empty(), "{name}");
                }
            }
            Some("down") => {
                let parsed = screen::parse_screen_down(&bytes);
                assert_eq!(parsed.is_some(), accept, "{name}");
                if let Some((channel, from, fragment)) = parsed {
                    assert_eq!(
                        screen::build_screen_down(channel, from, fragment),
                        bytes,
                        "{name}"
                    );
                }
            }
            other => panic!("{name}: unknown direction {other:?}"),
        }
    }
}

/// T-55: messages of 37 and 16,401 bytes are forwarded byte for byte;
/// messages of 36 and 16,402 bytes, type bytes 0x02 and 0x00 upstream, a
/// 16-byte message, and `SCREEN_UP` from a sharer's other device, from a
/// non-participant and from a participant who is not sharing are dropped.
#[tokio::test]
async fn t55_binary_checks() {
    let fixture = Fixture::default().await;
    let a = fixture.member("bin-a").await;
    let b = fixture.member("bin-b").await;
    let c = fixture.member("bin-c").await;
    let d = fixture.member("bin-d").await;
    let mut a1 = fixture.in_call(&a).await;
    let mut a2 = fixture.connect(&a).await;
    let mut b1 = fixture.in_call(&b).await;
    let mut c1 = fixture.in_call(&c).await;
    let mut d1 = fixture.connect(&d).await; // not in the call
    start_share(&mut a1, fixture.channel).await;
    watch_synced(&mut b1, fixture.channel, a.id).await;

    let channel = fixture.channel;
    let bad = |len: usize, kind: u8| {
        let mut m = up(channel, &vec![0xEE; len.saturating_sub(17)]);
        m.truncate(len);
        m[0] = kind;
        m
    };
    for message in [
        bad(36, screen::SCREEN_UP),
        bad(16_402, screen::SCREEN_UP),
        bad(37, screen::SCREEN_DOWN),
        bad(37, 0x00),
        bad(16, screen::SCREEN_UP),
    ] {
        a1.send_binary(message).await;
    }
    sync(&mut a1, fixture.channel).await;
    for ws in [&mut a2, &mut c1, &mut d1] {
        ws.send_binary(up(fixture.channel, &fragment(99, 100)))
            .await;
        sync(ws, fixture.channel).await;
    }
    assert!(b1.binaries_for(SHORT).await.is_empty());

    for len in [20, 16_384] {
        let f = fragment(len as u32, len);
        a1.send_binary(up(fixture.channel, &f)).await;
        let down = b1.next_binary(WAIT).await.expect("forwarded");
        assert_eq!(down.len(), len + 33);
        assert_down(&down, fixture.channel, a.id, &f);
    }
}

/// T-55: fragments go only to watching connections of participants, never
/// to the sender, to non-watchers or to the sharer's other devices, byte for
/// byte with the relay-stamped `from`. A non-participant cannot watch.
#[tokio::test]
async fn t55_forwarding() {
    let fixture = Fixture::default().await;
    let a = fixture.member("fwd-a").await;
    let b = fixture.member("fwd-b").await;
    let c = fixture.member("fwd-c").await;
    let e = fixture.member("fwd-e").await;
    let mut a1 = fixture.in_call(&a).await;
    let mut a2 = fixture.connect(&a).await;
    let mut b1 = fixture.in_call(&b).await;
    let mut b2 = fixture.connect(&b).await;
    let mut c1 = fixture.in_call(&c).await;
    let mut e1 = fixture.connect(&e).await;
    start_share(&mut a1, fixture.channel).await;
    watch_synced(&mut b1, fixture.channel, a.id).await;
    watch(&mut e1, fixture.channel, a.id, true).await;
    assert_eq!(
        e1.wait_for("screen_watch_rejected", WAIT).await.unwrap()["reason"],
        "not_participant"
    );

    let fragments: Vec<Vec<u8>> = (0..3u32).map(|i| fragment(i, 1000 + i as usize)).collect();
    for f in &fragments {
        a1.send_binary(up(fixture.channel, f)).await;
    }
    for f in &fragments {
        let down = b1.next_binary(WAIT).await.expect("forwarded");
        assert_down(&down, fixture.channel, a.id, f);
    }
    for ws in [&mut a1, &mut a2, &mut b2, &mut c1, &mut e1] {
        assert!(ws.binaries_for(SHORT).await.is_empty());
    }
}

/// T-55 and the relay side of RG-SCR-8: a watcher that stops reading, with a
/// 64 KiB receive buffer, while the sharer sends near the full byte rate.
/// Its screen queue never holds more than 256 messages or 1 MiB and drops
/// the oldest fragments first; a `sender_key_rotation_required` sent during
/// the stall arrives (no lag); when it reads again it receives no fragment
/// that the relay received more than 2 s earlier, apart from those already
/// in the transport buffers when the stall began, and it receives the newest
/// fragments sent before it resumed; the other watcher keeps receiving
/// everything; and the stalled watcher recovers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t55_stalled_watcher() {
    const BUFFER: u32 = 64 * 1024;
    let state = state_with(ScreenConfig::default(), true).await;
    let relay = TestRelay::with_state_and_send_buffer(Arc::new(state), BUFFER).await;
    let fixture = Fixture::new(relay).await;
    let a = fixture.member("stall-a").await;
    let b = fixture.member("stall-b").await;
    let d = fixture.member("stall-d").await;
    let e = fixture.member("stall-e").await;
    let mut ws_a = fixture.in_call(&a).await;
    let mut ws_b = WsClient::connect_with_recv_buffer(&fixture.relay, &b.token, BUFFER).await;
    join_voice(&mut ws_b, fixture.channel).await;
    // B subscribes to the channel, so it receives the rotation event of a
    // removal from the node.
    ws_b.send(json!({ "JoinChannel": { "channel_id": fixture.channel } }))
        .await;
    let mut ws_d = fixture.in_call(&d).await;
    start_share(&mut ws_a, fixture.channel).await;
    watch_synced(&mut ws_b, fixture.channel, a.id).await;
    watch_synced(&mut ws_d, fixture.channel, a.id).await;
    ws_b.frames_for(SHORT).await;

    // D reads all the time.
    let reader = tokio::spawn(async move {
        let mut seqs = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Some(down) = ws_d.next_binary(Duration::from_millis(200)).await {
                seqs.push(seq_of(&down));
            }
        }
        seqs
    });

    // B stops reading. A sends about 475,000 bytes per second (95 % of the
    // rate) for 4 s, and the owner kicks E after 1.5 s.
    const LEN: usize = 16_384;
    let stall = Instant::now();
    let interval = Duration::from_secs_f64((LEN + 17) as f64 / 475_000.0);
    let mut sent_at: HashMap<u32, Instant> = HashMap::new();
    let mut seq = 0u32;
    let mut kicked = false;
    while stall.elapsed() < Duration::from_millis(4000) {
        sent_at.insert(seq, Instant::now());
        ws_a.send_binary(up(fixture.channel, &fragment(seq, LEN)))
            .await;
        seq += 1;
        if !kicked && stall.elapsed() > Duration::from_millis(1500) {
            kicked = true;
            let response = fixture
                .relay
                .client
                .delete(
                    fixture
                        .relay
                        .url(&format!("/nodes/{}/members/{}", fixture.node, e.id)),
                )
                .bearer_auth(&fixture.owner.token)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), 200);
        }
        let next = stall + interval * seq;
        tokio::time::sleep(next.saturating_duration_since(Instant::now())).await;
    }
    let sent = seq;
    sync(&mut ws_a, fixture.channel).await;
    // B resumes 1 s after the last fragment: the oldest queued fragments
    // are then well past 2 s, the newest well within it.
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // The relay held B's queue within its bounds and dropped the oldest.
    let stats = fixture.relay.state.screen.user_queue_stats(b.id);
    assert_eq!(stats.len(), 1);
    let before = stats[0];
    assert!(before.max_len <= screen::QUEUE_MAX_MESSAGES, "{before:?}");
    assert!(before.max_bytes <= screen::QUEUE_MAX_BYTES, "{before:?}");
    assert!(
        before.dropped_head > 0,
        "the queue never filled: {before:?}"
    );

    // B reads again.
    let resumed = Instant::now();
    let mut received: Vec<(u32, Instant)> = Vec::new();
    let mut texts = Vec::new();
    let deadline = resumed + Duration::from_secs(2);
    while Instant::now() < deadline {
        if let Some(down) = ws_b.next_binary(Duration::from_millis(100)).await {
            received.push((seq_of(&down), Instant::now()));
        }
    }
    texts.extend(ws_b.frames_for(SHORT).await);
    let rotations = frames_of(&texts, "sender_key_rotation_required");
    assert!(
        rotations
            .iter()
            .any(|f| f["channel_id"] == json!(fixture.channel)
                && f["removed_user_id"] == json!(e.id)),
        "{texts:?}"
    );

    let seqs: Vec<u32> = received.iter().map(|(s, _)| *s).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "order kept: {seqs:?}");
    // The fragments in the transport buffers at the stall: a prefix that
    // starts at 0 and is contiguous.
    let in_flight = seqs
        .iter()
        .enumerate()
        .take_while(|(i, s)| **s == *i as u32)
        .count();
    let in_flight_bytes = in_flight * (LEN + 33);
    assert!(
        in_flight_bytes <= 512 * 1024,
        "{in_flight} fragments were in flight: {seqs:?}"
    );
    // Everything after it came from the queue and was at most 2 s old when
    // the relay dequeued it (with 500 ms for the hops on either side).
    for (s, at) in &received[in_flight..] {
        let age = at.saturating_duration_since(sent_at[s]);
        assert!(
            age <= Duration::from_millis(2500),
            "fragment {s} reached B {age:?} after it was sent: {seqs:?}"
        );
    }
    // The fragments lost were screen fragments in one contiguous run: the
    // oldest queued ones.
    let lost: Vec<u32> = (0..sent).filter(|s| !seqs.contains(s)).collect();
    assert!(!lost.is_empty());
    assert!(lost.windows(2).all(|w| w[1] == w[0] + 1), "{lost:?}");
    // The newest fragment sent before B resumed arrived.
    assert_eq!(seqs.last(), Some(&(sent - 1)), "{seqs:?}");
    let after = fixture.relay.state.screen.user_queue_stats(b.id)[0];
    assert!(after.dropped_age > 0, "{after:?}");

    // B recovers.
    ws_a.send_binary(up(fixture.channel, &fragment(sent, LEN)))
        .await;
    let down = ws_b.next_binary(WAIT).await.expect("B receives again");
    assert_eq!(seq_of(&down), sent);

    // D received everything.
    let d_seqs = reader.await.unwrap();
    assert_eq!(d_seqs, (0..=sent).collect::<Vec<u32>>());
}

/// T-55: `screen_watchers` is sent at share start (0) and on changes, at
/// most once per second per share, the latest value winning.
#[tokio::test]
async fn t55_screen_watchers_coalesced() {
    let fixture = Fixture::default().await;
    let a = fixture.member("count-a").await;
    let b = fixture.member("count-b").await;
    let c = fixture.member("count-c").await;
    let mut ws_a = fixture.in_call(&a).await;
    let mut ws_b = fixture.in_call(&b).await;
    let mut ws_c = fixture.in_call(&c).await;
    start_share(&mut ws_a, fixture.channel).await;
    let zero_at = Instant::now();

    // Three changes within the first second: one message with the latest
    // value, one second after the 0.
    watch_synced(&mut ws_b, fixture.channel, a.id).await;
    watch_synced(&mut ws_c, fixture.channel, a.id).await;
    watch(&mut ws_b, fixture.channel, a.id, false).await;
    sync(&mut ws_b, fixture.channel).await;
    let first = ws_a
        .wait_for("screen_watchers", Duration::from_secs(3))
        .await
        .expect("coalesced screen_watchers");
    let first_at = Instant::now();
    assert_eq!(first["watchers"], 1, "{first}");
    assert_eq!(first["channel_id"], json!(fixture.channel));
    assert!(
        first_at.duration_since(zero_at) >= Duration::from_millis(900),
        "{:?}",
        first_at.duration_since(zero_at)
    );
    assert_eq!(
        count_frames(&ws_a.frames_for(SHORT).await, "screen_watchers"),
        0
    );

    // After a quiet second, a change is reported at once.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let watched = Instant::now();
    watch(&mut ws_b, fixture.channel, a.id, true).await;
    let second = ws_a
        .wait_for("screen_watchers", Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(second["watchers"], 2);
    assert!(watched.elapsed() < Duration::from_millis(500));

    // A change and its reversal within the gap send nothing more.
    watch(&mut ws_c, fixture.channel, a.id, false).await;
    watch(&mut ws_c, fixture.channel, a.id, true).await;
    sync(&mut ws_c, fixture.channel).await;
    assert_eq!(
        count_frames(
            &ws_a.frames_for(Duration::from_millis(1500)).await,
            "screen_watchers"
        ),
        0
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  T-55: clean-up (§6.12.4)
// ─────────────────────────────────────────────────────────────────────────

/// T-55: clean-up on `ScreenShareStop`: watches go with the share, so
/// keyframe requests and fragments are no longer forwarded, and the share
/// leaves `screen_sharers`.
#[tokio::test]
async fn t55_cleanup_on_stop() {
    let fixture = Fixture::default().await;
    let a = fixture.member("cstop-a").await;
    let b = fixture.member("cstop-b").await;
    let mut ws_a = fixture.in_call(&a).await;
    let mut ws_b = fixture.in_call(&b).await;
    start_share(&mut ws_a, fixture.channel).await;
    watch_synced(&mut ws_b, fixture.channel, a.id).await;
    stop(&mut ws_a, fixture.channel).await;
    let stopped = ws_b.wait_for("screen_share_stopped", WAIT).await.unwrap();
    assert_eq!(stopped["reason"], "stopped");
    ws_a.frames_for(SHORT).await;

    keyframe_request(&mut ws_b, fixture.channel, a.id).await;
    ws_a.send_binary(up(fixture.channel, &fragment(1, 100)))
        .await;
    let participants = sync(&mut ws_b, fixture.channel).await;
    assert_eq!(participants["screen_sharers"], json!([]));
    assert_eq!(
        count_frames(&ws_a.frames_for(SHORT).await, "screen_keyframe_request"),
        0
    );
    assert!(ws_b.binaries_for(SHORT).await.is_empty());
    // A new share starts without the old watches.
    start_share(&mut ws_a, fixture.channel).await;
    ws_a.send_binary(up(fixture.channel, &fragment(2, 100)))
        .await;
    assert!(ws_b.binaries_for(SHORT).await.is_empty());
}

/// T-55: clean-up on `LeaveVoiceChannel`: the sharer's share ends with
/// `left` (to the remaining participants, ahead of `voice_peer_left`, and to
/// the sharing connection), and its fragments are dropped, also after it
/// rejoins.
#[tokio::test]
async fn t55_cleanup_on_leave() {
    let fixture = Fixture::default().await;
    let a = fixture.member("cleave-a").await;
    let b = fixture.member("cleave-b").await;
    let mut ws_a = fixture.in_call(&a).await;
    let mut ws_b = fixture.in_call(&b).await;
    start_share(&mut ws_a, fixture.channel).await;
    watch_synced(&mut ws_b, fixture.channel, a.id).await;

    ws_a.send(json!({ "LeaveVoiceChannel": { "channel_id": fixture.channel } }))
        .await;
    let frames = ws_a.frames_for(SHORT).await;
    let stopped = frames_of(&frames, "screen_share_stopped");
    assert_eq!(stopped.len(), 1, "{frames:?}");
    assert_eq!(stopped[0]["reason"], "left");
    let left = frames_of(&frames, "voice_channel_left");
    assert_eq!(left.len(), 1, "{frames:?}");
    assert!(left[0].get("reason").is_none(), "{frames:?}");

    let frames = ws_b.frames_for(SHORT).await;
    let types: Vec<&str> = frames.iter().filter_map(|f| f["type"].as_str()).collect();
    let stopped_at = types.iter().position(|t| *t == "screen_share_stopped");
    let peer_left_at = types.iter().position(|t| *t == "voice_peer_left");
    assert!(
        stopped_at.is_some() && stopped_at < peer_left_at,
        "{frames:?}"
    );
    assert_eq!(frames[stopped_at.unwrap()]["user_id"], json!(a.id));
    assert_eq!(frames[stopped_at.unwrap()]["reason"], "left");

    join_voice(&mut ws_a, fixture.channel).await;
    ws_a.send_binary(up(fixture.channel, &fragment(1, 100)))
        .await;
    sync(&mut ws_a, fixture.channel).await;
    assert!(ws_b.binaries_for(SHORT).await.is_empty());
    assert!(fixture
        .relay
        .state
        .screen
        .sharers(fixture.channel)
        .is_empty());
}

/// T-55: clean-up when the sharing connection closes (`left`) and when a
/// watching connection closes (the sharer's watcher count drops).
#[tokio::test]
async fn t55_cleanup_on_connection_close() {
    let fixture = Fixture::default().await;
    let a = fixture.member("cclose-a").await;
    let b = fixture.member("cclose-b").await;
    let c = fixture.member("cclose-c").await;
    let mut ws_a = fixture.in_call(&a).await;
    let ws_b = fixture.in_call(&b).await;
    let mut ws_c = fixture.in_call(&c).await;

    // A watching connection closes.
    start_share(&mut ws_a, fixture.channel).await;
    let mut ws_b = ws_b;
    watch_synced(&mut ws_b, fixture.channel, a.id).await;
    let count = ws_a
        .wait_for("screen_watchers", Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(count["watchers"], 1);
    ws_b.close().await;
    let count = ws_a
        .wait_for("screen_watchers", Duration::from_secs(3))
        .await
        .expect("the count drops");
    assert_eq!(count["watchers"], 0);

    // The sharing connection closes.
    ws_c.frames_for(SHORT).await;
    ws_a.close().await;
    let stopped = ws_c
        .wait_for("screen_share_stopped", WAIT)
        .await
        .expect("share ended");
    assert_eq!(stopped["user_id"], json!(a.id));
    assert_eq!(stopped["reason"], "left");
    let participants = sync(&mut ws_c, fixture.channel).await;
    assert_eq!(participants["screen_sharers"], json!([]));
}

/// T-55 (C154): U shares from connection 1 and U's idle connection 2
/// closes. The remaining participants receive `screen_share_stopped` with
/// `left`, `voice_participants` lists no share of U, the share no longer
/// counts toward `max_sharers`, connection 1's later `SCREEN_UP` messages
/// are dropped (also after U rejoins), and U's watches in C, from any
/// connection, are gone.
#[tokio::test]
async fn t55_c154_idle_connection_close_ends_the_share() {
    let fixture = Fixture::default().await;
    let u = fixture.member("c154-u").await;
    let b = fixture.member("c154-b").await;
    let c = fixture.member("c154-c").await;
    let mut u1 = fixture.in_call(&u).await;
    let u2 = fixture.connect(&u).await;
    let mut ws_b = fixture.in_call(&b).await;
    let mut ws_c = fixture.in_call(&c).await;
    start_share(&mut u1, fixture.channel).await;
    start_share(&mut ws_b, fixture.channel).await;
    watch_synced(&mut ws_c, fixture.channel, u.id).await;
    watch_synced(&mut u1, fixture.channel, b.id).await;
    let count = ws_b
        .wait_for("screen_watchers", Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(count["watchers"], 1);
    ws_c.frames_for(SHORT).await;
    u1.frames_for(SHORT).await;

    u2.close().await;
    for ws in [&mut ws_b, &mut ws_c, &mut u1] {
        let stopped = ws
            .wait_for("screen_share_stopped", WAIT)
            .await
            .expect("U's share ends");
        assert_eq!(stopped["user_id"], json!(u.id));
        assert_eq!(stopped["reason"], "left");
    }
    let participants = sync(&mut ws_c, fixture.channel).await;
    assert_eq!(participants["screen_sharers"], json!([b.id]));
    // U's watch of B's share, from connection 1, is gone.
    let count = ws_b
        .wait_for("screen_watchers", Duration::from_secs(3))
        .await
        .expect("B's count drops");
    assert_eq!(count["watchers"], 0);
    // The share no longer counts toward max_sharers (2).
    start_share(&mut ws_c, fixture.channel).await;
    stop(&mut ws_c, fixture.channel).await;
    ws_c.wait_for("screen_share_stopped", WAIT).await.unwrap();

    // Connection 1's fragments are dropped, before and after U rejoins.
    let watcher = fixture.member("c154-w").await;
    let mut ws_w = fixture.in_call(&watcher).await;
    watch(&mut ws_w, fixture.channel, u.id, true).await;
    assert_eq!(
        ws_w.wait_for("screen_watch_rejected", WAIT).await.unwrap()["reason"],
        "not_sharing"
    );
    u1.send_binary(up(fixture.channel, &fragment(1, 100))).await;
    join_voice(&mut u1, fixture.channel).await;
    u1.send_binary(up(fixture.channel, &fragment(2, 100))).await;
    sync(&mut u1, fixture.channel).await;
    for ws in [&mut ws_b, &mut ws_c, &mut ws_w] {
        assert!(ws.binaries_for(SHORT).await.is_empty());
    }
    assert_eq!(
        fixture.relay.state.screen.sharers(fixture.channel),
        vec![b.id]
    );
}

/// T-55 clean-up on eviction (T-29) and the relay side of RG-SCR-9: kicking
/// a watcher removes its watch (the count drops and no fragment reaches its
/// connections afterwards); kicking the sharer ends its share with
/// `removed`, ahead of `voice_peer_left`.
#[tokio::test]
async fn t55_cleanup_on_eviction() {
    let fixture = Fixture::default().await;
    let a = fixture.member("cevict-a").await;
    let b = fixture.member("cevict-b").await;
    let c = fixture.member("cevict-c").await;
    let mut ws_a = fixture.in_call(&a).await;
    let mut ws_b = fixture.in_call(&b).await;
    let mut ws_c = fixture.in_call(&c).await;
    start_share(&mut ws_a, fixture.channel).await;
    watch_synced(&mut ws_b, fixture.channel, a.id).await;
    watch_synced(&mut ws_c, fixture.channel, a.id).await;
    let count = ws_a
        .wait_for("screen_watchers", Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(count["watchers"], 2);

    kick(&fixture, b.id).await;
    let left = ws_b
        .wait_for("voice_channel_left", WAIT)
        .await
        .expect("B is evicted");
    assert_eq!(left["reason"], "removed");
    let count = ws_a
        .wait_for("screen_watchers", Duration::from_secs(3))
        .await
        .expect("A's count drops");
    assert_eq!(count["watchers"], 1);
    ws_a.send_binary(up(fixture.channel, &fragment(7, 100)))
        .await;
    assert_eq!(seq_of(&ws_c.next_binary(WAIT).await.unwrap()), 7);
    assert!(ws_b.binaries_for(SHORT).await.is_empty());

    ws_c.frames_for(SHORT).await;
    kick(&fixture, a.id).await;
    let frames = ws_c.frames_for(Duration::from_millis(800)).await;
    let types: Vec<&str> = frames.iter().filter_map(|f| f["type"].as_str()).collect();
    let stopped_at = types.iter().position(|t| *t == "screen_share_stopped");
    let peer_left_at = types.iter().position(|t| *t == "voice_peer_left");
    assert!(
        stopped_at.is_some() && stopped_at < peer_left_at,
        "{frames:?}"
    );
    let stopped = &frames[stopped_at.unwrap()];
    assert_eq!(stopped["user_id"], json!(a.id));
    assert_eq!(stopped["reason"], "removed");
    let stopped = ws_a
        .wait_for("screen_share_stopped", WAIT)
        .await
        .expect("the sharing connection learns of it");
    assert_eq!(stopped["reason"], "removed");
    assert!(fixture
        .relay
        .state
        .screen
        .sharers(fixture.channel)
        .is_empty());
}

async fn kick(fixture: &Fixture, target: Uuid) {
    let response = fixture
        .relay
        .client
        .delete(
            fixture
                .relay
                .url(&format!("/nodes/{}/members/{}", fixture.node, target)),
        )
        .bearer_auth(&fixture.owner.token)
        .send()
        .await
        .expect("kick request");
    assert_eq!(response.status().as_u16(), 200);
}

/// T-55: `voice_channel_joined` and `voice_participants` carry
/// `screen_sharers`, oldest first.
#[tokio::test]
async fn t55_screen_sharers_in_replies() {
    let fixture = Fixture::default().await;
    let a = fixture.member("list-a").await;
    let b = fixture.member("list-b").await;
    let c = fixture.member("list-c").await;
    let mut ws_a = fixture.connect(&a).await;
    let joined = join_voice(&mut ws_a, fixture.channel).await;
    assert_eq!(joined["screen_sharers"], json!([]));
    let mut ws_b = fixture.in_call(&b).await;
    start_share(&mut ws_b, fixture.channel).await;
    start_share(&mut ws_a, fixture.channel).await;

    let mut ws_c = fixture.connect(&c).await;
    let joined = join_voice(&mut ws_c, fixture.channel).await;
    assert_eq!(joined["screen_sharers"], json!([b.id, a.id]));
    let participants = sync(&mut ws_c, fixture.channel).await;
    assert_eq!(participants["screen_sharers"], json!([b.id, a.id]));
}

/// T-55: with log capture at INFO during a share, a watch, keyframe
/// requests and fragments, no captured event contains fragment bytes, and
/// no event above debug level names a watch or a keyframe request.
#[tokio::test]
async fn t55_logs_carry_no_fragments_watches_or_requests() {
    let fixture = Fixture::default().await;
    let a = fixture.member("log-a").await;
    let b = fixture.member("log-b").await;
    let mut ws_a = fixture.in_call(&a).await;
    let mut ws_b = fixture.in_call(&b).await;

    let capture = LogCapture::new();
    let marker = b"FRAGMENT-BYTES-MUST-NOT-BE-LOGGED";
    {
        let _guard = capture.start(tracing::Level::INFO);
        start_share(&mut ws_a, fixture.channel).await;
        watch_synced(&mut ws_b, fixture.channel, a.id).await;
        for _ in 0..3 {
            keyframe_request(&mut ws_b, fixture.channel, a.id).await;
        }
        let mut f = fragment(1, 200);
        f[10..10 + marker.len()].copy_from_slice(marker);
        ws_a.send_binary(up(fixture.channel, &f)).await;
        ws_a.send_binary(vec![0x07; 40]).await; // malformed
        ws_b.next_binary(WAIT).await.expect("forwarded");
        ws_a.wait_for("screen_keyframe_request", WAIT)
            .await
            .unwrap();
        watch(&mut ws_b, fixture.channel, a.id, false).await;
        stop(&mut ws_a, fixture.channel).await;
        ws_b.wait_for("screen_share_stopped", WAIT).await.unwrap();
    }
    let text = capture.text();
    let marker_text = String::from_utf8_lossy(marker);
    assert!(!text.contains(&*marker_text), "{text}");
    assert!(!text.contains(&hex::encode(marker)), "{text}");
    let lower = text.to_lowercase();
    for word in ["watch", "keyframe"] {
        assert!(!lower.contains(word), "{word}: {text}");
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  RG-SCR-7 (S): oversized and flooding binary
// ─────────────────────────────────────────────────────────────────────────

/// RG-SCR-7: a participant sends binary messages of 16,402 bytes and of
/// 1 MiB, with type bytes 0x00 and 0x02, from a connection that is not
/// sharing, and ten times the byte rate from the sharing connection. The
/// relay drops all of them except fragments within the bucket, its screen
/// queues stay within their bounds, and other connections' control messages
/// are delivered unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rg_scr_7_oversized_and_flooding_binary() {
    let fixture = Fixture::default().await;
    let a = fixture.member("flood-a").await;
    let b = fixture.member("flood-b").await;
    let c = fixture.member("flood-c").await;
    let d = fixture.member("flood-d").await;
    let mut a1 = fixture.in_call(&a).await;
    let mut a2 = fixture.connect(&a).await;
    let mut ws_b = fixture.in_call(&b).await;
    let mut ws_c = fixture.in_call(&c).await;
    let mut ws_d = fixture.connect(&d).await;
    start_share(&mut a1, fixture.channel).await;
    watch_synced(&mut ws_b, fixture.channel, a.id).await;
    ws_c.frames_for(SHORT).await;

    // B reads all the time. The reader hands B's connection back, so that
    // it stays open (and its queue registered) until the counters are read.
    let reader = tokio::spawn(async move {
        let mut downs = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Some(down) = ws_b.next_binary(Duration::from_millis(200)).await {
                downs.push(down);
            }
        }
        (downs, ws_b)
    });

    // The non-sharing connection: oversized and unknown messages.
    let channel = fixture.channel;
    let mut junk = Vec::new();
    for (len, kind) in [
        (16_402usize, screen::SCREEN_UP),
        (1 << 20, screen::SCREEN_UP),
        (100, 0x00),
        (100, screen::SCREEN_DOWN),
        (100, screen::SCREEN_UP), // well formed, but A2 holds no share
    ] {
        let mut m = vec![0xEE; len];
        m[0] = kind;
        m[1..17].copy_from_slice(channel.as_bytes());
        junk.push(m);
    }
    for m in &junk {
        a2.send_binary(m.clone()).await;
    }

    // The sharing connection at ten times the byte rate for 2 s, while D
    // joins the call.
    const LEN: usize = 16_384;
    let rate = 10.0 * 500_000.0;
    let interval = Duration::from_secs_f64((LEN + 17) as f64 / rate);
    let started = Instant::now();
    let mut seq = 0u32;
    let mut joined = false;
    while started.elapsed() < Duration::from_secs(2) {
        a1.send_binary(up(channel, &fragment(seq, LEN))).await;
        seq += 1;
        if !joined && started.elapsed() > Duration::from_millis(700) {
            joined = true;
            ws_d.send(json!({ "JoinVoiceChannel": { "channel_id": channel } }))
                .await;
        }
        let next = started + interval * seq;
        tokio::time::sleep(next.saturating_duration_since(Instant::now())).await;
    }
    sync(&mut a1, channel).await;
    let elapsed = started.elapsed().as_secs_f64();

    // C's control messages arrive unchanged.
    let peer_joined = ws_c
        .wait_for("voice_peer_joined", WAIT)
        .await
        .expect("control message during the flood");
    assert_eq!(
        peer_joined,
        json!({ "type": "voice_peer_joined", "channel_id": channel, "user_id": d.id })
    );
    let participants = sync(&mut ws_c, channel).await;
    assert_eq!(participants["screen_sharers"], json!([a.id]));

    let (downs, _ws_b) = reader.await.unwrap();
    for down in &downs {
        assert_eq!(down.len(), LEN + 33);
        assert_eq!(&down[17..33], a.id.as_bytes());
        assert_ne!(
            down[40], 0xEE,
            "a non-sharing connection's message was forwarded"
        );
    }
    // Only fragments within the bucket: 1,500,000 bytes of burst plus
    // 500,000 bytes per second.
    let allowed = ((1_500_000.0 + 500_000.0 * elapsed) / (LEN + 17) as f64).floor() as u64 + 2;
    let stats = fixture.relay.state.screen.user_queue_stats(b.id);
    assert_eq!(stats.len(), 1);
    let stats = stats[0];
    assert!(
        stats.enqueued <= allowed,
        "{} forwarded of {seq} sent, allowed {allowed}: {stats:?}",
        stats.enqueued
    );
    assert!(stats.enqueued >= 91, "{stats:?}");
    assert_eq!(
        downs.len() as u64,
        stats.enqueued - stats.dropped_head - stats.dropped_age,
        "{stats:?}"
    );
    for (_, stats) in fixture.relay.state.screen.queue_stats() {
        assert!(stats.max_len <= screen::QUEUE_MAX_MESSAGES, "{stats:?}");
        assert!(stats.max_bytes <= screen::QUEUE_MAX_BYTES, "{stats:?}");
    }
}

/// §6.12.2 (MAY): a connection that sends 100 oversized or unknown binary
/// messages within 60 s is closed; 99 are tolerated.
#[tokio::test]
async fn malformed_binary_messages_close_the_connection_at_100() {
    let fixture = Fixture::default().await;
    let a = fixture.member("malformed-a").await;
    let mut ws_a = fixture.in_call(&a).await;
    for _ in 0..99 {
        ws_a.send_binary(vec![0x09; 50]).await;
    }
    let participants = sync(&mut ws_a, fixture.channel).await;
    assert_eq!(participants["participants"], json!([a.id]));
    ws_a.send_binary(vec![0x09; 50]).await;
    assert!(ws_a.is_closed_within(WAIT).await);
}

// ─────────────────────────────────────────────────────────────────────────
//  T-29 (REQ-29): voice eviction on removal from the node
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum Removal {
    Kick,
    Ban,
    RestLeave,
    WsLeaveNode,
}

async fn ban(fixture: &Fixture, account: &Account) {
    let response = fixture
        .relay
        .client
        .post(fixture.relay.url(&format!("/nodes/{}/bans", fixture.node)))
        .bearer_auth(&fixture.owner.token)
        .json(&json!({
            "public_key_hash": accord_server::db::compute_public_key_hash(&account.public_key)
        }))
        .send()
        .await
        .expect("ban request");
    assert_eq!(response.status().as_u16(), 200);
}

/// The frames of these types are what an eviction sends (REQ-29, §6.12.4).
const EVICTION_FRAMES: [&str; 3] = [
    "voice_peer_left",
    "voice_channel_left",
    "screen_share_stopped",
];

/// The participant set of a `voice_participants` reply.
fn participant_set(reply: &Value) -> HashSet<Uuid> {
    reply["participants"]
        .as_array()
        .expect("participants")
        .iter()
        .map(|id| Uuid::parse_str(id.as_str().expect("user id")).expect("uuid"))
        .collect()
}

/// T-29: for each of kick, ban, REST leave and WS `LeaveNode` on a member
/// T in a voice channel, where T shares a screen that R watches and T
/// watches S's share:
/// - R and S receive `screen_share_stopped` for T with reason `removed`,
///   and `voice_peer_left`;
/// - T receives `voice_channel_left` with reason `removed`, and its sharing
///   connection `screen_share_stopped` with reason `removed`;
/// - the participants no longer list T, and `voice_participants` lists only
///   S in `screen_sharers`;
/// - a `SCREEN_UP` from T's connection no longer reaches R;
/// - T's own watch is gone: S's `screen_watchers` count drops to 0 and S's
///   fragments no longer reach T.
#[tokio::test]
async fn t29_eviction_on_removal() {
    for removal in [
        Removal::Kick,
        Removal::Ban,
        Removal::RestLeave,
        Removal::WsLeaveNode,
    ] {
        let fixture = Fixture::default().await;
        let r = fixture.member("t29-remaining").await;
        let s = fixture.member("t29-sharer").await;
        let t = fixture.member("t29-target").await;
        let channel = fixture.channel;
        let mut ws_r = fixture.in_call(&r).await;
        let mut ws_s = fixture.in_call(&s).await;
        let mut ws_t = fixture.in_call(&t).await;
        start_share(&mut ws_t, channel).await;
        start_share(&mut ws_s, channel).await;
        watch_synced(&mut ws_r, channel, t.id).await;
        watch_synced(&mut ws_t, channel, s.id).await;

        // Both watches carry fragments before the removal.
        ws_t.send_binary(up(channel, &fragment(1, 100))).await;
        let down = ws_r.next_binary(WAIT).await.expect("T's fragment");
        assert_down(&down, channel, t.id, &fragment(1, 100));
        ws_s.send_binary(up(channel, &fragment(2, 100))).await;
        let down = ws_t.next_binary(WAIT).await.expect("S's fragment");
        assert_down(&down, channel, s.id, &fragment(2, 100));
        // Let S's coalesced count settle, then drop what was received.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let counts = frames_of(&ws_s.frames_for(SHORT).await, "screen_watchers")
            .iter()
            .map(|f| f["watchers"].as_i64().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(counts.last(), Some(&1), "{removal:?}: {counts:?}");
        ws_r.frames_for(Duration::from_millis(50)).await;
        ws_t.frames_for(Duration::from_millis(50)).await;

        match removal {
            Removal::Kick => kick(&fixture, t.id).await,
            Removal::Ban => ban(&fixture, &t).await,
            Removal::RestLeave => {
                let response = fixture
                    .relay
                    .client
                    .post(fixture.relay.url(&format!("/nodes/{}/leave", fixture.node)))
                    .bearer_auth(&t.token)
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status().as_u16(), 200, "{removal:?}");
            }
            Removal::WsLeaveNode => {
                ws_t.send(json!({ "LeaveNode": { "node_id": fixture.node } }))
                    .await;
            }
        }

        // R and S: the share ends with `removed`, then T leaves the call.
        let frames_r = ws_r.frames_for(Duration::from_millis(800)).await;
        let frames_s = ws_s.frames_for(Duration::from_millis(1500)).await;
        for (who, frames) in [("R", &frames_r), ("S", &frames_s)] {
            let stopped = frames_of(frames, "screen_share_stopped");
            assert_eq!(stopped.len(), 1, "{removal:?} {who}: {frames:?}");
            assert_eq!(stopped[0]["user_id"], json!(t.id), "{removal:?} {who}");
            assert_eq!(stopped[0]["channel_id"], json!(channel));
            assert_eq!(stopped[0]["reason"], "removed", "{removal:?} {who}");
            let peer_left = frames_of(frames, "voice_peer_left");
            assert_eq!(peer_left.len(), 1, "{removal:?} {who}: {frames:?}");
            assert_eq!(peer_left[0]["user_id"], json!(t.id), "{removal:?} {who}");
            assert_eq!(peer_left[0]["channel_id"], json!(channel));
        }
        // T's watch of S is gone: S's count drops to 0.
        let counts: Vec<i64> = frames_of(&frames_s, "screen_watchers")
            .iter()
            .map(|f| f["watchers"].as_i64().unwrap())
            .collect();
        assert_eq!(counts.last(), Some(&0), "{removal:?}: {frames_s:?}");

        // T: evicted, and its sharing connection learns its share ended.
        let frames_t = ws_t.frames_for(Duration::from_millis(800)).await;
        let left = frames_of(&frames_t, "voice_channel_left");
        assert_eq!(left.len(), 1, "{removal:?}: {frames_t:?}");
        let left = left[0];
        if let Removal::WsLeaveNode = removal {
            assert_eq!(count_frames(&frames_t, "node_left"), 1, "{frames_t:?}");
        }
        assert_eq!(left["reason"], "removed", "{removal:?}");
        assert_eq!(left["user_id"], json!(t.id), "{removal:?}");
        assert_eq!(left["channel_id"], json!(channel), "{removal:?}");
        let stopped = frames_of(&frames_t, "screen_share_stopped");
        assert_eq!(stopped.len(), 1, "{removal:?}: {frames_t:?}");
        assert_eq!(stopped[0]["user_id"], json!(t.id), "{removal:?}");
        assert_eq!(stopped[0]["reason"], "removed", "{removal:?}");

        // The participants and the sharers no longer list T.
        let mut participants = fixture
            .relay
            .state
            .get_voice_channel_participants(channel)
            .await;
        participants.sort();
        let mut expected = vec![r.id, s.id];
        expected.sort();
        assert_eq!(participants, expected, "{removal:?}");
        let reply = sync(&mut ws_r, channel).await;
        assert_eq!(
            participant_set(&reply),
            [r.id, s.id].into_iter().collect(),
            "{removal:?}: {reply}"
        );
        assert_eq!(
            reply["screen_sharers"],
            json!([s.id]),
            "{removal:?}: {reply}"
        );

        // No more fragments from T to R, nor from S to T.
        ws_t.send_binary(up(channel, &fragment(3, 100))).await;
        sync(&mut ws_t, channel).await;
        ws_s.send_binary(up(channel, &fragment(4, 100))).await;
        sync(&mut ws_s, channel).await;
        assert!(
            ws_r.binaries_for(SHORT).await.is_empty(),
            "{removal:?}: R received a fragment from the evicted sharer"
        );
        assert!(
            ws_t.binaries_for(SHORT).await.is_empty(),
            "{removal:?}: the evicted watcher received a fragment"
        );
    }
}

/// T-29: kicking or banning a non-member removes no membership row, so no
/// one is evicted: neither the call of this node nor the non-member's own
/// call elsewhere gets an eviction message, and the shares go on.
#[tokio::test]
async fn t29_removing_a_non_member_evicts_no_one() {
    let fixture = Fixture::default().await;
    let r = fixture.member("t29-nm-remaining").await;
    let t = fixture.member("t29-nm-sharer").await;
    let n = register(&fixture.relay, "t29-nm-outsider").await;
    let mut ws_r = fixture.in_call(&r).await;
    let mut ws_t = fixture.in_call(&t).await;
    start_share(&mut ws_t, fixture.channel).await;
    watch_synced(&mut ws_r, fixture.channel, t.id).await;
    // N is in a call of its own node, sharing there.
    let other_node = fixture.relay.create_node(&n.token, "Elsewhere").await;
    let other_channel = create_channel(&fixture.relay, &n.token, other_node, "call").await;
    let mut ws_n = fixture.connect(&n).await;
    join_voice(&mut ws_n, other_channel).await;
    start_share(&mut ws_n, other_channel).await;
    for ws in [&mut ws_r, &mut ws_t, &mut ws_n] {
        ws.frames_for(SHORT).await;
    }

    let response = fixture
        .relay
        .client
        .delete(
            fixture
                .relay
                .url(&format!("/nodes/{}/members/{}", fixture.node, n.id)),
        )
        .bearer_auth(&fixture.owner.token)
        .send()
        .await
        .expect("kick request");
    assert_eq!(response.status().as_u16(), 404);
    ban(&fixture, &n).await;

    for (who, ws) in [("R", &mut ws_r), ("T", &mut ws_t), ("N", &mut ws_n)] {
        let frames = ws.frames_for(Duration::from_millis(800)).await;
        for frame_type in EVICTION_FRAMES {
            assert_eq!(
                count_frames(&frames, frame_type),
                0,
                "{who}: {frame_type} in {frames:?}"
            );
        }
    }
    let reply = sync(&mut ws_r, fixture.channel).await;
    assert_eq!(
        participant_set(&reply),
        [r.id, t.id].into_iter().collect(),
        "{reply}"
    );
    assert_eq!(reply["screen_sharers"], json!([t.id]));
    let reply = sync(&mut ws_n, other_channel).await;
    assert_eq!(reply["participants"], json!([n.id]));
    assert_eq!(reply["screen_sharers"], json!([n.id]));
    ws_t.send_binary(up(fixture.channel, &fragment(5, 100)))
        .await;
    let down = ws_r.next_binary(WAIT).await.expect("the share goes on");
    assert_down(&down, fixture.channel, t.id, &fragment(5, 100));
}

/// T-29 and the relay side of RG-SCR-9: a `JoinVoiceChannel` whose
/// membership check passed before a kick committed, and whose insert into
/// the call comes after the kick's eviction hook found the user absent, is
/// undone: the removed user gets the join's error, is not a participant,
/// cannot watch, and receives no fragments.
#[tokio::test]
async fn t29_join_racing_a_removal_is_undone() {
    let fixture = Fixture::default().await;
    let r = fixture.member("t29-race-remaining").await;
    let t = fixture.member("t29-race-target").await;
    let mut ws_r = fixture.in_call(&r).await;
    start_share(&mut ws_r, fixture.channel).await;
    let mut ws_t = fixture.connect(&t).await;

    // Hold T's join between its membership check and its insert, and kick
    // T meanwhile: the kick's hook runs while T is not yet in the call.
    let gate = fixture.relay.state.faults().hold("voice:join");
    ws_t.send(json!({ "JoinVoiceChannel": { "channel_id": fixture.channel } }))
        .await;
    tokio::time::timeout(WAIT, gate.reached())
        .await
        .expect("the join reaches the pause point");
    kick(&fixture, t.id).await;
    gate.release();

    let frames = ws_t.frames_for(Duration::from_millis(800)).await;
    let errors = frames_of(&frames, "error");
    assert_eq!(errors.len(), 1, "{frames:?}");
    assert!(
        errors[0]["error"]
            .as_str()
            .is_some_and(|e| e.contains("member")),
        "{frames:?}"
    );
    assert_eq!(
        count_frames(&frames, "voice_channel_joined"),
        0,
        "{frames:?}"
    );
    assert_eq!(
        fixture
            .relay
            .state
            .get_voice_channel_participants(fixture.channel)
            .await,
        vec![r.id]
    );
    let frames = ws_r.frames_for(SHORT).await;
    assert_eq!(count_frames(&frames, "voice_peer_joined"), 0, "{frames:?}");

    let request = watch(&mut ws_t, fixture.channel, r.id, true).await;
    let frame = ws_t
        .wait_for("screen_watch_rejected", WAIT)
        .await
        .expect("rejection");
    assert_rejection(
        &frame,
        "screen_watch_rejected",
        fixture.channel,
        "not_participant",
        request,
    );
    ws_r.send_binary(up(fixture.channel, &fragment(6, 100)))
        .await;
    sync(&mut ws_r, fixture.channel).await;
    assert!(ws_t.binaries_for(SHORT).await.is_empty());
}
