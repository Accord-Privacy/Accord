//! SPEC-03 §6.14 (REQ-56): the relay's P2P retirement, which ships in the
//! same relay release as the screen path `screen/1` (relay release R-A1,
//! OD-108). T-56, and the relay regression test RG-C003-2, which replays the
//! review's C003 attack against an emulated outdated client.
//!
//! The refusal of legacy voice messages (REQ-58, T-58) ships one relay
//! release later (R-A1b) and is not tested here: `VoicePacket` and raw-key
//! `VoiceKeyExchange` are still forwarded.

use accord_server::test_support::{count_frames, TestRelay, WsClient};
use serde_json::{json, Value};
use std::time::Duration;
use uuid::Uuid;

/// How long observers record after an action. Every observed action is
/// followed by a round trip on the acting connection first, so this only
/// has to cover delivery to the other connections.
const SHORT: Duration = Duration::from_millis(400);
const WAIT: Duration = Duration::from_secs(5);

/// The frame types through which a relay switches a channel to P2P or
/// forwards P2P signaling (§4.2, C003).
const P2P_FRAMES: [&str; 5] = [
    "voice_mode_changed",
    "p2p_signal",
    "voice_offer",
    "voice_answer",
    "voice_ice_candidate",
];

/// An address from the documentation range (RFC 5737) carried in every SDP
/// and ICE candidate sent here, so that any frame that reveals one is
/// recognized.
const LEAK_MARKER: &str = "192.0.2.77";

// ─────────────────────────────────────────────────────────────────────────
//  Fixture
// ─────────────────────────────────────────────────────────────────────────

struct Account {
    id: Uuid,
    token: String,
}

/// A node owned by `owner` with one voice channel.
struct Fixture {
    relay: TestRelay,
    owner: Account,
    node: Uuid,
    channel: Uuid,
}

impl Fixture {
    async fn new() -> Self {
        let relay = TestRelay::start().await;
        let owner = register(&relay, "owner").await;
        let node = relay.create_node(&owner.token, "P2P retirement").await;
        let channel = create_voice_channel(&relay, &owner.token, node).await;
        Self {
            relay,
            owner,
            node,
            channel,
        }
    }

    /// A registered account that the owner admitted to the node.
    async fn member(&self, name: &str) -> Account {
        let account = register(&self.relay, name).await;
        self.relay
            .join_with_owner_invite(&account.token, self.node)
            .await;
        account
    }

    /// A registered account that is not a member of the node (A7).
    async fn outsider(&self, name: &str) -> Account {
        register(&self.relay, name).await
    }

    async fn connect(&self, account: &Account) -> WsClient {
        WsClient::connect(&self.relay, &account.token).await
    }

    /// A connection of `account` that has joined the voice channel.
    async fn in_call(&self, account: &Account) -> WsClient {
        let mut ws = self.connect(account).await;
        let joined = join_voice(&mut ws, self.channel).await;
        assert_eq!(joined["voice_mode"], "relay", "{joined}");
        ws
    }
}

async fn register(relay: &TestRelay, name: &str) -> Account {
    let (id, token) = relay.register_and_auth(&format!("spec03-p2p-{name}")).await;
    Account { id, token }
}

async fn create_voice_channel(relay: &TestRelay, token: &str, node: Uuid) -> Uuid {
    let response = relay
        .client
        .post(relay.url(&format!("/nodes/{node}/channels")))
        .bearer_auth(token)
        .json(&json!({ "name": "call", "channel_type": "voice" }))
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

/// A round trip on `ws`, returning every frame received before its answer.
/// When it returns, the relay has handled every message this connection sent
/// before (one connection's messages are handled in order). `GetVoiceMode`
/// is answered to every connection of the user, so the answer is matched by
/// a channel id that nothing else uses.
async fn sync(ws: &mut WsClient) -> Vec<Value> {
    let marker = Uuid::new_v4();
    ws.send(json!({ "GetVoiceMode": { "channel_id": marker } }))
        .await;
    let mut before = Vec::new();
    loop {
        let frame = ws.next_frame(WAIT).await.expect("GetVoiceMode answer");
        if frame["type"] == "voice_mode" && frame["channel_id"] == json!(marker) {
            assert_eq!(frame["voice_mode"], "relay", "{frame}");
            return before;
        }
        before.push(frame);
    }
}

/// The `voice_mode` that `GetVoiceMode` reports for `channel`.
async fn voice_mode(ws: &mut WsClient, channel: Uuid) -> Value {
    ws.send(json!({ "GetVoiceMode": { "channel_id": channel } }))
        .await;
    loop {
        let frame = ws.wait_for("voice_mode", WAIT).await.expect("voice_mode");
        if frame["channel_id"] == json!(channel) {
            return frame["voice_mode"].clone();
        }
    }
}

async fn set_voice_mode(ws: &mut WsClient, channel: Uuid, mode: &str) -> Uuid {
    ws.send(json!({ "SetVoiceMode": { "channel_id": channel, "mode": mode } }))
        .await
}

/// Every frame `ws` receives during [`SHORT`], JSON and binary (binary
/// messages are returned as their length only).
async fn record(ws: &mut WsClient) -> (Vec<Value>, Vec<usize>) {
    let frames = ws.frames_for(SHORT).await;
    let mut binaries = Vec::new();
    while let Some(data) = ws.next_binary(Duration::from_millis(20)).await {
        binaries.push(data.len());
    }
    (frames, binaries)
}

/// Assert that `frames` contain no P2P frame and nothing that carries the
/// SDP or ICE candidates sent in this test.
fn assert_no_p2p(frames: &[Value], who: &str) {
    for frame_type in P2P_FRAMES {
        assert_eq!(
            count_frames(frames, frame_type),
            0,
            "{who} received {frame_type}: {frames:?}"
        );
    }
    for frame in frames {
        assert!(
            !frame.to_string().contains(LEAK_MARKER),
            "{who} received an address: {frame}"
        );
    }
}

/// Assert that `frame` is the `p2p_retired` error frame answering
/// `request` for `channel` (§6.14, SPEC-01 §6.3).
fn assert_p2p_retired(frame: &Value, channel: Uuid, request: Uuid) {
    assert_eq!(frame["type"], "error", "{frame}");
    assert_eq!(frame["code"], "p2p_retired", "{frame}");
    assert_eq!(frame["reason"], "p2p_retired", "{frame}");
    assert!(
        frame["error"].as_str().is_some_and(|e| !e.is_empty()),
        "{frame}"
    );
    assert_eq!(frame["request_id"], json!(request), "{frame}");
    assert_eq!(frame["channel_id"], json!(channel), "{frame}");
}

/// The error frames among `frames`.
fn errors(frames: &[Value]) -> Vec<&Value> {
    frames.iter().filter(|f| f["type"] == "error").collect()
}

/// An SDP offer of an outdated client, carrying a host candidate.
fn sdp(kind: &str) -> String {
    format!(
        "v=0\r\no=- 4611731400430051336 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
         m={kind} 9 UDP/TLS/RTP/SAVPF 111\r\nc=IN IP4 {LEAK_MARKER}\r\n\
         a=fingerprint:sha-256 AA:BB:CC\r\n\
         a=candidate:1 1 udp 2122260223 {LEAK_MARKER} 54400 typ host\r\n"
    )
}

/// An ICE candidate of an outdated client.
fn candidate() -> String {
    json!({
        "candidate": format!("candidate:1 1 udp 2122260223 {LEAK_MARKER} 54400 typ host"),
        "sdpMid": "0",
        "sdpMLineIndex": 0,
    })
    .to_string()
}

/// Every P2P signaling message of §4.2 that `sender` can send to `target`:
/// `P2PSignal` with a voice offer, a `screen-sdp` offer, an answer and an
/// ICE candidate, then `VoiceOffer`, `VoiceAnswer` and `VoiceIceCandidate`.
async fn send_p2p_signaling(sender: &mut WsClient, channel: Uuid, target: Uuid) {
    let signals = [
        json!({ "type": "offer", "sdp": sdp("audio") }),
        json!({ "type": "screen-sdp", "sdp": { "type": "offer", "sdp": sdp("video") } }),
        json!({ "type": "answer", "sdp": sdp("audio") }),
        json!({ "type": "ice-candidate", "candidate": candidate() }),
    ];
    for signal in signals {
        sender
            .send(json!({
                "P2PSignal": {
                    "channel_id": channel,
                    "target_user_id": target,
                    "signal_data": signal.to_string(),
                }
            }))
            .await;
    }
    sender
        .send(json!({
            "VoiceOffer": { "channel_id": channel, "target_user_id": target, "sdp": sdp("audio") }
        }))
        .await;
    sender
        .send(json!({
            "VoiceAnswer": { "channel_id": channel, "target_user_id": target, "sdp": sdp("audio") }
        }))
        .await;
    sender
        .send(json!({
            "VoiceIceCandidate": {
                "channel_id": channel,
                "target_user_id": target,
                "candidate": candidate(),
            }
        }))
        .await;
}

// ─────────────────────────────────────────────────────────────────────────
//  T-56 (REQ-56)
// ─────────────────────────────────────────────────────────────────────────

/// T-56: `SetVoiceMode` with `p2p`, or any other mode but `relay`, from a
/// participant and from an outsider gets exactly one error frame with
/// `code` and `reason` `p2p_retired` and the request's `message_id` as
/// `request_id`, on the sending connection only, and causes no broadcast.
/// The channel still reports `relay` afterwards.
#[tokio::test]
async fn t56_set_voice_mode_p2p_is_refused_without_broadcast() {
    let fixture = Fixture::new().await;
    let alice = fixture.member("alice").await;
    let bob = fixture.member("bob").await;
    let outsider = fixture.outsider("outsider").await;

    let mut alice_call = fixture.in_call(&alice).await;
    let mut alice_idle = fixture.connect(&alice).await;
    let mut bob_call = fixture.in_call(&bob).await;
    let mut owner_idle = fixture.connect(&fixture.owner).await;
    let mut outsider_ws = fixture.connect(&outsider).await;
    // Drop the join announcements.
    for ws in [
        &mut alice_call,
        &mut alice_idle,
        &mut bob_call,
        &mut owner_idle,
    ] {
        ws.frames_for(SHORT).await;
    }

    for mode in ["p2p", "P2P", "", "mesh", "relay ", "Relay"] {
        for (who, ws) in [
            ("participant", &mut alice_call),
            ("outsider", &mut outsider_ws),
        ] {
            let request = set_voice_mode(ws, fixture.channel, mode).await;
            let before = sync(ws).await;
            let errors = errors(&before);
            assert_eq!(errors.len(), 1, "{who}, mode {mode:?}: {before:?}");
            assert_p2p_retired(errors[0], fixture.channel, request);
            assert_no_p2p(&before, who);
        }
    }

    // No broadcast reached anyone, and the refusals went to the sending
    // connections only.
    for (who, ws) in [
        ("alice's other connection", &mut alice_idle),
        ("bob", &mut bob_call),
        ("the owner", &mut owner_idle),
    ] {
        let (frames, _) = record(ws).await;
        assert_no_p2p(&frames, who);
        assert!(errors(&frames).is_empty(), "{who}: {frames:?}");
    }

    // The channel is still in relay mode.
    assert_eq!(voice_mode(&mut alice_call, fixture.channel).await, "relay");
    // `Fixture::in_call` asserts that the join reply says `relay`.
    let carol = fixture.member("carol").await;
    let _carol_call = fixture.in_call(&carol).await;
}

/// T-56: `SetVoiceMode` with `relay` is accepted without a broadcast and
/// without an error frame, from a participant and from an outsider.
#[tokio::test]
async fn t56_set_voice_mode_relay_is_accepted_without_broadcast() {
    let fixture = Fixture::new().await;
    let alice = fixture.member("alice").await;
    let bob = fixture.member("bob").await;
    let outsider = fixture.outsider("outsider").await;

    let mut alice_call = fixture.in_call(&alice).await;
    let mut bob_call = fixture.in_call(&bob).await;
    let mut outsider_ws = fixture.connect(&outsider).await;
    alice_call.frames_for(SHORT).await;
    bob_call.frames_for(SHORT).await;

    for (who, ws) in [
        ("participant", &mut alice_call),
        ("outsider", &mut outsider_ws),
    ] {
        set_voice_mode(ws, fixture.channel, "relay").await;
        let before = sync(ws).await;
        assert!(errors(&before).is_empty(), "{who}: {before:?}");
        assert_no_p2p(&before, who);
    }
    let (frames, _) = record(&mut bob_call).await;
    assert_no_p2p(&frames, "bob");
    assert!(errors(&frames).is_empty(), "bob: {frames:?}");
}

/// T-56: `GetVoiceMode` and the join replies say `relay`: for the call's
/// channel after `SetVoiceMode` `p2p` attempts, for a channel nobody has
/// joined, and when asked by an outsider. `GetVoiceMode` itself stays.
#[tokio::test]
async fn t56_get_voice_mode_and_join_replies_say_relay() {
    let fixture = Fixture::new().await;
    let alice = fixture.member("alice").await;
    let outsider = fixture.outsider("outsider").await;

    // Before anyone joins, and after a refused switch.
    let mut alice_ws = fixture.connect(&alice).await;
    set_voice_mode(&mut alice_ws, fixture.channel, "p2p").await;
    let mut outsider_ws = fixture.connect(&outsider).await;
    set_voice_mode(&mut outsider_ws, fixture.channel, "p2p").await;
    sync(&mut outsider_ws).await;

    assert_eq!(voice_mode(&mut alice_ws, fixture.channel).await, "relay");
    assert_eq!(voice_mode(&mut alice_ws, Uuid::new_v4()).await, "relay");
    assert_eq!(voice_mode(&mut outsider_ws, fixture.channel).await, "relay");

    // The join reply, for the first participant and for a later one.
    let joined = join_voice(&mut alice_ws, fixture.channel).await;
    assert_eq!(joined["voice_mode"], "relay", "{joined}");
    let bob = fixture.member("bob").await;
    let mut bob_ws = fixture.connect(&bob).await;
    set_voice_mode(&mut bob_ws, fixture.channel, "p2p").await;
    let joined = join_voice(&mut bob_ws, fixture.channel).await;
    assert_eq!(joined["voice_mode"], "relay", "{joined}");
}

/// T-56: `P2PSignal`, `VoiceOffer`, `VoiceAnswer` and `VoiceIceCandidate`
/// reach no one, whether the target is a participant (on any of its
/// connections), an outsider or the sender itself, and produce no error
/// frame (in particular no "Invalid message format"). The sender's later
/// messages are handled as usual.
#[tokio::test]
async fn t56_p2p_signaling_reaches_no_one() {
    let fixture = Fixture::new().await;
    let alice = fixture.member("alice").await;
    let bob = fixture.member("bob").await;
    let outsider = fixture.outsider("outsider").await;

    let mut alice_call = fixture.in_call(&alice).await;
    let mut bob_call = fixture.in_call(&bob).await;
    let mut bob_idle = fixture.connect(&bob).await;
    let mut outsider_ws = fixture.connect(&outsider).await;
    let mut owner_idle = fixture.connect(&fixture.owner).await;
    for ws in [
        &mut alice_call,
        &mut bob_call,
        &mut bob_idle,
        &mut owner_idle,
    ] {
        ws.frames_for(SHORT).await;
    }

    for target in [bob.id, outsider.id, fixture.owner.id, alice.id] {
        send_p2p_signaling(&mut alice_call, fixture.channel, target).await;
    }
    // Also after an attempt to switch the channel to P2P first.
    set_voice_mode(&mut alice_call, fixture.channel, "p2p").await;
    send_p2p_signaling(&mut alice_call, fixture.channel, bob.id).await;

    let before = sync(&mut alice_call).await;
    assert_no_p2p(&before, "alice");
    // The only error frame is the refusal of the switch.
    let alice_errors = errors(&before);
    assert_eq!(alice_errors.len(), 1, "{before:?}");
    assert_eq!(alice_errors[0]["reason"], "p2p_retired");
    assert!(
        !before
            .iter()
            .any(|f| f.to_string().contains("Invalid message format")),
        "{before:?}"
    );

    for (who, ws) in [
        ("bob in the call", &mut bob_call),
        ("bob's other connection", &mut bob_idle),
        ("the outsider", &mut outsider_ws),
        ("the owner", &mut owner_idle),
    ] {
        let (frames, binaries) = record(ws).await;
        assert_no_p2p(&frames, who);
        assert!(errors(&frames).is_empty(), "{who}: {frames:?}");
        assert!(binaries.is_empty(), "{who}: {binaries:?}");
    }

    // The sender's connection still works: relay-mode traffic flows.
    alice_call
        .send(json!({
            "SrtpVoicePacket": { "channel_id": fixture.channel, "packet_data": "AAEC" }
        }))
        .await;
    let frame = bob_call
        .wait_for("srtp_voice_packet", WAIT)
        .await
        .expect("srtp_voice_packet");
    assert_eq!(frame["from"], json!(alice.id));
}

// ─────────────────────────────────────────────────────────────────────────
//  RG-C003-2 (S)
// ─────────────────────────────────────────────────────────────────────────

/// RG-C003-2: the review's C003 attack against a relay with REQ-56, with an
/// emulated outdated client as the target: a raw WebSocket client in the
/// call that records everything it receives. The attacker sends
/// `SetVoiceMode` `p2p` for the channel, then `P2PSignal` with voice `sdp`
/// offers, `screen-sdp` offers and ICE candidates to every participant, and
/// `VoiceOffer` and `VoiceIceCandidate`. It runs once as an outsider account
/// (A7) and once as a participant (A2).
///
/// Expected: `SetVoiceMode` `p2p` is rejected with `p2p_retired` and no
/// `voice_mode_changed` is broadcast; the emulated old client receives no
/// `p2p_signal`, `voice_offer` or `voice_ice_candidate`, nor anything else
/// that carries the attacker's SDP. At bbf2f17 the relay broadcast
/// `voice_mode_changed` to the call and then forwarded every one of these
/// messages to the target.
#[tokio::test]
async fn rg_c003_2_p2p_attack_against_an_old_client() {
    for attacker_is_participant in [false, true] {
        let fixture = Fixture::new().await;
        let old = fixture.member("old-client").await;
        let other = fixture.member("other").await;
        let attacker = if attacker_is_participant {
            fixture.member("attacker").await
        } else {
            fixture.outsider("attacker").await
        };
        let who = if attacker_is_participant {
            "participant attacker"
        } else {
            "outsider attacker"
        };

        let mut old_client = fixture.in_call(&old).await;
        let mut other_call = fixture.in_call(&other).await;
        let mut attacker_ws = if attacker_is_participant {
            fixture.in_call(&attacker).await
        } else {
            fixture.connect(&attacker).await
        };
        old_client.frames_for(SHORT).await;
        other_call.frames_for(SHORT).await;

        // 1. Flip the channel to P2P.
        let request = set_voice_mode(&mut attacker_ws, fixture.channel, "p2p").await;
        let before = sync(&mut attacker_ws).await;
        let refusals = errors(&before);
        assert_eq!(refusals.len(), 1, "{who}: {before:?}");
        assert_p2p_retired(refusals[0], fixture.channel, request);
        assert_no_p2p(&before, who);

        // 2. Offer voice and screen P2P sessions to every participant.
        for target in [old.id, other.id] {
            send_p2p_signaling(&mut attacker_ws, fixture.channel, target).await;
        }
        let before = sync(&mut attacker_ws).await;
        assert!(errors(&before).is_empty(), "{who}: {before:?}");

        // The emulated old client, which would answer any offer and switch
        // modes on any `voice_mode_changed`, received none of it.
        let (frames, binaries) = record(&mut old_client).await;
        assert_no_p2p(&frames, &format!("the old client ({who})"));
        assert!(binaries.is_empty(), "{who}: {binaries:?}");
        let (frames, _) = record(&mut other_call).await;
        assert_no_p2p(&frames, &format!("the other participant ({who})"));

        // The call itself is unaffected and still in relay mode.
        assert_eq!(
            voice_mode(&mut old_client, fixture.channel).await,
            "relay",
            "{who}"
        );
        old_client
            .send(json!({ "GetVoiceParticipants": { "channel_id": fixture.channel } }))
            .await;
        let participants = old_client
            .wait_for("voice_participants", WAIT)
            .await
            .expect("voice_participants");
        let listed = participants["participants"]
            .as_array()
            .expect("participants");
        assert!(listed.contains(&json!(old.id)), "{who}: {participants}");
        assert!(listed.contains(&json!(other.id)), "{who}: {participants}");
    }
}
