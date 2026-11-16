//! Relay admission control (SPEC-01): the reserved DM system node and user,
//! the credential predicates that keep password-less accounts locked, and
//! the admission service through which every membership comes into being.
//!
//! The reserved-id predicates and `is_unusable_password_hash` are defined here
//! once (SPEC-01 REQ-1, REQ-6); every check that needs them calls these
//! functions instead of comparing names or testing for an empty string.
//!
//! The admission service (SPEC-01 REQ-18 to REQ-28, REQ-36 to REQ-39,
//! REQ-45) has three parts:
//!
//! - the types every entry point shares: the request context, the grant, the
//!   outcome and [`AdmissionError`], which maps each refusal to a reason code
//!   of section 6.4;
//! - the entry-point wrappers ([`join`], the invite management functions and
//!   the preview), which run after authentication and request-syntax
//!   validation, charge the per-user rate limits and broadcast only after the
//!   admission transaction has committed;
//! - the database side, `db::admission`, which owns the only `node_members`
//!   insert and runs each admission in one `BEGIN IMMEDIATE` transaction.
//!
//! Log events of this module use the target `accord::admission` and never
//! carry invite codes, user ids or node ids at INFO or above (REQ-41).

use crate::db::{DM_SYSTEM_NODE_ID, DM_SYSTEM_USER_ID};
use crate::models::{ApiErrorResponse, ErrorResponse, NodeInvite};
use crate::node::Node;
use crate::rate_limit::ActionType;
use crate::state::AppState;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{http::StatusCode, Json};
use std::sync::OnceLock;
use uuid::Uuid;

/// Tracing target of every admission log event (SPEC-01 REQ-41).
pub use crate::db::repair::LOG_TARGET;

/// Stored in `users.password_hash` for accounts that must never log in.
/// It is never a valid PHC string, so it can never verify.
pub const LOCK_MARKER: &str = "!locked";

/// True for the DM system node (`DM_SYSTEM_NODE_ID`), whatever its name.
pub fn is_reserved_node(node_id: Uuid) -> bool {
    node_id == DM_SYSTEM_NODE_ID
}

/// True for the DM sentinel user (`DM_SYSTEM_USER_ID`).
pub fn is_reserved_user(user_id: Uuid) -> bool {
    user_id == DM_SYSTEM_USER_ID
}

/// A stored password hash is unusable when it is empty, is the lock marker,
/// or does not parse as a PHC string. Such an account has no credential:
/// every authentication path refuses it exactly like a wrong password.
pub fn is_unusable_password_hash(stored_hash: &str) -> bool {
    stored_hash.is_empty() || stored_hash == LOCK_MARKER || PasswordHash::new(stored_hash).is_err()
}

/// The value to persist in `users.password_hash`: an empty hash is never
/// stored, the lock marker is stored instead (SPEC-01 REQ-4(b)).
pub fn storable_password_hash(password_hash: &str) -> &str {
    if password_hash.is_empty() {
        LOCK_MARKER
    } else {
        password_hash
    }
}

/// The Argon2 instance, and therefore the parameters, used for every new
/// password hash.
fn password_hasher() -> Argon2<'static> {
    Argon2::default()
}

/// Hash a new password as a PHC string with a fresh random salt.
pub fn hash_new_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    password_hasher()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| {
            tracing::error!("Failed to hash password: {}", e);
            "Failed to hash password".to_string()
        })
}

/// Run one Argon2 verification of `password` against the PHC string
/// `phc_hash`. The cost parameters are taken from the hash itself.
/// Returns true only on a match.
pub fn verify_password(password: &str, phc_hash: &str) -> bool {
    match PasswordHash::new(phc_hash) {
        Ok(parsed) => password_hasher()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

static DUMMY_PASSWORD_HASH: OnceLock<String> = OnceLock::new();

/// The fixed dummy PHC hash that credential refusals verify against, so that
/// they cost about as much as a wrong password on a real account
/// (SPEC-01 REQ-2(b)). It is computed once, on first call, with the same
/// parameters as new password hashes; the relay calls this at startup.
pub fn dummy_password_hash() -> Result<&'static str, String> {
    if let Some(hash) = DUMMY_PASSWORD_HASH.get() {
        return Ok(hash.as_str());
    }
    // The hashed secret is random and immediately discarded: no password can
    // be known to match the dummy hash.
    let secret = SaltString::generate(&mut OsRng);
    let hash = hash_new_password(secret.as_str())?;
    Ok(DUMMY_PASSWORD_HASH.get_or_init(|| hash).as_str())
}

// ── Admission service (SPEC-01 REQ-18 to REQ-28, REQ-36 to REQ-39, REQ-45) ──

/// Length of a newly minted invite code (REQ-36): 22 characters of base62,
/// about 131 bits.
pub const INVITE_CODE_LEN: usize = 22;
/// Retries with a fresh code after a collision on the unique code (REQ-36).
pub const INVITE_CODE_RETRIES: usize = 3;
/// Upper bound of `max_uses` (REQ-37).
pub const MAX_INVITE_USES: u64 = 100_000;
/// Shortest invite lifetime, in seconds (REQ-37).
pub const MIN_INVITE_LIFETIME_SECS: u64 = 60;
/// Longest invite lifetime, in seconds: 365 days (REQ-37).
pub const MAX_INVITE_LIFETIME_SECS: u64 = 31_536_000;
/// Lifetime of a join request: 14 days (REQ-30).
pub const JOIN_REQUEST_LIFETIME_SECS: u64 = 1_209_600;
/// Unexpired pending join requests a node accepts from other users (REQ-30).
pub const MAX_PENDING_JOIN_REQUESTS: i64 = 200;
/// Longest build hash a join request may store (REQ-30).
pub const MAX_BUILD_HASH_LEN: usize = 128;

/// Every refusal of the admission service, with its reason code, HTTP status
/// and `error` text (SPEC-01 section 6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    /// 400: malformed body, code, fingerprint or other syntax; the text
    /// names the field.
    InvalidRequest(String),
    /// 429: a REQ-27 limit; `retry_after` is in seconds.
    RateLimited { retry_after: u64 },
    /// 404: the node named in the request is missing or reserved.
    NodeNotFound,
    /// 403: no grant, `join_policy = invite`.
    InviteRequired,
    /// 404: V1, V2, V5 or V6 of REQ-22 failed, or the code is unknown.
    InviteInvalid,
    /// 410: V3 failed.
    InviteExpired,
    /// 410: V4 failed.
    InviteExhausted,
    /// 409: REQ-24(b).
    AlreadyMember,
    /// 403: REQ-24(c).
    Banned,
    /// 403: REQ-24(d), the node has device bans and no fingerprint was sent.
    FingerprintRequired,
    /// 403: REQ-24(d).
    DeviceBanned,
    /// 403: REQ-24(d).
    DeviceLimit,
    /// 403: REQ-24(e).
    BuildNotAllowed,
    /// 403: REQ-30.
    JoinRequestsFull,
    /// 404: missing or expired join request.
    RequestNotFound,
    /// 404: leave of a node the caller is not in (REQ-34).
    NotMember,
    /// 404: kick of a user who is not a member (REQ-35).
    TargetNotMember,
    /// 400: the owner tried to leave (REQ-34).
    OwnerCannotLeave,
    /// 403: no admission authority, missing permission, or the reserved user.
    Forbidden,
    /// 503: database error (fail closed), or invite-code collisions
    /// exhausted.
    Unavailable,
}

impl AdmissionError {
    /// The machine-readable reason of section 6.4.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::RateLimited { .. } => "rate_limited",
            Self::NodeNotFound => "node_not_found",
            Self::InviteRequired => "invite_required",
            Self::InviteInvalid => "invite_invalid",
            Self::InviteExpired => "invite_expired",
            Self::InviteExhausted => "invite_exhausted",
            Self::AlreadyMember => "already_member",
            Self::Banned => "banned",
            Self::FingerprintRequired => "fingerprint_required",
            Self::DeviceBanned => "device_banned",
            Self::DeviceLimit => "device_limit",
            Self::BuildNotAllowed => "build_not_allowed",
            Self::JoinRequestsFull => "join_requests_full",
            Self::RequestNotFound => "request_not_found",
            Self::NotMember | Self::TargetNotMember => "not_member",
            Self::OwnerCannotLeave => "owner_cannot_leave",
            Self::Forbidden => "forbidden",
            Self::Unavailable => "unavailable",
        }
    }

    /// The HTTP status of section 6.4.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::InvalidRequest(_) | Self::OwnerCannotLeave => StatusCode::BAD_REQUEST,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::NodeNotFound
            | Self::InviteInvalid
            | Self::RequestNotFound
            | Self::NotMember
            | Self::TargetNotMember => StatusCode::NOT_FOUND,
            Self::InviteExpired | Self::InviteExhausted => StatusCode::GONE,
            Self::AlreadyMember => StatusCode::CONFLICT,
            Self::InviteRequired
            | Self::Banned
            | Self::FingerprintRequired
            | Self::DeviceBanned
            | Self::DeviceLimit
            | Self::BuildNotAllowed
            | Self::JoinRequestsFull
            | Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// The human-readable `error` text of section 6.4.
    pub fn message(&self) -> String {
        match self {
            Self::InvalidRequest(detail) => detail.clone(),
            Self::RateLimited { .. } => "Rate limit exceeded".into(),
            Self::NodeNotFound => "Node not found".into(),
            Self::InviteRequired => "This node requires an invite".into(),
            Self::InviteInvalid => "Invalid invite code".into(),
            Self::InviteExpired => "Invite has expired".into(),
            Self::InviteExhausted => "Invite has reached maximum uses".into(),
            Self::AlreadyMember => "Already a member of this node".into(),
            Self::Banned => "You are banned from this node".into(),
            Self::FingerprintRequired => "This node requires a device check to join".into(),
            Self::DeviceBanned => "Your device is banned from this node".into(),
            Self::DeviceLimit => "Device account limit reached".into(),
            Self::BuildNotAllowed => "Build not allowed by Node admin".into(),
            Self::JoinRequestsFull => {
                "This node is not accepting more join requests right now".into()
            }
            Self::RequestNotFound => "Join request not found".into(),
            Self::NotMember => "You are not a member of this node".into(),
            Self::TargetNotMember => "That user is not a member of this node".into(),
            Self::OwnerCannotLeave => "Node owner cannot leave their own node".into(),
            Self::Forbidden => "Insufficient permissions".into(),
            Self::Unavailable => "Service temporarily unavailable".into(),
        }
    }

    /// Seconds until a rate-limited request may be retried.
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::RateLimited { retry_after } => Some(*retry_after),
            _ => None,
        }
    }

    /// The REST error body of section 6.2.
    pub fn body(&self) -> ApiErrorResponse {
        ApiErrorResponse {
            error: self.message(),
            code: self.status().as_u16(),
            reason: Some(self.reason().to_string()),
            retry_after: self.retry_after(),
        }
    }

    /// The REST error response: status and body.
    pub fn into_rest(self) -> ApiError {
        (self.status(), Json(self.body()))
    }

    /// A typed WebSocket failure frame (section 6.3) such as `join_failed`
    /// or `leave_failed`, answering the message `request_id`.
    pub fn ws_frame(&self, frame_type: &str, node_id: Uuid, request_id: Uuid) -> serde_json::Value {
        let mut frame = serde_json::json!({
            "type": frame_type,
            "node_id": node_id,
            "reason": self.reason(),
            "error": self.message(),
            "request_id": request_id,
        });
        if let Some(retry_after) = self.retry_after() {
            frame["retry_after"] = serde_json::json!(retry_after);
        }
        frame
    }
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for AdmissionError {}

/// A REST error of the routes this spec adds or changes.
pub type ApiError = (StatusCode, Json<ApiErrorResponse>);

/// Keep the shared token extractor's 401 body unchanged (REQ-28) while
/// returning it from a route whose errors carry reasons.
pub fn auth_error((status, Json(e)): (StatusCode, Json<ErrorResponse>)) -> ApiError {
    (status, Json(ApiErrorResponse::from(e)))
}

/// Log a database error behind an `unavailable` refusal: the error class
/// only, never ids or codes (REQ-41).
pub(crate) fn unavailable(e: &sqlx::Error) -> AdmissionError {
    tracing::warn!(
        target: LOG_TARGET,
        "admission refused (unavailable): {}",
        crate::db::repair::error_class(e)
    );
    AdmissionError::Unavailable
}

/// The request context of an admission (SPEC-01 section 5 definitions): the
/// user being admitted, an optional node-scoped device fingerprint, and the
/// build hash, which is the empty string when none was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionContext {
    pub user_id: Uuid,
    pub device_fingerprint_hash: Option<String>,
    pub build_hash: String,
}

impl AdmissionContext {
    /// A context with no fingerprint and no build hash.
    pub fn bare(user_id: Uuid) -> Self {
        Self {
            user_id,
            device_fingerprint_hash: None,
            build_hash: String::new(),
        }
    }
}

/// The admission entry point a request came through (REQ-45).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionEntry {
    /// `POST /invites/:code/join`: the node is the invite's node.
    InviteCode { code: String },
    /// `POST /nodes/:id/join` and WS `JoinNode`: the node is named, and an
    /// invite code of that node may be supplied.
    Node {
        node_id: Uuid,
        invite_code: Option<String>,
    },
}

/// The single grant an admission runs under (REQ-18). The admission
/// transaction resolves an entry point's request to exactly one of these
/// before it writes a membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionGrant {
    /// A valid invite, consumed atomically; `expected_node` binds it to the
    /// node an entry point names.
    Invite {
        code: String,
        expected_node: Option<Uuid>,
    },
    /// A join request approved by someone with admission authority.
    ApprovedRequest {
        node: Uuid,
        requester: Uuid,
        approver: Uuid,
    },
    /// The node's owner re-admitting themselves (REQ-26).
    OwnerSelf { node: Uuid },
}

/// What an admission did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionOutcome {
    /// A membership was created under the given grant.
    Joined {
        node_id: Uuid,
        node_name: String,
        grant: AdmissionGrant,
    },
    /// A join request was created or refreshed (REQ-30).
    Pending { node_id: Uuid, expires_at: u64 },
}

/// The reserved node and a missing node are refused identically, before any
/// other node check (REQ-7). Database errors fail closed.
pub async fn require_live_node(state: &AppState, node_id: Uuid) -> Result<Node, AdmissionError> {
    if is_reserved_node(node_id) {
        return Err(AdmissionError::NodeNotFound);
    }
    match state.db.get_node(node_id).await {
        Ok(Some(node)) => Ok(node),
        Ok(None) => Err(AdmissionError::NodeNotFound),
        Err(_) => {
            tracing::warn!(target: LOG_TARGET, "node lookup failed");
            Err(AdmissionError::Unavailable)
        }
    }
}

/// Charge one `MembershipChange` token to `user_id` (REQ-27). Every
/// membership entry point calls this once per attempt, after authentication
/// and request-syntax validation and before any database read.
pub async fn charge_membership_change(
    state: &AppState,
    user_id: Uuid,
) -> Result<(), AdmissionError> {
    state
        .rate_limiter
        .check(user_id, ActionType::MembershipChange)
        .await
        .map_err(|e| AdmissionError::RateLimited {
            retry_after: e.retry_after_secs,
        })
}

/// Validate the optional request fields every admission entry point accepts
/// (REQ-45 step 2): an invite code and a device fingerprint.
pub fn validate_join_fields(
    invite_code: Option<&str>,
    device_fingerprint_hash: Option<&str>,
) -> Result<(), AdmissionError> {
    if let Some(code) = invite_code {
        crate::validation::validate_invite_code(code).map_err(AdmissionError::InvalidRequest)?;
    }
    if let Some(fph) = device_fingerprint_hash {
        crate::validation::validate_device_fingerprint_hash(fph)
            .map_err(AdmissionError::InvalidRequest)?;
    }
    Ok(())
}

/// The build hash of a REST request: its `X-Build-Hash` header, or the empty
/// string when none was sent (REQ-24(e), D25).
pub fn rest_build_hash(headers: &axum::http::HeaderMap) -> Result<String, AdmissionError> {
    match headers.get("X-Build-Hash") {
        None => Ok(String::new()),
        Some(value) => value
            .to_str()
            .map(str::to_string)
            .map_err(|_| AdmissionError::InvalidRequest("Invalid X-Build-Hash header".into())),
    }
}

/// An admission entry point (REQ-19 to REQ-21), called after authentication
/// and request-syntax validation (REQ-45 steps 1 and 2). It charges the
/// `MembershipChange` token, runs the admission transaction and, only after
/// it committed, broadcasts the join exactly once (REQ-25). A failure
/// broadcasts nothing.
pub async fn join(
    state: &AppState,
    ctx: AdmissionContext,
    entry: AdmissionEntry,
) -> Result<AdmissionOutcome, AdmissionError> {
    charge_membership_change(state, ctx.user_id).await?;
    let result = state.db.admit(&ctx, &entry, &state.rate_limiter).await;
    match &result {
        Ok(AdmissionOutcome::Joined { node_id, .. }) => {
            tracing::debug!(target: LOG_TARGET, "admission granted");
            broadcast_member_joined(state, *node_id, ctx.user_id).await;
        }
        Ok(AdmissionOutcome::Pending {
            node_id,
            expires_at,
        }) => {
            tracing::debug!(target: LOG_TARGET, "join request recorded");
            let created_at = expires_at.saturating_sub(JOIN_REQUEST_LIFETIME_SECS);
            notify_join_request_created(state, *node_id, ctx.user_id, created_at).await;
        }
        Err(e) => {
            tracing::debug!(target: LOG_TARGET, "admission refused: {}", e.reason());
        }
    }
    result
}

/// Notify the node's channels that a user joined, so that members send their
/// sender keys to the newcomer, and broadcast `member_joined` for member
/// lists. Called once per admission, after the commit (REQ-25). Join hooks
/// that other batch specs add run at this point too.
pub async fn broadcast_member_joined(state: &AppState, node_id: Uuid, user_id: Uuid) {
    let display_name = state
        .db
        .get_user_profile(user_id)
        .await
        .ok()
        .flatten()
        .map(|p| p.display_name)
        .unwrap_or_default();
    let pk_hash = state
        .db
        .get_user_public_key_hash(user_id)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    if let Ok(channels) = state.db.get_node_channels(node_id).await {
        for channel in &channels {
            let join_event = serde_json::json!({
                "type": "sender_key_new_member",
                "channel_id": channel.id,
                "node_id": node_id,
                "new_user_id": user_id,
            });
            let _ = state
                .send_to_channel(channel.id, join_event.to_string())
                .await;

            let member_event = serde_json::json!({
                "type": "member_joined",
                "node_id": node_id,
                "user_id": user_id,
                "display_name": display_name,
                "public_key_hash": pk_hash,
            });
            let _ = state
                .send_to_channel(channel.id, member_event.to_string())
                .await;
        }
    }
}

// ── Leave, kick and the removal routine (REQ-34, REQ-35, REQ-50) ──

/// Name of the fault-injection counter that records each run of the removal
/// hook list (SPEC-01 section 10.1).
pub const REMOVAL_HOOKS_COUNTER: &str = "removal:hooks";

/// The removal hooks of REQ-34 step 6, run exactly once after a membership
/// removal (a leave, kick or ban whose delete removed exactly one row) has
/// committed, and never while its transaction is held. This is the single
/// hook list of the batch; other specs attach to it only here, never to the
/// leave, kick or ban handlers (REQ-50).
pub async fn run_removal_hooks(
    state: &AppState,
    node_id: Uuid,
    removed_user_id: Uuid,
    channel_ids: &[Uuid],
) {
    state.faults().count(REMOVAL_HOOKS_COUNTER);

    // Hook 1: every remaining subscriber rotates the sender key of every
    // channel of the node.
    for channel_id in channel_ids {
        let rotation_event = serde_json::json!({
            "type": "sender_key_rotation_required",
            "channel_id": channel_id,
            "removed_user_id": removed_user_id,
        });
        let _ = state
            .send_to_channel(*channel_id, rotation_event.to_string())
            .await;
    }

    // Hook 2: SPEC-03 REQ-29. Evict `removed_user_id` from the node's voice
    // channels: `voice_peer_left` to the remaining participants,
    // `voice_channel_left` with reason `removed` to the user, and the end of
    // the user's screen shares and watches there (SPEC-03 §6.9, §6.12.4).
    state
        .evict_from_voice_channels(removed_user_id, channel_ids)
        .await;

    // Hook 3: SPEC-06 REQ-36 (node-key distribution clean-up for `node_id`
    // and `removed_user_id`) and REQ-37 (`audience_changed`) attach here
    // once SPEC-06 has landed.
    let _ = node_id; // read only by hook 3, which is still empty

    tracing::debug!(target: LOG_TARGET, "removal hooks ran");
}

/// The single removal routine of leave, kick and ban (REQ-50): run the
/// removal transaction and, only if it deleted exactly one membership row,
/// the removal hooks after the commit. Returns what the transaction did.
pub async fn remove_member(
    state: &AppState,
    node_id: Uuid,
    removal: crate::db::admission::Removal<'_>,
) -> Result<crate::db::admission::MemberRemoval, AdmissionError> {
    let outcome = state.db.remove_member(node_id, removal).await?;
    if let Some(user_id) = outcome.removed_user {
        run_removal_hooks(state, node_id, user_id, &outcome.channel_ids).await;
    }
    Ok(outcome)
}

/// The one leave routine of `POST /nodes/:id/leave` and WS `LeaveNode`
/// (REQ-34), called after authentication:
///
/// 1. the `MembershipChange` charge;
/// 2. the reserved node and a missing node give `node_not_found`;
/// 3. the owner gets `owner_cannot_leave`;
/// 4. and 5. the removal transaction; no membership row deleted gives
///    `not_member` with no other change;
/// 6. the removal hooks, after the commit.
pub async fn leave(state: &AppState, user_id: Uuid, node_id: Uuid) -> Result<(), AdmissionError> {
    charge_membership_change(state, user_id).await?;
    let node = require_live_node(state, node_id).await?;
    if node.owner_id == user_id {
        return Err(AdmissionError::OwnerCannotLeave);
    }
    let outcome = remove_member(
        state,
        node_id,
        crate::db::admission::Removal::Leave { user_id },
    )
    .await?;
    if outcome.removed_user.is_none() {
        tracing::debug!(target: LOG_TARGET, "leave refused: not_member");
        return Err(AdmissionError::NotMember);
    }
    tracing::debug!(target: LOG_TARGET, "member left");
    Ok(())
}

/// Kick `target` from `node_id` as `actor` (`DELETE
/// /nodes/:id/members/:user_id`, REQ-35), called after authentication:
///
/// - one `MembershipChange` token for the acting user;
/// - the reserved node and a missing node give `node_not_found` (section
///   6.7, SHOULD);
/// - today's authorization: the actor is a member holding KICK_MEMBERS
///   (`forbidden`), and the owner cannot be kicked (400);
/// - the removal routine; no membership row deleted gives `not_member` and
///   nothing else happens: no rotation, no distribution deletion, no audit
///   row;
/// - otherwise today's `member_kick` audit row, then the removal hooks.
pub async fn kick(
    state: &AppState,
    actor: Uuid,
    node_id: Uuid,
    target: Uuid,
) -> Result<(), AdmissionError> {
    charge_membership_change(state, actor).await?;
    let node = require_live_node(state, node_id).await?;
    let actor_is_member = state
        .db
        .is_node_member(node_id, actor)
        .await
        .map_err(|_| AdmissionError::Unavailable)?;
    if !actor_is_member {
        return Err(AdmissionError::Forbidden);
    }
    let perms = state
        .db
        .compute_node_permissions(node_id, actor)
        .await
        .map_err(|_| AdmissionError::Unavailable)?;
    if !crate::permissions::perms_have(perms, crate::permissions::Permission::KickMembers) {
        return Err(AdmissionError::Forbidden);
    }
    if node.owner_id == target {
        return Err(AdmissionError::InvalidRequest(
            "Cannot kick the node owner".into(),
        ));
    }
    let outcome = state
        .db
        .remove_member(
            node_id,
            crate::db::admission::Removal::Kick { user_id: target },
        )
        .await?;
    let Some(removed) = outcome.removed_user else {
        tracing::debug!(target: LOG_TARGET, "kick refused: not_member");
        return Err(AdmissionError::TargetNotMember);
    };
    let details = serde_json::json!({ "kicked_user_id": removed });
    if state
        .db
        .log_audit_event(
            node_id,
            actor,
            "member_kick",
            "user",
            Some(removed),
            Some(&details.to_string()),
        )
        .await
        .is_err()
    {
        tracing::warn!(target: LOG_TARGET, "member_kick audit entry not written");
    }
    run_removal_hooks(state, node_id, removed, &outcome.channel_ids).await;
    tracing::debug!(target: LOG_TARGET, "member kicked");
    Ok(())
}

/// The ban write of `POST /nodes/:id/bans` (REQ-50): the ban row and the
/// removal of the account with that public-key hash, if it is a member, in
/// one transaction, then the removal hooks after the commit when a member
/// was removed. The handler keeps its authorization and audit entry.
/// Returns the removed member, if any.
pub async fn ban(
    state: &AppState,
    node_id: Uuid,
    ban: crate::db::admission::NewBan<'_>,
) -> Result<Option<Uuid>, AdmissionError> {
    let outcome = remove_member(state, node_id, crate::db::admission::Removal::Ban(ban)).await?;
    Ok(outcome.removed_user)
}

// ── Join requests (REQ-29 to REQ-33) ──

/// Apply `PATCH /nodes/:id` (REQ-29), called after authentication and the
/// request's syntax checks: the reserved node and a missing node give
/// `node_not_found`; then one transaction authorizes every field (the join
/// policy alone: the owner or a member holding MANAGE_NODE; anything else: a
/// member holding MANAGE_NODE) and writes all of them or none. Switching to
/// `invite` deletes pending requests.
pub async fn update_node_settings(
    state: &AppState,
    actor: Uuid,
    node_id: Uuid,
    update: crate::db::admission::NodeSettingsUpdate<'_>,
) -> Result<(), AdmissionError> {
    require_live_node(state, node_id).await?;
    state
        .db
        .update_node_settings(actor, node_id, update)
        .await?;
    tracing::debug!(target: LOG_TARGET, "node settings changed");
    Ok(())
}

/// Users currently connected over WebSocket among `candidates`.
async fn online_users(state: &AppState, candidates: Vec<Uuid>) -> Vec<Uuid> {
    let connections = state.connections.read().await;
    let mut online: Vec<Uuid> = candidates
        .into_iter()
        .filter(|user| connections.contains_key(user))
        .collect();
    online.sort();
    online.dedup();
    online
}

/// Send `join_request_created` to the node's online users with admission
/// authority (REQ-30, SHOULD; OD-19). Best effort: lookup errors only skip
/// the notification.
pub async fn notify_join_request_created(
    state: &AppState,
    node_id: Uuid,
    requester: Uuid,
    created_at: u64,
) {
    let Ok(Some(node)) = state.db.get_node(node_id).await else {
        return;
    };
    let mut candidates: Vec<Uuid> = match state.db.get_node_members(node_id).await {
        Ok(members) => members.into_iter().map(|m| m.user_id).collect(),
        Err(_) => return,
    };
    candidates.push(node.owner_id);
    let frame = serde_json::json!({
        "type": "join_request_created",
        "node_id": node_id,
        "user_id": requester,
        "created_at": created_at,
    })
    .to_string();
    for user in online_users(state, candidates).await {
        if user == requester {
            continue;
        }
        if let Ok(true) = state.db.admission_authority(node_id, user).await {
            let _ = state.send_to_user(user, frame.clone()).await;
        }
    }
}

/// `GET /nodes/:id/join-requests` (REQ-31): the node's unexpired requests,
/// for users with admission authority only.
pub async fn list_join_requests(
    state: &AppState,
    user_id: Uuid,
    node_id: Uuid,
) -> Result<Vec<crate::models::JoinRequestInfo>, AdmissionError> {
    require_live_node(state, node_id).await?;
    state.db.list_join_requests(user_id, node_id).await
}

/// `POST /nodes/:id/join-requests/:user_id/approve` (REQ-31, REQ-32). Not
/// charged to the approver. After the approval transaction committed, the
/// join is broadcast once and then `node_joined` is pushed to the
/// requester's connections.
pub async fn approve_join_request(
    state: &AppState,
    approver: Uuid,
    node_id: Uuid,
    requester: Uuid,
) -> Result<AdmissionOutcome, AdmissionError> {
    require_live_node(state, node_id).await?;
    let result = state
        .db
        .approve_join_request(approver, node_id, requester)
        .await;
    match &result {
        Ok(AdmissionOutcome::Joined {
            node_id, node_name, ..
        }) => {
            tracing::debug!(target: LOG_TARGET, "join request approved");
            broadcast_member_joined(state, *node_id, requester).await;
            let frame = serde_json::json!({
                "type": "node_joined",
                "node_id": node_id,
                "node_name": node_name,
            });
            let _ = state.send_to_user(requester, frame.to_string()).await;
        }
        Ok(AdmissionOutcome::Pending { .. }) => {}
        Err(e) => {
            tracing::debug!(target: LOG_TARGET, "approval refused: {}", e.reason());
        }
    }
    result
}

/// `POST /nodes/:id/join-requests/:user_id/deny` (REQ-31). Not charged to
/// the approver. Deletes the request and tells the requester's connections
/// with `join_request_denied`.
pub async fn deny_join_request(
    state: &AppState,
    approver: Uuid,
    node_id: Uuid,
    requester: Uuid,
) -> Result<(), AdmissionError> {
    require_live_node(state, node_id).await?;
    state
        .db
        .deny_join_request(approver, node_id, requester)
        .await?;
    tracing::debug!(target: LOG_TARGET, "join request denied");
    let frame = serde_json::json!({ "type": "join_request_denied", "node_id": node_id });
    let _ = state.send_to_user(requester, frame.to_string()).await;
    Ok(())
}

/// `DELETE /nodes/:id/join-request` (REQ-31): the requester withdraws their
/// own request. A membership action: one `MembershipChange` token, charged
/// before any database read (REQ-27).
pub async fn withdraw_join_request(
    state: &AppState,
    user_id: Uuid,
    node_id: Uuid,
) -> Result<(), AdmissionError> {
    charge_membership_change(state, user_id).await?;
    require_live_node(state, node_id).await?;
    state.db.withdraw_join_request(node_id, user_id).await?;
    tracing::debug!(target: LOG_TARGET, "join request withdrawn");
    Ok(())
}

// ── Invites (REQ-36 to REQ-39) ──

/// Generate a new invite code: [`INVITE_CODE_LEN`] characters drawn
/// uniformly from the 62 ASCII letters and digits with `ThreadRng`, which is
/// a cryptographically secure generator seeded from the OS (REQ-36).
pub fn generate_invite_code() -> String {
    use rand::{distributions::Alphanumeric, Rng};
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(INVITE_CODE_LEN)
        .map(char::from)
        .collect()
}

/// The code the generator repeats while the `admission:code_collision`
/// fault point is armed (tests only).
const COLLISION_TEST_CODE: &str = "CollisionTestCodeXXXXX";

/// A parsed `POST /nodes/:id/invites` body (REQ-37).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CreateInviteParams {
    pub max_uses: Option<u32>,
    /// The effective lifetime in seconds, `None` for an invite that never
    /// expires.
    pub lifetime_secs: Option<u64>,
}

/// Convert fractional hours to seconds as REQ-37 defines it: hours × 3600,
/// rounded to 3 decimal places, then the smallest integer not below it.
fn hours_to_secs(hours: f64) -> Option<f64> {
    let product = hours * 3600.0;
    if !product.is_finite() {
        return None;
    }
    let rounded = (product * 1000.0).round() / 1000.0;
    Some(rounded.ceil())
}

/// Check that a lifetime in seconds is in range and return it.
fn lifetime_in_range(field: &str, secs: f64) -> Result<u64, AdmissionError> {
    if secs.is_finite()
        && secs >= MIN_INVITE_LIFETIME_SECS as f64
        && secs <= MAX_INVITE_LIFETIME_SECS as f64
    {
        Ok(secs as u64)
    } else {
        Err(AdmissionError::InvalidRequest(format!(
            "{field} must give a lifetime between {MIN_INVITE_LIFETIME_SECS} and {MAX_INVITE_LIFETIME_SECS} seconds"
        )))
    }
}

/// Parse a `POST /nodes/:id/invites` body strictly (REQ-37). An absent or
/// zero-length body means "no use limit, no expiry". A non-empty body must
/// be a JSON object with only the fields `max_uses`, `expires_in_seconds`,
/// `expires_in_hours` and `expires_hours`; `null` counts as absent. Every
/// present field is type- and range-checked, and the first expiry field in
/// that order is used.
pub fn parse_create_invite_body(body: &[u8]) -> Result<CreateInviteParams, AdmissionError> {
    if body.is_empty() {
        return Ok(CreateInviteParams::default());
    }
    let invalid = |msg: &str| AdmissionError::InvalidRequest(msg.to_string());
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| invalid("Request body must be a JSON object"))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("Request body must be a JSON object"))?;

    let mut params = CreateInviteParams::default();
    let mut seconds: Option<u64> = None;
    let mut hours: Option<u64> = None;
    let mut hours_alias: Option<u64> = None;
    for (key, field) in object {
        if field.is_null() {
            if matches!(
                key.as_str(),
                "max_uses" | "expires_in_seconds" | "expires_in_hours" | "expires_hours"
            ) {
                continue;
            }
            return Err(AdmissionError::InvalidRequest(format!(
                "Unknown field: {key}"
            )));
        }
        match key.as_str() {
            "max_uses" => {
                let n = field
                    .as_u64()
                    .filter(|n| (1..=MAX_INVITE_USES).contains(n))
                    .ok_or_else(|| invalid("max_uses must be an integer between 1 and 100000"))?;
                params.max_uses = Some(n as u32);
            }
            "expires_in_seconds" => {
                let n = field
                    .as_u64()
                    .ok_or_else(|| invalid("expires_in_seconds must be an integer"))?;
                seconds = Some(lifetime_in_range("expires_in_seconds", n as f64)?);
            }
            "expires_in_hours" | "expires_hours" => {
                let h = field
                    .as_f64()
                    .filter(|h| field.is_number() && *h >= 0.0)
                    .ok_or_else(|| {
                        AdmissionError::InvalidRequest(format!(
                            "{key} must be a non-negative number"
                        ))
                    })?;
                let secs = hours_to_secs(h).ok_or_else(|| {
                    AdmissionError::InvalidRequest(format!("{key} is out of range"))
                })?;
                let secs = lifetime_in_range(key, secs)?;
                if key == "expires_in_hours" {
                    hours = Some(secs);
                } else {
                    hours_alias = Some(secs);
                }
            }
            other => {
                return Err(AdmissionError::InvalidRequest(format!(
                    "Unknown field: {other}"
                )));
            }
        }
    }
    params.lifetime_secs = seconds.or(hours).or(hours_alias);
    Ok(params)
}

/// Create an invite in `node_id` as `creator` (REQ-36 to REQ-38). Requires
/// admission authority. A collision on the unique code is retried with a
/// fresh code at most [`INVITE_CODE_RETRIES`] times; after that the request
/// fails with `unavailable` and no invite exists. The audit entry stores the
/// invite id, never the code (REQ-41).
pub async fn create_invite(
    state: &AppState,
    node_id: Uuid,
    creator: Uuid,
    params: CreateInviteParams,
) -> Result<NodeInvite, AdmissionError> {
    require_live_node(state, node_id).await?;
    if !state.db.admission_authority(node_id, creator).await? {
        return Err(AdmissionError::Forbidden);
    }
    let created_at = now_secs();
    let expires_at = params.lifetime_secs.map(|secs| created_at + secs);
    let forced_collision = state.faults().check("admission:code_collision").is_err();
    let mut attempts = 0;
    let invite = loop {
        attempts += 1;
        state.faults().count("admission:code_attempt");
        let code = if forced_collision {
            COLLISION_TEST_CODE.to_string()
        } else {
            generate_invite_code()
        };
        match state
            .db
            .insert_invite(
                node_id,
                creator,
                &code,
                params.max_uses,
                expires_at,
                created_at,
            )
            .await
        {
            Ok(invite) => break invite,
            Err(crate::db::admission::InsertInviteError::Collision)
                if attempts <= INVITE_CODE_RETRIES =>
            {
                continue;
            }
            Err(crate::db::admission::InsertInviteError::Collision) => {
                tracing::warn!(target: LOG_TARGET, "invite code collisions exhausted");
                return Err(AdmissionError::Unavailable);
            }
            Err(crate::db::admission::InsertInviteError::Refused(e)) => return Err(e),
        }
    };
    let details = serde_json::json!({
        "invite_id": invite.id,
        "max_uses": invite.max_uses,
        "expires_at": invite.expires_at,
    });
    if state
        .db
        .log_audit_event(
            node_id,
            creator,
            "invite_create",
            "invite",
            Some(invite.id),
            Some(&details.to_string()),
        )
        .await
        .is_err()
    {
        tracing::warn!(target: LOG_TARGET, "invite_create audit entry not written");
    }
    tracing::debug!(target: LOG_TARGET, "invite created");
    Ok(invite)
}

/// List a node's invites (REQ-38). Requires admission authority.
pub async fn list_invites(
    state: &AppState,
    node_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<NodeInvite>, AdmissionError> {
    require_live_node(state, node_id).await?;
    if !state.db.admission_authority(node_id, user_id).await? {
        return Err(AdmissionError::Forbidden);
    }
    state.db.get_node_invites(node_id).await.map_err(|_| {
        tracing::warn!(target: LOG_TARGET, "invite list failed");
        AdmissionError::Unavailable
    })
}

/// The JSON of one invite in `GET /nodes/:id/invites`, with the aliases
/// `code` and `uses` that the desktop reads (REQ-38).
pub fn invite_list_item(invite: &NodeInvite) -> serde_json::Value {
    serde_json::json!({
        "id": invite.id,
        "node_id": invite.node_id,
        "created_by": invite.created_by,
        "invite_code": invite.invite_code,
        "code": invite.invite_code,
        "max_uses": invite.max_uses,
        "current_uses": invite.current_uses,
        "uses": invite.current_uses,
        "expires_at": invite.expires_at,
        "created_at": invite.created_at,
    })
}

/// May `user_id` revoke `invite`? Admission-authority holders may revoke
/// every invite of the node; a creator who is still a member may revoke
/// their own (REQ-38).
async fn may_revoke(
    state: &AppState,
    invite: &NodeInvite,
    user_id: Uuid,
) -> Result<bool, AdmissionError> {
    if state
        .db
        .admission_authority(invite.node_id, user_id)
        .await?
    {
        return Ok(true);
    }
    if invite.created_by != user_id {
        return Ok(false);
    }
    state
        .db
        .is_node_member(invite.node_id, user_id)
        .await
        .map_err(|_| AdmissionError::Unavailable)
}

/// Delete `invite` and write the `invite_revoke` audit entry with its id only.
async fn revoke(
    state: &AppState,
    invite: &NodeInvite,
    user_id: Uuid,
) -> Result<(), AdmissionError> {
    state
        .db
        .delete_node_invite(invite.id)
        .await
        .map_err(|_| AdmissionError::Unavailable)?;
    let details = serde_json::json!({ "invite_id": invite.id });
    if state
        .db
        .log_audit_event(
            invite.node_id,
            user_id,
            "invite_revoke",
            "invite",
            Some(invite.id),
            Some(&details.to_string()),
        )
        .await
        .is_err()
    {
        tracing::warn!(target: LOG_TARGET, "invite_revoke audit entry not written");
    }
    tracing::debug!(target: LOG_TARGET, "invite revoked");
    Ok(())
}

/// `DELETE /invites/:invite_id` (REQ-38): an unknown invite gives
/// `invite_invalid`, a caller who may not revoke it `forbidden`.
pub async fn revoke_invite_by_id(
    state: &AppState,
    invite_id: Uuid,
    user_id: Uuid,
) -> Result<NodeInvite, AdmissionError> {
    let invite = state
        .db
        .get_node_invite(invite_id)
        .await
        .map_err(|_| AdmissionError::Unavailable)?
        .filter(|invite| !is_reserved_node(invite.node_id))
        .ok_or(AdmissionError::InviteInvalid)?;
    if !may_revoke(state, &invite, user_id).await? {
        return Err(AdmissionError::Forbidden);
    }
    revoke(state, &invite, user_id).await?;
    Ok(invite)
}

/// `DELETE /nodes/:id/invites/:code` (REQ-38): revoke the invite with that
/// code in that node, under the authorization of `DELETE /invites/:id`. A
/// caller without admission authority cannot tell an unknown code from
/// another member's invite: both give `forbidden`.
pub async fn revoke_invite_by_code(
    state: &AppState,
    node_id: Uuid,
    code: &str,
    user_id: Uuid,
) -> Result<NodeInvite, AdmissionError> {
    require_live_node(state, node_id).await?;
    let authority = state.db.admission_authority(node_id, user_id).await?;
    let invite = state
        .db
        .get_node_invite_by_code(code)
        .await
        .map_err(|_| AdmissionError::Unavailable)?
        .filter(|invite| invite.node_id == node_id);
    let invite = match (invite, authority) {
        (Some(invite), _) => invite,
        (None, true) => return Err(AdmissionError::InviteInvalid),
        (None, false) => return Err(AdmissionError::Forbidden),
    };
    if !authority && !may_revoke(state, &invite, user_id).await? {
        return Err(AdmissionError::Forbidden);
    }
    revoke(state, &invite, user_id).await?;
    Ok(invite)
}

/// `GET /invites/:code/preview` (REQ-39): REQ-22 without consuming. Returns
/// the invite's node and its member count.
pub async fn preview_invite(state: &AppState, code: &str) -> Result<(Node, i64), AdmissionError> {
    let invite = state.db.check_invite(code, now_secs()).await?;
    let node = state
        .db
        .get_node(invite.node_id)
        .await
        .map_err(|_| AdmissionError::Unavailable)?
        .ok_or(AdmissionError::InviteInvalid)?;
    let members = state
        .db
        .get_node_members(invite.node_id)
        .await
        .map_err(|_| AdmissionError::Unavailable)?;
    Ok((node, members.len() as i64))
}

/// Charge the invite-preview limit of the socket peer `peer` (REQ-27). A
/// request without connect information, or from a loopback peer, is never
/// limited.
pub async fn charge_preview(
    state: &AppState,
    peer: Option<std::net::SocketAddr>,
) -> Result<(), AdmissionError> {
    let Some(key) = peer.and_then(|addr| crate::rate_limit::preview_peer_key(addr.ip())) else {
        return Ok(());
    };
    state
        .rate_limiter
        .check_ip(&key, ActionType::InvitePreview)
        .await
        .map_err(|e| AdmissionError::RateLimited {
            retry_after: e.retry_after_secs,
        })
}

/// Seconds since the Unix epoch.
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T-1b (REQ-1): the shared "no credential" predicate.
    #[test]
    fn unusable_password_hash_predicate() {
        let real = hash_new_password("correct horse").unwrap();
        assert!(is_unusable_password_hash(""));
        assert!(is_unusable_password_hash(LOCK_MARKER));
        assert!(is_unusable_password_hash("SYSTEM"));
        assert!(!is_unusable_password_hash(&real));
    }

    #[test]
    fn lock_marker_is_never_a_phc_string() {
        assert!(PasswordHash::new(LOCK_MARKER).is_err());
        assert!(!verify_password("", LOCK_MARKER));
        assert!(!verify_password("!locked", LOCK_MARKER));
    }

    #[test]
    fn storable_hash_never_empty() {
        assert_eq!(storable_password_hash(""), LOCK_MARKER);
        assert_eq!(storable_password_hash("$argon2id$x"), "$argon2id$x");
    }

    #[test]
    fn reserved_predicates_compare_ids() {
        assert!(is_reserved_node(DM_SYSTEM_NODE_ID));
        assert!(!is_reserved_node(DM_SYSTEM_USER_ID));
        assert!(!is_reserved_node(Uuid::new_v4()));
        assert!(is_reserved_user(DM_SYSTEM_USER_ID));
        assert!(!is_reserved_user(DM_SYSTEM_NODE_ID));
        assert!(!is_reserved_user(Uuid::new_v4()));
    }

    #[test]
    fn verify_password_matches_only_the_right_password() {
        let hash = hash_new_password("pw").unwrap();
        assert!(verify_password("pw", &hash));
        assert!(!verify_password("wrong", &hash));
        assert!(!verify_password("pw", ""));
        assert!(!verify_password("pw", "SYSTEM"));
    }

    /// T-36 (REQ-36), unit part: generated codes and accepted lengths.
    #[test]
    fn t36_invite_codes_are_long_base62_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let code = generate_invite_code();
            assert_eq!(code.len(), INVITE_CODE_LEN);
            assert!(code.bytes().all(|b| b.is_ascii_alphanumeric()), "{code}");
            assert!(seen.insert(code));
        }
        let validate = crate::validation::validate_invite_code;
        for len in [6, 8, 22, 32] {
            assert!(validate(&"a".repeat(len)).is_ok(), "{len}");
        }
        for len in [5, 33] {
            assert!(validate(&"a".repeat(len)).is_err(), "{len}");
        }
        assert!(validate("abc-defg").is_err());
    }

    /// REQ-37: hour conversion and strict parsing.
    #[test]
    fn create_invite_body_parsing() {
        let parse = |body: &str| parse_create_invite_body(body.as_bytes());
        assert_eq!(parse(""), Ok(CreateInviteParams::default()));
        assert_eq!(parse("{}"), Ok(CreateInviteParams::default()));
        let secs = |body: &str| parse(body).unwrap().lifetime_secs;
        assert_eq!(secs(r#"{"expires_hours":0.5}"#), Some(1800));
        assert_eq!(secs(r#"{"expires_hours":0.1}"#), Some(360));
        assert_eq!(secs(r#"{"expires_in_hours":24}"#), Some(86_400));
        assert_eq!(
            secs(r#"{"expires_in_hours":1, "expires_hours":2}"#),
            Some(3600)
        );
        assert_eq!(
            secs(r#"{"expires_in_seconds":120,"expires_hours":5}"#),
            Some(120)
        );
        assert_eq!(
            secs(r#"{"expires_in_seconds":null,"expires_hours":0.5}"#),
            Some(1800)
        );
        assert_eq!(parse(r#"{"max_uses":3}"#).unwrap().max_uses, Some(3));
        for bad in [
            r#"{"expires_in_seconds":120,"expires_hours":-5}"#,
            r#"{"expires_hours":"abc"}"#,
            r#"{"max_uses":0}"#,
            r#"{"max_uses":1.5}"#,
            r#"{"foo":1}"#,
            r#"{"foo":null}"#,
            r#"{"expires_in_seconds":30}"#,
            r#"{"expires_in_hours":0.01}"#,
            r#"{"expires_in_hours":1e300}"#,
            "[]",
            "null",
            " ",
        ] {
            assert!(
                matches!(parse(bad), Err(AdmissionError::InvalidRequest(_))),
                "{bad}"
            );
        }
    }

    /// REQ-27: preview buckets per IPv4 address or IPv6 /64; loopback is
    /// never limited; IPv4-mapped addresses count as IPv4.
    #[test]
    fn preview_peer_keys() {
        use crate::rate_limit::preview_peer_key;
        let key = |s: &str| preview_peer_key(s.parse().unwrap());
        assert_eq!(key("203.0.113.1"), Some("203.0.113.1".into()));
        assert_eq!(key("::ffff:203.0.113.1"), Some("203.0.113.1".into()));
        assert_eq!(key("2001:db8:1:2::1"), key("2001:db8:1:2::2"));
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
        assert_eq!(key("127.0.0.1"), None);
        assert_eq!(key("::1"), None);
        assert_eq!(key("::ffff:127.0.0.1"), None);
    }

    /// Section 6.4: every reason maps to its status and text.
    #[test]
    fn reasons_map_to_section_6_4() {
        let cases = [
            (AdmissionError::NodeNotFound, 404, "node_not_found"),
            (AdmissionError::InviteRequired, 403, "invite_required"),
            (AdmissionError::InviteInvalid, 404, "invite_invalid"),
            (AdmissionError::InviteExpired, 410, "invite_expired"),
            (AdmissionError::InviteExhausted, 410, "invite_exhausted"),
            (AdmissionError::AlreadyMember, 409, "already_member"),
            (AdmissionError::Banned, 403, "banned"),
            (
                AdmissionError::FingerprintRequired,
                403,
                "fingerprint_required",
            ),
            (AdmissionError::DeviceBanned, 403, "device_banned"),
            (AdmissionError::DeviceLimit, 403, "device_limit"),
            (AdmissionError::BuildNotAllowed, 403, "build_not_allowed"),
            (AdmissionError::JoinRequestsFull, 403, "join_requests_full"),
            (AdmissionError::RequestNotFound, 404, "request_not_found"),
            (AdmissionError::NotMember, 404, "not_member"),
            (AdmissionError::TargetNotMember, 404, "not_member"),
            (AdmissionError::OwnerCannotLeave, 400, "owner_cannot_leave"),
            (AdmissionError::Forbidden, 403, "forbidden"),
            (
                AdmissionError::InvalidRequest("x".into()),
                400,
                "invalid_request",
            ),
            (
                AdmissionError::RateLimited { retry_after: 3 },
                429,
                "rate_limited",
            ),
            (AdmissionError::Unavailable, 503, "unavailable"),
        ];
        for (error, status, reason) in cases {
            let body = serde_json::to_value(error.body()).unwrap();
            assert_eq!(error.status().as_u16(), status, "{reason}");
            assert_eq!(body["reason"], reason);
            assert_eq!(body["code"], status);
            assert!(body["error"].as_str().is_some_and(|e| !e.is_empty()));
            assert_eq!(body.get("retry_after").is_some(), reason == "rate_limited");
        }
        let frame = AdmissionError::RateLimited { retry_after: 42 }.ws_frame(
            "join_failed",
            Uuid::nil(),
            Uuid::nil(),
        );
        assert_eq!(frame["retry_after"], 42);
        assert_eq!(frame["reason"], "rate_limited");
    }

    #[test]
    fn dummy_hash_is_fixed_and_uses_new_hash_parameters() {
        let dummy = dummy_password_hash().unwrap();
        assert_eq!(dummy, dummy_password_hash().unwrap());
        assert!(!is_unusable_password_hash(dummy));

        let fresh = hash_new_password("pw").unwrap();
        let dummy = PasswordHash::new(dummy).unwrap();
        let fresh = PasswordHash::new(&fresh).unwrap();
        assert_eq!(dummy.algorithm, fresh.algorithm);
        assert_eq!(dummy.version, fresh.version);
        assert_eq!(dummy.params, fresh.params);
    }
}
