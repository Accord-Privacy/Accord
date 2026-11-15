//! The version-2 attachment routes (SPEC-02 sections 6.4.1 to 6.4.3).
//!
//! - `POST /channels/{channel_id}/attachments` (REQ-32 to REQ-34): checks the
//!   headers, the sender's rights, the rate limit and the reservation before
//!   reading any body byte, then streams the body to a temporary file while
//!   hashing it, and moves the result into place as a pending attachment.
//! - `GET /attachments/{id}` (REQ-38): serves a claimed blob to whoever may
//!   read its channel, while its message exists and has not expired.
//! - `DELETE /attachments/{id}` (REQ-39): deletes the requester's own
//!   pending upload.
//!
//! All three authenticate from `Authorization: Bearer <token>` only, and
//! answer errors with [`AttachmentErrorResponse`]. Every check fails closed:
//! an error while authorizing denies. No log event here carries an
//! attachment id at INFO or above (REQ-43).

use super::{AttachmentStore, LOG_TARGET, MIN_BLOB_BYTES};
use crate::db::attachments::{
    AttachmentRecord, AttachmentReservation, AttachmentState, PendingDeletion, ReservationOutcome,
};
use crate::models::{permission_bits, AttachmentErrorResponse, AttachmentUploadResponse};
use crate::rate_limit::ActionType;
use crate::state::{AppState, SharedState};
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};
use uuid::Uuid;

/// Size of the read buffer used to stream a blob to a downloader.
const DOWNLOAD_CHUNK_BYTES: usize = 64 * 1024;

// ── Answers ──

pub(super) fn error_response(status: StatusCode, reason: &str, text: &str) -> Response {
    (
        status,
        Json(AttachmentErrorResponse::with_reason(
            status.as_u16(),
            reason,
            text,
        )),
    )
        .into_response()
}

/// A 429 answer with `Retry-After` (seconds) and the same value in the body.
fn retry_response(reason: &str, text: &str, retry_after: u64) -> Response {
    let retry_after = retry_after.max(1);
    let mut body =
        AttachmentErrorResponse::with_reason(StatusCode::TOO_MANY_REQUESTS.as_u16(), reason, text);
    body.retry_after = Some(retry_after);
    let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(retry_after));
    response
}

/// 401 keeps the body of the shared token extractor, without a reason
/// (section 6.4.1).
pub(super) fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(AttachmentErrorResponse::plain(
            401,
            "Missing or invalid token. Use the Authorization: Bearer <token> header",
        )),
    )
        .into_response()
}

pub(super) fn internal() -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "Internal server error",
    )
}

fn attachment_not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "not_found", "Attachment not found")
}

fn forbidden() -> Response {
    error_response(
        StatusCode::FORBIDDEN,
        "forbidden",
        "You are not allowed to attach files in this channel",
    )
}

/// The user named by the `Authorization: Bearer` header. The `?token=`
/// query parameter is never read, so a request that carries only it is
/// unauthenticated (REQ-32, REQ-38).
async fn bearer_user(state: &AppState, headers: &HeaderMap) -> Option<Uuid> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    if token.is_empty() {
        return None;
    }
    state.validate_token(token).await
}

fn is_octet_stream(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/octet-stream")
        })
        .unwrap_or(false)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── POST /channels/{channel_id}/attachments ──

/// Upload one blob (section 6.4.1).
///
/// Before any body byte is read: authentication (401), the channel id (400),
/// `Content-Length` (411), `Content-Type` (415), the size range (400, 413),
/// authorization (403, 404, 429 `slow_mode`), the rate limit (429
/// `rate_limited`) and the atomic reservation (429 `too_many_pending`, 507).
/// The body is never buffered whole: it streams into
/// `.tmp/<id>.part` while its SHA-256 and length are computed (REQ-34).
pub async fn upload_attachment_handler(
    State(state): State<SharedState>,
    Path(channel_id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(user_id) = bearer_user(&state, &headers).await else {
        return unauthorized();
    };
    let Ok(channel_id) = Uuid::parse_str(&channel_id) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "Malformed channel id",
        );
    };

    // REQ-33: the request's shape.
    let Some(length) = headers.get(header::CONTENT_LENGTH) else {
        return error_response(
            StatusCode::LENGTH_REQUIRED,
            "length_required",
            "Content-Length is required",
        );
    };
    let Some(length) = length
        .to_str()
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "Invalid Content-Length",
        );
    };
    if !is_octet_stream(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "Content-Type must be application/octet-stream",
        );
    }
    if length < MIN_BLOB_BYTES {
        return error_response(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "A blob has at least 16 bytes",
        );
    }
    let config = state.attachments.config().clone();
    if length > config.max_blob_bytes {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            "The blob is larger than this relay accepts",
        );
    }

    // REQ-32: the sender's rights, failing closed.
    let node_id = match authorize_upload(&state, user_id, channel_id).await {
        Ok(node_id) => node_id,
        Err(refusal) => return refusal.response(),
    };

    // REQ-33: the per-user upload rate, applied here because the middleware
    // only sees `?token=` requests (C160).
    if let Err(limited) = state
        .rate_limiter
        .check(user_id, ActionType::FileUpload)
        .await
    {
        return retry_response(
            "rate_limited",
            "Upload rate limit exceeded",
            limited.retry_after_secs,
        );
    }

    // REQ-33: the pending cap, the quotas and the free-space floor, checked
    // and reserved in one transaction.
    let id = Uuid::new_v4();
    let reservation = AttachmentReservation {
        id,
        channel_id,
        node_id,
        uploader_id: user_id,
        blob_size: length,
        now: state.attachments.now(),
    };
    let store: &AttachmentStore = &state.attachments;
    let free_bytes = || store.free_bytes();
    match state
        .db
        .reserve_attachment(&reservation, &config.limits(), &free_bytes)
        .await
    {
        Ok(ReservationOutcome::Reserved { .. }) => {}
        Ok(ReservationOutcome::TooManyPending { retry_after }) => {
            return retry_response(
                "too_many_pending",
                "Too many uploads are waiting for a message",
                retry_after,
            )
        }
        Ok(ReservationOutcome::QuotaExceeded) => {
            return error_response(
                StatusCode::INSUFFICIENT_STORAGE,
                "quota_exceeded",
                "Attachment storage quota exceeded",
            )
        }
        Ok(ReservationOutcome::StorageFull) => {
            return error_response(
                StatusCode::INSUFFICIENT_STORAGE,
                "storage_full",
                "The relay is low on storage",
            )
        }
        Err(_) => {
            warn!(target: LOG_TARGET, "attachment upload: the reservation failed");
            return internal();
        }
    }

    // REQ-34: receive the body in a task of its own, so that the cleanup of
    // an aborted request runs to the end even when the connection is gone.
    match tokio::spawn(receive_upload(state.clone(), id, length, body)).await {
        Ok(response) => response,
        Err(_) => {
            warn!(target: LOG_TARGET, "attachment upload: the upload task failed");
            internal()
        }
    }
}

/// Why an upload was refused by the REQ-32 checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadRefusal {
    /// A lookup or permission computation failed; the request is denied.
    Internal,
    /// The channel does not exist (or is in the reserved node).
    NotFound,
    /// Not allowed to attach in the channel.
    Forbidden,
    /// The DM peer has blocked the requester.
    Blocked,
    /// A slow-mode cooldown is active for this many more seconds.
    SlowMode(u64),
}

impl UploadRefusal {
    fn response(self) -> Response {
        match self {
            UploadRefusal::Internal => internal(),
            UploadRefusal::NotFound => {
                error_response(StatusCode::NOT_FOUND, "not_found", "Channel not found")
            }
            UploadRefusal::Forbidden => forbidden(),
            UploadRefusal::Blocked => error_response(
                StatusCode::FORBIDDEN,
                "blocked",
                "This user has blocked you",
            ),
            UploadRefusal::SlowMode(remaining) => {
                retry_response("slow_mode", "Slow mode active", remaining)
            }
        }
    }
}

/// REQ-32: the upload rights of `user_id` in `channel_id`. Returns the
/// channel's node (`None` for a DM channel) or the refusal. Every lookup or
/// permission error refuses with 500, and a failed DM lookup is never taken
/// for "not a DM".
async fn authorize_upload(
    state: &AppState,
    user_id: Uuid,
    channel_id: Uuid,
) -> Result<Option<Uuid>, UploadRefusal> {
    let dm = state
        .db
        .dm_participants(channel_id)
        .await
        .map_err(|_| UploadRefusal::Internal)?;
    if let Some((user1, user2)) = dm {
        if user1 != user_id && user2 != user_id {
            return Err(UploadRefusal::Forbidden);
        }
        let other = if user1 == user_id { user2 } else { user1 };
        let blocked = state
            .db
            .is_user_blocked(other, user_id)
            .await
            .map_err(|_| UploadRefusal::Internal)?;
        if blocked {
            return Err(UploadRefusal::Blocked);
        }
        return Ok(None);
    }

    let channel = state
        .db
        .get_channel(channel_id)
        .await
        .map_err(|_| UploadRefusal::Internal)?
        .ok_or(UploadRefusal::NotFound)?;
    if crate::admission::is_reserved_node(channel.node_id) {
        return Err(UploadRefusal::NotFound);
    }
    let node_id = channel.node_id;

    if !state
        .user_can_access_channel(user_id, channel_id)
        .await
        .map_err(|_| UploadRefusal::Internal)?
    {
        return Err(UploadRefusal::Forbidden);
    }
    let perms = state
        .db
        .compute_channel_permissions(node_id, user_id, channel_id)
        .await
        .map_err(|_| UploadRefusal::Internal)?;
    let needed = permission_bits::SEND_MESSAGES | permission_bits::ATTACH_FILES;
    if perms & needed != needed {
        return Err(UploadRefusal::Forbidden);
    }

    let build_hash = state.get_client_build_hash(user_id).await;
    let allowed = state
        .db
        .is_build_hash_allowed(node_id, build_hash.as_deref().unwrap_or(""))
        .await
        .map_err(|_| UploadRefusal::Internal)?;
    if !allowed {
        return Err(UploadRefusal::Forbidden);
    }

    // Slow mode: an active cooldown refuses the upload; nothing is recorded.
    let slow_mode = state
        .db
        .get_channel_slow_mode(channel_id)
        .await
        .map_err(|_| UploadRefusal::Internal)?;
    if slow_mode > 0 {
        let cooldowns = state.slow_mode_cooldowns.read().await;
        if let Some(&last_sent) = cooldowns.get(&(channel_id, user_id)) {
            let elapsed = unix_now().saturating_sub(last_sent);
            if elapsed < u64::from(slow_mode) {
                return Err(UploadRefusal::SlowMode(u64::from(slow_mode) - elapsed));
            }
        }
    }
    Ok(Some(node_id))
}

/// Why receiving a body failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadFailure {
    /// More bytes than `Content-Length` arrived.
    TooLarge,
    /// The body ended, or failed, before `Content-Length` bytes arrived.
    Incomplete,
    /// The temporary file could not be written.
    Storage,
    /// The upload was not complete within the deadline.
    Timeout,
}

impl UploadFailure {
    fn response(self) -> Response {
        match self {
            UploadFailure::TooLarge => error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "too_large",
                "The body is longer than Content-Length",
            ),
            UploadFailure::Incomplete => error_response(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "The body ended before Content-Length bytes arrived",
            ),
            UploadFailure::Storage => internal(),
            UploadFailure::Timeout => error_response(
                StatusCode::REQUEST_TIMEOUT,
                "timeout",
                "The upload did not complete in time",
            ),
        }
    }
}

/// Receive the reserved upload `id` and answer the request. Any failure
/// deletes the temporary file, any renamed file and the row, which releases
/// the reservation (REQ-34, section 8.4).
async fn receive_upload(state: SharedState, id: Uuid, declared: u64, body: Body) -> Response {
    let store = &state.attachments;
    let deadline = Duration::from_secs(store.config().upload_deadline_secs);
    let received =
        match tokio::time::timeout(deadline, stream_to_part(store, id, declared, body)).await {
            Ok(result) => result,
            Err(_) => Err(UploadFailure::Timeout),
        };
    let digest = match received {
        Ok(digest) => digest,
        Err(failure) => {
            match failure {
                UploadFailure::Storage => {
                    warn!(target: LOG_TARGET, "attachment upload: writing the blob failed")
                }
                _ => debug!(target: LOG_TARGET, "attachment upload aborted: {:?}", failure),
            }
            discard_upload(&state, id).await;
            return failure.response();
        }
    };

    if tokio::fs::rename(store.part_path(id), store.blob_path(id))
        .await
        .is_err()
    {
        warn!(target: LOG_TARGET, "attachment upload: moving the blob into place failed");
        discard_upload(&state, id).await;
        return internal();
    }
    let ttl = i64::try_from(store.config().pending_ttl_secs).unwrap_or(i64::MAX);
    let pending_expires_at = store.now().saturating_add(ttl);
    match state
        .db
        .complete_attachment_upload(id, &digest, pending_expires_at)
        .await
    {
        Ok(true) => {}
        Ok(false) | Err(_) => {
            warn!(target: LOG_TARGET, "attachment upload: recording the blob failed");
            discard_upload(&state, id).await;
            return internal();
        }
    }

    (
        StatusCode::CREATED,
        Json(AttachmentUploadResponse {
            attachment_id: id,
            blob_size: declared,
            blob_sha256: hex::encode(digest),
            pending_expires_at: u64::try_from(pending_expires_at).unwrap_or(0),
        }),
    )
        .into_response()
}

/// Stream the body into `.tmp/<id>.part` (mode 0600), hashing it as it
/// arrives. Only one body chunk is held in memory at a time.
async fn stream_to_part(
    store: &AttachmentStore,
    id: Uuid,
    declared: u64,
    body: Body,
) -> Result<[u8; 32], UploadFailure> {
    let mut file = create_private_file(&store.part_path(id))
        .await
        .map_err(|_| UploadFailure::Storage)?;
    let mut hasher = Sha256::new();
    let mut received: u64 = 0;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| UploadFailure::Incomplete)?;
        received = received.saturating_add(chunk.len() as u64);
        if received > declared {
            return Err(UploadFailure::TooLarge);
        }
        store.note_chunk(chunk.len());
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|_| UploadFailure::Storage)?;
    }
    if received != declared {
        return Err(UploadFailure::Incomplete);
    }
    file.flush().await.map_err(|_| UploadFailure::Storage)?;
    file.sync_all().await.map_err(|_| UploadFailure::Storage)?;
    Ok(hasher.finalize().into())
}

/// Create a new file with mode 0600 (REQ-43); fails if it exists.
async fn create_private_file(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path).await
}

/// Delete the files and the row of a failed upload. What cannot be removed
/// now is removed by the GC (the row's deadline) and the reconciliation.
async fn discard_upload(state: &AppState, id: Uuid) {
    let files_removed = state.attachments.unlink(id).await;
    let row_removed = state.db.discard_attachment_upload(id).await.is_ok();
    if !files_removed || !row_removed {
        warn!(
            target: LOG_TARGET,
            "attachment upload: cleanup incomplete; the GC and the reconciliation will finish it"
        );
    }
}

// ── GET /attachments/{id} ──

/// Download a claimed blob (section 6.4.2, REQ-38). Every case other than
/// success and a missing or invalid token answers 404; pending blobs are
/// never served, not even to their uploader.
pub async fn download_attachment_handler(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(user_id) = bearer_user(&state, &headers).await else {
        return unauthorized();
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return attachment_not_found();
    };
    match authorize_download(&state, user_id, id).await {
        Some(record) => serve_blob(&state.attachments, record.id, record.blob_size).await,
        None => attachment_not_found(),
    }
}

/// The attachment, if `user_id` may download it now: it is claimed, the
/// user passes `user_can_access_channel` for its channel, and its message
/// exists and has not expired. Any error denies.
async fn authorize_download(state: &AppState, user_id: Uuid, id: Uuid) -> Option<AttachmentRecord> {
    let record = state.db.get_attachment(id).await.ok()??;
    if record.state != AttachmentState::Claimed {
        return None;
    }
    let message_id = record.message_id?;
    let can_read = state
        .user_can_access_channel(user_id, record.channel_id)
        .await
        .ok()?;
    if !can_read {
        return None;
    }
    let live = state
        .db
        .attachment_message_is_live(message_id, record.channel_id, state.attachments.now())
        .await
        .ok()?;
    live.then_some(record)
}

/// Stream the blob with the headers of REQ-38. A missing blob, or one whose
/// length differs from the row, answers 404 (section 8.4).
async fn serve_blob(store: &AttachmentStore, id: Uuid, size: u64) -> Response {
    let Ok(file) = tokio::fs::File::open(store.blob_path(id)).await else {
        return attachment_not_found();
    };
    match file.metadata().await {
        Ok(meta) if meta.is_file() && meta.len() == size => {}
        _ => return attachment_not_found(),
    }
    let stream = futures_util::stream::try_unfold(file.take(size), |mut reader| async move {
        let mut buffer = vec![0u8; DOWNLOAD_CHUNK_BYTES];
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok::<_, std::io::Error>(None);
        }
        buffer.truncate(read);
        Ok(Some((Bytes::from(buffer), reader)))
    });
    let mut response = Response::new(Body::from_stream(stream));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    if let Ok(value) = HeaderValue::from_str(&format!("attachment; filename=\"{id}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

// ── DELETE /attachments/{id} ──

/// Delete the requester's pending upload (section 6.4.3, REQ-39): 204, or
/// 409 `claimed` only for the uploader of a claimed attachment, and 404 in
/// every other case, upload reservations and other users' attachments
/// included.
pub async fn delete_attachment_handler(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(user_id) = bearer_user(&state, &headers).await else {
        return unauthorized();
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return attachment_not_found();
    };
    match state.db.delete_pending_attachment(id, user_id).await {
        Ok(PendingDeletion::Deleted) => {
            if !state.attachments.unlink(id).await {
                warn!(
                    target: LOG_TARGET,
                    "attachment delete: the blob could not be removed; the reconciliation will retry"
                );
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(PendingDeletion::Claimed) => error_response(
            StatusCode::CONFLICT,
            "claimed",
            "The attachment belongs to a message; delete the message instead",
        ),
        Ok(PendingDeletion::NotFound) => attachment_not_found(),
        Err(_) => {
            warn!(target: LOG_TARGET, "attachment delete failed");
            internal()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn octet_stream_detection() {
        let mut headers = HeaderMap::new();
        assert!(!is_octet_stream(&headers));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        assert!(is_octet_stream(&headers));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("Application/Octet-Stream; x=y"),
        );
        assert!(is_octet_stream(&headers));
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert!(!is_octet_stream(&headers));
    }

    #[test]
    fn retry_answers_carry_the_header_and_at_least_one_second() {
        let response = retry_response("rate_limited", "x", 0);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");
    }
}
