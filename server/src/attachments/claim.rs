//! The claim in WS `ChannelMessage` and the edit guard (SPEC-02 sections
//! 6.5.1 to 6.5.3; REQ-35 to REQ-37): the validation of the attachment list
//! and the typed error frames.
//!
//! A `ChannelMessage` that carries `attachment_ids` is answered, on any
//! refusal, with exactly one `attachment_claim_failed` frame, sent to the
//! originating connection only. It always echoes the request's list, except
//! when the list has more than 10 entries or an entry longer than 36 bytes,
//! so that the sender can tell which message failed. An edit of a message
//! with claimed attachments is answered with `attachments_not_editable`.
//!
//! Both keep the generic `{"type": "error", "error": …}` shape, so older
//! clients still show the text, and add `code` (the failure) and `reason`
//! (SPEC-01 section 6.3), plus `request_id`, the envelope `message_id` of the
//! frame they answer.

use super::{is_canonical_uuid, MAX_ATTACHMENTS_PER_MESSAGE};
use serde_json::{json, Value};
use std::collections::HashSet;
use uuid::Uuid;

/// `code` of the claim failure frame.
pub const CLAIM_FAILED: &str = "attachment_claim_failed";

/// `code` (and `reason`) of the edit guard's frame and 409 answer (REQ-37).
pub const NOT_EDITABLE: &str = "attachments_not_editable";

/// The error text of the edit guard.
pub const NOT_EDITABLE_TEXT: &str = "Messages with attachments cannot be edited";

/// The longest list entry the frame echoes: a canonical UUID.
const MAX_ECHOED_ENTRY_BYTES: usize = 36;

/// Why a `ChannelMessage` that claims attachments was refused (section
/// 6.5.3). Nothing was stored or broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimFailure {
    /// More than 10 ids, duplicates or malformed ids. `echo` is false when
    /// the list has more than 10 entries or an entry longer than 36 bytes;
    /// the frame then omits `attachment_ids`.
    InvalidList { echo: bool },
    /// The payload is not valid base64.
    InvalidPayload,
    /// Not a DM participant, no SEND_MESSAGES or ATTACH_FILES, no access to
    /// the channel, or no such channel.
    Forbidden,
    /// The DM peer has blocked the sender.
    Blocked,
    /// The node's build allowlist rejects the sender's client build.
    Allowlist,
    /// A slow-mode cooldown is active for this many more seconds.
    SlowMode { retry_after: u64 },
    /// These blobs are not found, not the sender's, in another channel,
    /// expired or already claimed. The causes are deliberately not told
    /// apart.
    Unavailable { ids: Vec<Uuid> },
    /// A database or storage error. Nothing was stored.
    Internal,
}

impl ClaimFailure {
    /// The machine-readable reason (section 6.5.3).
    pub fn reason(&self) -> &'static str {
        match self {
            ClaimFailure::InvalidList { .. } | ClaimFailure::InvalidPayload => "invalid",
            ClaimFailure::Forbidden => "forbidden",
            ClaimFailure::Blocked => "blocked",
            ClaimFailure::Allowlist => "allowlist",
            ClaimFailure::SlowMode { .. } => "slow_mode",
            ClaimFailure::Unavailable { .. } => "unavailable",
            ClaimFailure::Internal => "internal",
        }
    }

    /// The human-readable text of the frame.
    fn text(&self) -> &'static str {
        match self {
            ClaimFailure::InvalidList { .. } => "Invalid attachment list",
            ClaimFailure::InvalidPayload => "Invalid base64 encoded data",
            ClaimFailure::Forbidden => "You can't attach files here",
            ClaimFailure::Blocked => "This user has blocked you",
            ClaimFailure::Allowlist => "Build not allowed by Node admin",
            ClaimFailure::SlowMode { .. } => "Slow mode active",
            ClaimFailure::Unavailable { .. } => "One or more attachments are unavailable",
            ClaimFailure::Internal => "The relay could not store the message",
        }
    }

    /// The `attachment_claim_failed` frame for a request whose list was
    /// `requested` and whose envelope `message_id` was `request_id`.
    pub fn frame(&self, requested: &[String], request_id: Uuid) -> Value {
        let mut frame = json!({
            "type": "error",
            "code": CLAIM_FAILED,
            "reason": self.reason(),
            "error": self.text(),
            "request_id": request_id,
        });
        if !matches!(self, ClaimFailure::InvalidList { echo: false }) {
            frame["attachment_ids"] = json!(requested);
        }
        match self {
            ClaimFailure::Unavailable { ids } => {
                let ids: Vec<String> = ids.iter().map(Uuid::to_string).collect();
                frame["unavailable_ids"] = json!(ids);
            }
            ClaimFailure::SlowMode { retry_after } => {
                frame["retry_after"] = json!((*retry_after).max(1));
            }
            _ => {}
        }
        frame
    }
}

/// Validate a request's `attachment_ids` (REQ-35 step 1): at most 10
/// entries, each a lowercase canonical UUID, pairwise distinct. Returns the
/// ids in request order.
pub fn parse_attachment_ids(requested: &[String]) -> Result<Vec<Uuid>, ClaimFailure> {
    if requested.len() > MAX_ATTACHMENTS_PER_MESSAGE
        || requested
            .iter()
            .any(|entry| entry.len() > MAX_ECHOED_ENTRY_BYTES)
    {
        return Err(ClaimFailure::InvalidList { echo: false });
    }
    let mut seen = HashSet::with_capacity(requested.len());
    let mut ids = Vec::with_capacity(requested.len());
    for entry in requested {
        if !is_canonical_uuid(entry) {
            return Err(ClaimFailure::InvalidList { echo: true });
        }
        let id = Uuid::parse_str(entry).map_err(|_| ClaimFailure::InvalidList { echo: true })?;
        if !seen.insert(id) {
            return Err(ClaimFailure::InvalidList { echo: true });
        }
        ids.push(id);
    }
    Ok(ids)
}

/// The `attachments_not_editable` frame (section 6.5.3, REQ-37).
pub fn not_editable_frame(message_id: Uuid, request_id: Uuid) -> Value {
    json!({
        "type": "error",
        "code": NOT_EDITABLE,
        "reason": NOT_EDITABLE,
        "error": NOT_EDITABLE_TEXT,
        "message_id": message_id,
        "request_id": request_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: usize) -> Vec<String> {
        (0..n).map(|_| Uuid::new_v4().to_string()).collect()
    }

    #[test]
    fn valid_lists_keep_their_order() {
        let list = ids(10);
        let parsed = parse_attachment_ids(&list).unwrap();
        assert_eq!(parsed.iter().map(Uuid::to_string).collect::<Vec<_>>(), list);
        assert_eq!(parse_attachment_ids(&ids(1)).unwrap().len(), 1);
    }

    #[test]
    fn invalid_lists_say_whether_they_are_echoed() {
        // Eleven entries, or an entry longer than 36 bytes: not echoed.
        assert_eq!(
            parse_attachment_ids(&ids(11)),
            Err(ClaimFailure::InvalidList { echo: false })
        );
        let mut long = ids(2);
        long[1] = "x".repeat(37);
        assert_eq!(
            parse_attachment_ids(&long),
            Err(ClaimFailure::InvalidList { echo: false })
        );
        // Duplicates, upper case, braces, missing hyphens, junk: echoed.
        let one = Uuid::new_v4().to_string();
        for list in [
            vec![one.clone(), one.clone()],
            vec![one.to_uppercase()],
            vec![one.replace('-', "")],
            vec!["not-a-uuid".to_string()],
            vec![String::new()],
        ] {
            assert_eq!(
                parse_attachment_ids(&list),
                Err(ClaimFailure::InvalidList { echo: true }),
                "{list:?}"
            );
        }
    }

    #[test]
    fn frames_carry_code_reason_ids_and_request_id() {
        let request = Uuid::new_v4();
        let list = ids(2);
        let missing = Uuid::parse_str(&list[1]).unwrap();
        let frame = ClaimFailure::Unavailable { ids: vec![missing] }.frame(&list, request);
        assert_eq!(frame["type"], "error");
        assert_eq!(frame["code"], CLAIM_FAILED);
        assert_eq!(frame["reason"], "unavailable");
        assert_eq!(frame["attachment_ids"], json!(list));
        assert_eq!(frame["unavailable_ids"], json!([list[1]]));
        assert_eq!(frame["request_id"], request.to_string());
        assert!(frame["error"].is_string());

        let frame = ClaimFailure::SlowMode { retry_after: 0 }.frame(&list, request);
        assert_eq!(frame["reason"], "slow_mode");
        assert_eq!(frame["retry_after"], 1);

        let frame = ClaimFailure::InvalidList { echo: false }.frame(&ids(11), request);
        assert_eq!(frame["reason"], "invalid");
        assert!(frame.get("attachment_ids").is_none());

        for (failure, reason) in [
            (ClaimFailure::InvalidList { echo: true }, "invalid"),
            (ClaimFailure::InvalidPayload, "invalid"),
            (ClaimFailure::Forbidden, "forbidden"),
            (ClaimFailure::Blocked, "blocked"),
            (ClaimFailure::Allowlist, "allowlist"),
            (ClaimFailure::Internal, "internal"),
        ] {
            let frame = failure.frame(&list, request);
            assert_eq!(frame["reason"], reason);
            assert_eq!(frame["attachment_ids"], json!(list));
            assert!(frame.get("unavailable_ids").is_none());
            assert!(frame.get("retry_after").is_none());
        }
    }

    #[test]
    fn not_editable_frame_names_the_message() {
        let (message, request) = (Uuid::new_v4(), Uuid::new_v4());
        let frame = not_editable_frame(message, request);
        assert_eq!(frame["type"], "error");
        assert_eq!(frame["code"], NOT_EDITABLE);
        assert_eq!(frame["reason"], NOT_EDITABLE);
        assert_eq!(frame["message_id"], message.to_string());
        assert_eq!(frame["request_id"], request.to_string());
    }
}
