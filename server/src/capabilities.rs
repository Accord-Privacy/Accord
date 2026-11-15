//! The relay capability registry (SPEC-01 section 6.8, REQ-42).
//!
//! The relay tells clients what it implements with a `features` array of
//! strings, sent in the WebSocket `hello` frame and in `GET /health`. Each
//! token names a feature and its version. Clients test whether a token is a
//! member of the array, never equality or order, and a missing token always
//! means "not implemented": a client never relaxes a check because a token is
//! absent.
//!
//! This is the single definition for the whole batch. A token is listed in
//! [`RELAY_FEATURES`] only once this relay implements everything its defining
//! requirement ties to it. The registry (SPEC-01 §6.8) is:
//!
//! | Token | Meaning | Defined by | Implemented here |
//! |---|---|---|---|
//! | `admission/1` | Relay admission: invite-only joins, join requests, `expires_in_seconds`, the reason codes of SPEC-01 §6.4; `GET /health` also carries `admission_since` | SPEC-01 REQ-42 | yes |
//! | `attachments/2` | Version-2 attachment routes, claim and limits; `GET /health` also carries `attachment_limits` | SPEC-02 REQ-44 | yes |
//! | `keys-status/1` | `GET /keys/status` | SPEC-04 REQ-42 | no |
//! | `ctl-queue/1` | Non-destructive prekey queue: peek, acknowledge, push | SPEC-04 REQ-42, REQ-43 | no |
//! | `identity/1` | Identity registration, `GET /keys/identity`, `POST /keys/identity/reset` | SPEC-05 REQ-77 | no |
//! | `governance/1` | Governance log, receipts, audience endpoint, node-key queue, routing checks | SPEC-06 REQ-39 | no |
//! | `screen/1` | Encrypted screen-sharing relay path; `hello` and `GET /health` also carry `screen_limits` | SPEC-03 REQ-55, §6.12 | no |
//!
//! Each later relay release adds its own token to [`RELAY_FEATURES`] in the
//! same change that completes the feature, and a new token is added to the
//! table above only by amending SPEC-01 §6.8.

/// Relay admission (SPEC-01): invite-only joins, join requests,
/// `expires_in_seconds` on invite creation, the reason codes of section 6.4,
/// and `admission_since` in `GET /health`.
pub const ADMISSION_V1: &str = "admission/1";

/// Version-2 attachments (SPEC-02): the upload, download and delete routes,
/// the claim in `ChannelMessage` with its error frames, the edit guard, the
/// read-only legacy routes, and `attachment_limits` in `GET /health`.
pub const ATTACHMENTS_V2: &str = "attachments/2";

/// Every token this relay implements, in the order it lists them. Clients
/// must test membership only.
pub const RELAY_FEATURES: &[&str] = &[ADMISSION_V1, ATTACHMENTS_V2];

/// Every token the batch registry defines (SPEC-01 §6.8). A token outside
/// this list must never be advertised.
pub const REGISTERED_TOKENS: &[&str] = &[
    ADMISSION_V1,
    ATTACHMENTS_V2,
    "keys-status/1",
    "ctl-queue/1",
    "identity/1",
    "governance/1",
    "screen/1",
];

/// The `features` array of `hello` and `GET /health`.
pub fn relay_features() -> Vec<String> {
    RELAY_FEATURES.iter().map(|t| (*t).to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertises_admission_and_attachments() {
        assert_eq!(
            relay_features(),
            vec!["admission/1".to_string(), "attachments/2".to_string()]
        );
    }

    #[test]
    fn every_advertised_token_is_registered() {
        for token in RELAY_FEATURES {
            assert!(
                REGISTERED_TOKENS.contains(token),
                "{token} is not registered"
            );
        }
    }

    #[test]
    fn unimplemented_tokens_are_not_advertised() {
        // SPEC-03's screen-sharing path, and the other batch specs' relay
        // parts, have not landed on this relay.
        for token in [
            "screen/1",
            "keys-status/1",
            "ctl-queue/1",
            "identity/1",
            "governance/1",
        ] {
            assert!(!RELAY_FEATURES.contains(&token), "{token} is advertised");
        }
    }
}
