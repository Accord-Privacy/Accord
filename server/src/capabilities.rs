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
//! | `screen/1` | Encrypted screen-sharing relay path; `hello` and `GET /health` also carry `screen_limits` | SPEC-03 REQ-55, §6.12 | yes, unless the operator turns screen sharing off |
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

/// The encrypted screen-sharing relay path (SPEC-03 §6.12, REQ-55): the
/// four JSON arms, the binary `SCREEN_UP` and `SCREEN_DOWN` messages and the
/// per-connection screen queue, with `screen_limits` in `hello` and
/// `GET /health`. Advertised only while the operator has screen sharing on
/// (`--screen-share on`, the default). A relay that lists it also implements
/// the P2P retirement of SPEC-03 §6.14 (REQ-56), which this relay applies
/// whatever the screen-sharing setting.
pub const SCREEN_V1: &str = "screen/1";

/// Every token this relay implements, in the order it lists them. Clients
/// must test membership only. [`SCREEN_V1`] is left out of the advertised
/// array while screen sharing is off ([`relay_features`]).
pub const RELAY_FEATURES: &[&str] = &[ADMISSION_V1, ATTACHMENTS_V2, SCREEN_V1];

/// Every token the batch registry defines (SPEC-01 §6.8). A token outside
/// this list must never be advertised.
pub const REGISTERED_TOKENS: &[&str] = &[
    ADMISSION_V1,
    ATTACHMENTS_V2,
    "keys-status/1",
    "ctl-queue/1",
    "identity/1",
    "governance/1",
    SCREEN_V1,
];

/// The `features` array of `hello` and `GET /health`: every implemented
/// token, without [`SCREEN_V1`] when the operator has screen sharing off.
pub fn relay_features(screen_enabled: bool) -> Vec<String> {
    RELAY_FEATURES
        .iter()
        .filter(|token| screen_enabled || **token != SCREEN_V1)
        .map(|t| (*t).to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertises_admission_attachments_and_screen() {
        assert_eq!(
            relay_features(true),
            vec![
                "admission/1".to_string(),
                "attachments/2".to_string(),
                "screen/1".to_string()
            ]
        );
    }

    #[test]
    fn screen_sharing_off_removes_only_screen() {
        assert_eq!(
            relay_features(false),
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
        // The other batch specs' relay parts have not landed on this relay.
        for token in ["keys-status/1", "ctl-queue/1", "identity/1", "governance/1"] {
            assert!(!RELAY_FEATURES.contains(&token), "{token} is advertised");
        }
    }
}
