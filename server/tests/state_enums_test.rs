//! Unit tests for pure enum logic in state.rs
//!
//! Tests: MetadataMode, BuildHashEnforcementMode, BuildVerificationMode, BuildVerification

use accord_core::build_hash::{BuildInfo, BuildTrust, KnownBuild};
use accord_server::state::{
    BuildHashEnforcementMode, BuildVerification, BuildVerificationMode, MetadataMode,
};

// ── MetadataMode ─────────────────────────────────────────────────────────────

#[test]
fn metadata_mode_default_is_standard() {
    assert_eq!(MetadataMode::default(), MetadataMode::Standard);
}

#[test]
fn metadata_mode_display_standard() {
    assert_eq!(MetadataMode::Standard.to_string(), "standard");
}

#[test]
fn metadata_mode_display_minimal() {
    assert_eq!(MetadataMode::Minimal.to_string(), "minimal");
}

#[test]
fn metadata_mode_from_str_standard() {
    let m: MetadataMode = "standard".parse().unwrap();
    assert_eq!(m, MetadataMode::Standard);
}

#[test]
fn metadata_mode_from_str_minimal() {
    let m: MetadataMode = "minimal".parse().unwrap();
    assert_eq!(m, MetadataMode::Minimal);
}

#[test]
fn metadata_mode_from_str_case_insensitive() {
    let m: MetadataMode = "STANDARD".parse().unwrap();
    assert_eq!(m, MetadataMode::Standard);
    let m2: MetadataMode = "Minimal".parse().unwrap();
    assert_eq!(m2, MetadataMode::Minimal);
}

#[test]
fn metadata_mode_from_str_unknown_errors() {
    let result: Result<MetadataMode, _> = "verbose".parse();
    assert!(result.is_err());
    let msg = result.unwrap_err();
    assert!(
        msg.contains("unknown metadata mode"),
        "error message should mention 'unknown metadata mode', got: {msg}"
    );
}

#[test]
fn metadata_mode_serde_roundtrip() {
    for mode in [MetadataMode::Standard, MetadataMode::Minimal] {
        let json = serde_json::to_string(&mode).unwrap();
        let decoded: MetadataMode = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, mode);
    }
}

#[test]
fn metadata_mode_serde_lowercase_names() {
    assert_eq!(
        serde_json::to_string(&MetadataMode::Standard).unwrap(),
        r#""standard""#
    );
    assert_eq!(
        serde_json::to_string(&MetadataMode::Minimal).unwrap(),
        r#""minimal""#
    );
}

// ── BuildHashEnforcementMode ──────────────────────────────────────────────────

#[test]
fn build_hash_enforcement_default_is_off() {
    assert_eq!(
        BuildHashEnforcementMode::default(),
        BuildHashEnforcementMode::Off
    );
}

#[test]
fn build_hash_enforcement_display() {
    assert_eq!(BuildHashEnforcementMode::Off.to_string(), "off");
    assert_eq!(BuildHashEnforcementMode::Warn.to_string(), "warn");
    assert_eq!(BuildHashEnforcementMode::Strict.to_string(), "strict");
}

#[test]
fn build_hash_enforcement_from_str_all_variants() {
    assert_eq!(
        "off".parse::<BuildHashEnforcementMode>().unwrap(),
        BuildHashEnforcementMode::Off
    );
    assert_eq!(
        "warn".parse::<BuildHashEnforcementMode>().unwrap(),
        BuildHashEnforcementMode::Warn
    );
    assert_eq!(
        "strict".parse::<BuildHashEnforcementMode>().unwrap(),
        BuildHashEnforcementMode::Strict
    );
}

#[test]
fn build_hash_enforcement_from_str_case_insensitive() {
    assert_eq!(
        "OFF".parse::<BuildHashEnforcementMode>().unwrap(),
        BuildHashEnforcementMode::Off
    );
    assert_eq!(
        "WARN".parse::<BuildHashEnforcementMode>().unwrap(),
        BuildHashEnforcementMode::Warn
    );
    assert_eq!(
        "STRICT".parse::<BuildHashEnforcementMode>().unwrap(),
        BuildHashEnforcementMode::Strict
    );
}

#[test]
fn build_hash_enforcement_from_str_unknown_errors() {
    let result: Result<BuildHashEnforcementMode, _> = "block".parse();
    assert!(result.is_err());
    let msg = result.unwrap_err();
    assert!(
        msg.contains("unknown build-hash-enforcement mode"),
        "got: {msg}"
    );
}

#[test]
fn build_hash_enforcement_serde_roundtrip() {
    for mode in [
        BuildHashEnforcementMode::Off,
        BuildHashEnforcementMode::Warn,
        BuildHashEnforcementMode::Strict,
    ] {
        let json = serde_json::to_string(&mode).unwrap();
        let decoded: BuildHashEnforcementMode = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, mode);
    }
}

#[test]
fn build_hash_enforcement_serde_lowercase_names() {
    assert_eq!(
        serde_json::to_string(&BuildHashEnforcementMode::Off).unwrap(),
        r#""off""#
    );
    assert_eq!(
        serde_json::to_string(&BuildHashEnforcementMode::Warn).unwrap(),
        r#""warn""#
    );
    assert_eq!(
        serde_json::to_string(&BuildHashEnforcementMode::Strict).unwrap(),
        r#""strict""#
    );
}

// ── BuildVerificationMode ─────────────────────────────────────────────────────

#[test]
fn build_verification_mode_default_is_disabled() {
    assert_eq!(
        BuildVerificationMode::default(),
        BuildVerificationMode::Disabled
    );
}

#[test]
fn build_verification_mode_serde_roundtrip() {
    for mode in [
        BuildVerificationMode::Disabled,
        BuildVerificationMode::Warn,
        BuildVerificationMode::Enforce,
    ] {
        let json = serde_json::to_string(&mode).unwrap();
        let decoded: BuildVerificationMode = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, mode);
    }
}

#[test]
fn build_verification_mode_serde_lowercase_names() {
    assert_eq!(
        serde_json::to_string(&BuildVerificationMode::Disabled).unwrap(),
        r#""disabled""#
    );
    assert_eq!(
        serde_json::to_string(&BuildVerificationMode::Warn).unwrap(),
        r#""warn""#
    );
    assert_eq!(
        serde_json::to_string(&BuildVerificationMode::Enforce).unwrap(),
        r#""enforce""#
    );
}

// ── BuildVerification::verify_client_hash ─────────────────────────────────────

/// Construct a `BuildVerification` directly (no file I/O) by using
/// `server_build_info` and an inline `known_hashes` vec.
fn make_bv(known: Vec<KnownBuild>) -> BuildVerification {
    BuildVerification {
        server_build_info: BuildInfo {
            commit_hash: "abc123".into(),
            build_timestamp: "2024-01-01T00:00:00Z".into(),
            target_triple: "x86_64-unknown-linux-gnu".into(),
            build_hash: "deadbeef".into(),
            version: "0.1.0".into(),
        },
        known_hashes: known,
        mode: BuildVerificationMode::Disabled,
    }
}

#[test]
fn verify_client_hash_empty_list_returns_unknown() {
    let bv = make_bv(vec![]);
    assert_eq!(bv.verify_client_hash("anything"), BuildTrust::Unknown);
}

#[test]
fn verify_client_hash_verified() {
    let bv = make_bv(vec![KnownBuild {
        version: "0.1.0".into(),
        platform: "linux".into(),
        hash: "abc123hash".into(),
        revoked: false,
        signature: None,
        signature_timestamp: None,
    }]);
    assert_eq!(bv.verify_client_hash("abc123hash"), BuildTrust::Verified);
}

#[test]
fn verify_client_hash_revoked() {
    let bv = make_bv(vec![KnownBuild {
        version: "0.1.0".into(),
        platform: "linux".into(),
        hash: "oldhash".into(),
        revoked: true,
        signature: None,
        signature_timestamp: None,
    }]);
    assert_eq!(bv.verify_client_hash("oldhash"), BuildTrust::Revoked);
}

#[test]
fn verify_client_hash_unknown_when_not_in_list() {
    let bv = make_bv(vec![KnownBuild {
        version: "0.1.0".into(),
        platform: "linux".into(),
        hash: "knownhash".into(),
        revoked: false,
        signature: None,
        signature_timestamp: None,
    }]);
    assert_eq!(bv.verify_client_hash("differenthash"), BuildTrust::Unknown);
}

#[test]
fn verify_client_hash_case_sensitive() {
    let bv = make_bv(vec![KnownBuild {
        version: "0.1.0".into(),
        platform: "linux".into(),
        hash: "ABCDEF".into(),
        revoked: false,
        signature: None,
        signature_timestamp: None,
    }]);
    // Lowercase version should NOT match — hashes are case-sensitive
    assert_eq!(bv.verify_client_hash("abcdef"), BuildTrust::Unknown);
    // Exact case should match
    assert_eq!(bv.verify_client_hash("ABCDEF"), BuildTrust::Verified);
}

#[test]
fn verify_client_hash_first_match_wins_verified_over_revoked() {
    // Two entries with same hash: one verified, one revoked (shouldn't happen
    // in practice, but the implementation returns on first match)
    let bv = make_bv(vec![
        KnownBuild {
            version: "0.1.0".into(),
            platform: "linux".into(),
            hash: "samehash".into(),
            revoked: false,
            signature: None,
            signature_timestamp: None,
        },
        KnownBuild {
            version: "0.1.0".into(),
            platform: "linux".into(),
            hash: "samehash".into(),
            revoked: true,
            signature: None,
            signature_timestamp: None,
        },
    ]);
    assert_eq!(bv.verify_client_hash("samehash"), BuildTrust::Verified);
}
