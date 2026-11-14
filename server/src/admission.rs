//! Relay admission control (SPEC-01): the reserved DM system node and user,
//! and the credential predicates that keep password-less accounts locked.
//!
//! The reserved-id predicates and `is_unusable_password_hash` are defined here
//! once (SPEC-01 REQ-1, REQ-6); every check that needs them calls these
//! functions instead of comparing names or testing for an empty string.

use crate::db::{DM_SYSTEM_NODE_ID, DM_SYSTEM_USER_ID};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use std::sync::OnceLock;
use uuid::Uuid;

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
