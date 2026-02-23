//! # Friendship Privacy
//!
//! Privacy-preserving friendship tokens that hide the social graph from the relay.
//!
//! Instead of storing `(user_a_id, user_b_id)` pairs in plaintext, clients compute
//! a one-way token: `SHA-256(sorted(user_a_pubkey_hash, user_b_pubkey_hash) || shared_secret)`.
//! The relay stores only this opaque token and can verify a friendship exists when both
//! parties present the same token, but cannot enumerate a user's friends without knowing
//! the shared secret.

use sha2::{Digest, Sha256};

/// Compute a deterministic, order-independent friendship token.
///
/// The token is `SHA-256(min(a, b) || max(a, b) || shared_secret)` where the ordering
/// is lexicographic over the raw 32-byte arrays. This ensures `compute(a, b, s) == compute(b, a, s)`.
pub fn compute_friendship_token(
    user_a: &[u8; 32],
    user_b: &[u8; 32],
    shared_secret: &[u8],
) -> [u8; 32] {
    let (first, second) = if user_a <= user_b {
        (user_a, user_b)
    } else {
        (user_b, user_a)
    };

    let mut hasher = Sha256::new();
    hasher.update(b"accord-friendship-token-v1");
    hasher.update(first);
    hasher.update(second);
    hasher.update(shared_secret);
    hasher.finalize().into()
}

/// Verify that a token matches the friendship between two users with the given shared secret.
pub fn verify_friendship(
    token: &[u8; 32],
    user_a: &[u8; 32],
    user_b: &[u8; 32],
    shared_secret: &[u8],
) -> bool {
    let expected = compute_friendship_token(user_a, user_b, shared_secret);
    // Constant-time comparison to prevent timing attacks
    // Constant-time comparison
    let mut diff = 0u8;
    for (a, b) in token.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(seed: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = seed;
        // Fill with deterministic pattern
        for (i, byte) in k.iter_mut().enumerate().skip(1) {
            *byte = seed.wrapping_add(i as u8);
        }
        k
    }

    #[test]
    fn deterministic() {
        let a = make_key(1);
        let b = make_key(2);
        let secret = b"test-secret";
        let t1 = compute_friendship_token(&a, &b, secret);
        let t2 = compute_friendship_token(&a, &b, secret);
        assert_eq!(t1, t2);
    }

    #[test]
    fn order_independent() {
        let a = make_key(1);
        let b = make_key(2);
        let secret = b"test-secret";
        let t_ab = compute_friendship_token(&a, &b, secret);
        let t_ba = compute_friendship_token(&b, &a, secret);
        assert_eq!(t_ab, t_ba);
    }

    #[test]
    fn verify_correct() {
        let a = make_key(1);
        let b = make_key(2);
        let secret = b"my-secret";
        let token = compute_friendship_token(&a, &b, secret);
        assert!(verify_friendship(&token, &a, &b, secret));
        assert!(verify_friendship(&token, &b, &a, secret));
    }

    #[test]
    fn wrong_secret_rejected() {
        let a = make_key(1);
        let b = make_key(2);
        let token = compute_friendship_token(&a, &b, b"correct");
        assert!(!verify_friendship(&token, &a, &b, b"wrong"));
    }

    #[test]
    fn wrong_users_rejected() {
        let a = make_key(1);
        let b = make_key(2);
        let c = make_key(3);
        let secret = b"secret";
        let token = compute_friendship_token(&a, &b, secret);
        assert!(!verify_friendship(&token, &a, &c, secret));
        assert!(!verify_friendship(&token, &c, &b, secret));
    }

    #[test]
    fn different_secrets_produce_different_tokens() {
        let a = make_key(1);
        let b = make_key(2);
        let t1 = compute_friendship_token(&a, &b, b"secret-1");
        let t2 = compute_friendship_token(&a, &b, b"secret-2");
        assert_ne!(t1, t2);
    }

    #[test]
    fn different_pairs_produce_different_tokens() {
        let a = make_key(1);
        let b = make_key(2);
        let c = make_key(3);
        let secret = b"same-secret";
        let t_ab = compute_friendship_token(&a, &b, secret);
        let t_ac = compute_friendship_token(&a, &c, secret);
        assert_ne!(t_ab, t_ac);
    }
}
