//! # Membership Privacy
//!
//! Blinded Node membership tokens that prevent the relay from trivially enumerating
//! all members of a Node or all Nodes a user belongs to.
//!
//! ## Scheme
//!
//! Each Node has a `node_secret` (shared among members via encrypted channels).
//! A membership token is: `SHA-256("accord-membership-v1" || user_pubkey_hash || node_id_hash || node_secret)`.
//!
//! The relay stores only this opaque token. To verify membership (e.g., for message routing),
//! the client presents the token. The relay can check `token ∈ stored_tokens` but cannot:
//! - Given a user, enumerate their Nodes (without knowing each Node's secret)
//! - Given a Node, enumerate its members (without knowing the node_secret)
//!
//! For authorization checks (e.g., "is user X in Node Y?"), the client computes
//! the token client-side and the relay does a simple lookup.

use sha2::{Digest, Sha256};

/// Compute a blinded membership token for a user in a Node.
///
/// - `user_pubkey_hash`: 32-byte hash of the user's public key
/// - `node_id`: 32-byte identifier for the Node (could be SHA-256 of the Node UUID)
/// - `node_secret`: shared secret known only to Node members
pub fn compute_membership_token(
    user_pubkey_hash: &[u8; 32],
    node_id: &[u8; 32],
    node_secret: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"accord-membership-v1");
    hasher.update(user_pubkey_hash);
    hasher.update(node_id);
    hasher.update(node_secret);
    hasher.finalize().into()
}

/// Verify that a membership token is valid for the given user, Node, and secret.
pub fn verify_membership(
    token: &[u8; 32],
    user_pubkey_hash: &[u8; 32],
    node_id: &[u8; 32],
    node_secret: &[u8],
) -> bool {
    let expected = compute_membership_token(user_pubkey_hash, node_id, node_secret);
    // Constant-time comparison
    let mut diff = 0u8;
    for (a, b) in token.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Compute a blinded Node identifier that the relay stores instead of the real Node ID.
/// This is derived from the Node ID and secret, so the relay can't correlate across secrets.
pub fn compute_blinded_node_id(node_id: &[u8; 32], node_secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"accord-blinded-node-v1");
    hasher.update(node_id);
    hasher.update(node_secret);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_id(seed: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        for i in 0..32 {
            id[i] = seed.wrapping_add(i as u8);
        }
        id
    }

    #[test]
    fn deterministic() {
        let user = make_id(1);
        let node = make_id(2);
        let secret = b"node-secret";
        let t1 = compute_membership_token(&user, &node, secret);
        let t2 = compute_membership_token(&user, &node, secret);
        assert_eq!(t1, t2);
    }

    #[test]
    fn verify_correct() {
        let user = make_id(1);
        let node = make_id(2);
        let secret = b"node-secret";
        let token = compute_membership_token(&user, &node, secret);
        assert!(verify_membership(&token, &user, &node, secret));
    }

    #[test]
    fn wrong_secret_rejected() {
        let user = make_id(1);
        let node = make_id(2);
        let token = compute_membership_token(&user, &node, b"correct");
        assert!(!verify_membership(&token, &user, &node, b"wrong"));
    }

    #[test]
    fn wrong_user_rejected() {
        let user = make_id(1);
        let other = make_id(3);
        let node = make_id(2);
        let secret = b"secret";
        let token = compute_membership_token(&user, &node, secret);
        assert!(!verify_membership(&token, &other, &node, secret));
    }

    #[test]
    fn wrong_node_rejected() {
        let user = make_id(1);
        let node = make_id(2);
        let other_node = make_id(4);
        let secret = b"secret";
        let token = compute_membership_token(&user, &node, secret);
        assert!(!verify_membership(&token, &user, &other_node, secret));
    }

    #[test]
    fn different_users_different_tokens() {
        let user1 = make_id(1);
        let user2 = make_id(2);
        let node = make_id(10);
        let secret = b"secret";
        let t1 = compute_membership_token(&user1, &node, secret);
        let t2 = compute_membership_token(&user2, &node, secret);
        assert_ne!(t1, t2);
    }

    #[test]
    fn different_nodes_different_tokens() {
        let user = make_id(1);
        let node1 = make_id(10);
        let node2 = make_id(20);
        let secret = b"secret";
        let t1 = compute_membership_token(&user, &node1, secret);
        let t2 = compute_membership_token(&user, &node2, secret);
        assert_ne!(t1, t2);
    }

    #[test]
    fn blinded_node_id_deterministic() {
        let node = make_id(5);
        let secret = b"secret";
        let b1 = compute_blinded_node_id(&node, secret);
        let b2 = compute_blinded_node_id(&node, secret);
        assert_eq!(b1, b2);
    }

    #[test]
    fn blinded_node_id_different_with_different_secret() {
        let node = make_id(5);
        let b1 = compute_blinded_node_id(&node, b"secret-1");
        let b2 = compute_blinded_node_id(&node, b"secret-2");
        assert_ne!(b1, b2);
    }
}
