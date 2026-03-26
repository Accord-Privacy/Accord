//! Unit tests for node.rs — NodeRole enum

use accord_server::node::NodeRole;

// ── as_str ────────────────────────────────────────────────────────────────────

#[test]
fn node_role_as_str_admin() {
    assert_eq!(NodeRole::Admin.as_str(), "admin");
}

#[test]
fn node_role_as_str_moderator() {
    assert_eq!(NodeRole::Moderator.as_str(), "moderator");
}

#[test]
fn node_role_as_str_member() {
    assert_eq!(NodeRole::Member.as_str(), "member");
}

// ── from_str ──────────────────────────────────────────────────────────────────

#[test]
fn node_role_from_str_admin() {
    assert_eq!(NodeRole::from_str("admin"), Some(NodeRole::Admin));
}

#[test]
fn node_role_from_str_moderator() {
    assert_eq!(NodeRole::from_str("moderator"), Some(NodeRole::Moderator));
}

#[test]
fn node_role_from_str_member() {
    assert_eq!(NodeRole::from_str("member"), Some(NodeRole::Member));
}

#[test]
fn node_role_from_str_unknown_returns_none() {
    assert_eq!(NodeRole::from_str("superadmin"), None);
    assert_eq!(NodeRole::from_str(""), None);
    assert_eq!(NodeRole::from_str("Admin"), None); // case-sensitive
}

// ── roundtrip ─────────────────────────────────────────────────────────────────

#[test]
fn node_role_as_str_from_str_roundtrip() {
    for role in [NodeRole::Admin, NodeRole::Moderator, NodeRole::Member] {
        let s = role.as_str();
        let parsed = NodeRole::from_str(s).expect("should round-trip");
        assert_eq!(parsed, role, "round-trip failed for {s}");
    }
}

// ── serde ─────────────────────────────────────────────────────────────────────

#[test]
fn node_role_serde_roundtrip() {
    for role in [NodeRole::Admin, NodeRole::Moderator, NodeRole::Member] {
        let json = serde_json::to_string(&role).unwrap();
        let decoded: NodeRole = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, role);
    }
}

#[test]
fn node_role_serde_lowercase_names() {
    assert_eq!(
        serde_json::to_string(&NodeRole::Admin).unwrap(),
        r#""admin""#
    );
    assert_eq!(
        serde_json::to_string(&NodeRole::Moderator).unwrap(),
        r#""moderator""#
    );
    assert_eq!(
        serde_json::to_string(&NodeRole::Member).unwrap(),
        r#""member""#
    );
}
