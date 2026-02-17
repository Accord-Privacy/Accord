//! # Session Manager
//!
//! Manages Double Ratchet sessions per (user, channel) pair.
//! Provides a high-level API for initiating sessions, encrypting, and decrypting messages.

use crate::double_ratchet::{
    x3dh_initiate, x3dh_respond, DoubleRatchetMessage, DoubleRatchetSession, IdentityKeyPair,
    OneTimePreKeyPair, PreKeyBundle, SignedPreKeyPair,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Serializable key bundle for publishing to the server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublishableKeyBundle {
    pub identity_key: [u8; 32],
    pub signed_prekey: [u8; 32],
    pub one_time_prekeys: Vec<[u8; 32]>,
}

/// Initial message sent from Alice to Bob to establish a session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct X3DHInitialMessage {
    /// Alice's identity public key.
    pub identity_key: [u8; 32],
    /// Alice's ephemeral public key used in X3DH.
    pub ephemeral_key: [u8; 32],
    /// Which one-time prekey was used (if any).
    pub one_time_prekey_used: Option<[u8; 32]>,
    /// The first Double Ratchet message (encrypted with the new session).
    pub initial_ratchet_message: DoubleRatchetMessage,
}

/// A serializable session identifier: (peer_user_id, channel_id).
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionId {
    pub peer_user_id: String,
    pub channel_id: String,
}

/// Local key material for the current user.
pub struct LocalKeyMaterial {
    pub identity: IdentityKeyPair,
    pub signed_prekey: SignedPreKeyPair,
    pub one_time_prekeys: Vec<OneTimePreKeyPair>,
}

impl LocalKeyMaterial {
    /// Generate fresh key material with the specified number of one-time prekeys.
    pub fn generate(num_one_time_prekeys: usize) -> Self {
        let identity = IdentityKeyPair::generate();
        let signed_prekey = SignedPreKeyPair::generate();
        let one_time_prekeys = (0..num_one_time_prekeys)
            .map(|_| OneTimePreKeyPair::generate())
            .collect();
        Self {
            identity,
            signed_prekey,
            one_time_prekeys,
        }
    }

    /// Build a publishable key bundle from local key material.
    pub fn to_publishable_bundle(&self) -> PublishableKeyBundle {
        PublishableKeyBundle {
            identity_key: self.identity.public.to_bytes(),
            signed_prekey: self.signed_prekey.public.to_bytes(),
            one_time_prekeys: self
                .one_time_prekeys
                .iter()
                .map(|opk| opk.public.to_bytes())
                .collect(),
        }
    }

    /// Consume a one-time prekey by its public key, returning the keypair.
    pub fn consume_one_time_prekey(&mut self, public_key: &[u8; 32]) -> Option<OneTimePreKeyPair> {
        if let Some(pos) = self
            .one_time_prekeys
            .iter()
            .position(|opk| opk.public.to_bytes() == *public_key)
        {
            Some(self.one_time_prekeys.remove(pos))
        } else {
            None
        }
    }
}

/// Manages Double Ratchet sessions for a user.
pub struct SessionManager {
    /// Active sessions keyed by (peer, channel).
    sessions: HashMap<SessionId, DoubleRatchetSession>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Check if a session exists for the given peer/channel.
    pub fn has_session(&self, session_id: &SessionId) -> bool {
        self.sessions.contains_key(session_id)
    }

    /// Initiate a new session with a remote user (Alice's side).
    ///
    /// Returns the X3DH initial message to send to the peer, with the first
    /// encrypted message embedded.
    pub fn initiate_session(
        &mut self,
        local_keys: &LocalKeyMaterial,
        their_bundle: &PreKeyBundle,
        session_id: SessionId,
        first_plaintext: &[u8],
    ) -> Result<X3DHInitialMessage> {
        let x3dh_out =
            x3dh_initiate(&local_keys.identity, their_bundle).context("X3DH initiation failed")?;

        let mut session =
            DoubleRatchetSession::init_alice(x3dh_out.shared_secret, their_bundle.signed_prekey)
                .context("Failed to initialize Alice session")?;

        let initial_msg = session
            .encrypt(first_plaintext)
            .context("Failed to encrypt initial message")?;

        self.sessions.insert(session_id, session);

        Ok(X3DHInitialMessage {
            identity_key: local_keys.identity.public.to_bytes(),
            ephemeral_key: x3dh_out.ephemeral_public.to_bytes(),
            one_time_prekey_used: their_bundle.one_time_prekey,
            initial_ratchet_message: initial_msg,
        })
    }

    /// Receive an initial X3DH message and establish a session (Bob's side).
    ///
    /// Returns the decrypted first message.
    pub fn receive_initial_message(
        &mut self,
        local_keys: &mut LocalKeyMaterial,
        initial_msg: &X3DHInitialMessage,
        session_id: SessionId,
    ) -> Result<Vec<u8>> {
        let opk = initial_msg
            .one_time_prekey_used
            .as_ref()
            .and_then(|pk| local_keys.consume_one_time_prekey(pk));

        let shared_secret = x3dh_respond(
            &local_keys.identity,
            &local_keys.signed_prekey,
            opk.as_ref(),
            initial_msg.identity_key,
            initial_msg.ephemeral_key,
        )
        .context("X3DH response failed")?;

        let mut session =
            DoubleRatchetSession::init_bob(shared_secret, local_keys.signed_prekey.secret.clone());

        let plaintext = session
            .decrypt(&initial_msg.initial_ratchet_message)
            .context("Failed to decrypt initial message")?;

        self.sessions.insert(session_id, session);

        Ok(plaintext)
    }

    /// Encrypt a message for an established session.
    pub fn encrypt_message(
        &mut self,
        session_id: &SessionId,
        plaintext: &[u8],
    ) -> Result<DoubleRatchetMessage> {
        let session = self
            .sessions
            .get_mut(session_id)
            .context("No session found for this peer/channel")?;
        session.encrypt(plaintext)
    }

    /// Decrypt a message from an established session.
    pub fn decrypt_message(
        &mut self,
        session_id: &SessionId,
        message: &DoubleRatchetMessage,
    ) -> Result<Vec<u8>> {
        let session = self
            .sessions
            .get_mut(session_id)
            .context("No session found for this peer/channel")?;
        session.decrypt(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_manager_full_flow() {
        // Alice and Bob generate key material
        let alice_keys = LocalKeyMaterial::generate(5);
        let mut bob_keys = LocalKeyMaterial::generate(5);

        let bob_bundle = PreKeyBundle {
            identity_key: bob_keys.identity.public.to_bytes(),
            signed_prekey: bob_keys.signed_prekey.public.to_bytes(),
            one_time_prekey: Some(bob_keys.one_time_prekeys[0].public.to_bytes()),
        };

        let session_id = SessionId {
            peer_user_id: "bob".to_string(),
            channel_id: "general".to_string(),
        };

        let bob_session_id = SessionId {
            peer_user_id: "alice".to_string(),
            channel_id: "general".to_string(),
        };

        // Alice initiates session
        let mut alice_mgr = SessionManager::new();
        let initial_msg = alice_mgr
            .initiate_session(&alice_keys, &bob_bundle, session_id.clone(), b"Hello Bob!")
            .unwrap();

        // Bob receives initial message
        let mut bob_mgr = SessionManager::new();
        let decrypted = bob_mgr
            .receive_initial_message(&mut bob_keys, &initial_msg, bob_session_id.clone())
            .unwrap();
        assert_eq!(decrypted, b"Hello Bob!");

        // Bob replies
        let bob_msg = bob_mgr
            .encrypt_message(&bob_session_id, b"Hello Alice!")
            .unwrap();
        let decrypted = alice_mgr.decrypt_message(&session_id, &bob_msg).unwrap();
        assert_eq!(decrypted, b"Hello Alice!");

        // Alice sends another message
        let alice_msg = alice_mgr
            .encrypt_message(&session_id, b"How are you?")
            .unwrap();
        let decrypted = bob_mgr
            .decrypt_message(&bob_session_id, &alice_msg)
            .unwrap();
        assert_eq!(decrypted, b"How are you?");
    }

    #[test]
    fn test_publishable_key_bundle() {
        let keys = LocalKeyMaterial::generate(3);
        let bundle = keys.to_publishable_bundle();
        assert_eq!(bundle.one_time_prekeys.len(), 3);
        assert_eq!(bundle.identity_key, keys.identity.public.to_bytes());
        assert_eq!(bundle.signed_prekey, keys.signed_prekey.public.to_bytes());
    }

    #[test]
    fn test_session_manager_without_one_time_prekey() {
        let alice_keys = LocalKeyMaterial::generate(0);
        let mut bob_keys = LocalKeyMaterial::generate(0);

        let bob_bundle = PreKeyBundle {
            identity_key: bob_keys.identity.public.to_bytes(),
            signed_prekey: bob_keys.signed_prekey.public.to_bytes(),
            one_time_prekey: None,
        };

        let session_id = SessionId {
            peer_user_id: "bob".to_string(),
            channel_id: "general".to_string(),
        };
        let bob_session_id = SessionId {
            peer_user_id: "alice".to_string(),
            channel_id: "general".to_string(),
        };

        let mut alice_mgr = SessionManager::new();
        let initial_msg = alice_mgr
            .initiate_session(&alice_keys, &bob_bundle, session_id.clone(), b"No OPK!")
            .unwrap();

        let mut bob_mgr = SessionManager::new();
        let decrypted = bob_mgr
            .receive_initial_message(&mut bob_keys, &initial_msg, bob_session_id.clone())
            .unwrap();
        assert_eq!(decrypted, b"No OPK!");
    }

    #[test]
    fn test_multiple_messages_after_session_establishment() {
        let alice_keys = LocalKeyMaterial::generate(1);
        let mut bob_keys = LocalKeyMaterial::generate(1);

        let bob_bundle = PreKeyBundle {
            identity_key: bob_keys.identity.public.to_bytes(),
            signed_prekey: bob_keys.signed_prekey.public.to_bytes(),
            one_time_prekey: Some(bob_keys.one_time_prekeys[0].public.to_bytes()),
        };

        let sid_a = SessionId {
            peer_user_id: "bob".to_string(),
            channel_id: "ch".to_string(),
        };
        let sid_b = SessionId {
            peer_user_id: "alice".to_string(),
            channel_id: "ch".to_string(),
        };

        let mut alice_mgr = SessionManager::new();
        let initial = alice_mgr
            .initiate_session(&alice_keys, &bob_bundle, sid_a.clone(), b"msg1")
            .unwrap();

        let mut bob_mgr = SessionManager::new();
        let dec = bob_mgr
            .receive_initial_message(&mut bob_keys, &initial, sid_b.clone())
            .unwrap();
        assert_eq!(dec, b"msg1");

        // Send 10 alternating messages
        for i in 0..10 {
            if i % 2 == 0 {
                let msg = bob_mgr
                    .encrypt_message(&sid_b, format!("bob-{i}").as_bytes())
                    .unwrap();
                let dec = alice_mgr.decrypt_message(&sid_a, &msg).unwrap();
                assert_eq!(dec, format!("bob-{i}").as_bytes());
            } else {
                let msg = alice_mgr
                    .encrypt_message(&sid_a, format!("alice-{i}").as_bytes())
                    .unwrap();
                let dec = bob_mgr.decrypt_message(&sid_b, &msg).unwrap();
                assert_eq!(dec, format!("alice-{i}").as_bytes());
            }
        }
    }
}
