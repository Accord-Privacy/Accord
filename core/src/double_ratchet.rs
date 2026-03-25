//! # Double Ratchet Protocol Implementation
//!
//! Full Signal-style Double Ratchet with:
//! - DH ratchet (X25519 ephemeral key rotation)
//! - Symmetric ratchet (separate sending/receiving chains)
//! - Out-of-order message handling (skipped message keys)
//! - X3DH-style session initialization
//!
//! Reference: <https://signal.org/docs/specifications/doubleratchet/>

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use std::collections::HashMap;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use anyhow::{Context, Result};

/// Maximum number of skipped message keys to store per chain.
const MAX_SKIP: u32 = 100;

/// Info strings for HKDF derivations.
const KDF_RK_INFO: &[u8] = b"accord-double-ratchet-root-v2";
const KDF_CK_MSG_INFO: &[u8] = b"accord-double-ratchet-msg-v2";
const KDF_CK_CHAIN_INFO: &[u8] = b"accord-double-ratchet-chain-v2";

// ─── Key types ───────────────────────────────────────────────────────────────

/// A 32-byte secret that zeroizes on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes([u8; 32]);

impl SecretBytes {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

// ─── Message header ──────────────────────────────────────────────────────────

/// Unencrypted header sent with each message.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MessageHeader {
    /// Sender's current DH ratchet public key.
    pub dh_public_key: [u8; 32],
    /// Number of messages in the previous sending chain.
    pub previous_chain_length: u32,
    /// Message number in the current sending chain.
    pub message_number: u32,
}

/// A complete encrypted message (header + ciphertext).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DoubleRatchetMessage {
    pub header: MessageHeader,
    /// 12-byte nonce ++ AES-GCM ciphertext (with tag).
    pub ciphertext: Vec<u8>,
}

// ─── X3DH key bundles ────────────────────────────────────────────────────────

/// Long-term identity key pair.
#[derive(Clone)]
pub struct IdentityKeyPair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl IdentityKeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

/// Signed pre-key (we skip actual signature verification for brevity).
#[derive(Clone)]
pub struct SignedPreKeyPair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl SignedPreKeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

/// One-time pre-key.
#[derive(Clone)]
pub struct OneTimePreKeyPair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl OneTimePreKeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

/// Published pre-key bundle (what the server stores for Bob).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PreKeyBundle {
    pub identity_key: [u8; 32],
    pub signed_prekey: [u8; 32],
    pub one_time_prekey: Option<[u8; 32]>,
}

/// Output of an X3DH key agreement.
pub struct X3DHOutput {
    pub shared_secret: SecretBytes,
    /// Alice's ephemeral public key (sent to Bob so he can complete X3DH).
    pub ephemeral_public: PublicKey,
}

// ─── X3DH ────────────────────────────────────────────────────────────────────

/// Perform X3DH as the initiator (Alice).
///
/// Computes SK = KDF(DH1 || DH2 || DH3 [|| DH4]) where:
///   DH1 = DH(IK_A, SPK_B)
///   DH2 = DH(EK_A, IK_B)
///   DH3 = DH(EK_A, SPK_B)
///   DH4 = DH(EK_A, OPK_B)  (if one-time prekey available)
pub fn x3dh_initiate(
    our_identity: &IdentityKeyPair,
    their_bundle: &PreKeyBundle,
) -> Result<X3DHOutput> {
    let ek_secret = StaticSecret::random_from_rng(OsRng);
    let ek_public = PublicKey::from(&ek_secret);

    let ik_b = PublicKey::from(their_bundle.identity_key);
    let spk_b = PublicKey::from(their_bundle.signed_prekey);

    let dh1 = our_identity.secret.diffie_hellman(&spk_b);
    let dh2 = ek_secret.diffie_hellman(&ik_b);
    let dh3 = ek_secret.diffie_hellman(&spk_b);

    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());

    if let Some(opk_bytes) = their_bundle.one_time_prekey {
        let opk_b = PublicKey::from(opk_bytes);
        let dh4 = ek_secret.diffie_hellman(&opk_b);
        ikm.extend_from_slice(dh4.as_bytes());
    }

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut sk = [0u8; 32];
    hk.expand(b"accord-x3dh-v1", &mut sk)
        .map_err(|_| anyhow::anyhow!("X3DH HKDF expand failed"))?;

    // Zeroize intermediate key material
    ikm.zeroize();

    Ok(X3DHOutput {
        shared_secret: SecretBytes::new(sk),
        ephemeral_public: ek_public,
    })
}

/// Perform X3DH as the responder (Bob).
pub fn x3dh_respond(
    our_identity: &IdentityKeyPair,
    our_signed_prekey: &SignedPreKeyPair,
    our_one_time_prekey: Option<&OneTimePreKeyPair>,
    their_identity_key: [u8; 32],
    their_ephemeral_key: [u8; 32],
) -> Result<SecretBytes> {
    let ik_a = PublicKey::from(their_identity_key);
    let ek_a = PublicKey::from(their_ephemeral_key);

    let dh1 = our_signed_prekey.secret.diffie_hellman(&ik_a);
    let dh2 = our_identity.secret.diffie_hellman(&ek_a);
    let dh3 = our_signed_prekey.secret.diffie_hellman(&ek_a);

    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());

    if let Some(opk) = our_one_time_prekey {
        let dh4 = opk.secret.diffie_hellman(&ek_a);
        ikm.extend_from_slice(dh4.as_bytes());
    }

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut sk = [0u8; 32];
    hk.expand(b"accord-x3dh-v1", &mut sk)
        .map_err(|_| anyhow::anyhow!("X3DH HKDF expand failed"))?;

    ikm.zeroize();

    Ok(SecretBytes::new(sk))
}

// ─── Double Ratchet session ──────────────────────────────────────────────────

/// Key for looking up skipped message keys: (DH public key, message number).
type SkippedKey = ([u8; 32], u32);

/// A Double Ratchet session between two parties.
pub struct DoubleRatchetSession {
    /// Our current DH ratchet key pair (secret).
    dh_secret: StaticSecret,
    /// Our current DH ratchet public key.
    dh_public: PublicKey,
    /// Their current DH ratchet public key.
    dh_remote: Option<PublicKey>,
    /// Root key.
    root_key: SecretBytes,
    /// Sending chain key.
    chain_key_send: Option<SecretBytes>,
    /// Receiving chain key.
    chain_key_recv: Option<SecretBytes>,
    /// Number of messages sent in current sending chain.
    send_n: u32,
    /// Number of messages received in current receiving chain.
    recv_n: u32,
    /// Number of messages in previous sending chain (sent in header).
    previous_chain_length: u32,
    /// Stored skipped message keys for out-of-order decryption.
    skipped_keys: HashMap<SkippedKey, SecretBytes>,
}

impl DoubleRatchetSession {
    /// Initialize as the session initiator (Alice).
    ///
    /// Alice has already completed X3DH and knows the shared secret and Bob's
    /// signed prekey (used as Bob's initial ratchet public key).
    pub fn init_alice(shared_secret: SecretBytes, bob_ratchet_pub: [u8; 32]) -> Result<Self> {
        let dh_secret = StaticSecret::random_from_rng(OsRng);
        let dh_public = PublicKey::from(&dh_secret);
        let bob_pub = PublicKey::from(bob_ratchet_pub);

        // Perform initial DH ratchet step
        let dh_output = dh_secret.diffie_hellman(&bob_pub);
        let (new_root_key, chain_key_send) = kdf_rk(&shared_secret, dh_output.as_bytes())?;

        Ok(Self {
            dh_secret,
            dh_public,
            dh_remote: Some(bob_pub),
            root_key: new_root_key,
            chain_key_send: Some(chain_key_send),
            chain_key_recv: None,
            send_n: 0,
            recv_n: 0,
            previous_chain_length: 0,
            skipped_keys: HashMap::new(),
        })
    }

    /// Initialize as the session responder (Bob).
    ///
    /// Bob uses his signed prekey as the initial ratchet key pair and waits
    /// for Alice's first message to complete the DH ratchet.
    pub fn init_bob(shared_secret: SecretBytes, our_signed_prekey: StaticSecret) -> Self {
        let dh_public = PublicKey::from(&our_signed_prekey);
        Self {
            dh_secret: our_signed_prekey,
            dh_public,
            dh_remote: None,
            root_key: shared_secret,
            chain_key_send: None,
            chain_key_recv: None,
            send_n: 0,
            recv_n: 0,
            previous_chain_length: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Encrypt a plaintext message, advancing the sending chain.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<DoubleRatchetMessage> {
        let ck = self
            .chain_key_send
            .as_mut()
            .context("No sending chain key")?;
        let (new_ck, mk) = kdf_ck(ck)?;
        *ck = new_ck;

        let header = MessageHeader {
            dh_public_key: self.dh_public.to_bytes(),
            previous_chain_length: self.previous_chain_length,
            message_number: self.send_n,
        };

        let ciphertext = aes_gcm_encrypt(mk.as_bytes(), plaintext, &header)?;

        self.send_n += 1;

        Ok(DoubleRatchetMessage { header, ciphertext })
    }

    /// Decrypt a received message, performing DH ratchet if needed.
    pub fn decrypt(&mut self, msg: &DoubleRatchetMessage) -> Result<Vec<u8>> {
        // Try skipped keys first
        let skip_key = (msg.header.dh_public_key, msg.header.message_number);
        if let Some(mk) = self.skipped_keys.remove(&skip_key) {
            return aes_gcm_decrypt(mk.as_bytes(), &msg.ciphertext, &msg.header);
        }

        let their_pub = PublicKey::from(msg.header.dh_public_key);

        // Check if we need a DH ratchet step
        let need_dh_ratchet = match &self.dh_remote {
            Some(current) => current.as_bytes() != their_pub.as_bytes(),
            None => true,
        };

        if need_dh_ratchet {
            // Skip any remaining messages in the current receiving chain
            if self.chain_key_recv.is_some() {
                self.skip_message_keys(msg.header.previous_chain_length)?;
            }

            // DH ratchet step: receiving
            let dh_output = self.dh_secret.diffie_hellman(&their_pub);
            let (new_root, new_ck_recv) = kdf_rk(&self.root_key, dh_output.as_bytes())?;
            self.root_key = new_root;
            self.chain_key_recv = Some(new_ck_recv);
            self.dh_remote = Some(their_pub);
            self.recv_n = 0;

            // DH ratchet step: sending (generate new key pair)
            self.previous_chain_length = self.send_n;
            self.send_n = 0;
            let new_secret = StaticSecret::random_from_rng(OsRng);
            self.dh_public = PublicKey::from(&new_secret);
            self.dh_secret = new_secret;

            let dh_output2 = self.dh_secret.diffie_hellman(&self.dh_remote.unwrap());
            let (new_root2, new_ck_send) = kdf_rk(&self.root_key, dh_output2.as_bytes())?;
            self.root_key = new_root2;
            self.chain_key_send = Some(new_ck_send);
        }

        // Skip any messages before this one in the current chain
        self.skip_message_keys(msg.header.message_number)?;

        // Derive the message key
        let ck = self
            .chain_key_recv
            .as_mut()
            .context("No receiving chain key")?;
        let (new_ck, mk) = kdf_ck(ck)?;
        *ck = new_ck;
        self.recv_n += 1;

        aes_gcm_decrypt(mk.as_bytes(), &msg.ciphertext, &msg.header)
    }

    /// Store skipped message keys up to `until` message number.
    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        if let Some(ck) = &self.chain_key_recv {
            if until.saturating_sub(self.recv_n) > MAX_SKIP {
                return Err(anyhow::anyhow!(
                    "Too many skipped messages ({})",
                    until - self.recv_n
                ));
            }

            let dh_pub_bytes = self.dh_remote.map(|k| k.to_bytes()).unwrap_or([0u8; 32]);

            let mut ck = ck.clone();
            while self.recv_n < until {
                let (new_ck, mk) = kdf_ck(&ck)?;
                ck = new_ck;
                self.skipped_keys.insert((dh_pub_bytes, self.recv_n), mk);
                self.recv_n += 1;

                // Evict oldest if over limit
                if self.skipped_keys.len() > MAX_SKIP as usize {
                    if let Some(&key) = self.skipped_keys.keys().next() {
                        self.skipped_keys.remove(&key);
                    }
                }
            }
            self.chain_key_recv = Some(ck);
        }
        Ok(())
    }

    /// Get our current ratchet public key (useful for debugging / protocol).
    pub fn our_public_key(&self) -> [u8; 32] {
        self.dh_public.to_bytes()
    }
}

// ─── KDF functions ───────────────────────────────────────────────────────────

/// Root key KDF: (root_key, dh_output) -> (new_root_key, chain_key)
fn kdf_rk(root_key: &SecretBytes, dh_output: &[u8]) -> Result<(SecretBytes, SecretBytes)> {
    let hk = Hkdf::<Sha256>::new(Some(root_key.as_bytes()), dh_output);
    let mut new_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    hk.expand(KDF_RK_INFO, &mut new_rk)
        .map_err(|_| anyhow::anyhow!("HKDF-RK expand failed"))?;
    // Use different info for chain key
    hk.expand(b"accord-double-ratchet-ck-v2", &mut ck)
        .map_err(|_| anyhow::anyhow!("HKDF-RK chain expand failed"))?;
    Ok((SecretBytes::new(new_rk), SecretBytes::new(ck)))
}

/// Chain key KDF: chain_key -> (new_chain_key, message_key)
fn kdf_ck(chain_key: &SecretBytes) -> Result<(SecretBytes, SecretBytes)> {
    let hk = Hkdf::<Sha256>::new(None, chain_key.as_bytes());
    let mut new_ck = [0u8; 32];
    let mut mk = [0u8; 32];
    hk.expand(KDF_CK_CHAIN_INFO, &mut new_ck)
        .map_err(|_| anyhow::anyhow!("HKDF-CK chain expand failed"))?;
    hk.expand(KDF_CK_MSG_INFO, &mut mk)
        .map_err(|_| anyhow::anyhow!("HKDF-CK message expand failed"))?;
    Ok((SecretBytes::new(new_ck), SecretBytes::new(mk)))
}

// ─── AES-GCM encrypt/decrypt ────────────────────────────────────────────────

fn header_ad(header: &MessageHeader) -> Vec<u8> {
    // Use header as associated data to bind it to the ciphertext
    bincode::serialize(header).unwrap_or_default()
}

fn aes_gcm_encrypt(key: &[u8; 32], plaintext: &[u8], header: &MessageHeader) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("Failed to create AES-GCM cipher"))?;

    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ad = header_ad(header);
    let payload = aes_gcm::aead::Payload {
        msg: plaintext,
        aad: &ad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?;

    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn aes_gcm_decrypt(key: &[u8; 32], ciphertext: &[u8], header: &MessageHeader) -> Result<Vec<u8>> {
    if ciphertext.len() < 12 {
        return Err(anyhow::anyhow!("Ciphertext too short"));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("Failed to create AES-GCM cipher"))?;

    let nonce = Nonce::from_slice(&ciphertext[..12]);
    let ad = header_ad(header);
    let payload = aes_gcm::aead::Payload {
        msg: &ciphertext[12..],
        aad: &ad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| anyhow::anyhow!("AES-GCM decryption failed"))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: run X3DH between Alice and Bob, return their sessions.
    fn setup_sessions() -> (DoubleRatchetSession, DoubleRatchetSession) {
        let alice_ik = IdentityKeyPair::generate();
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKeyPair::generate();
        let bob_opk = OneTimePreKeyPair::generate();

        let bundle = PreKeyBundle {
            identity_key: bob_ik.public.to_bytes(),
            signed_prekey: bob_spk.public.to_bytes(),
            one_time_prekey: Some(bob_opk.public.to_bytes()),
        };

        let x3dh_out = x3dh_initiate(&alice_ik, &bundle).unwrap();

        let bob_sk = x3dh_respond(
            &bob_ik,
            &bob_spk,
            Some(&bob_opk),
            alice_ik.public.to_bytes(),
            x3dh_out.ephemeral_public.to_bytes(),
        )
        .unwrap();

        // Verify shared secrets match
        assert_eq!(x3dh_out.shared_secret.as_bytes(), bob_sk.as_bytes());

        let alice_session =
            DoubleRatchetSession::init_alice(x3dh_out.shared_secret, bob_spk.public.to_bytes())
                .unwrap();

        let bob_session = DoubleRatchetSession::init_bob(bob_sk, bob_spk.secret.clone());

        (alice_session, bob_session)
    }

    #[test]
    fn test_x3dh_key_agreement() {
        let alice_ik = IdentityKeyPair::generate();
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKeyPair::generate();
        let bob_opk = OneTimePreKeyPair::generate();

        let bundle = PreKeyBundle {
            identity_key: bob_ik.public.to_bytes(),
            signed_prekey: bob_spk.public.to_bytes(),
            one_time_prekey: Some(bob_opk.public.to_bytes()),
        };

        let alice_out = x3dh_initiate(&alice_ik, &bundle).unwrap();
        let bob_out = x3dh_respond(
            &bob_ik,
            &bob_spk,
            Some(&bob_opk),
            alice_ik.public.to_bytes(),
            alice_out.ephemeral_public.to_bytes(),
        )
        .unwrap();

        assert_eq!(alice_out.shared_secret.as_bytes(), bob_out.as_bytes());
    }

    #[test]
    fn test_x3dh_without_one_time_prekey() {
        let alice_ik = IdentityKeyPair::generate();
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKeyPair::generate();

        let bundle = PreKeyBundle {
            identity_key: bob_ik.public.to_bytes(),
            signed_prekey: bob_spk.public.to_bytes(),
            one_time_prekey: None,
        };

        let alice_out = x3dh_initiate(&alice_ik, &bundle).unwrap();
        let bob_out = x3dh_respond(
            &bob_ik,
            &bob_spk,
            None,
            alice_ik.public.to_bytes(),
            alice_out.ephemeral_public.to_bytes(),
        )
        .unwrap();

        assert_eq!(alice_out.shared_secret.as_bytes(), bob_out.as_bytes());
    }

    #[test]
    fn test_alice_sends_5_messages_bob_receives_in_order() {
        let (mut alice, mut bob) = setup_sessions();

        let messages: Vec<&[u8]> = vec![
            b"Hello Bob!",
            b"How are you?",
            b"Nice weather today",
            b"Let's meet up",
            b"See you at 5pm",
        ];

        let encrypted: Vec<_> = messages.iter().map(|m| alice.encrypt(m).unwrap()).collect();

        for (i, enc) in encrypted.iter().enumerate() {
            let decrypted = bob.decrypt(enc).unwrap();
            assert_eq!(decrypted, messages[i]);
        }
    }

    #[test]
    fn test_alternating_messages_triggers_dh_ratchet() {
        let (mut alice, mut bob) = setup_sessions();

        // Alice -> Bob
        let msg1 = alice.encrypt(b"Hello from Alice").unwrap();
        let dec1 = bob.decrypt(&msg1).unwrap();
        assert_eq!(dec1, b"Hello from Alice");

        // Bob -> Alice (triggers DH ratchet for Bob, then Alice on decrypt)
        let msg2 = bob.encrypt(b"Hello from Bob").unwrap();
        let dec2 = alice.decrypt(&msg2).unwrap();
        assert_eq!(dec2, b"Hello from Bob");

        // Alice -> Bob again (new DH ratchet)
        let msg3 = alice.encrypt(b"Alice again").unwrap();
        let dec3 = bob.decrypt(&msg3).unwrap();
        assert_eq!(dec3, b"Alice again");

        // Bob -> Alice again
        let msg4 = bob.encrypt(b"Bob again").unwrap();
        let dec4 = alice.decrypt(&msg4).unwrap();
        assert_eq!(dec4, b"Bob again");

        // Verify DH keys rotated (headers have different public keys)
        assert_ne!(msg1.header.dh_public_key, msg3.header.dh_public_key);
        assert_ne!(msg2.header.dh_public_key, msg4.header.dh_public_key);
    }

    #[test]
    fn test_out_of_order_message_decryption() {
        let (mut alice, mut bob) = setup_sessions();

        // Alice sends 3 messages
        let msg0 = alice.encrypt(b"Message 0").unwrap();
        let msg1 = alice.encrypt(b"Message 1").unwrap();
        let msg2 = alice.encrypt(b"Message 2").unwrap();

        // Bob receives them out of order: 2, 0, 1
        let dec2 = bob.decrypt(&msg2).unwrap();
        assert_eq!(dec2, b"Message 2");

        let dec0 = bob.decrypt(&msg0).unwrap();
        assert_eq!(dec0, b"Message 0");

        let dec1 = bob.decrypt(&msg1).unwrap();
        assert_eq!(dec1, b"Message 1");
    }

    #[test]
    fn test_key_material_is_zeroized() {
        let sk = SecretBytes::new([0xAA; 32]);
        let _ptr = sk.as_bytes().as_ptr();
        drop(sk);
        // After drop, we can't easily verify memory is zeroed without unsafe,
        // but we verify the type implements ZeroizeOnDrop via compilation.
        // The real check is that SecretBytes derives ZeroizeOnDrop.
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SecretBytes>();
    }

    #[test]
    fn test_session_initialization_from_x3dh() {
        // Full round-trip: X3DH -> session init -> encrypt/decrypt
        let (mut alice, mut bob) = setup_sessions();

        let msg = alice.encrypt(b"First message after X3DH").unwrap();
        let dec = bob.decrypt(&msg).unwrap();
        assert_eq!(dec, b"First message after X3DH");

        let reply = bob.encrypt(b"Bob's reply after X3DH").unwrap();
        let dec_reply = alice.decrypt(&reply).unwrap();
        assert_eq!(dec_reply, b"Bob's reply after X3DH");
    }

    #[test]
    fn test_many_messages_same_direction() {
        let (mut alice, mut bob) = setup_sessions();

        for i in 0..50 {
            let msg = alice.encrypt(format!("Message {i}").as_bytes()).unwrap();
            let dec = bob.decrypt(&msg).unwrap();
            assert_eq!(dec, format!("Message {i}").as_bytes());
        }
    }

    #[test]
    fn test_complex_conversation_pattern() {
        let (mut alice, mut bob) = setup_sessions();

        // Alice sends 3
        let a1 = alice.encrypt(b"a1").unwrap();
        let a2 = alice.encrypt(b"a2").unwrap();
        let a3 = alice.encrypt(b"a3").unwrap();

        // Bob receives first one
        assert_eq!(bob.decrypt(&a1).unwrap(), b"a1");

        // Bob sends 2
        let b1 = bob.encrypt(b"b1").unwrap();
        let b2 = bob.encrypt(b"b2").unwrap();

        // Alice receives Bob's messages
        assert_eq!(alice.decrypt(&b1).unwrap(), b"b1");
        assert_eq!(alice.decrypt(&b2).unwrap(), b"b2");

        // Bob receives remaining Alice messages (out of order relative to Bob's sends)
        assert_eq!(bob.decrypt(&a2).unwrap(), b"a2");
        assert_eq!(bob.decrypt(&a3).unwrap(), b"a3");
    }

    // ─── NEW TESTS: Edge Cases ──────────────────────────────────────────────

    #[test]
    fn test_encrypt_empty_message() {
        let (mut alice, mut bob) = setup_sessions();
        let msg = alice.encrypt(b"").unwrap();
        let dec = bob.decrypt(&msg).unwrap();
        assert_eq!(dec, b"");
    }

    #[test]
    fn test_encrypt_single_byte() {
        let (mut alice, mut bob) = setup_sessions();
        let msg = alice.encrypt(b"x").unwrap();
        let dec = bob.decrypt(&msg).unwrap();
        assert_eq!(dec, b"x");
    }

    #[test]
    fn test_encrypt_max_length_message() {
        let (mut alice, mut bob) = setup_sessions();
        let large = vec![0xAB; 64 * 1024]; // 64KB message
        let msg = alice.encrypt(&large).unwrap();
        let dec = bob.decrypt(&msg).unwrap();
        assert_eq!(dec, large);
    }

    #[test]
    fn test_repeated_encryption_produces_different_ciphertexts() {
        let (mut alice, _bob) = setup_sessions();
        let msg1 = alice.encrypt(b"hello").unwrap();
        let msg2 = alice.encrypt(b"hello").unwrap();
        // Same plaintext should produce different ciphertexts (different nonces + keys)
        assert_ne!(msg1.ciphertext, msg2.ciphertext);
        assert_ne!(msg1.header.message_number, msg2.header.message_number);
    }

    #[test]
    fn test_message_numbers_increment_correctly() {
        let (mut alice, mut bob) = setup_sessions();
        for i in 0..10 {
            let msg = alice.encrypt(b"test").unwrap();
            assert_eq!(msg.header.message_number, i);
            bob.decrypt(&msg).unwrap();
        }
    }

    // ─── NEW TESTS: Error Paths ─────────────────────────────────────────────

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let (mut alice, _) = setup_sessions();
        let (_, mut charlie) = setup_sessions();

        let msg = alice.encrypt(b"secret").unwrap();
        let result = charlie.decrypt(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_corrupted_ciphertext_fails() {
        let (mut alice, mut bob) = setup_sessions();
        let mut msg = alice.encrypt(b"valid message").unwrap();

        // Corrupt the last byte of ciphertext
        if let Some(last) = msg.ciphertext.last_mut() {
            *last ^= 0xFF;
        }

        let result = bob.decrypt(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_header_fails() {
        let (mut alice, mut bob) = setup_sessions();
        let mut msg = alice.encrypt(b"valid message").unwrap();

        // Tamper with message number in header
        msg.header.message_number = 999;

        let result = bob.decrypt(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_short_ciphertext_fails() {
        let (mut alice, mut bob) = setup_sessions();
        let msg = alice.encrypt(b"test").unwrap();

        // Create message with too-short ciphertext (less than nonce size)
        let bad_msg = DoubleRatchetMessage {
            header: msg.header,
            ciphertext: vec![0u8; 5], // Less than 12 bytes for nonce
        };

        let result = bob.decrypt(&bad_msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_too_many_skipped_messages_fails() {
        let (mut alice, mut bob) = setup_sessions();

        // Alice sends many messages
        let mut messages = Vec::new();
        for _ in 0..150 {
            messages.push(alice.encrypt(b"skip me").unwrap());
        }

        // Bob tries to decrypt the last message, skipping MAX_SKIP + 1 messages
        let result = bob.decrypt(messages.last().unwrap());
        assert!(result.is_err());
    }

    // ─── NEW TESTS: Chain Advancement ───────────────────────────────────────

    #[test]
    fn test_chain_advances_on_each_message() {
        let (mut alice, mut bob) = setup_sessions();

        let msg1 = alice.encrypt(b"first").unwrap();
        let msg2 = alice.encrypt(b"second").unwrap();
        let msg3 = alice.encrypt(b"third").unwrap();

        // Message numbers should be sequential
        assert_eq!(msg1.header.message_number, 0);
        assert_eq!(msg2.header.message_number, 1);
        assert_eq!(msg3.header.message_number, 2);

        // All should decrypt successfully
        assert_eq!(bob.decrypt(&msg1).unwrap(), b"first");
        assert_eq!(bob.decrypt(&msg2).unwrap(), b"second");
        assert_eq!(bob.decrypt(&msg3).unwrap(), b"third");
    }

    #[test]
    fn test_sending_chain_reset_after_dh_ratchet() {
        let (mut alice, mut bob) = setup_sessions();

        // Alice sends some messages
        alice.encrypt(b"a1").unwrap();
        alice.encrypt(b"a2").unwrap();
        let msg_a3 = alice.encrypt(b"a3").unwrap();

        // Message 3 should have number 2
        assert_eq!(msg_a3.header.message_number, 2);
        bob.decrypt(&msg_a3).unwrap();

        // Bob replies, triggering DH ratchet
        let msg_b1 = bob.encrypt(b"b1").unwrap();
        assert_eq!(msg_b1.header.message_number, 0); // Reset for Bob's new chain
        assert_eq!(msg_b1.header.previous_chain_length, 0); // Bob had no previous sends

        alice.decrypt(&msg_b1).unwrap();

        // Alice replies again, triggering another DH ratchet
        let msg_a4 = alice.encrypt(b"a4").unwrap();
        assert_eq!(msg_a4.header.message_number, 0); // Reset for Alice's new chain
        assert_eq!(msg_a4.header.previous_chain_length, 3); // Alice sent 3 messages before
    }

    #[test]
    fn test_100_message_chain() {
        let (mut alice, mut bob) = setup_sessions();

        for i in 0..100 {
            let msg = alice.encrypt(format!("msg{}", i).as_bytes()).unwrap();
            let dec = bob.decrypt(&msg).unwrap();
            assert_eq!(dec, format!("msg{}", i).as_bytes());
        }
    }

    // ─── NEW TESTS: Out-of-Order Delivery ───────────────────────────────────

    #[test]
    fn test_reverse_order_delivery() {
        let (mut alice, mut bob) = setup_sessions();

        let m0 = alice.encrypt(b"0").unwrap();
        let m1 = alice.encrypt(b"1").unwrap();
        let m2 = alice.encrypt(b"2").unwrap();
        let m3 = alice.encrypt(b"3").unwrap();
        let m4 = alice.encrypt(b"4").unwrap();

        // Deliver in reverse order
        assert_eq!(bob.decrypt(&m4).unwrap(), b"4");
        assert_eq!(bob.decrypt(&m3).unwrap(), b"3");
        assert_eq!(bob.decrypt(&m2).unwrap(), b"2");
        assert_eq!(bob.decrypt(&m1).unwrap(), b"1");
        assert_eq!(bob.decrypt(&m0).unwrap(), b"0");
    }

    #[test]
    fn test_random_order_delivery() {
        let (mut alice, mut bob) = setup_sessions();

        let m0 = alice.encrypt(b"0").unwrap();
        let m1 = alice.encrypt(b"1").unwrap();
        let m2 = alice.encrypt(b"2").unwrap();
        let m3 = alice.encrypt(b"3").unwrap();
        let m4 = alice.encrypt(b"4").unwrap();

        // Random order: 2, 4, 0, 3, 1
        assert_eq!(bob.decrypt(&m2).unwrap(), b"2");
        assert_eq!(bob.decrypt(&m4).unwrap(), b"4");
        assert_eq!(bob.decrypt(&m0).unwrap(), b"0");
        assert_eq!(bob.decrypt(&m3).unwrap(), b"3");
        assert_eq!(bob.decrypt(&m1).unwrap(), b"1");
    }

    #[test]
    fn test_duplicate_message_decryption() {
        let (mut alice, mut bob) = setup_sessions();

        let msg = alice.encrypt(b"once").unwrap();

        // First decryption succeeds
        assert_eq!(bob.decrypt(&msg).unwrap(), b"once");

        // Second decryption of same message should fail (key was consumed)
        let result = bob.decrypt(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_skip_many_messages_within_limit() {
        let (mut alice, mut bob) = setup_sessions();

        // Alice sends 50 messages
        let mut messages = Vec::new();
        for i in 0..50 {
            messages.push(alice.encrypt(format!("{}", i).as_bytes()).unwrap());
        }

        // Bob receives only every 5th message
        for i in (0..50).step_by(5) {
            let dec = bob.decrypt(&messages[i]).unwrap();
            assert_eq!(dec, format!("{}", i).as_bytes());
        }
    }

    // ─── NEW TESTS: Key Rotation & Forward Secrecy ──────────────────────────

    #[test]
    fn test_dh_public_keys_rotate() {
        let (mut alice, mut bob) = setup_sessions();

        let msg1 = alice.encrypt(b"before").unwrap();
        let alice_key_1 = msg1.header.dh_public_key;
        bob.decrypt(&msg1).unwrap();

        // Bob replies, Alice will ratchet on decrypt
        let msg2 = bob.encrypt(b"reply").unwrap();
        alice.decrypt(&msg2).unwrap();

        // Alice sends again, should have new DH key
        let msg3 = alice.encrypt(b"after").unwrap();
        let alice_key_2 = msg3.header.dh_public_key;

        assert_ne!(
            alice_key_1, alice_key_2,
            "Alice's DH key should have rotated"
        );
    }

    #[test]
    fn test_forward_secrecy_old_messages_undecryptable_after_ratchet() {
        let (mut alice, mut bob) = setup_sessions();

        // Alice sends a message
        let old_msg = alice.encrypt(b"old secret").unwrap();
        bob.decrypt(&old_msg).unwrap();

        // Trigger multiple DH ratchets
        for i in 0..5 {
            let b_msg = bob.encrypt(format!("b{}", i).as_bytes()).unwrap();
            alice.decrypt(&b_msg).unwrap();
            let a_msg = alice.encrypt(format!("a{}", i).as_bytes()).unwrap();
            bob.decrypt(&a_msg).unwrap();
        }

        // Old message should fail to decrypt again (keys were advanced)
        let result = bob.decrypt(&old_msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_dh_ratchet_cycles() {
        let (mut alice, mut bob) = setup_sessions();

        for round in 0..10 {
            let a_msg = alice.encrypt(format!("alice{}", round).as_bytes()).unwrap();
            assert_eq!(
                bob.decrypt(&a_msg).unwrap(),
                format!("alice{}", round).as_bytes()
            );

            let b_msg = bob.encrypt(format!("bob{}", round).as_bytes()).unwrap();
            assert_eq!(
                alice.decrypt(&b_msg).unwrap(),
                format!("bob{}", round).as_bytes()
            );
        }
    }

    // ─── NEW TESTS: Serialization ───────────────────────────────────────────

    #[test]
    fn test_message_header_serialization_roundtrip() {
        let header = MessageHeader {
            dh_public_key: [42u8; 32],
            previous_chain_length: 123,
            message_number: 456,
        };

        let serialized = bincode::serialize(&header).unwrap();
        let deserialized: MessageHeader = bincode::deserialize(&serialized).unwrap();

        assert_eq!(header, deserialized);
    }

    #[test]
    fn test_double_ratchet_message_serialization_roundtrip() {
        let (mut alice, mut bob) = setup_sessions();
        let msg = alice.encrypt(b"serialize me").unwrap();

        let serialized = bincode::serialize(&msg).unwrap();
        let deserialized: DoubleRatchetMessage = bincode::deserialize(&serialized).unwrap();

        let dec = bob.decrypt(&deserialized).unwrap();
        assert_eq!(dec, b"serialize me");
    }

    #[test]
    fn test_prekey_bundle_serialization() {
        let bundle = PreKeyBundle {
            identity_key: [1u8; 32],
            signed_prekey: [2u8; 32],
            one_time_prekey: Some([3u8; 32]),
        };

        let json = serde_json::to_string(&bundle).unwrap();
        let deserialized: PreKeyBundle = serde_json::from_str(&json).unwrap();

        assert_eq!(bundle.identity_key, deserialized.identity_key);
        assert_eq!(bundle.signed_prekey, deserialized.signed_prekey);
        assert_eq!(bundle.one_time_prekey, deserialized.one_time_prekey);
    }

    // ─── NEW TESTS: Concurrent/Interleaved Sessions ─────────────────────────

    #[test]
    fn test_interleaved_messages_from_both_parties() {
        let (mut alice, mut bob) = setup_sessions();

        // Alice sends first (she can send immediately)
        let a1 = alice.encrypt(b"a1").unwrap();
        let a2 = alice.encrypt(b"a2").unwrap();

        // Bob receives first message to establish his sending chain
        assert_eq!(bob.decrypt(&a1).unwrap(), b"a1");

        // Now Bob can send
        let b1 = bob.encrypt(b"b1").unwrap();
        let b2 = bob.encrypt(b"b2").unwrap();

        // Cross-deliver remaining
        assert_eq!(alice.decrypt(&b1).unwrap(), b"b1");
        assert_eq!(bob.decrypt(&a2).unwrap(), b"a2");
        assert_eq!(alice.decrypt(&b2).unwrap(), b"b2");
    }

    #[test]
    fn test_bob_sends_after_receiving() {
        let (mut alice, mut bob) = setup_sessions();

        // Alice must send first to establish the ratchet
        let a1 = alice.encrypt(b"alice first").unwrap();
        assert_eq!(bob.decrypt(&a1).unwrap(), b"alice first");

        // Now Bob can send
        let b1 = bob.encrypt(b"bob reply").unwrap();
        assert_eq!(alice.decrypt(&b1).unwrap(), b"bob reply");
    }

    #[test]
    fn test_batch_send_then_batch_receive() {
        let (mut alice, mut bob) = setup_sessions();

        // Alice sends a batch
        let mut alice_msgs = Vec::new();
        for i in 0..20 {
            alice_msgs.push(alice.encrypt(format!("a{}", i).as_bytes()).unwrap());
        }

        // Bob receives Alice's batch (this establishes Bob's sending chain)
        for (i, msg) in alice_msgs.iter().enumerate() {
            assert_eq!(bob.decrypt(msg).unwrap(), format!("a{}", i).as_bytes());
        }

        // Now Bob sends a batch
        let mut bob_msgs = Vec::new();
        for i in 0..20 {
            bob_msgs.push(bob.encrypt(format!("b{}", i).as_bytes()).unwrap());
        }

        // Alice receives Bob's batch
        for (i, msg) in bob_msgs.iter().enumerate() {
            assert_eq!(alice.decrypt(msg).unwrap(), format!("b{}", i).as_bytes());
        }
    }

    // ─── NEW TESTS: Additional X3DH & Session Init Tests ────────────────────

    #[test]
    fn test_x3dh_with_different_bundles_produces_different_secrets() {
        let alice_ik = IdentityKeyPair::generate();
        let bob_ik1 = IdentityKeyPair::generate();
        let bob_ik2 = IdentityKeyPair::generate();
        let bob_spk1 = SignedPreKeyPair::generate();
        let bob_spk2 = SignedPreKeyPair::generate();

        let bundle1 = PreKeyBundle {
            identity_key: bob_ik1.public.to_bytes(),
            signed_prekey: bob_spk1.public.to_bytes(),
            one_time_prekey: None,
        };

        let bundle2 = PreKeyBundle {
            identity_key: bob_ik2.public.to_bytes(),
            signed_prekey: bob_spk2.public.to_bytes(),
            one_time_prekey: None,
        };

        let out1 = x3dh_initiate(&alice_ik, &bundle1).unwrap();
        let out2 = x3dh_initiate(&alice_ik, &bundle2).unwrap();

        assert_ne!(out1.shared_secret.as_bytes(), out2.shared_secret.as_bytes());
    }

    #[test]
    fn test_alice_init_bob_init_can_communicate() {
        let alice_ik = IdentityKeyPair::generate();
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKeyPair::generate();
        let bob_opk = OneTimePreKeyPair::generate();

        let bundle = PreKeyBundle {
            identity_key: bob_ik.public.to_bytes(),
            signed_prekey: bob_spk.public.to_bytes(),
            one_time_prekey: Some(bob_opk.public.to_bytes()),
        };

        let alice_x3dh = x3dh_initiate(&alice_ik, &bundle).unwrap();
        let bob_sk = x3dh_respond(
            &bob_ik,
            &bob_spk,
            Some(&bob_opk),
            alice_ik.public.to_bytes(),
            alice_x3dh.ephemeral_public.to_bytes(),
        )
        .unwrap();

        let mut alice =
            DoubleRatchetSession::init_alice(alice_x3dh.shared_secret, bob_spk.public.to_bytes())
                .unwrap();

        let mut bob = DoubleRatchetSession::init_bob(bob_sk, bob_spk.secret);

        // Test communication
        let msg = alice.encrypt(b"hello from alice").unwrap();
        let dec = bob.decrypt(&msg).unwrap();
        assert_eq!(dec, b"hello from alice");
    }

    #[test]
    fn test_session_public_key_accessor() {
        let (alice, bob) = setup_sessions();

        let alice_pub = alice.our_public_key();
        let bob_pub = bob.our_public_key();

        assert_eq!(alice_pub.len(), 32);
        assert_eq!(bob_pub.len(), 32);
        assert_ne!(alice_pub, bob_pub);
    }

    #[test]
    fn test_previous_chain_length_tracking() {
        let (mut alice, mut bob) = setup_sessions();

        // Alice sends 7 messages
        for _ in 0..7 {
            let msg = alice.encrypt(b"x").unwrap();
            bob.decrypt(&msg).unwrap();
        }

        // Bob replies (Alice will see previous_chain_length = 0 since Bob hasn't sent before)
        let b_msg = bob.encrypt(b"reply").unwrap();
        assert_eq!(b_msg.header.previous_chain_length, 0);
        alice.decrypt(&b_msg).unwrap();

        // Alice sends again (previous_chain_length should be 7)
        let a_msg = alice.encrypt(b"after").unwrap();
        assert_eq!(a_msg.header.previous_chain_length, 7);
    }
}
