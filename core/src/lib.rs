//! # Accord Core
//!
//! Core cryptographic and networking primitives for the Accord secure communication platform.
//!
//! This library provides:
//! - End-to-end encryption using Signal Protocol
//! - Real-time voice encryption
//! - Key management and rotation
//! - Network protocols for secure message relay

pub mod bots;
pub mod channels;
pub mod crypto;
pub mod double_ratchet;
pub mod invites;
pub mod protocol;
pub mod session_manager;
pub mod srtp;
pub mod voice;

use anyhow::Result;

// Re-export the canonical protocol version from the protocol module
pub use protocol::PROTOCOL_VERSION;

/// Initialize the Accord core library
pub fn init() -> Result<()> {
    tracing_subscriber::fmt::init();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(PROTOCOL_VERSION, 1u8);
    }
}
