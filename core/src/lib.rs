//! # Accord Core
//! 
//! Core cryptographic and networking primitives for the Accord secure communication platform.
//! 
//! This library provides:
//! - End-to-end encryption using Signal Protocol
//! - Real-time voice encryption
//! - Key management and rotation
//! - Network protocols for secure message relay

pub mod crypto;
pub mod channels;
pub mod bots;
pub mod invites;
pub mod voice;
pub mod protocol;

use anyhow::Result;

/// Accord protocol version
pub const PROTOCOL_VERSION: u32 = 1;

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
        assert_eq!(PROTOCOL_VERSION, 1);
    }
}