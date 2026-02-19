//! # Accord Bot SDK
//!
//! A Rust SDK for building bots on the [Accord](https://accord.chat) platform.
//!
//! ## Quick Start
//!
//! ```no_run
//! use accord_bot_sdk::AccordBot;
//!
//! #[tokio::main]
//! async fn main() -> accord_bot_sdk::Result<()> {
//!     let mut bot = AccordBot::new("ws://localhost:8080", "your-bot-token");
//!     bot.connect().await?;
//!
//!     bot.on_message(|msg| async move {
//!         println!("Got message: {:?}", msg.content);
//!     }).await;
//!
//!     bot.run().await
//! }
//! ```

pub mod client;
pub mod error;
pub mod models;

pub use client::AccordBot;
pub use error::{BotError, Result};
pub use models::{Channel, Event, Message, Reaction, User};
