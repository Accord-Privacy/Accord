//! Accord server library
//!
//! Exposes modules for testing and reuse

// Federation and Bot API are scaffolding — not yet fully wired into production routes.
// Allow dead code until integration is complete.
#![allow(dead_code)]

pub mod bot_api;
pub mod db;
pub mod files;
pub mod handlers;
pub mod metadata;
pub mod models;
pub mod node;
pub mod permissions;
pub mod rate_limit;
pub mod relay_mesh;
pub mod state;
pub mod validation;
pub mod webhooks;
