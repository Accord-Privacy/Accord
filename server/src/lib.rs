//! Accord server library
//!
//! The relay binary (`main.rs`) and every test use this crate, so they share
//! one module tree and one route table (`router`).

// Federation and Bot API are scaffolding — not yet fully wired into production routes.
// Allow dead code until integration is complete.
#![allow(dead_code)]

pub mod admin;
pub mod admission;
pub mod attachments;
pub mod backup;
pub mod batch_handlers;
pub mod bot_api;
pub mod capabilities;
pub mod db;
pub mod faults;
pub mod federation;
pub mod files;
pub mod handlers;
pub mod metadata;
pub mod models;
pub mod node;
pub mod permissions;
pub mod push;
pub mod rate_limit;
pub mod relay_mesh;
pub mod router;
pub mod screen;
pub mod socket_opts;
pub mod state;
/// Shared in-process relay harness for tests (SPEC-01 section 10.1). Only
/// compiled for this crate's unit tests and with the `test-helpers` feature.
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_support;
pub mod validation;
pub mod webhooks;
