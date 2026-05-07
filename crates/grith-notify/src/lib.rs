// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Multi-channel notification system for real-time digest delivery.
//!
//! Routes digest items to configured channels (Slack, Discord, webhook, desktop,
//! email, etc.) with batching, rate limiting, severity routing, and plan tier gating.

pub mod batcher;
pub mod channels;
pub mod dispatcher;
pub mod error;
pub mod hmac_verify;
pub mod rate_limiter;
pub mod registry;
pub mod routing;
pub mod tracker;

pub use dispatcher::NotificationDispatcher;
pub use error::{Error, Result};
pub use registry::ChannelRegistry;
pub use routing::RoutingEngine;
