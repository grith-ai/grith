// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Digest queue for quarantined tool calls awaiting human review.
//!
//! When the security proxy scores a call between 3.0 and 8.0, it is queued
//! here for approval, denial, or escalation via the CLI or dashboard.

pub mod actions;
pub mod delivery;
pub mod error;
pub mod notification;
pub mod queue;
pub mod scheduler;
pub mod types;

pub use error::Error;
pub use notification::{
    CallbackNonceStore, CallbackPayload, ChannelHealth, NotificationChannel, NotificationEvent,
    NotifyResult, PlanTier,
};
pub use queue::DigestQueue;
pub use scheduler::DigestScheduler;
pub use types::{
    DigestItem, DigestStatus, PermissionReviewAction, ReviewAction, ReviewOutcome,
    ScopedAllowRequest, ScopedDenyRequest,
};
