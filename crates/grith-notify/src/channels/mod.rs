// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Notification channel implementations for various delivery backends.

pub mod desktop;
pub mod discord;
pub mod email;
pub mod opsgenie;
pub mod pagerduty;
pub mod slack;
pub mod teams;
pub mod telegram;
pub mod webhook;
pub mod websocket;
pub mod whatsapp;
