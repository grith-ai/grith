// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! # grith-supervisor
//!
//! OS-level syscall interception for external CLI tools, routing every
//! security-relevant operation through grith's multi-filter security proxy.
//!
//! This crate provides the supervisor subsystem that sits between the host
//! operating system and any external tool (Claude Code, Aider, Codex, etc.)
//! that grith launches or attaches to. Unlike the WASM sandbox — which
//! mediates access for *plugins* — the supervisor mediates access for
//! *native processes* that run with full OS privileges.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────┐
//! │  External Tool (e.g. claude)    │
//! └────────────┬────────────────────┘
//!              │ syscalls
//!              ▼
//! ┌─────────────────────────────────┐
//! │  Platform Interceptor           │
//! │  (ptrace / Endpoint Security)   │
//! └────────────┬────────────────────┘
//!              │ SyscallEvent
//!              ▼
//! ┌─────────────────────────────────┐
//! │  grith-proxy pipeline           │
//! │  (scoring → allow/queue/deny)   │
//! └────────────┬────────────────────┘
//!              │ SyscallResponse
//!              ▼
//! ┌─────────────────────────────────┐
//! │  allow / deny(EPERM) / freeze   │
//! └─────────────────────────────────┘
//! ```
//!
//! ## Modules
//!
//! - [`config`] — TOML-deserializable configuration structs.
//! - [`error`] — Unified error type and `Result` alias.
//! - [`freezer`] — Process freeze/thaw primitives for QUEUE decisions.
//! - [`interceptor`] — Platform-agnostic trait and event types.
//! - [`platform`] — Platform detection factory and OS-specific implementations.
//! - [`process_tree`] — Process hierarchy tracking.
//! - [`pty`] — PTY forwarding for interactive supervised tools.
//! - [`profiles`] — Pre-built supervisor profiles for known AI tools.
//! - [`supervisor`] — Main supervisor event loop and session management.
//! - [`syscall_map`] — Mapping from OS syscalls to proxy `ToolCallType`.

pub(crate) mod audit_analytics;
pub mod audit_sink;
pub mod cdp;
pub mod config;
pub mod connected_dns_proxy;
pub(crate) mod dbus;
pub mod dns_cache;
pub mod dns_proxy;
pub mod error;
pub(crate) mod forensics_trace;
pub mod freezer;
pub mod interceptor;
pub mod inventory_cache;
pub mod inventory_sink;
pub mod learned_rules;
pub mod platform;
pub mod process_tree;
pub mod profiles;
pub mod provenance;
pub mod pty;
pub mod reviewer;
pub mod scoped_permissions;
pub mod session_sync;
pub mod supervisor;
pub mod syscall_map;
pub mod workspace_only;

pub use audit_sink::{AuditSink, StorageAuditSink};
pub use config::SupervisorConfig;
pub use error::Error;
pub use interceptor::{SyscallEvent, SyscallInterceptor, SyscallKind, SyscallResponse};
pub use inventory_sink::InventorySink;
pub use profiles::SupervisorProfile;
pub use reviewer::{DigestStore, LocalDigestStore, PollingQueueReviewer, QueueReviewer};
pub use session_sync::{RegistrySessionSync, SessionSync, SyncFailure, SyncOutcome};
