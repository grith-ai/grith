// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Cross-process push of the session-pinned binary inventory.
//!
//! `SessionStateRegistry::global()` is per-process. The supervisor runs
//! in the `grith exec` process; the dashboard server runs in the daemon
//! process. Both have their own globals. Without IPC, the dashboard's
//! `/api/inventory` endpoint can never serve the inventory the
//! supervisor pinned, so opening *Trusted Binaries* in the UI
//! consistently returned 404.
//!
//! [`InventorySink`] is the supervisor-side hook: after the inventory
//! walk lands in the local registry, the supervisor calls
//! [`InventorySink::install`] with the same payload. A concrete
//! implementation (in `grith-core`) POSTs it to the daemon, which
//! installs it into its own registry. The dashboard endpoint then sees
//! a populated inventory and renders normally.
//!
//! In-process supervisor sessions (community fallback when the daemon
//! is unreachable) simply pass `None` — the local registry is already
//! populated, no push needed.

use async_trait::async_trait;
use grith_proxy::session_state::SessionPinnedInventory;
use grith_proxy::types::SessionScopeKey;

/// Sink for the session-pinned binary inventory.
///
/// One call per session, immediately after the supervisor's local
/// `set_pinned_inventory`. Failures are non-fatal: a missed push only
/// affects dashboard visibility, not security enforcement (the proxy's
/// routine-spawn signal reads from the local registry).
#[async_trait]
pub trait InventorySink: Send + Sync {
    async fn install(
        &self,
        scope: SessionScopeKey,
        inventory: SessionPinnedInventory,
    ) -> std::result::Result<(), String>;
}
