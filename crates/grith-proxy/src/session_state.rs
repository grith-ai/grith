// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Per-session state for the proxy: containment activation and session bookkeeping.
//!
//! This module is the structural piece of PR 1 Phase C. It exposes a
//! [`SessionStateRegistry`] keyed by [`SessionScopeKey`], storing
//! session-lifetime-sticky state — most importantly the `containment_active`
//! flag set by a sensitive access (read, write, or modify) on a path the
//! taint filter classifies at the highest sensitivity level.
//!
//! # Why a separate type from `ContainmentTracker`?
//!
//! `filters::session_containment::ContainmentTracker` already exists and arms
//! a 10-minute TTL-windowed containment in response to specific behavioural
//! sequences (sensitive source → outbound action). PR 1 needs a different,
//! **session-lifetime** flag that:
//!
//! * Cannot be waited out by an attacker (no TTL — sticky for the whole
//!   supervised session).
//! * Is consulted in `event_handler.rs` *before* the noise-reduction and
//!   session-allowlist short-circuits, so a contained session cannot
//!   silently bypass containment via `routine_destinations`.
//!
//! Phase D wires the `is_containment_active` check into `event_handler.rs`.
//! Phase F adds eviction at session-start/end. This file is structural only.

use crate::types::SessionScopeKey;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

/// Reason containment was activated. Recorded for forensic clarity in
/// audit logs and dashboard displays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainmentReason {
    /// A sensitive access (read, write, rename, chmod, or delete) occurred
    /// on a path the taint filter classifies at the highest sensitivity
    /// level — typically SSH keys, `shadow`, or other unambiguously-secret
    /// targets. The trigger fires regardless of operation direction
    /// because a write to `~/.ssh/authorized_keys` is at least as alarming
    /// as a read of `~/.ssh/id_rsa`.
    ///
    /// **Naming note:** the variant ends in `OutsideScope` to telegraph the
    /// intended end state, but the *current* implementation fires on any
    /// `TaintLevel::High` access regardless of whether the path is inside
    /// the supervised tool's profile-declared scope. The High-taint
    /// pattern list (`.ssh`, `id_rsa`, `id_ed25519`, `private_key`,
    /// `shadow`) is tightly scoped to genuinely-secret material, so this
    /// produces no false positives on routine Codex/Claude startup paths
    /// like `~/.codex/auth.json` (those classify Medium or lower). PR 2 of
    /// the codex-prompt-flood remediation plan adds the profile-aware
    /// "outside declared scope" refinement for medium-taint paths.
    SensitiveAccessOutsideScope { path: String, taint_level: String },
    /// Explicit activation (e.g. CLI command or dashboard action).
    Manual { actor: String },
}

/// PR 4 Phase C — session-pinned binary inventory.
///
/// Snapshot of every executable found under the profile's
/// `routine_exec_roots` at session start, recorded as
/// `canonical_path → sha256-hex`. The inventory is immutable for the
/// session lifetime: a binary appearing in a routine root *after*
/// session start does not gain trust during that session, which closes
/// the "LLM does `npm install -g <malicious>` mid-session" gap.
///
/// Stored on [`SessionState`] via `set_pinned_inventory` and read
/// later by PR 4 Phase D's routine-signal check.
#[derive(Debug, Default, Clone)]
pub struct SessionPinnedInventory {
    /// `canonical_path → sha256-hex`. Hex (not raw bytes) so it can be
    /// JSON-serialised straight onto audit/dashboard payloads without
    /// bespoke encoding. Lower-case, 64 chars.
    entries: HashMap<String, String>,
    /// Total files actually walked while building this inventory.
    /// Useful for forensic diff vs. the configured cap.
    pub total_scanned: usize,
    /// `true` if the walk hit the per-session file cap and stopped
    /// short. Phase D's signal check stays correct (trust requires a
    /// hit) but operators should see this so they can split a too-broad
    /// `routine_exec_roots` glob.
    pub truncated: bool,
}

impl SessionPinnedInventory {
    /// Construct from a `(canonical_path, sha256_hex)` iterator. Empty
    /// inventories are valid (e.g. profile with no `routine_exec_roots`
    /// installed on this host).
    ///
    /// `total_scanned` defaults to `entries.len()` here. The supervisor's
    /// `build_session_pinned_inventory` overwrites it post-construction
    /// with the actual walk count (which may exceed `len()` when files
    /// were scanned but skipped — non-executable, unsafe ancestor, etc.).
    pub fn from_entries<I, P, H>(entries: I) -> Self
    where
        I: IntoIterator<Item = (P, H)>,
        P: Into<String>,
        H: Into<String>,
    {
        let entries: HashMap<String, String> = entries
            .into_iter()
            .map(|(p, h)| (p.into(), h.into()))
            .collect();
        Self {
            total_scanned: entries.len(),
            truncated: false,
            entries,
        }
    }

    /// Number of pinned binaries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the inventory is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return the expected hex SHA-256 for a canonical path, or `None`
    /// if the path isn't in the inventory.
    pub fn expected_hash(&self, canonical_path: &str) -> Option<&str> {
        self.entries.get(canonical_path).map(String::as_str)
    }

    /// `true` iff the canonical path is in the inventory and the recorded
    /// hash matches `sha256_hex`. Hash comparison is case-insensitive on
    /// the hex digits to match common hex-encoding conventions.
    pub fn contains(&self, canonical_path: &str, sha256_hex: &str) -> bool {
        match self.entries.get(canonical_path) {
            Some(expected) => expected.eq_ignore_ascii_case(sha256_hex),
            None => false,
        }
    }

    /// Iterate `(path, sha256_hex)` for dashboard/audit consumers.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(p, h)| (p.as_str(), h.as_str()))
    }
}

/// Per-session state stored in the registry.
///
/// Access patterns: containment activation is a one-shot transition from
/// `false` to `true` (sticky). After activation the reason is read
/// occasionally (audit log, dashboard). `last_seen` is touched on every
/// scope access so the Phase F sweep can detect crashed sessions.
pub struct SessionState {
    pub scope: SessionScopeKey,
    containment_active: AtomicBool,
    containment_reason: Mutex<Option<ContainmentReason>>,
    last_seen: Mutex<Instant>,
    /// PR 4 Phase C: set-once snapshot of trusted binaries under the
    /// profile's `routine_exec_roots`. `OnceLock` ensures the supervisor
    /// can install it at session-start and the proxy filters can read
    /// it cheaply (no lock) on every spawn evaluation.
    pinned_inventory: OnceLock<Arc<SessionPinnedInventory>>,
}

impl SessionState {
    fn new(scope: SessionScopeKey) -> Self {
        Self {
            scope,
            containment_active: AtomicBool::new(false),
            containment_reason: Mutex::new(None),
            last_seen: Mutex::new(Instant::now()),
            pinned_inventory: OnceLock::new(),
        }
    }

    /// PR 4 Phase C: install the session-pinned binary inventory.
    /// First call wins; later calls are silently ignored (the inventory
    /// is immutable for the session lifetime by design).
    pub fn set_pinned_inventory(&self, inventory: SessionPinnedInventory) {
        let _ = self.pinned_inventory.set(Arc::new(inventory));
    }

    /// PR 4 Phase C: read the session-pinned binary inventory. Returns
    /// `None` if `set_pinned_inventory` hasn't been called yet (e.g.
    /// LLM-path sessions that don't go through supervisor session-start).
    /// Callers that treat absence as "no routine signal" stay fail-closed.
    pub fn pinned_inventory(&self) -> Option<Arc<SessionPinnedInventory>> {
        self.pinned_inventory.get().cloned()
    }

    /// Whether containment is currently active for this session.
    ///
    /// Cheap (single atomic load); safe to call on every proxy evaluation.
    pub fn is_containment_active(&self) -> bool {
        self.containment_active.load(Ordering::Relaxed)
    }

    /// Activate containment. Idempotent: subsequent calls leave the existing
    /// `ContainmentReason` in place (we record the *first* trigger, since
    /// later events happen inside an already-contained session and are less
    /// forensically interesting than the activation point).
    pub fn activate_containment(&self, reason: ContainmentReason) {
        // Compare-and-swap from false to true. If we won the race, record
        // the reason. If we lost, leave the existing reason alone.
        if self
            .containment_active
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            let mut slot = self.containment_reason.lock().expect("lock poisoned");
            *slot = Some(reason);
        }
    }

    /// Read the recorded containment reason. `None` when containment has
    /// not been activated.
    pub fn containment_reason(&self) -> Option<ContainmentReason> {
        self.containment_reason
            .lock()
            .expect("lock poisoned")
            .clone()
    }

    /// Update the "last seen" timestamp; called by [`SessionStateRegistry::touch`]
    /// on every scope access so a Phase F sweep can detect crashed sessions.
    fn touch(&self) {
        let mut last = self.last_seen.lock().expect("lock poisoned");
        *last = Instant::now();
    }

    /// Last-seen timestamp. Used by Phase F's sweep.
    pub fn last_seen(&self) -> Instant {
        *self.last_seen.lock().expect("lock poisoned")
    }
}

/// Registry of per-session state. One instance per daemon process; obtained
/// via [`SessionStateRegistry::global`]. Thread-safe.
pub struct SessionStateRegistry {
    sessions: Mutex<HashMap<SessionScopeKey, Arc<SessionState>>>,
}

impl SessionStateRegistry {
    fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Process-wide registry instance.
    ///
    /// In tests, prefer [`SessionStateRegistry::fresh`] to get an isolated
    /// instance — the global is shared across the test process and would
    /// otherwise let tests influence each other.
    pub fn global() -> &'static Self {
        static INSTANCE: OnceLock<SessionStateRegistry> = OnceLock::new();
        INSTANCE.get_or_init(Self::new)
    }

    /// Allocate a fresh registry. Tests should use this instead of [`global`]
    /// so that cross-scope writes don't leak between test cases.
    pub fn fresh() -> Self {
        Self::new()
    }

    /// Get-or-insert the state for a scope. Touches `last_seen` as a side
    /// effect so a fresh sweep sees the entry as live.
    pub fn get_or_create(&self, scope: SessionScopeKey) -> Arc<SessionState> {
        let mut sessions = self.sessions.lock().expect("lock poisoned");
        let state = sessions
            .entry(scope)
            .or_insert_with(|| Arc::new(SessionState::new(scope)))
            .clone();
        state.touch();
        state
    }

    /// Get the state for a scope without creating it. Returns `None` when
    /// the scope is unknown (no prior activity).
    pub fn get(&self, scope: SessionScopeKey) -> Option<Arc<SessionState>> {
        let sessions = self.sessions.lock().expect("lock poisoned");
        sessions.get(&scope).cloned()
    }

    /// Cheap "is containment active?" check used by Phase D's ordering
    /// gates. Returns `false` for unknown scopes.
    pub fn is_containment_active(&self, scope: SessionScopeKey) -> bool {
        self.get(scope)
            .map(|s| s.is_containment_active())
            .unwrap_or(false)
    }

    /// Activate containment on the scope, creating its state entry if it
    /// doesn't yet exist. Idempotent.
    pub fn activate_containment(&self, scope: SessionScopeKey, reason: ContainmentReason) {
        self.get_or_create(scope).activate_containment(reason);
    }

    /// Remove the state entry for a scope. Used by Phase F's session-end
    /// hook and session-start sweep.
    pub fn evict(&self, scope: SessionScopeKey) -> bool {
        let mut sessions = self.sessions.lock().expect("lock poisoned");
        sessions.remove(&scope).is_some()
    }

    /// Number of tracked scopes. For observability and tests.
    pub fn len(&self) -> usize {
        self.sessions.lock().expect("lock poisoned").len()
    }

    /// Whether the registry currently tracks any scopes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate all scopes whose `last_seen` is older than `cutoff`,
    /// returning a snapshot of the matching `(scope, last_seen)` pairs.
    /// The caller may then call [`evict`] on each — the iteration does not
    /// hold the registry lock, so it cannot deadlock against eviction.
    pub fn snapshot_stale(&self, cutoff: Instant) -> Vec<(SessionScopeKey, Instant)> {
        let sessions = self.sessions.lock().expect("lock poisoned");
        sessions
            .iter()
            .filter_map(|(scope, state)| {
                let last = state.last_seen();
                if last < cutoff {
                    Some((*scope, last))
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> SessionScopeKey {
        SessionScopeKey::fresh()
    }

    #[test]
    fn registry_get_or_create_is_idempotent() {
        let reg = SessionStateRegistry::fresh();
        let s = scope();
        let a = reg.get_or_create(s);
        let b = reg.get_or_create(s);
        assert!(
            Arc::ptr_eq(&a, &b),
            "same scope must map to same SessionState"
        );
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn containment_starts_inactive() {
        let reg = SessionStateRegistry::fresh();
        let s = scope();
        assert!(!reg.is_containment_active(s));
        // Unknown scope returns false (does not create state).
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn activation_records_reason_and_is_idempotent() {
        let reg = SessionStateRegistry::fresh();
        let s = scope();
        let r1 = ContainmentReason::SensitiveAccessOutsideScope {
            path: "/home/u/.ssh/id_rsa".into(),
            taint_level: "high".into(),
        };
        let r2 = ContainmentReason::Manual {
            actor: "test".into(),
        };
        reg.activate_containment(s, r1.clone());
        assert!(reg.is_containment_active(s));

        // Second activation must NOT overwrite the recorded reason — the
        // first trigger is the forensically interesting event.
        reg.activate_containment(s, r2);
        let state = reg.get(s).unwrap();
        assert_eq!(state.containment_reason(), Some(r1));
    }

    #[test]
    fn evict_removes_scope() {
        let reg = SessionStateRegistry::fresh();
        let s = scope();
        reg.activate_containment(
            s,
            ContainmentReason::Manual {
                actor: "test".into(),
            },
        );
        assert!(reg.evict(s));
        assert!(!reg.is_containment_active(s));
        assert!(!reg.evict(s), "evicting an unknown scope returns false");
    }

    #[test]
    fn cross_scope_isolation() {
        let reg = SessionStateRegistry::fresh();
        let a = scope();
        let b = scope();
        reg.activate_containment(
            a,
            ContainmentReason::SensitiveAccessOutsideScope {
                path: "/home/alice/.ssh/id_rsa".into(),
                taint_level: "high".into(),
            },
        );
        assert!(reg.is_containment_active(a));
        assert!(
            !reg.is_containment_active(b),
            "containment on A must not appear on B"
        );
    }

    #[test]
    fn snapshot_stale_filters_by_cutoff() {
        let reg = SessionStateRegistry::fresh();
        let s = scope();
        reg.get_or_create(s);
        // Stale cutoff way in the future → all current scopes considered stale.
        let cutoff = Instant::now() + std::time::Duration::from_secs(3600);
        let stale = reg.snapshot_stale(cutoff);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].0, s);

        // Cutoff in the past → nothing stale.
        let cutoff = Instant::now()
            .checked_sub(std::time::Duration::from_secs(3600))
            .unwrap_or_else(Instant::now);
        let stale = reg.snapshot_stale(cutoff);
        assert!(stale.is_empty());
    }

    #[test]
    fn global_singleton_is_shared() {
        let a = SessionStateRegistry::global() as *const _;
        let b = SessionStateRegistry::global() as *const _;
        assert_eq!(a, b, "global() must return the same instance");
    }

    // ---- PR 4 Phase C: pinned inventory tests ----

    #[test]
    fn pinned_inventory_starts_empty() {
        let inv = SessionPinnedInventory::default();
        assert!(inv.is_empty());
        assert_eq!(inv.len(), 0);
        assert!(!inv.contains("/usr/bin/anything", "00"));
    }

    #[test]
    fn pinned_inventory_contains_matches_case_insensitively() {
        let inv = SessionPinnedInventory::from_entries([(
            "/usr/bin/sh",
            "abcd1234".repeat(8), // 64 chars
        )]);
        let upper: String = inv.expected_hash("/usr/bin/sh").unwrap().to_uppercase();
        assert!(inv.contains("/usr/bin/sh", &upper));
        assert!(!inv.contains("/usr/bin/sh", "0000"));
        assert!(!inv.contains("/usr/bin/other", "abcd"));
    }

    #[test]
    fn session_state_pinned_inventory_is_set_once() {
        let reg = SessionStateRegistry::fresh();
        let s = scope();
        let state = reg.get_or_create(s);
        assert!(state.pinned_inventory().is_none(), "starts unset");
        let first = SessionPinnedInventory::from_entries([("/a", "11")]);
        state.set_pinned_inventory(first);
        let second = SessionPinnedInventory::from_entries([("/b", "22")]);
        state.set_pinned_inventory(second);
        let snap = state.pinned_inventory().expect("inventory set");
        // Set-once: the second call must NOT overwrite.
        assert!(snap.contains("/a", "11"));
        assert!(!snap.contains("/b", "22"));
    }

    #[test]
    fn pinned_inventory_iter_yields_all_entries() {
        let inv = SessionPinnedInventory::from_entries([("/bin/a", "aa"), ("/bin/b", "bb")]);
        let mut seen: Vec<(String, String)> = inv
            .iter()
            .map(|(p, h)| (p.to_string(), h.to_string()))
            .collect();
        seen.sort();
        assert_eq!(
            seen,
            vec![
                ("/bin/a".to_string(), "aa".to_string()),
                ("/bin/b".to_string(), "bb".to_string()),
            ]
        );
    }
}
