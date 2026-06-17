// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Session state tracking, statistics, and the session registry.
//!
//! Contains [`SessionStats`], [`SessionSummary`], [`SupervisorSession`], and
//! [`SupervisorRegistry`] -- the types that represent and manage the lifecycle
//! of one or more active supervisor sessions.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::SupervisorConfig;
use crate::error::{Error, Result};
use crate::process_tree::ProcessTree;

/// Check whether a process is still alive via a zero-signal kill.
/// Returns `true` if the process exists (even if we lack permission to signal it).
fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        use nix::errno::Errno;
        use nix::sys::signal;
        use nix::unistd::Pid;
        match signal::kill(Pid::from_raw(pid as i32), None) {
            Ok(()) => true,            // Process exists, we can signal it
            Err(Errno::EPERM) => true, // Process exists, but we lack permission
            Err(_) => false,           // ESRCH or other — process is gone
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

// ---------------------------------------------------------------------------
// Session types
// ---------------------------------------------------------------------------

/// Statistics collected during a supervisor session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionStats {
    /// Total syscall events intercepted (including noise).
    pub total_intercepted: u64,
    /// Events that the proxy allowed.
    pub total_allowed: u64,
    /// Events that were queued for human review.
    pub total_queued: u64,
    /// Events that the proxy denied.
    pub total_denied: u64,
    /// Events filtered out as noise before reaching the proxy.
    pub total_filtered_noise: u64,
}

impl SessionStats {
    /// Increment the intercepted counter and return the new total.
    pub(crate) fn tick(&mut self) -> u64 {
        self.total_intercepted += 1;
        self.total_intercepted
    }

    /// Count of calls the proxy actually evaluated (allowed/queued/denied),
    /// excluding noise-filtered syscalls. Used as the "meaningful activity"
    /// signal that drives the session's idle age — noise must not reset idle.
    pub fn proxy_evals(&self) -> u64 {
        self.total_allowed + self.total_queued + self.total_denied
    }
}

/// A single active supervisor session tracking one supervised CLI tool.
pub struct SupervisorSession {
    /// Unique identifier for this session.
    pub id: Uuid,
    /// Human-readable tool name (e.g., "claude-code", "codex", "aider").
    pub tool_name: String,
    /// The supervisor profile name (e.g., "claude-code", "codex", "aider").
    /// Used to apply per-profile destination policies in the egress filter.
    pub profile_name: Option<String>,
    /// Effective policy scope key for learned-rule and reputation isolation.
    ///
    /// Examples:
    /// - `codex`
    /// - `codex+launcher:vscode-terminal`
    /// - `grith-repl+provider:openai`
    pub policy_scope: Option<String>,
    /// Applied launcher overlay name, if any.
    pub launcher_overlay_name: Option<String>,
    /// Applied provider overlay name, if any.
    pub provider_overlay_name: Option<String>,
    /// The root PID of the supervised process tree.
    pub root_pid: u32,
    /// Tracks forked/exec'd children of the root process.
    pub process_tree: ProcessTree,
    /// When the session was created.
    pub started_at: Instant,
    /// Last time this session was synced via IPC (heartbeat).
    /// Used by `reap_dead()` to detect stale thin-client sessions whose
    /// PID liveness checks may be unreliable (e.g. ptraced processes).
    ///
    /// This is a pure liveness signal — it is refreshed on *every* snapshot
    /// push (including noise-only traffic), so it must NOT be used as the
    /// session's idle age. Use `last_activity_at` for that.
    pub last_synced_at: Instant,
    /// Last time the proxy evaluated a real (non-noise) call for this session.
    /// Bumped by the sync paths when `stats.proxy_evals()` increases. Drives
    /// the dashboard "Idle" column so background noise does not pin idle to 0.
    pub last_activity_at: Instant,
    /// Cumulative statistics for this session.
    pub stats: SessionStats,
    /// Project name derived from the working directory (e.g., "grith-website").
    pub project_name: Option<String>,
    /// Absolute working directory the supervised tool was launched from.
    /// Surfaced in `grith exec list` and the dashboard so an operator can
    /// locate a forgotten/orphaned session.
    pub cwd: Option<String>,
    /// Controlling terminal of the launching CLI (e.g. "pts/21"). The single
    /// most useful "where do I go to close this" hint for a human.
    pub tty: Option<String>,
    /// Wedge-watchdog dedup: tids we've already reported as wedged this
    /// session. Avoids spamming the log + audit DB on every 10s scan when
    /// the same tid stays stuck. Cleared at session end.
    pub wedge_reported_tids: std::collections::HashSet<u32>,
    /// H2 Option 1: the supervised tool's own controlling terminal (e.g.
    /// `/dev/pts/3`), resolved once (lazily) from `/proc/<root_pid>/fd/0` and
    /// cached. `Some(None)` means "resolved, but not a pts" (redirected
    /// stdin). Used to distinguish writes to the tool's own terminal from
    /// writes injected into a sibling pane's pts.
    pub controlling_pts: std::sync::OnceLock<Option<String>>,
}

impl SupervisorSession {
    /// Create a new session. Call this after spawning or attaching to the root
    /// process but before entering the event loop.
    pub fn new(tool_name: impl Into<String>, root_pid: u32) -> Self {
        let name = tool_name.into();
        let now = Instant::now();
        Self {
            id: Uuid::new_v4(),
            process_tree: ProcessTree::new(root_pid, &name),
            tool_name: name,
            profile_name: None,
            policy_scope: None,
            launcher_overlay_name: None,
            provider_overlay_name: None,
            root_pid,
            started_at: now,
            last_synced_at: now,
            last_activity_at: now,
            stats: SessionStats::default(),
            project_name: None,
            cwd: None,
            tty: None,
            wedge_reported_tids: std::collections::HashSet::new(),
            controlling_pts: std::sync::OnceLock::new(),
        }
    }

    /// H2 Option 1: the supervised tool's controlling pts (`/dev/pts/N`),
    /// resolved once from `/proc/<root_pid>/fd/0` and cached. Returns `None`
    /// if stdin is not a pts or the link can't be read.
    pub fn controlling_pts(&self) -> Option<&str> {
        self.controlling_pts
            .get_or_init(|| {
                std::fs::read_link(format!("/proc/{}/fd/0", self.root_pid))
                    .ok()
                    .and_then(|p| p.to_str().map(str::to_string))
                    .filter(|s| s.starts_with("/dev/pts/"))
            })
            .as_deref()
    }

    /// Wall-clock seconds since the session was created.
    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Scope identifier used for learned rules and reputation.
    pub fn scope_name(&self) -> Option<&str> {
        self.policy_scope
            .as_deref()
            .or(self.profile_name.as_deref())
    }

    /// Produce a lightweight summary suitable for list endpoints.
    pub fn summary(&self) -> SessionSummary {
        SessionSummary {
            id: self.id,
            tool_name: self.tool_name.clone(),
            project_name: self.project_name.clone(),
            cwd: self.cwd.clone(),
            tty: self.tty.clone(),
            root_pid: self.root_pid,
            uptime_seconds: self.started_at.elapsed().as_secs(),
            // Seconds since the last *meaningful* (proxy-evaluated, non-noise)
            // call — the session's idle age. Decoupled from the liveness
            // heartbeat (`last_synced_at`) so background noise traffic does not
            // pin idle to 0.
            last_activity_seconds: self.last_activity_at.elapsed().as_secs(),
            stats: self.stats.clone(),
            containment_remaining_seconds: None,
        }
    }

    /// Produce a summary enriched with containment state from the tracker.
    pub fn summary_with_containment(
        &self,
        tracker: &grith_proxy::filters::session_containment::ContainmentTracker,
    ) -> SessionSummary {
        let mut s = self.summary();
        s.containment_remaining_seconds = tracker.remaining_seconds(self.id);
        s
    }
}

/// Compact, serializable snapshot of a session for API / CLI listing.
#[derive(Debug, Clone, Serialize)]
pub struct SessionSummary {
    pub id: Uuid,
    pub tool_name: String,
    /// Project name derived from the working directory (e.g., "grith-website").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_name: Option<String>,
    /// Absolute working directory the supervised tool was launched from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Controlling terminal of the launching CLI (e.g. "pts/21").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tty: Option<String>,
    pub root_pid: u32,
    pub uptime_seconds: u64,
    /// Seconds since the last heartbeat/activity — the session's "idle" age.
    #[serde(default)]
    pub last_activity_seconds: u64,
    pub stats: SessionStats,
    /// Remaining seconds of containment, or `None` if this session is not
    /// currently in containment mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containment_remaining_seconds: Option<u64>,
}

// ---------------------------------------------------------------------------
// Session registry
// ---------------------------------------------------------------------------

/// Thread-safe registry that tracks all active supervisor sessions and
/// enforces the configured concurrency limit.
pub struct SupervisorRegistry {
    sessions: HashMap<Uuid, SupervisorSession>,
    config: SupervisorConfig,
    max_sessions: usize,
}

impl SupervisorRegistry {
    /// Create an empty registry bound to the given configuration.
    pub fn new(config: SupervisorConfig) -> Self {
        let max_sessions = config.max_concurrent_sessions;
        Self {
            sessions: HashMap::new(),
            config,
            max_sessions,
        }
    }

    /// Register a new session.
    ///
    /// Returns `Error::SessionLimitReached` if the concurrency limit would be
    /// exceeded.
    pub fn register(&mut self, session: SupervisorSession) -> Result<()> {
        if self.sessions.len() >= self.max_sessions {
            return Err(Error::SessionLimitReached(self.max_sessions));
        }
        self.sessions.insert(session.id, session);
        Ok(())
    }

    /// Get an immutable reference to a session by ID.
    pub fn get(&self, id: &Uuid) -> Option<&SupervisorSession> {
        self.sessions.get(id)
    }

    /// Get a mutable reference to a session by ID.
    pub fn get_mut(&mut self, id: &Uuid) -> Option<&mut SupervisorSession> {
        self.sessions.get_mut(id)
    }

    /// Remove and return a session (e.g., on detach or shutdown).
    pub fn remove(&mut self, id: &Uuid) -> Option<SupervisorSession> {
        self.sessions.remove(id)
    }

    /// Return lightweight summaries of every active session.
    pub fn list(&self) -> Vec<SessionSummary> {
        self.sessions.values().map(|s| s.summary()).collect()
    }

    /// Number of currently tracked sessions.
    pub fn count(&self) -> usize {
        self.sessions.len()
    }

    /// Remove sessions that are no longer alive.
    ///
    /// A session is considered dead if its last IPC sync was more than 30
    /// seconds ago **and** its root PID is no longer alive. The sync-staleness
    /// check prevents false-positive reaping of thin-client sessions whose
    /// ptraced child PID may not respond to `kill(pid, 0)` from the daemon
    /// process due to YAMA ptrace_scope restrictions.
    pub fn reap_dead(&mut self) -> usize {
        let stale_threshold = Duration::from_secs(30);
        let dead: Vec<uuid::Uuid> = self
            .sessions
            .iter()
            .filter(|(_, s)| {
                let sync_stale = s.last_synced_at.elapsed() > stale_threshold;
                let pid_dead = !is_pid_alive(s.root_pid);
                // Only reap if the session has gone silent AND the PID is dead.
                sync_stale && pid_dead
            })
            .map(|(id, _)| *id)
            .collect();
        let n = dead.len();
        for id in dead {
            self.sessions.remove(&id);
        }
        n
    }

    /// Override the maximum concurrent sessions limit.
    ///
    /// Used by the daemon to enforce license-based seat caps that may be lower
    /// than the configuration value.
    pub fn set_max_sessions(&mut self, max: usize) {
        self.max_sessions = max;
    }

    /// Effective maximum concurrent sessions currently enforced.
    pub fn max_sessions(&self) -> usize {
        self.max_sessions
    }

    /// Read-only access to the underlying config.
    pub fn config(&self) -> &SupervisorConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- SessionStats tests ---

    #[test]
    fn session_stats_default_is_zeroed() {
        let stats = SessionStats::default();
        assert_eq!(stats.total_intercepted, 0);
        assert_eq!(stats.total_allowed, 0);
        assert_eq!(stats.total_queued, 0);
        assert_eq!(stats.total_denied, 0);
        assert_eq!(stats.total_filtered_noise, 0);
    }

    #[test]
    fn session_stats_tick_increments() {
        let mut stats = SessionStats::default();
        assert_eq!(stats.tick(), 1);
        assert_eq!(stats.tick(), 2);
        assert_eq!(stats.total_intercepted, 2);
    }

    #[test]
    fn session_stats_serde_roundtrip() {
        let stats = SessionStats {
            total_intercepted: 100,
            total_allowed: 80,
            total_queued: 15,
            total_denied: 3,
            total_filtered_noise: 2,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let parsed: SessionStats = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_intercepted, 100);
        assert_eq!(parsed.total_allowed, 80);
        assert_eq!(parsed.total_queued, 15);
        assert_eq!(parsed.total_denied, 3);
        assert_eq!(parsed.total_filtered_noise, 2);
    }

    #[test]
    fn session_stats_clone() {
        let stats = SessionStats {
            total_intercepted: 42,
            ..Default::default()
        };
        let cloned = stats.clone();
        assert_eq!(cloned.total_intercepted, 42);
    }

    // --- SupervisorSession tests ---

    #[test]
    fn session_new_sets_fields() {
        let session = SupervisorSession::new("claude-code", 12345);
        assert_eq!(session.tool_name, "claude-code");
        assert_eq!(session.root_pid, 12345);
        assert_eq!(session.stats.total_intercepted, 0);
    }

    #[test]
    fn session_uptime_is_nonnegative() {
        let session = SupervisorSession::new("aider", 1);
        let uptime = session.uptime();
        // Should be very close to zero, but non-negative.
        assert!(uptime.as_nanos() < 1_000_000_000); // < 1 second
    }

    #[test]
    fn session_summary_captures_snapshot() {
        let mut session = SupervisorSession::new("codex", 9999);
        session.stats.total_intercepted = 50;
        session.stats.total_allowed = 40;
        session.stats.total_denied = 5;
        session.stats.total_queued = 3;
        session.stats.total_filtered_noise = 2;

        let summary = session.summary();
        assert_eq!(summary.id, session.id);
        assert_eq!(summary.tool_name, "codex");
        assert_eq!(summary.root_pid, 9999);
        assert_eq!(summary.stats.total_intercepted, 50);
        assert_eq!(summary.stats.total_allowed, 40);
    }

    #[test]
    fn session_scope_name_prefers_policy_scope() {
        let mut session = SupervisorSession::new("codex", 9999);
        session.profile_name = Some("codex".into());
        assert_eq!(session.scope_name(), Some("codex"));

        session.policy_scope = Some("codex+launcher:vscode-terminal".into());
        assert_eq!(session.scope_name(), Some("codex+launcher:vscode-terminal"));
    }

    // --- SessionSummary tests ---

    #[test]
    fn session_summary_serialization() {
        let summary = SessionSummary {
            id: Uuid::nil(),
            tool_name: "claude-code".into(),
            project_name: None,
            cwd: None,
            tty: None,
            root_pid: 42,
            uptime_seconds: 120,
            last_activity_seconds: 5,
            stats: SessionStats {
                total_intercepted: 10,
                total_allowed: 8,
                total_queued: 1,
                total_denied: 1,
                total_filtered_noise: 0,
            },
            containment_remaining_seconds: None,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("claude-code"));
        assert!(json.contains("42"));
        assert!(json.contains("120"));
        // containment_remaining_seconds is skipped when None
        assert!(!json.contains("containment_remaining_seconds"));
    }

    #[test]
    fn session_summary_serialization_with_containment() {
        let summary = SessionSummary {
            id: Uuid::nil(),
            tool_name: "codex".into(),
            project_name: None,
            cwd: None,
            tty: None,
            root_pid: 10,
            uptime_seconds: 60,
            last_activity_seconds: 0,
            stats: SessionStats::default(),
            containment_remaining_seconds: Some(245),
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("containment_remaining_seconds"));
        assert!(json.contains("245"));
    }

    #[test]
    fn session_summary_contains_id_and_name() {
        let id = Uuid::new_v4();
        let summary = SessionSummary {
            id,
            tool_name: "aider".into(),
            project_name: None,
            cwd: None,
            tty: None,
            root_pid: 1,
            uptime_seconds: 0,
            last_activity_seconds: 0,
            stats: SessionStats::default(),
            containment_remaining_seconds: None,
        };
        assert_eq!(summary.id, id);
        assert_eq!(summary.tool_name, "aider");
    }

    // --- SupervisorRegistry tests ---

    fn test_config() -> SupervisorConfig {
        SupervisorConfig::default()
    }

    #[test]
    fn registry_new_is_empty() {
        let reg = SupervisorRegistry::new(test_config());
        assert_eq!(reg.count(), 0);
        assert!(reg.list().is_empty());
    }

    #[test]
    fn registry_register_and_get() {
        let mut reg = SupervisorRegistry::new(test_config());
        let session = SupervisorSession::new("claude-code", 100);
        let id = session.id;
        reg.register(session).unwrap();

        assert_eq!(reg.count(), 1);
        let s = reg.get(&id).unwrap();
        assert_eq!(s.tool_name, "claude-code");
        assert_eq!(s.root_pid, 100);
    }

    #[test]
    fn registry_get_mut_updates() {
        let mut reg = SupervisorRegistry::new(test_config());
        let session = SupervisorSession::new("codex", 200);
        let id = session.id;
        reg.register(session).unwrap();

        let s = reg.get_mut(&id).unwrap();
        s.stats.total_intercepted = 42;

        assert_eq!(reg.get(&id).unwrap().stats.total_intercepted, 42);
    }

    #[test]
    fn registry_remove() {
        let mut reg = SupervisorRegistry::new(test_config());
        let session = SupervisorSession::new("aider", 300);
        let id = session.id;
        reg.register(session).unwrap();

        let removed = reg.remove(&id);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().tool_name, "aider");
        assert_eq!(reg.count(), 0);
        assert!(reg.get(&id).is_none());
    }

    #[test]
    fn registry_remove_nonexistent_returns_none() {
        let mut reg = SupervisorRegistry::new(test_config());
        assert!(reg.remove(&Uuid::new_v4()).is_none());
    }

    #[test]
    fn registry_list_returns_all_summaries() {
        let mut reg = SupervisorRegistry::new(test_config());
        reg.register(SupervisorSession::new("a", 1)).unwrap();
        reg.register(SupervisorSession::new("b", 2)).unwrap();
        reg.register(SupervisorSession::new("c", 3)).unwrap();

        let list = reg.list();
        assert_eq!(list.len(), 3);

        let names: Vec<&str> = list.iter().map(|s| s.tool_name.as_str()).collect();
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
        assert!(names.contains(&"c"));
    }

    #[test]
    fn registry_enforces_session_limit() {
        let mut config = test_config();
        config.max_concurrent_sessions = 2;
        let mut reg = SupervisorRegistry::new(config);

        reg.register(SupervisorSession::new("a", 1)).unwrap();
        reg.register(SupervisorSession::new("b", 2)).unwrap();

        let result = reg.register(SupervisorSession::new("c", 3));
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::SessionLimitReached(max) => assert_eq!(max, 2),
            other => panic!("expected SessionLimitReached, got: {other}"),
        }
    }

    #[test]
    fn registry_allows_reuse_after_remove() {
        let mut config = test_config();
        config.max_concurrent_sessions = 1;
        let mut reg = SupervisorRegistry::new(config);

        let session = SupervisorSession::new("a", 1);
        let id = session.id;
        reg.register(session).unwrap();

        // At limit now.
        assert!(reg.register(SupervisorSession::new("b", 2)).is_err());

        // Remove the first session.
        reg.remove(&id);

        // Should succeed now.
        reg.register(SupervisorSession::new("b", 2)).unwrap();
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn registry_get_nonexistent_returns_none() {
        let reg = SupervisorRegistry::new(test_config());
        assert!(reg.get(&Uuid::new_v4()).is_none());
    }

    #[test]
    fn registry_reports_effective_max_sessions() {
        let mut reg = SupervisorRegistry::new(test_config());
        assert_eq!(reg.max_sessions(), test_config().max_concurrent_sessions);
        reg.set_max_sessions(1);
        assert_eq!(reg.max_sessions(), 1);
    }
}
