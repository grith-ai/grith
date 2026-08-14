// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Core digest data types: items, statuses, review actions, and severity levels.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Status of a digest queue item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestStatus {
    /// Awaiting human review.
    Pending,
    /// Reviewer approved the call.
    Approved,
    /// Reviewer denied the call.
    Denied,
    /// Review window elapsed without action.
    Expired,
    /// Forwarded for senior review.
    Escalated,
}

impl std::fmt::Display for DigestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Approved => write!(f, "approved"),
            Self::Denied => write!(f, "denied"),
            Self::Expired => write!(f, "expired"),
            Self::Escalated => write!(f, "escalated"),
        }
    }
}

impl DigestStatus {
    /// Parse a status string, falling back to `Pending` for unrecognized values.
    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "approved" => Self::Approved,
            "denied" => Self::Denied,
            "expired" => Self::Expired,
            "escalated" => Self::Escalated,
            _ => Self::Pending,
        }
    }
}

/// Outcome of waiting for a digest item to be reviewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewOutcome {
    /// The item was approved by a reviewer.
    Approved,
    /// The item was denied by a reviewer.
    Denied,
    /// The review window expired without a decision.
    TimedOut,
}

/// A directory-scoped, operation-specific permission requested by a reviewer.
///
/// Scoped permissions are session-only in v1. The `persist` field is retained
/// in the wire format so a future persistence flow can add an explicit opt-in
/// without changing the action schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ScopedAllowRequest {
    /// Directory whose subtree should be allowed.
    pub directory: String,
    /// Allow file reads and directory listings.
    pub read: bool,
    /// Allow file writes, appends, and directory creation.
    pub write: bool,
    /// Allow file deletion and rename removal from the directory.
    pub delete: bool,
    /// Whether the rule should be persisted for the active profile.
    pub persist: bool,
}

/// Structured action returned by an interactive permission reviewer.
///
/// Existing actions continue to be stored as their legacy string values.
/// Scoped actions are stored as JSON so their directory and operation bits
/// survive the digest queue round trip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", content = "scope", rename_all = "snake_case")]
pub enum PermissionReviewAction {
    /// Allow only the current request.
    Approve,
    /// Deny the current request.
    Deny,
    /// Allow the current request and persist its exact learned rule.
    ApproveAndLearn,
    /// Allow the current request and add session-scoped directory rules.
    ScopedAllow(ScopedAllowRequest),
    /// Deny the request and terminate the supervised process.
    DenyAndTerminate,
}

impl PermissionReviewAction {
    /// Whether this action allows the current request to proceed.
    pub fn is_approved(&self) -> bool {
        matches!(
            self,
            Self::Approve | Self::ApproveAndLearn | Self::ScopedAllow(_)
        )
    }

    /// Serialize for the existing `digest_queue.review_action` text column.
    pub fn to_storage_value(&self) -> String {
        match self {
            Self::Approve => "approve".to_string(),
            Self::Deny => "deny".to_string(),
            Self::ApproveAndLearn => "approve_and_learn".to_string(),
            Self::DenyAndTerminate => "deny_and_terminate".to_string(),
            Self::ScopedAllow(_) => serde_json::to_string(self)
                .expect("PermissionReviewAction serialization cannot fail"),
        }
    }

    /// Parse either a legacy action string or a structured JSON action.
    pub fn from_storage_value(value: &str) -> Option<Self> {
        match value {
            "approve" => Some(Self::Approve),
            "deny" => Some(Self::Deny),
            "approve_and_learn" => Some(Self::ApproveAndLearn),
            "deny_and_terminate" => Some(Self::DenyAndTerminate),
            _ => serde_json::from_str(value).ok(),
        }
    }
}

/// The action a reviewer can take on a digest item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewAction {
    /// Allow the queued tool call to proceed.
    Approve,
    /// Block the queued tool call.
    Deny,
    /// Approve and record a learned reputation signal for future trust decisions.
    ApproveAndLearn,
    /// Forward to senior review without deciding.
    Escalate,
    /// Approve the call and lift egress containment for the session.
    UnlockEgress,
    /// Deny the call and signal the supervisor to terminate the process.
    DenyAndTerminate,
    /// Approve the call and add destination/pattern to permanent allowlist.
    AllowAlways,
}

impl std::fmt::Display for ReviewAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Approve => write!(f, "approve"),
            Self::Deny => write!(f, "deny"),
            Self::ApproveAndLearn => write!(f, "approve_and_learn"),
            Self::Escalate => write!(f, "escalate"),
            Self::UnlockEgress => write!(f, "unlock_egress"),
            Self::DenyAndTerminate => write!(f, "deny_and_terminate"),
            Self::AllowAlways => write!(f, "allow_always"),
        }
    }
}

/// Severity classification for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreSeverity {
    /// Score below 4.0.
    Low,
    /// Score 4.0 to 5.5.
    Medium,
    /// Score 5.5 to 7.0.
    High,
    /// Score 7.0 and above.
    Critical,
}

impl ScoreSeverity {
    /// Map a composite proxy score to a severity level.
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s >= 7.0 => Self::Critical,
            s if s >= 5.5 => Self::High,
            s if s >= 4.0 => Self::Medium,
            _ => Self::Low,
        }
    }
}

/// Filter breakdown for a digest item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterBreakdown {
    pub filter_name: String,
    pub score: f64,
    pub rule_id: String,
    pub message: String,
}

/// A digest item for display and review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestItem {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    /// Session ID associated with this decision when available.
    /// Needed for actions such as containment unlock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
    pub tool_call_type: String,
    pub arguments_summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,
    pub composite_score: f64,
    pub severity: ScoreSeverity,
    pub filter_breakdown: Vec<FilterBreakdown>,
    pub task_context: Option<String>,
    pub plugin_id: String,
    pub status: DigestStatus,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub review_action: Option<String>,
    pub reviewer_notes: Option<String>,
    /// Whether this item was auto-denied (informational only, not actionable).
    pub informational_only: bool,
    /// When this item was escalated for senior review.
    pub escalated_at: Option<DateTime<Utc>>,
    /// Who escalated this item (e.g., "cli", "dashboard", or a username).
    pub escalated_by: Option<String>,
}

impl DigestItem {
    /// Generate a human-readable summary of what the agent was trying to do.
    pub fn human_summary(&self) -> String {
        let action = match self.tool_call_type.as_str() {
            "FileRead" => "read a file",
            "FileWrite" => "write to a file",
            "FileAppend" => "append to a file",
            "FileDelete" => "delete a file",
            "DirList" => "list a directory",
            "ShellExec" => "execute a shell command",
            "HttpRequest" => "make an HTTP request",
            _ => "perform an action",
        };
        format!("Agent attempted to {action}: {}", self.arguments_summary)
    }

    /// Whether this item can be acted upon (not already reviewed, not informational).
    pub fn is_actionable(&self) -> bool {
        (self.status == DigestStatus::Pending || self.status == DigestStatus::Escalated)
            && !self.informational_only
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_severity() {
        assert_eq!(ScoreSeverity::from_score(3.0), ScoreSeverity::Low);
        assert_eq!(ScoreSeverity::from_score(4.5), ScoreSeverity::Medium);
        assert_eq!(ScoreSeverity::from_score(6.0), ScoreSeverity::High);
        assert_eq!(ScoreSeverity::from_score(7.5), ScoreSeverity::Critical);
    }

    #[test]
    fn test_digest_status_display() {
        assert_eq!(DigestStatus::Pending.to_string(), "pending");
        assert_eq!(DigestStatus::Approved.to_string(), "approved");
        assert_eq!(DigestStatus::Escalated.to_string(), "escalated");
    }

    #[test]
    fn test_digest_status_from_str_lossy() {
        assert_eq!(
            DigestStatus::from_str_lossy("escalated"),
            DigestStatus::Escalated
        );
        assert_eq!(
            DigestStatus::from_str_lossy("unknown"),
            DigestStatus::Pending
        );
    }

    #[test]
    fn test_review_action_display() {
        assert_eq!(ReviewAction::Escalate.to_string(), "escalate");
    }

    #[test]
    fn permission_review_action_preserves_legacy_storage_values() {
        for (action, stored) in [
            (PermissionReviewAction::Approve, "approve"),
            (PermissionReviewAction::Deny, "deny"),
            (PermissionReviewAction::ApproveAndLearn, "approve_and_learn"),
            (
                PermissionReviewAction::DenyAndTerminate,
                "deny_and_terminate",
            ),
        ] {
            assert_eq!(action.to_storage_value(), stored);
            assert_eq!(
                PermissionReviewAction::from_storage_value(stored),
                Some(action)
            );
        }
    }

    #[test]
    fn scoped_permission_review_action_round_trips_as_json() {
        let action = PermissionReviewAction::ScopedAllow(ScopedAllowRequest {
            directory: "/repo/target/debug/deps/".to_string(),
            read: false,
            write: false,
            delete: true,
            persist: false,
        });

        let stored = action.to_storage_value();
        assert!(stored.starts_with('{'));
        assert_eq!(
            PermissionReviewAction::from_storage_value(&stored),
            Some(action)
        );
    }

    #[test]
    fn test_human_summary() {
        let item = DigestItem {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            session_id: None,
            tool_call_type: "ShellExec".into(),
            arguments_summary: "rm -rf /tmp/test".into(),
            decision_reason: Some("review required".into()),
            composite_score: 5.0,
            severity: ScoreSeverity::Medium,
            filter_breakdown: vec![],
            task_context: None,
            plugin_id: "shell".into(),
            status: DigestStatus::Pending,
            reviewed_at: None,
            review_action: None,
            reviewer_notes: None,
            informational_only: false,
            escalated_at: None,
            escalated_by: None,
        };
        assert!(item.human_summary().contains("execute a shell command"));
    }

    #[test]
    fn test_actionable() {
        let mut item = DigestItem {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            session_id: None,
            tool_call_type: "FileRead".into(),
            arguments_summary: "test".into(),
            decision_reason: None,
            composite_score: 5.0,
            severity: ScoreSeverity::Medium,
            filter_breakdown: vec![],
            task_context: None,
            plugin_id: "file-ops".into(),
            status: DigestStatus::Pending,
            reviewed_at: None,
            review_action: None,
            reviewer_notes: None,
            informational_only: false,
            escalated_at: None,
            escalated_by: None,
        };
        assert!(item.is_actionable());

        item.informational_only = true;
        assert!(!item.is_actionable());

        item.informational_only = false;
        item.status = DigestStatus::Approved;
        assert!(!item.is_actionable());

        // Escalated items are still actionable (need final approve/deny)
        item.status = DigestStatus::Escalated;
        assert!(item.is_actionable());
    }
}
