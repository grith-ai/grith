// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Digest review actions: approve, deny, learn, escalate, and containment controls.

use crate::error::{Error, Result};
use crate::queue::DigestQueue;
use crate::types::{DigestStatus, ReviewAction};
use uuid::Uuid;

/// Digest review actions: approve, deny, approve-and-learn.
pub struct DigestActions<'a> {
    queue: &'a DigestQueue,
}

impl<'a> DigestActions<'a> {
    /// Create a new actions handler backed by the given queue.
    pub fn new(queue: &'a DigestQueue) -> Self {
        Self { queue }
    }

    /// Approve a pending digest item.
    pub fn approve(&self, id: &Uuid) -> Result<()> {
        self.validate_actionable(id)?;
        self.queue
            .update_status(id, DigestStatus::Approved, Some("approve"), None)
    }

    /// Deny a pending digest item.
    pub fn deny(&self, id: &Uuid) -> Result<()> {
        self.validate_actionable(id)?;
        self.queue
            .update_status(id, DigestStatus::Denied, Some("deny"), None)
    }

    /// Approve and record a learned reputation signal.
    pub fn approve_and_learn(&self, id: &Uuid) -> Result<()> {
        self.validate_actionable(id)?;
        self.queue
            .update_status(id, DigestStatus::Approved, Some("approve_and_learn"), None)
    }

    /// Add reviewer notes to an item.
    pub fn add_notes(&self, id: &Uuid, notes: &str) -> Result<()> {
        let item = self.queue.get_by_id(id)?;
        self.queue
            .update_status(id, item.status, item.review_action.as_deref(), Some(notes))
    }

    /// Escalate a pending item for senior review.
    pub fn escalate(&self, id: &Uuid, escalated_by: Option<&str>) -> Result<()> {
        self.validate_escalatable(id)?;
        self.queue.update_escalation(id, escalated_by)
    }

    /// Approve and lift egress containment for the session.
    pub fn unlock_egress(&self, id: &Uuid) -> Result<()> {
        self.validate_actionable(id)?;
        self.queue
            .update_status(id, DigestStatus::Approved, Some("unlock_egress"), None)
    }

    /// Deny the call and flag for process termination.
    pub fn deny_and_terminate(&self, id: &Uuid) -> Result<()> {
        self.validate_actionable(id)?;
        self.queue
            .update_status(id, DigestStatus::Denied, Some("deny_and_terminate"), None)
    }

    /// Approve and flag for permanent policy allowlisting.
    pub fn allow_always(&self, id: &Uuid) -> Result<()> {
        self.validate_actionable(id)?;
        self.queue
            .update_status(id, DigestStatus::Approved, Some("allow_always"), None)
    }

    /// Perform a review action.
    pub fn review(&self, id: &Uuid, action: ReviewAction, notes: Option<&str>) -> Result<()> {
        if action == ReviewAction::Escalate {
            return self.escalate(id, None);
        }
        self.validate_actionable(id)?;
        let (status, action_str) = match action {
            ReviewAction::Approve => (DigestStatus::Approved, "approve"),
            ReviewAction::Deny => (DigestStatus::Denied, "deny"),
            ReviewAction::ApproveAndLearn => (DigestStatus::Approved, "approve_and_learn"),
            ReviewAction::Escalate => {
                tracing::error!("ReviewAction::Escalate reached match arm that should be handled by early return");
                return Err(Error::InvalidAction(
                    "escalate should be handled before this point".into(),
                ));
            }
            ReviewAction::UnlockEgress => (DigestStatus::Approved, "unlock_egress"),
            ReviewAction::DenyAndTerminate => (DigestStatus::Denied, "deny_and_terminate"),
            ReviewAction::AllowAlways => (DigestStatus::Approved, "allow_always"),
        };
        self.queue
            .update_status(id, status, Some(action_str), notes)
    }

    /// Validate that an item can be approved/denied (Pending or Escalated, not informational).
    fn validate_actionable(&self, id: &Uuid) -> Result<()> {
        let item = self.queue.get_by_id(id)?;
        if item.status != DigestStatus::Pending && item.status != DigestStatus::Escalated {
            return Err(Error::InvalidAction(format!(
                "item {} is already {} and cannot be reviewed",
                id, item.status
            )));
        }
        if item.informational_only {
            return Err(Error::InvalidAction(format!(
                "item {} is informational only (auto-denied) and cannot be approved",
                id
            )));
        }
        Ok(())
    }

    /// Validate that an item can be escalated (must be Pending, not already escalated/reviewed).
    fn validate_escalatable(&self, id: &Uuid) -> Result<()> {
        let item = self.queue.get_by_id(id)?;
        if item.status != DigestStatus::Pending {
            return Err(Error::InvalidAction(format!(
                "item {} is {} and can only be escalated from pending status",
                id, item.status
            )));
        }
        if item.informational_only {
            return Err(Error::InvalidAction(format!(
                "item {} is informational only and cannot be escalated",
                id
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use chrono::Utc;

    fn make_queue_with_items() -> (DigestQueue, Uuid, Uuid) {
        let queue = DigestQueue::open_in_memory().unwrap();
        let normal = DigestItem {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            session_id: None,
            tool_call_type: "FileRead".into(),
            arguments_summary: "/etc/shadow".into(),
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
        let info = DigestItem {
            id: Uuid::new_v4(),
            session_id: None,
            informational_only: true,
            composite_score: 9.5,
            severity: ScoreSeverity::Critical,
            ..normal.clone()
        };
        let normal_id = normal.id;
        let info_id = info.id;
        queue.enqueue(&normal).unwrap();
        queue.enqueue(&info).unwrap();
        (queue, normal_id, info_id)
    }

    #[test]
    fn test_approve() {
        let (queue, id, _) = make_queue_with_items();
        let actions = DigestActions::new(&queue);
        actions.approve(&id).unwrap();

        let item = queue.get_by_id(&id).unwrap();
        assert_eq!(item.status, DigestStatus::Approved);
        assert!(item.reviewed_at.is_some());
    }

    #[test]
    fn test_deny() {
        let (queue, id, _) = make_queue_with_items();
        let actions = DigestActions::new(&queue);
        actions.deny(&id).unwrap();

        let item = queue.get_by_id(&id).unwrap();
        assert_eq!(item.status, DigestStatus::Denied);
    }

    #[test]
    fn test_approve_and_learn() {
        let (queue, id, _) = make_queue_with_items();
        let actions = DigestActions::new(&queue);
        actions.approve_and_learn(&id).unwrap();

        let item = queue.get_by_id(&id).unwrap();
        assert_eq!(item.status, DigestStatus::Approved);
        assert_eq!(item.review_action.as_deref(), Some("approve_and_learn"));
    }

    #[test]
    fn test_cannot_review_already_reviewed() {
        let (queue, id, _) = make_queue_with_items();
        let actions = DigestActions::new(&queue);
        actions.approve(&id).unwrap();

        let result = actions.deny(&id);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already"));
    }

    #[test]
    fn test_cannot_approve_informational() {
        let (queue, _, info_id) = make_queue_with_items();
        let actions = DigestActions::new(&queue);

        let result = actions.approve(&info_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("informational"));
    }

    #[test]
    fn test_add_notes() {
        let (queue, id, _) = make_queue_with_items();
        let actions = DigestActions::new(&queue);
        actions.add_notes(&id, "looks suspicious").unwrap();

        let item = queue.get_by_id(&id).unwrap();
        assert_eq!(item.reviewer_notes.as_deref(), Some("looks suspicious"));
    }

    #[test]
    fn test_escalate() {
        let (queue, id, _) = make_queue_with_items();
        let actions = DigestActions::new(&queue);
        actions.escalate(&id, Some("cli")).unwrap();

        let item = queue.get_by_id(&id).unwrap();
        assert_eq!(item.status, DigestStatus::Escalated);
        assert!(item.escalated_at.is_some());
        assert_eq!(item.escalated_by.as_deref(), Some("cli"));
    }

    #[test]
    fn test_cannot_re_escalate() {
        let (queue, id, _) = make_queue_with_items();
        let actions = DigestActions::new(&queue);
        actions.escalate(&id, None).unwrap();

        let result = actions.escalate(&id, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_approve_escalated_item() {
        let (queue, id, _) = make_queue_with_items();
        let actions = DigestActions::new(&queue);
        actions.escalate(&id, None).unwrap();

        // Escalated items can still be approved/denied
        actions.approve(&id).unwrap();
        let item = queue.get_by_id(&id).unwrap();
        assert_eq!(item.status, DigestStatus::Approved);
    }

    #[test]
    fn test_cannot_escalate_informational() {
        let (queue, _, info_id) = make_queue_with_items();
        let actions = DigestActions::new(&queue);

        let result = actions.escalate(&info_id, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("informational"));
    }

    #[test]
    fn test_unlock_egress() {
        let (queue, id, _) = make_queue_with_items();
        let actions = DigestActions::new(&queue);
        actions.unlock_egress(&id).unwrap();

        let item = queue.get_by_id(&id).unwrap();
        assert_eq!(item.status, DigestStatus::Approved);
        assert_eq!(item.review_action.as_deref(), Some("unlock_egress"));
    }

    #[test]
    fn test_deny_and_terminate() {
        let (queue, id, _) = make_queue_with_items();
        let actions = DigestActions::new(&queue);
        actions.deny_and_terminate(&id).unwrap();

        let item = queue.get_by_id(&id).unwrap();
        assert_eq!(item.status, DigestStatus::Denied);
        assert_eq!(item.review_action.as_deref(), Some("deny_and_terminate"));
    }

    #[test]
    fn test_allow_always() {
        let (queue, id, _) = make_queue_with_items();
        let actions = DigestActions::new(&queue);
        actions.allow_always(&id).unwrap();

        let item = queue.get_by_id(&id).unwrap();
        assert_eq!(item.status, DigestStatus::Approved);
        assert_eq!(item.review_action.as_deref(), Some("allow_always"));
    }

    #[test]
    fn test_review_unlock_egress() {
        let (queue, id, _) = make_queue_with_items();
        let actions = DigestActions::new(&queue);
        actions
            .review(&id, ReviewAction::UnlockEgress, None)
            .unwrap();

        let item = queue.get_by_id(&id).unwrap();
        assert_eq!(item.status, DigestStatus::Approved);
        assert_eq!(item.review_action.as_deref(), Some("unlock_egress"));
    }

    #[test]
    fn test_review_deny_and_terminate() {
        let (queue, id, _) = make_queue_with_items();
        let actions = DigestActions::new(&queue);
        actions
            .review(&id, ReviewAction::DenyAndTerminate, None)
            .unwrap();

        let item = queue.get_by_id(&id).unwrap();
        assert_eq!(item.status, DigestStatus::Denied);
    }

    #[test]
    fn test_review_allow_always() {
        let (queue, id, _) = make_queue_with_items();
        let actions = DigestActions::new(&queue);
        actions
            .review(&id, ReviewAction::AllowAlways, None)
            .unwrap();

        let item = queue.get_by_id(&id).unwrap();
        assert_eq!(item.status, DigestStatus::Approved);
        assert_eq!(item.review_action.as_deref(), Some("allow_always"));
    }
}
