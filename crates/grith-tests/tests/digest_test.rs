// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Integration tests for the grith-digest crate.
//!
//! Tests cover: enqueue/retrieve, approve/deny/learn actions, re-review prevention,
//! expiration, informational-only items, pagination, and queue ordering.

use chrono::{Duration, Utc};
use grith_digest::actions::DigestActions;
use grith_digest::types::{DigestItem, DigestStatus, FilterBreakdown, ScoreSeverity};
use grith_digest::DigestQueue;
use uuid::Uuid;

/// Helper: create a DigestItem with the given score and informational flag.
fn make_item(score: f64, informational: bool) -> DigestItem {
    DigestItem {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        session_id: None,
        tool_call_type: "ShellExec".into(),
        arguments_summary: "ls -la".into(),
        decision_reason: None,
        composite_score: score,
        severity: ScoreSeverity::from_score(score),
        filter_breakdown: vec![FilterBreakdown {
            filter_name: "command".into(),
            score,
            rule_id: "test-rule".into(),
            message: "test match".into(),
        }],
        task_context: Some("integration-test".into()),
        plugin_id: "shell".into(),
        status: DigestStatus::Pending,
        reviewed_at: None,
        review_action: None,
        reviewer_notes: None,
        informational_only: informational,
        escalated_at: None,
        escalated_by: None,
    }
}

/// Helper: create an in-memory DigestQueue using TestFixtures-style setup.
fn new_queue() -> DigestQueue {
    DigestQueue::open_in_memory().expect("failed to create in-memory digest queue")
}

// ---------------------------------------------------------------------------
// Enqueue and pending list
// ---------------------------------------------------------------------------

#[test]
fn enqueue_item_with_queue_range_score_appears_in_pending() {
    let queue = new_queue();
    // QUEUE range is 3.0 - 8.0 per spec
    let item = make_item(5.0, false);
    let id = item.id;
    queue.enqueue(&item).unwrap();

    let pending = queue.get_pending(10, 0).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, id);
    assert_eq!(pending[0].status, DigestStatus::Pending);
    assert_eq!(pending[0].composite_score, 5.0);
    assert!(pending[0].is_actionable());
}

// ---------------------------------------------------------------------------
// Approve action
// ---------------------------------------------------------------------------

#[test]
fn approve_action_changes_status_to_approved() {
    let queue = new_queue();
    let item = make_item(5.5, false);
    let id = item.id;
    queue.enqueue(&item).unwrap();

    let actions = DigestActions::new(&queue);
    actions.approve(&id).unwrap();

    let updated = queue.get_by_id(&id).unwrap();
    assert_eq!(updated.status, DigestStatus::Approved);
    assert_eq!(updated.review_action.as_deref(), Some("approve"));
    assert!(updated.reviewed_at.is_some());

    // Should no longer appear in pending list
    assert_eq!(queue.count_pending().unwrap(), 0);
}

// ---------------------------------------------------------------------------
// Deny action
// ---------------------------------------------------------------------------

#[test]
fn deny_action_changes_status_to_denied() {
    let queue = new_queue();
    let item = make_item(6.0, false);
    let id = item.id;
    queue.enqueue(&item).unwrap();

    let actions = DigestActions::new(&queue);
    actions.deny(&id).unwrap();

    let updated = queue.get_by_id(&id).unwrap();
    assert_eq!(updated.status, DigestStatus::Denied);
    assert_eq!(updated.review_action.as_deref(), Some("deny"));
    assert!(updated.reviewed_at.is_some());
}

// ---------------------------------------------------------------------------
// Learn action (approve_and_learn)
// ---------------------------------------------------------------------------

#[test]
fn learn_action_approves_with_learn_flag() {
    let queue = new_queue();
    let item = make_item(4.5, false);
    let id = item.id;
    queue.enqueue(&item).unwrap();

    let actions = DigestActions::new(&queue);
    actions.approve_and_learn(&id).unwrap();

    let updated = queue.get_by_id(&id).unwrap();
    assert_eq!(updated.status, DigestStatus::Approved);
    assert_eq!(updated.review_action.as_deref(), Some("approve_and_learn"));
    assert!(updated.reviewed_at.is_some());
}

// ---------------------------------------------------------------------------
// Cannot re-review already reviewed items
// ---------------------------------------------------------------------------

#[test]
fn cannot_re_review_already_approved_item() {
    let queue = new_queue();
    let item = make_item(5.0, false);
    let id = item.id;
    queue.enqueue(&item).unwrap();

    let actions = DigestActions::new(&queue);
    actions.approve(&id).unwrap();

    // Attempting to deny an already-approved item should fail
    let result = actions.deny(&id);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("already"),
        "Error should mention item is already reviewed: {err_msg}"
    );
}

#[test]
fn cannot_re_review_already_denied_item() {
    let queue = new_queue();
    let item = make_item(5.0, false);
    let id = item.id;
    queue.enqueue(&item).unwrap();

    let actions = DigestActions::new(&queue);
    actions.deny(&id).unwrap();

    // Attempting to approve an already-denied item should fail
    let result = actions.approve(&id);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("already"),
        "Error should mention item is already reviewed: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// Expired items
// ---------------------------------------------------------------------------

#[test]
fn expire_before_removes_old_items_from_pending() {
    let queue = new_queue();
    // Enqueue two items (they will have created_at ~ now)
    queue.enqueue(&make_item(4.0, false)).unwrap();
    queue.enqueue(&make_item(6.0, false)).unwrap();
    assert_eq!(queue.count_pending().unwrap(), 2);

    // Expire everything before one hour in the future (should expire all)
    let cutoff = Utc::now() + Duration::hours(1);
    let expired_count = queue.expire_before(cutoff).unwrap();
    assert_eq!(expired_count, 2);
    assert_eq!(queue.count_pending().unwrap(), 0);

    // Total items still exist (just not pending)
    assert_eq!(queue.count_all().unwrap(), 2);
}

#[test]
fn expire_before_does_not_affect_future_items() {
    let queue = new_queue();
    queue.enqueue(&make_item(5.0, false)).unwrap();

    // Expire everything before one hour in the past (should expire nothing)
    let cutoff = Utc::now() - Duration::hours(1);
    let expired_count = queue.expire_before(cutoff).unwrap();
    assert_eq!(expired_count, 0);
    assert_eq!(queue.count_pending().unwrap(), 1);
}

// ---------------------------------------------------------------------------
// Informational-only items (score > 8.0, auto-denied)
// ---------------------------------------------------------------------------

#[test]
fn informational_only_items_are_not_actionable() {
    let queue = new_queue();
    let item = make_item(9.5, true);
    let id = item.id;
    queue.enqueue(&item).unwrap();

    let retrieved = queue.get_by_id(&id).unwrap();
    assert!(retrieved.informational_only);
    assert!(!retrieved.is_actionable());
}

#[test]
fn cannot_approve_informational_only_item() {
    let queue = new_queue();
    let item = make_item(9.0, true);
    let id = item.id;
    queue.enqueue(&item).unwrap();

    let actions = DigestActions::new(&queue);
    let result = actions.approve(&id);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("informational"),
        "Error should mention informational-only: {err_msg}"
    );
}

#[test]
fn cannot_deny_informational_only_item() {
    let queue = new_queue();
    let item = make_item(8.5, true);
    let id = item.id;
    queue.enqueue(&item).unwrap();

    let actions = DigestActions::new(&queue);
    let result = actions.deny(&id);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

#[test]
fn pagination_limit_and_offset_work_correctly() {
    let queue = new_queue();
    // Enqueue 5 items with distinct scores
    for i in 0..5 {
        queue.enqueue(&make_item(3.0 + i as f64, false)).unwrap();
    }
    assert_eq!(queue.count_pending().unwrap(), 5);

    // Page 1: first 2 items
    let page1 = queue.get_pending(2, 0).unwrap();
    assert_eq!(page1.len(), 2);

    // Page 2: next 2 items
    let page2 = queue.get_pending(2, 2).unwrap();
    assert_eq!(page2.len(), 2);

    // Page 3: last 1 item
    let page3 = queue.get_pending(2, 4).unwrap();
    assert_eq!(page3.len(), 1);

    // Pages should not overlap (all IDs should be unique)
    let mut all_ids: Vec<Uuid> = page1.iter().map(|i| i.id).collect();
    all_ids.extend(page2.iter().map(|i| i.id));
    all_ids.extend(page3.iter().map(|i| i.id));
    all_ids.sort();
    all_ids.dedup();
    assert_eq!(
        all_ids.len(),
        5,
        "All 5 items should be unique across pages"
    );
}

#[test]
fn pagination_beyond_total_returns_empty() {
    let queue = new_queue();
    queue.enqueue(&make_item(5.0, false)).unwrap();

    let page = queue.get_pending(10, 100).unwrap();
    assert!(page.is_empty());
}

// ---------------------------------------------------------------------------
// Queue ordering (highest score first)
// ---------------------------------------------------------------------------

#[test]
fn queue_ordering_highest_score_first() {
    let queue = new_queue();
    // Enqueue in arbitrary order
    queue.enqueue(&make_item(3.5, false)).unwrap();
    queue.enqueue(&make_item(7.0, false)).unwrap();
    queue.enqueue(&make_item(5.0, false)).unwrap();
    queue.enqueue(&make_item(4.2, false)).unwrap();
    queue.enqueue(&make_item(6.8, false)).unwrap();

    let items = queue.get_pending(10, 0).unwrap();
    assert_eq!(items.len(), 5);

    // Verify descending order
    for i in 0..items.len() - 1 {
        assert!(
            items[i].composite_score >= items[i + 1].composite_score,
            "Item at index {} (score {}) should be >= item at index {} (score {})",
            i,
            items[i].composite_score,
            i + 1,
            items[i + 1].composite_score,
        );
    }

    // First item should be the highest score
    assert_eq!(items[0].composite_score, 7.0);
    // Last item should be the lowest score
    assert_eq!(items[4].composite_score, 3.5);
}

// ---------------------------------------------------------------------------
// Additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn empty_queue_returns_empty_pending() {
    let queue = new_queue();
    let items = queue.get_pending(10, 0).unwrap();
    assert!(items.is_empty());
    assert_eq!(queue.count_pending().unwrap(), 0);
    assert_eq!(queue.count_all().unwrap(), 0);
}

#[test]
fn get_by_id_retrieves_correct_item() {
    let queue = new_queue();
    let item1 = make_item(4.0, false);
    let item2 = make_item(6.0, false);
    let id1 = item1.id;
    let id2 = item2.id;
    queue.enqueue(&item1).unwrap();
    queue.enqueue(&item2).unwrap();

    let retrieved1 = queue.get_by_id(&id1).unwrap();
    assert_eq!(retrieved1.id, id1);
    assert_eq!(retrieved1.composite_score, 4.0);

    let retrieved2 = queue.get_by_id(&id2).unwrap();
    assert_eq!(retrieved2.id, id2);
    assert_eq!(retrieved2.composite_score, 6.0);
}

#[test]
fn filter_breakdown_is_preserved_through_round_trip() {
    let queue = new_queue();
    let item = make_item(5.0, false);
    let id = item.id;
    queue.enqueue(&item).unwrap();

    let retrieved = queue.get_by_id(&id).unwrap();
    assert_eq!(retrieved.filter_breakdown.len(), 1);
    assert_eq!(retrieved.filter_breakdown[0].filter_name, "command");
    assert_eq!(retrieved.filter_breakdown[0].score, 5.0);
    assert_eq!(retrieved.filter_breakdown[0].rule_id, "test-rule");
    assert_eq!(retrieved.filter_breakdown[0].message, "test match");
}

#[test]
fn review_action_with_notes_via_generic_review() {
    let queue = new_queue();
    let item = make_item(5.0, false);
    let id = item.id;
    queue.enqueue(&item).unwrap();

    let actions = DigestActions::new(&queue);
    actions
        .review(
            &id,
            grith_digest::ReviewAction::Deny,
            Some("looks dangerous"),
        )
        .unwrap();

    let updated = queue.get_by_id(&id).unwrap();
    assert_eq!(updated.status, DigestStatus::Denied);
    assert_eq!(updated.review_action.as_deref(), Some("deny"));
    assert_eq!(updated.reviewer_notes.as_deref(), Some("looks dangerous"));
}
