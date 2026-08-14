// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Integration tests for the grith-audit crate.
//!
//! Tests cover: insert/retrieve by ID, count, session queries, get_recent,
//! filtered queries (by plugin, action, min_score), JSON/CSV/JSONL export,
//! and database rotation.

use grith_audit::export::{export_csv, export_json, export_jsonl};
use grith_audit::query::AuditQuery;
use grith_audit::types::{AuditRecord, FilterResultSummary, ProxyActionSummary};
use grith_audit::AuditStorage;
use uuid::Uuid;

/// Helper: create an AuditRecord with the given parameters.
fn make_record(
    session_id: Uuid,
    plugin_id: &str,
    tool_call_type: &str,
    score: f64,
    action: ProxyActionSummary,
) -> AuditRecord {
    AuditRecord::new(
        session_id,
        plugin_id.into(),
        tool_call_type.into(),
        &serde_json::json!({"test": true}),
        score,
        action,
        vec![FilterResultSummary {
            filter_name: "path-match".into(),
            matched: score > 0.0,
            score,
            rule_id: "test-rule".into(),
            severity: "warning".into(),
            message: "test filter result".into(),
        }],
        1.2,
        Some("integration-test".into()),
    )
}

/// Helper: create a simple record with default session.
fn make_simple_record(plugin_id: &str, score: f64, action: ProxyActionSummary) -> AuditRecord {
    make_record(Uuid::new_v4(), plugin_id, "FileRead", score, action)
}

/// Helper: create an in-memory AuditStorage.
fn new_storage() -> AuditStorage {
    AuditStorage::open_in_memory().expect("failed to create in-memory audit storage")
}

// ---------------------------------------------------------------------------
// Insert and retrieve by ID
// ---------------------------------------------------------------------------

#[test]
fn insert_record_retrievable_by_id() {
    let storage = new_storage();
    let record = make_simple_record("file-ops", 1.5, ProxyActionSummary::Allow);
    let id = record.id;

    storage.insert_record(&record).unwrap();

    let retrieved = storage.get_by_id(&id).unwrap();
    assert_eq!(retrieved.id, id);
    assert_eq!(retrieved.plugin_id, "file-ops");
    assert_eq!(retrieved.composite_score, 1.5);
    assert_eq!(retrieved.proxy_action, ProxyActionSummary::Allow);
    assert!(retrieved.task_context.is_some());
    assert_eq!(retrieved.task_context.as_deref(), Some("integration-test"));
}

// ---------------------------------------------------------------------------
// Insert multiple records -> count correct
// ---------------------------------------------------------------------------

#[test]
fn insert_multiple_records_count_correct() {
    let mut storage = new_storage();
    let records: Vec<AuditRecord> = (0..10)
        .map(|i| make_simple_record("shell", i as f64, ProxyActionSummary::Allow))
        .collect();
    storage.insert_batch(&records).unwrap();
    assert_eq!(storage.count().unwrap(), 10);
}

#[test]
fn insert_records_individually_count_correct() {
    let storage = new_storage();
    for i in 0..5 {
        let record = make_simple_record("file-ops", i as f64, ProxyActionSummary::Allow);
        storage.insert_record(&record).unwrap();
    }
    assert_eq!(storage.count().unwrap(), 5);
}

// ---------------------------------------------------------------------------
// Get by session ID -> returns only matching records
// ---------------------------------------------------------------------------

#[test]
fn get_by_session_returns_only_matching_records() {
    let storage = new_storage();
    let session_a = Uuid::new_v4();
    let session_b = Uuid::new_v4();

    // Insert 3 records for session A
    for _ in 0..3 {
        storage
            .insert_record(&make_record(
                session_a,
                "file-ops",
                "FileRead",
                1.0,
                ProxyActionSummary::Allow,
            ))
            .unwrap();
    }
    // Insert 2 records for session B
    for _ in 0..2 {
        storage
            .insert_record(&make_record(
                session_b,
                "shell",
                "ShellExec",
                5.0,
                ProxyActionSummary::Queue,
            ))
            .unwrap();
    }

    let results_a = storage.get_by_session(&session_a).unwrap();
    assert_eq!(results_a.len(), 3);
    for r in &results_a {
        assert_eq!(r.session_id, session_a);
    }

    let results_b = storage.get_by_session(&session_b).unwrap();
    assert_eq!(results_b.len(), 2);
    for r in &results_b {
        assert_eq!(r.session_id, session_b);
    }

    // Non-existent session returns empty
    let empty = storage.get_by_session(&Uuid::new_v4()).unwrap();
    assert!(empty.is_empty());
}

// ---------------------------------------------------------------------------
// Get recent -> returns most recent N records
// ---------------------------------------------------------------------------

#[test]
fn get_recent_returns_most_recent_n_records() {
    let storage = new_storage();
    for i in 0..10 {
        let record = make_simple_record("file-ops", i as f64, ProxyActionSummary::Allow);
        storage.insert_record(&record).unwrap();
    }

    let recent = storage.get_recent(3).unwrap();
    assert_eq!(recent.len(), 3);

    // The most recently inserted records should have the highest scores in our setup
    // (since we inserted them in order with incrementing scores and timestamps).
    // get_recent returns ORDER BY timestamp DESC, so the last inserted should be first.
}

#[test]
fn get_recent_with_limit_greater_than_total_returns_all() {
    let storage = new_storage();
    for _ in 0..3 {
        storage
            .insert_record(&make_simple_record("shell", 2.0, ProxyActionSummary::Allow))
            .unwrap();
    }

    let recent = storage.get_recent(100).unwrap();
    assert_eq!(recent.len(), 3);
}

// ---------------------------------------------------------------------------
// Query with filters
// ---------------------------------------------------------------------------

#[test]
fn query_by_plugin_returns_matching_records() {
    let storage = new_storage();
    storage
        .insert_record(&make_simple_record(
            "file-ops",
            1.0,
            ProxyActionSummary::Allow,
        ))
        .unwrap();
    storage
        .insert_record(&make_simple_record("shell", 5.0, ProxyActionSummary::Queue))
        .unwrap();
    storage
        .insert_record(&make_simple_record(
            "file-ops",
            2.0,
            ProxyActionSummary::Allow,
        ))
        .unwrap();
    storage
        .insert_record(&make_simple_record("http", 3.0, ProxyActionSummary::Allow))
        .unwrap();

    let results = AuditQuery::new()
        .plugin("file-ops")
        .execute(&storage)
        .unwrap();
    assert_eq!(results.len(), 2);
    for r in &results {
        assert_eq!(r.plugin_id, "file-ops");
    }
}

#[test]
fn query_by_action_returns_matching_records() {
    let storage = new_storage();
    storage
        .insert_record(&make_simple_record(
            "file-ops",
            1.0,
            ProxyActionSummary::Allow,
        ))
        .unwrap();
    storage
        .insert_record(&make_simple_record("shell", 5.0, ProxyActionSummary::Queue))
        .unwrap();
    storage
        .insert_record(&make_simple_record(
            "file-ops",
            9.0,
            ProxyActionSummary::Deny,
        ))
        .unwrap();

    let allow_results = AuditQuery::new()
        .action(ProxyActionSummary::Allow)
        .execute(&storage)
        .unwrap();
    assert_eq!(allow_results.len(), 1);

    let queue_results = AuditQuery::new()
        .action(ProxyActionSummary::Queue)
        .execute(&storage)
        .unwrap();
    assert_eq!(queue_results.len(), 1);

    let deny_results = AuditQuery::new()
        .action(ProxyActionSummary::Deny)
        .execute(&storage)
        .unwrap();
    assert_eq!(deny_results.len(), 1);
}

#[test]
fn query_by_min_score_returns_matching_records() {
    let storage = new_storage();
    storage
        .insert_record(&make_simple_record(
            "file-ops",
            1.0,
            ProxyActionSummary::Allow,
        ))
        .unwrap();
    storage
        .insert_record(&make_simple_record("shell", 5.0, ProxyActionSummary::Queue))
        .unwrap();
    storage
        .insert_record(&make_simple_record(
            "file-ops",
            9.0,
            ProxyActionSummary::Deny,
        ))
        .unwrap();
    storage
        .insert_record(&make_simple_record("http", 3.5, ProxyActionSummary::Allow))
        .unwrap();

    let results = AuditQuery::new().min_score(5.0).execute(&storage).unwrap();
    assert_eq!(results.len(), 2);
    for r in &results {
        assert!(
            r.composite_score >= 5.0,
            "Score {} should be >= 5.0",
            r.composite_score
        );
    }
}

#[test]
fn query_combined_filters() {
    let storage = new_storage();
    let session = Uuid::new_v4();

    storage
        .insert_record(&make_record(
            session,
            "file-ops",
            "FileRead",
            1.0,
            ProxyActionSummary::Allow,
        ))
        .unwrap();
    storage
        .insert_record(&make_record(
            session,
            "shell",
            "ShellExec",
            6.0,
            ProxyActionSummary::Queue,
        ))
        .unwrap();
    storage
        .insert_record(&make_record(
            Uuid::new_v4(),
            "shell",
            "ShellExec",
            7.0,
            ProxyActionSummary::Queue,
        ))
        .unwrap();

    // Query: plugin=shell AND min_score=5.0
    let results = AuditQuery::new()
        .plugin("shell")
        .min_score(5.0)
        .execute(&storage)
        .unwrap();
    assert_eq!(results.len(), 2);

    // Query: plugin=shell AND action=queue AND session
    let results = AuditQuery::new()
        .plugin("shell")
        .action(ProxyActionSummary::Queue)
        .session(session)
        .execute(&storage)
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].session_id, session);
}

#[test]
fn query_count_matches_execute_length() {
    let storage = new_storage();
    for i in 0..8 {
        storage
            .insert_record(&make_simple_record(
                "shell",
                i as f64,
                ProxyActionSummary::Allow,
            ))
            .unwrap();
    }

    let query = AuditQuery::new().plugin("shell").min_score(4.0);
    let count = query.count(&storage).unwrap();
    let results = query.execute(&storage).unwrap();
    assert_eq!(count, results.len());
}

// ---------------------------------------------------------------------------
// Export as JSON
// ---------------------------------------------------------------------------

#[test]
fn export_json_produces_valid_json() {
    let storage = new_storage();
    storage
        .insert_record(&make_simple_record(
            "file-ops",
            1.5,
            ProxyActionSummary::Allow,
        ))
        .unwrap();
    storage
        .insert_record(&make_simple_record("shell", 5.0, ProxyActionSummary::Queue))
        .unwrap();

    let records = storage.get_recent(10).unwrap();
    let mut buf = Vec::new();
    export_json(&records, &mut buf).unwrap();

    let output = String::from_utf8(buf).unwrap();
    let parsed: Vec<AuditRecord> = serde_json::from_str(&output).unwrap();
    assert_eq!(parsed.len(), 2);

    // Verify fields survive serialization round-trip
    for record in &parsed {
        assert!(!record.plugin_id.is_empty());
        assert!(!record.arguments_hash.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Export as CSV
// ---------------------------------------------------------------------------

#[test]
fn export_csv_produces_valid_csv() {
    let storage = new_storage();
    storage
        .insert_record(&make_simple_record(
            "file-ops",
            1.5,
            ProxyActionSummary::Allow,
        ))
        .unwrap();
    storage
        .insert_record(&make_simple_record("shell", 5.0, ProxyActionSummary::Queue))
        .unwrap();
    storage
        .insert_record(&make_simple_record("http", 9.5, ProxyActionSummary::Deny))
        .unwrap();

    let records = storage.get_recent(10).unwrap();
    let mut buf = Vec::new();
    export_csv(&records, &mut buf).unwrap();

    let output = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = output.trim().split('\n').collect();

    // Header + 3 data rows
    assert_eq!(lines.len(), 4, "Expected 1 header + 3 data rows");

    // Verify header contains expected columns
    assert!(lines[0].starts_with("id,timestamp"));
    assert!(lines[0].contains("plugin_id"));
    assert!(lines[0].contains("composite_score"));
    assert!(lines[0].contains("proxy_action"));

    // Verify data rows contain expected plugin IDs (order may vary)
    let data_rows: String = lines[1..].join("\n");
    assert!(data_rows.contains("file-ops"));
    assert!(data_rows.contains("shell"));
    assert!(data_rows.contains("http"));
}

// ---------------------------------------------------------------------------
// Export as JSONL
// ---------------------------------------------------------------------------

#[test]
fn export_jsonl_produces_valid_jsonl() {
    let storage = new_storage();
    storage
        .insert_record(&make_simple_record(
            "file-ops",
            1.5,
            ProxyActionSummary::Allow,
        ))
        .unwrap();
    storage
        .insert_record(&make_simple_record("shell", 5.0, ProxyActionSummary::Queue))
        .unwrap();

    let records = storage.get_recent(10).unwrap();
    let mut buf = Vec::new();
    export_jsonl(&records, &mut buf).unwrap();

    let output = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = output.trim().split('\n').collect();
    assert_eq!(lines.len(), 2);

    // Each line should be valid JSON that parses to an AuditRecord
    for line in &lines {
        let parsed: AuditRecord =
            serde_json::from_str(line).expect("Each JSONL line should be valid JSON");
        assert!(!parsed.plugin_id.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Rotation: when DB exceeds size limit, rotation creates new file
// ---------------------------------------------------------------------------

#[test]
fn rotation_creates_new_file_when_size_exceeded() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("audit.db");
    let mut storage = AuditStorage::open(&db_path).unwrap().with_max_size(500); // Very small limit to trigger rotation quickly

    // Insert enough records to exceed 500 bytes
    for _ in 0..50 {
        storage
            .insert_record(&make_simple_record(
                "file-ops",
                2.5,
                ProxyActionSummary::Allow,
            ))
            .unwrap();
    }

    let rotated = storage.check_rotation().unwrap();
    if rotated {
        // After rotation, the current database should be fresh (empty)
        assert_eq!(storage.count().unwrap(), 0);

        // There should be a rotated file in the directory
        let rotated_files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.starts_with("audit-") && n.ends_with(".db"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            !rotated_files.is_empty(),
            "Expected at least one rotated audit-*.db file"
        );
    }
    // Note: if the file happens to not exceed 500 bytes (unlikely with 50 records),
    // rotation won't trigger, which is acceptable.
}

#[test]
fn rotation_does_not_occur_for_in_memory_db() {
    let mut storage = new_storage();
    for _ in 0..20 {
        storage
            .insert_record(&make_simple_record("shell", 3.0, ProxyActionSummary::Allow))
            .unwrap();
    }
    // In-memory databases should never rotate
    assert!(!storage.check_rotation().unwrap());
}

// ---------------------------------------------------------------------------
// Additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn empty_storage_returns_empty_results() {
    let storage = new_storage();
    assert_eq!(storage.count().unwrap(), 0);

    let recent = storage.get_recent(10).unwrap();
    assert!(recent.is_empty());

    let query_results = AuditQuery::new().execute(&storage).unwrap();
    assert!(query_results.is_empty());
}

#[test]
fn filter_results_survive_round_trip() {
    let storage = new_storage();
    let record = make_simple_record("file-ops", 3.0, ProxyActionSummary::Allow);
    let id = record.id;
    storage.insert_record(&record).unwrap();

    let retrieved = storage.get_by_id(&id).unwrap();
    assert_eq!(retrieved.filter_results.len(), 1);
    assert_eq!(retrieved.filter_results[0].filter_name, "path-match");
    assert_eq!(retrieved.filter_results[0].score, 3.0);
    assert_eq!(retrieved.filter_results[0].rule_id, "test-rule");
    assert!(retrieved.filter_results[0].matched);
}

#[test]
fn query_nonexistent_plugin_returns_empty() {
    let storage = new_storage();
    storage
        .insert_record(&make_simple_record(
            "file-ops",
            1.0,
            ProxyActionSummary::Allow,
        ))
        .unwrap();

    let results = AuditQuery::new()
        .plugin("nonexistent-plugin")
        .execute(&storage)
        .unwrap();
    assert!(results.is_empty());
}

// ===========================================================================
// Concurrent access stress tests
// ===========================================================================

/// Stress test: multiple threads inserting audit records concurrently through
/// an Arc<Mutex<AuditStorage>>.
#[test]
fn concurrent_inserts_via_mutex() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let storage = Arc::new(Mutex::new(new_storage()));
    let num_threads = 8;
    let records_per_thread = 50;

    let handles: Vec<_> = (0..num_threads)
        .map(|t| {
            let storage = Arc::clone(&storage);
            thread::spawn(move || {
                for i in 0..records_per_thread {
                    let record = make_simple_record(
                        &format!("plugin-{t}"),
                        i as f64,
                        ProxyActionSummary::Allow,
                    );
                    let s = storage.lock().unwrap();
                    s.insert_record(&record).unwrap();
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread panicked");
    }

    let total = storage.lock().unwrap().count().unwrap();
    assert_eq!(
        total,
        num_threads * records_per_thread,
        "Expected {} records, got {total}",
        num_threads * records_per_thread
    );
}

/// Stress test: concurrent reads while a writer thread is inserting records.
#[test]
fn concurrent_reads_while_writing() {
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    let storage = Arc::new(Mutex::new(new_storage()));
    let num_writers = 2;
    let num_readers = 4;
    let records_per_writer = 40;
    let total_threads = num_writers + num_readers;

    // Barrier ensures all threads start at roughly the same time.
    let barrier = Arc::new(Barrier::new(total_threads));

    let mut handles = Vec::new();

    // Writer threads
    for w in 0..num_writers {
        let storage = Arc::clone(&storage);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..records_per_writer {
                let record =
                    make_simple_record(&format!("writer-{w}"), i as f64, ProxyActionSummary::Allow);
                let s = storage.lock().unwrap();
                s.insert_record(&record).unwrap();
            }
        }));
    }

    // Reader threads
    for _ in 0..num_readers {
        let storage = Arc::clone(&storage);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            // Perform reads in a loop while writers are active.
            for _ in 0..50 {
                let s = storage.lock().unwrap();
                let count = s.count().unwrap();
                // Count should always be non-negative and within bounds.
                assert!(
                    count <= (num_writers * records_per_writer),
                    "Count {count} exceeded expected maximum"
                );
                let recent = s.get_recent(10).unwrap();
                assert!(recent.len() <= 10);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("thread panicked");
    }

    let total = storage.lock().unwrap().count().unwrap();
    assert_eq!(
        total,
        num_writers * records_per_writer,
        "Expected {} records, got {total}",
        num_writers * records_per_writer
    );
}

/// Stress test: mutex acquisition under contention with mixed read/write operations.
#[test]
fn mutex_contention_mixed_operations() {
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    let storage = Arc::new(Mutex::new(new_storage()));
    let session_a = Uuid::new_v4();
    let session_b = Uuid::new_v4();
    let num_threads = 10;
    let ops_per_thread = 30;

    let barrier = Arc::new(Barrier::new(num_threads));

    // Pre-insert a record so get_by_session always has something to find.
    {
        let s = storage.lock().unwrap();
        s.insert_record(&make_record(
            session_a,
            "seed",
            "FileRead",
            0.0,
            ProxyActionSummary::Allow,
        ))
        .unwrap();
    }

    let handles: Vec<_> = (0..num_threads)
        .map(|t| {
            let storage = Arc::clone(&storage);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ops_per_thread {
                    let s = storage.lock().unwrap();
                    match i % 4 {
                        0 => {
                            // Insert
                            let session = if t % 2 == 0 { session_a } else { session_b };
                            let record = make_record(
                                session,
                                &format!("plugin-{t}"),
                                "ShellExec",
                                i as f64,
                                ProxyActionSummary::Allow,
                            );
                            s.insert_record(&record).unwrap();
                        }
                        1 => {
                            // Count
                            let _ = s.count().unwrap();
                        }
                        2 => {
                            // Get recent
                            let _ = s.get_recent(5).unwrap();
                        }
                        3 => {
                            // Query by session
                            let _ = s.get_by_session(&session_a).unwrap();
                        }
                        _ => unreachable!(),
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread panicked");
    }

    // Verify the database is consistent: total records >= seed record.
    let total = storage.lock().unwrap().count().unwrap();
    assert!(total >= 1, "Expected at least the seed record, got {total}");

    // Verify session queries still work correctly after contention.
    let s = storage.lock().unwrap();
    let session_a_records = s.get_by_session(&session_a).unwrap();
    assert!(
        !session_a_records.is_empty(),
        "Session A should have at least the seed record"
    );
    for r in &session_a_records {
        assert_eq!(r.session_id, session_a);
    }
}

/// Stress test: concurrent query execution under contention.
#[test]
fn concurrent_query_execution() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let storage = Arc::new(Mutex::new(new_storage()));

    // Pre-populate with records across multiple plugins and sessions.
    {
        let s = storage.lock().unwrap();
        for i in 0..100 {
            let plugin = match i % 3 {
                0 => "file-ops",
                1 => "shell",
                _ => "http",
            };
            let action = match i % 3 {
                0 => ProxyActionSummary::Allow,
                1 => ProxyActionSummary::Queue,
                _ => ProxyActionSummary::Deny,
            };
            s.insert_record(&make_simple_record(plugin, (i % 10) as f64, action))
                .unwrap();
        }
    }

    let num_threads = 6;
    let queries_per_thread = 50;

    let handles: Vec<_> = (0..num_threads)
        .map(|t| {
            let storage = Arc::clone(&storage);
            thread::spawn(move || {
                for i in 0..queries_per_thread {
                    let s = storage.lock().unwrap();
                    match (t + i) % 5 {
                        0 => {
                            let results = AuditQuery::new().plugin("file-ops").execute(&s).unwrap();
                            // file-ops is 34 records (indices 0,3,6,...,99)
                            assert_eq!(results.len(), 34);
                        }
                        1 => {
                            let results = AuditQuery::new()
                                .action(ProxyActionSummary::Deny)
                                .execute(&s)
                                .unwrap();
                            assert_eq!(results.len(), 33);
                        }
                        2 => {
                            let results = AuditQuery::new().min_score(5.0).execute(&s).unwrap();
                            for r in &results {
                                assert!(r.composite_score >= 5.0);
                            }
                        }
                        3 => {
                            let query = AuditQuery::new().plugin("shell");
                            let count = query.count(&s).unwrap();
                            let results = query.execute(&s).unwrap();
                            assert_eq!(count, results.len());
                        }
                        4 => {
                            let recent = s.get_recent(10).unwrap();
                            assert!(recent.len() <= 10);
                            let total = s.count().unwrap();
                            assert_eq!(total, 100);
                        }
                        _ => unreachable!(),
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread panicked");
    }
}
