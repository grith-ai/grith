// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Aggregate statistics computed from audit records.

use crate::error::Result;
use crate::storage::AuditStorage;
use rusqlite::params;
use serde::{Deserialize, Serialize};

/// Summary statistics for audit records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStats {
    pub total_calls: usize,
    pub allow_count: usize,
    pub queue_count: usize,
    pub deny_count: usize,
    pub avg_score: f64,
    pub avg_latency_ms: f64,
}

/// Latency percentile breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyPercentiles {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

/// Cost breakdown for a single LLM provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCost {
    pub provider: String,
    pub call_count: usize,
    pub prompt_tokens: usize,
    pub completion_tokens: usize,
    pub total_cost_usd: f64,
}

/// Daily evaluation counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyCount {
    pub date: String,
    pub total: usize,
    pub allow_count: usize,
    pub queue_count: usize,
    pub deny_count: usize,
}

/// Score zone distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreDistribution {
    /// Score < 3.0 (auto-allowed).
    pub low_risk: usize,
    /// Score 3.0–8.0 (queued for review).
    pub medium_risk: usize,
    /// Score >= 8.0 (auto-denied).
    pub high_risk: usize,
}

impl AuditStats {
    /// Compute stats for all records in the database.
    pub fn compute(storage: &AuditStorage) -> Result<Self> {
        let conn = storage.connection();
        let (total, avg_score, avg_latency): (i64, f64, f64) = conn.query_row(
            "SELECT COUNT(*), COALESCE(AVG(composite_score), 0), COALESCE(AVG(evaluation_time_ms), 0) FROM audit_log",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;

        let allow_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM audit_log WHERE proxy_action = 'allow'",
            [],
            |row| row.get(0),
        )?;
        let queue_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM audit_log WHERE proxy_action = 'queue'",
            [],
            |row| row.get(0),
        )?;
        let deny_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM audit_log WHERE proxy_action = 'deny'",
            [],
            |row| row.get(0),
        )?;

        Ok(Self {
            total_calls: total as usize,
            allow_count: allow_count as usize,
            queue_count: queue_count as usize,
            deny_count: deny_count as usize,
            avg_score,
            avg_latency_ms: avg_latency,
        })
    }

    /// Return the top N filters by how many audit records each appears in.
    ///
    /// Parses the `filter_scores` JSON column (a `{filter_name: score}` map)
    /// and counts how many records each filter key appears in.
    pub fn top_triggered_filters(
        storage: &AuditStorage,
        limit: usize,
    ) -> Result<Vec<(String, usize)>> {
        let conn = storage.connection();
        let mut stmt =
            conn.prepare("SELECT filter_scores FROM audit_log WHERE filter_scores IS NOT NULL")?;
        let rows = stmt.query_map([], |row| {
            let json_str: String = row.get(0)?;
            Ok(json_str)
        })?;

        let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for row in rows {
            let json_str = row?;
            if let Ok(map) =
                serde_json::from_str::<std::collections::HashMap<String, f64>>(&json_str)
            {
                for key in map.keys() {
                    *counts.entry(key.clone()).or_default() += 1;
                }
            }
        }

        let mut sorted: Vec<(String, usize)> = counts.into_iter().collect();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
        sorted.truncate(limit);
        Ok(sorted)
    }

    /// Compute latency percentiles (p50, p95, p99) from `evaluation_time_ms`.
    ///
    /// Returns zeros if no records exist.
    pub fn latency_percentiles(storage: &AuditStorage) -> Result<LatencyPercentiles> {
        let conn = storage.connection();
        let mut stmt =
            conn.prepare("SELECT evaluation_time_ms FROM audit_log ORDER BY evaluation_time_ms")?;
        let rows = stmt.query_map([], |row| {
            let ms: f64 = row.get(0)?;
            Ok(ms)
        })?;

        let mut latencies: Vec<f64> = Vec::new();
        for row in rows {
            latencies.push(row?);
        }

        if latencies.is_empty() {
            return Ok(LatencyPercentiles {
                p50_ms: 0.0,
                p95_ms: 0.0,
                p99_ms: 0.0,
            });
        }

        let n = latencies.len();
        let percentile = |p: f64| -> f64 {
            let idx = ((p / 100.0) * (n as f64 - 1.0)).round() as usize;
            latencies[idx.min(n - 1)]
        };

        Ok(LatencyPercentiles {
            p50_ms: percentile(50.0),
            p95_ms: percentile(95.0),
            p99_ms: percentile(99.0),
        })
    }

    /// Return the earliest and latest timestamps in the audit log.
    pub fn time_range(storage: &AuditStorage) -> Result<(Option<String>, Option<String>)> {
        let conn = storage.connection();
        let result = conn.query_row(
            "SELECT MIN(timestamp), MAX(timestamp) FROM audit_log",
            [],
            |row| {
                let earliest: Option<String> = row.get(0)?;
                let latest: Option<String> = row.get(1)?;
                Ok((earliest, latest))
            },
        )?;
        Ok(result)
    }

    /// Aggregate LLM cost data grouped by provider.
    pub fn cost_by_provider(storage: &AuditStorage) -> Result<Vec<ProviderCost>> {
        let conn = storage.connection();
        let mut stmt = conn.prepare(
            "SELECT llm_provider, \
                    COUNT(*) as calls, \
                    COALESCE(SUM(prompt_tokens), 0) as prompt_tok, \
                    COALESCE(SUM(completion_tokens), 0) as comp_tok, \
                    COALESCE(SUM(estimated_cost_usd), 0.0) as total_cost \
             FROM audit_log \
             WHERE llm_provider IS NOT NULL \
             GROUP BY llm_provider \
             ORDER BY total_cost DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ProviderCost {
                provider: row.get(0)?,
                call_count: row.get::<_, i64>(1)? as usize,
                prompt_tokens: row.get::<_, i64>(2)? as usize,
                completion_tokens: row.get::<_, i64>(3)? as usize,
                total_cost_usd: row.get(4)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| e.into())
    }

    /// Daily evaluation counts for the last N days.
    pub fn daily_activity(storage: &AuditStorage, days: usize) -> Result<Vec<DailyCount>> {
        let conn = storage.connection();
        let mut stmt = conn.prepare(
            "SELECT DATE(timestamp) as day, \
                    COUNT(*) as total, \
                    SUM(CASE WHEN proxy_action = 'allow' THEN 1 ELSE 0 END) as allowed, \
                    SUM(CASE WHEN proxy_action = 'queue' THEN 1 ELSE 0 END) as queued, \
                    SUM(CASE WHEN proxy_action = 'deny' THEN 1 ELSE 0 END) as denied \
             FROM audit_log \
             WHERE timestamp >= DATE('now', ?1) \
             GROUP BY day \
             ORDER BY day",
        )?;
        let offset = format!("-{days} days");
        let rows = stmt.query_map(params![offset], |row| {
            Ok(DailyCount {
                date: row.get(0)?,
                total: row.get::<_, i64>(1)? as usize,
                allow_count: row.get::<_, i64>(2)? as usize,
                queue_count: row.get::<_, i64>(3)? as usize,
                deny_count: row.get::<_, i64>(4)? as usize,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| e.into())
    }

    /// Score distribution: count of records in each score zone.
    pub fn score_distribution(storage: &AuditStorage) -> Result<ScoreDistribution> {
        let conn = storage.connection();
        let low: i64 = conn.query_row(
            "SELECT COUNT(*) FROM audit_log WHERE composite_score < 3.0",
            [],
            |row| row.get(0),
        )?;
        let medium: i64 = conn.query_row(
            "SELECT COUNT(*) FROM audit_log WHERE composite_score >= 3.0 AND composite_score < 8.0",
            [],
            |row| row.get(0),
        )?;
        let high: i64 = conn.query_row(
            "SELECT COUNT(*) FROM audit_log WHERE composite_score >= 8.0",
            [],
            |row| row.get(0),
        )?;
        Ok(ScoreDistribution {
            low_risk: low as usize,
            medium_risk: medium as usize,
            high_risk: high as usize,
        })
    }

    /// Top tool call types by frequency.
    pub fn top_tool_call_types(
        storage: &AuditStorage,
        limit: usize,
    ) -> Result<Vec<(String, usize)>> {
        let conn = storage.connection();
        let mut stmt = conn.prepare(
            "SELECT tool_call_type, COUNT(*) as cnt \
             FROM audit_log \
             GROUP BY tool_call_type \
             ORDER BY cnt DESC \
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let name: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            Ok((name, count as usize))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| e.into())
    }

    /// Compute stats for a specific session.
    pub fn compute_for_session(storage: &AuditStorage, session_id: &uuid::Uuid) -> Result<Self> {
        let conn = storage.connection();
        let sid = session_id.to_string();

        let (total, avg_score, avg_latency): (i64, f64, f64) = conn.query_row(
            "SELECT COUNT(*), COALESCE(AVG(composite_score), 0), COALESCE(AVG(evaluation_time_ms), 0) FROM audit_log WHERE session_id = ?1",
            params![sid],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;

        let allow_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM audit_log WHERE session_id = ?1 AND proxy_action = 'allow'",
            params![sid],
            |row| row.get(0),
        )?;
        let queue_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM audit_log WHERE session_id = ?1 AND proxy_action = 'queue'",
            params![sid],
            |row| row.get(0),
        )?;
        let deny_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM audit_log WHERE session_id = ?1 AND proxy_action = 'deny'",
            params![sid],
            |row| row.get(0),
        )?;

        Ok(Self {
            total_calls: total as usize,
            allow_count: allow_count as usize,
            queue_count: queue_count as usize,
            deny_count: deny_count as usize,
            avg_score,
            avg_latency_ms: avg_latency,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuditRecord, FilterResultSummary, ProxyActionSummary};
    use uuid::Uuid;

    fn insert_test_data(storage: &AuditStorage) {
        let session = Uuid::new_v4();
        let records = vec![
            AuditRecord::new(
                session,
                "p1".into(),
                "FileRead".into(),
                &serde_json::json!({}),
                1.0,
                ProxyActionSummary::Allow,
                vec![],
                0.5,
                None,
            ),
            AuditRecord::new(
                session,
                "p1".into(),
                "ShellExec".into(),
                &serde_json::json!({}),
                5.0,
                ProxyActionSummary::Queue,
                vec![],
                1.0,
                None,
            ),
            AuditRecord::new(
                session,
                "p1".into(),
                "FileWrite".into(),
                &serde_json::json!({}),
                9.0,
                ProxyActionSummary::Deny,
                vec![],
                2.0,
                None,
            ),
            AuditRecord::new(
                session,
                "p1".into(),
                "FileRead".into(),
                &serde_json::json!({}),
                0.5,
                ProxyActionSummary::Allow,
                vec![],
                0.3,
                None,
            ),
        ];
        for r in &records {
            storage.insert_record(r).unwrap();
        }
    }

    fn insert_data_with_filters(storage: &AuditStorage) {
        let session = Uuid::new_v4();
        let records = vec![
            AuditRecord::new(
                session,
                "p1".into(),
                "ShellExec".into(),
                &serde_json::json!({"cmd": "rm -rf /"}),
                7.5,
                ProxyActionSummary::Deny,
                vec![
                    FilterResultSummary {
                        filter_name: "secret-scan".into(),
                        matched: true,
                        score: 3.0,
                        rule_id: "r1".into(),
                        severity: "high".into(),
                        message: "found secret".into(),
                    },
                    FilterResultSummary {
                        filter_name: "path-match".into(),
                        matched: true,
                        score: 4.5,
                        rule_id: "r2".into(),
                        severity: "critical".into(),
                        message: "dangerous path".into(),
                    },
                ],
                1.2,
                None,
            ),
            AuditRecord::new(
                session,
                "p1".into(),
                "FileRead".into(),
                &serde_json::json!({"path": "/etc/passwd"}),
                4.0,
                ProxyActionSummary::Queue,
                vec![FilterResultSummary {
                    filter_name: "secret-scan".into(),
                    matched: true,
                    score: 4.0,
                    rule_id: "r1".into(),
                    severity: "high".into(),
                    message: "sensitive file".into(),
                }],
                0.8,
                None,
            ),
            AuditRecord::new(
                session,
                "p1".into(),
                "FileRead".into(),
                &serde_json::json!({"path": "/tmp/ok.txt"}),
                0.5,
                ProxyActionSummary::Allow,
                vec![FilterResultSummary {
                    filter_name: "path-match".into(),
                    matched: false,
                    score: 0.5,
                    rule_id: "".into(),
                    severity: "notice".into(),
                    message: "".into(),
                }],
                0.3,
                None,
            ),
        ];
        for r in &records {
            storage.insert_record(r).unwrap();
        }
    }

    #[test]
    fn test_compute_stats() {
        let storage = AuditStorage::open_in_memory().unwrap();
        insert_test_data(&storage);

        let stats = AuditStats::compute(&storage).unwrap();
        assert_eq!(stats.total_calls, 4);
        assert_eq!(stats.allow_count, 2);
        assert_eq!(stats.queue_count, 1);
        assert_eq!(stats.deny_count, 1);
        assert!((stats.avg_score - 3.875).abs() < 0.01);
    }

    #[test]
    fn test_empty_stats() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let stats = AuditStats::compute(&storage).unwrap();
        assert_eq!(stats.total_calls, 0);
        assert_eq!(stats.avg_score, 0.0);
    }

    #[test]
    fn test_top_triggered_filters() {
        let storage = AuditStorage::open_in_memory().unwrap();
        insert_data_with_filters(&storage);

        let top = AuditStats::top_triggered_filters(&storage, 10).unwrap();
        // secret-scan appears in 2 records, path-match in 2 records
        assert!(!top.is_empty());
        let secret_scan = top.iter().find(|(name, _)| name == "secret-scan");
        assert_eq!(secret_scan.unwrap().1, 2);
        let path_match = top.iter().find(|(name, _)| name == "path-match");
        assert_eq!(path_match.unwrap().1, 2);
    }

    #[test]
    fn test_top_triggered_filters_empty() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let top = AuditStats::top_triggered_filters(&storage, 10).unwrap();
        assert!(top.is_empty());
    }

    #[test]
    fn test_latency_percentiles() {
        let storage = AuditStorage::open_in_memory().unwrap();
        insert_data_with_filters(&storage);

        let pct = AuditStats::latency_percentiles(&storage).unwrap();
        // 3 records with latencies: 0.3, 0.8, 1.2
        assert!(pct.p50_ms > 0.0);
        assert!(pct.p95_ms >= pct.p50_ms);
        assert!(pct.p99_ms >= pct.p95_ms);
    }

    #[test]
    fn test_latency_percentiles_empty() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let pct = AuditStats::latency_percentiles(&storage).unwrap();
        assert_eq!(pct.p50_ms, 0.0);
        assert_eq!(pct.p95_ms, 0.0);
        assert_eq!(pct.p99_ms, 0.0);
    }

    #[test]
    fn test_time_range() {
        let storage = AuditStorage::open_in_memory().unwrap();
        insert_test_data(&storage);
        let (earliest, latest) = AuditStats::time_range(&storage).unwrap();
        assert!(earliest.is_some());
        assert!(latest.is_some());
    }

    #[test]
    fn test_time_range_empty() {
        let storage = AuditStorage::open_in_memory().unwrap();
        let (earliest, latest) = AuditStats::time_range(&storage).unwrap();
        assert!(earliest.is_none());
        assert!(latest.is_none());
    }
}
