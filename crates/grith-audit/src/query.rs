// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Builder-pattern query interface for filtering audit records.

use crate::error::Result;
use crate::record_parser::row_to_record;
use crate::storage::AuditStorage;
use crate::types::{AuditRecord, ProxyActionSummary};
use chrono::{DateTime, Utc};
use rusqlite::params_from_iter;
use uuid::Uuid;

/// Query parameters for filtering audit records.
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    pub session_id: Option<Uuid>,
    pub time_start: Option<DateTime<Utc>>,
    pub time_end: Option<DateTime<Utc>>,
    pub min_score: Option<f64>,
    pub max_score: Option<f64>,
    pub action_filter: Option<ProxyActionSummary>,
    pub plugin_filter: Option<String>,
    pub call_type_filter: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

impl AuditQuery {
    /// Create an empty query that matches all records.
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by session ID.
    pub fn session(mut self, id: Uuid) -> Self {
        self.session_id = Some(id);
        self
    }

    /// Filter to records within a time range (inclusive).
    pub fn time_range(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.time_start = Some(start);
        self.time_end = Some(end);
        self
    }

    /// Filter to records at or above the given composite score.
    pub fn min_score(mut self, score: f64) -> Self {
        self.min_score = Some(score);
        self
    }

    /// Filter by proxy action (allow / queue / deny).
    pub fn action(mut self, action: ProxyActionSummary) -> Self {
        self.action_filter = Some(action);
        self
    }

    /// Filter by plugin identifier.
    pub fn plugin(mut self, plugin_id: impl Into<String>) -> Self {
        self.plugin_filter = Some(plugin_id.into());
        self
    }

    /// Filter by tool call type (e.g., `"FileRead"`, `"ShellExec"`).
    pub fn call_type(mut self, call_type: impl Into<String>) -> Self {
        self.call_type_filter = Some(call_type.into());
        self
    }

    /// Filter to records on or after the given timestamp.
    pub fn since(mut self, start: DateTime<Utc>) -> Self {
        self.time_start = Some(start);
        self
    }

    /// Apply limit and offset for pagination.
    pub fn paginate(mut self, limit: usize, offset: usize) -> Self {
        self.limit = Some(limit);
        self.offset = Some(offset);
        self
    }

    /// Execute this query against the given storage.
    pub fn execute(&self, storage: &AuditStorage) -> Result<Vec<AuditRecord>> {
        let (where_clause, params) = self.build_where();
        let sql = format!(
            "SELECT * FROM audit_log {where_clause} ORDER BY timestamp DESC {} {}",
            self.limit.map(|l| format!("LIMIT {l}")).unwrap_or_default(),
            self.offset
                .map(|o| format!("OFFSET {o}"))
                .unwrap_or_default(),
        );
        let conn = storage.connection();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(params.iter()), |row| {
            row_to_record(row).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))
        })?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    /// Count matching records (for pagination).
    pub fn count(&self, storage: &AuditStorage) -> Result<usize> {
        let (where_clause, params) = self.build_where();
        let sql = format!("SELECT COUNT(*) FROM audit_log {where_clause}");
        let conn = storage.connection();
        let count: i64 = conn.query_row(&sql, params_from_iter(params.iter()), |row| row.get(0))?;
        Ok(count as usize)
    }

    fn build_where(&self) -> (String, Vec<String>) {
        let mut conditions = Vec::new();
        let mut params: Vec<String> = Vec::new();

        if let Some(sid) = &self.session_id {
            params.push(sid.to_string());
            conditions.push(format!("session_id = ?{}", params.len()));
        }
        if let Some(start) = &self.time_start {
            params.push(start.to_rfc3339());
            conditions.push(format!("timestamp >= ?{}", params.len()));
        }
        if let Some(end) = &self.time_end {
            params.push(end.to_rfc3339());
            conditions.push(format!("timestamp <= ?{}", params.len()));
        }
        if let Some(min) = self.min_score {
            params.push(min.to_string());
            conditions.push(format!("composite_score >= ?{}", params.len()));
        }
        if let Some(max) = self.max_score {
            params.push(max.to_string());
            conditions.push(format!("composite_score <= ?{}", params.len()));
        }
        if let Some(action) = &self.action_filter {
            params.push(action.to_string());
            conditions.push(format!("proxy_action = ?{}", params.len()));
        }
        if let Some(plugin) = &self.plugin_filter {
            params.push(plugin.clone());
            conditions.push(format!("plugin_id = ?{}", params.len()));
        }
        if let Some(ct) = &self.call_type_filter {
            params.push(ct.clone());
            conditions.push(format!("tool_call_type = ?{}", params.len()));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        (where_clause, params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(
        session: Uuid,
        plugin: &str,
        call_type: &str,
        score: f64,
        action: ProxyActionSummary,
    ) -> AuditRecord {
        AuditRecord::new(
            session,
            plugin.into(),
            call_type.into(),
            &serde_json::json!({"test": true}),
            score,
            action,
            vec![],
            1.0,
            None,
        )
    }

    fn setup() -> AuditStorage {
        let storage = AuditStorage::open_in_memory().unwrap();
        let s1 = Uuid::new_v4();
        let s2 = Uuid::new_v4();
        storage
            .insert_record(&make_record(
                s1,
                "file-ops",
                "FileRead",
                0.5,
                ProxyActionSummary::Allow,
            ))
            .unwrap();
        storage
            .insert_record(&make_record(
                s1,
                "shell",
                "ShellExec",
                5.0,
                ProxyActionSummary::Queue,
            ))
            .unwrap();
        storage
            .insert_record(&make_record(
                s2,
                "file-ops",
                "FileWrite",
                9.5,
                ProxyActionSummary::Deny,
            ))
            .unwrap();
        storage
            .insert_record(&make_record(
                s2,
                "http",
                "HttpRequest",
                1.0,
                ProxyActionSummary::Allow,
            ))
            .unwrap();
        storage
    }

    #[test]
    fn test_query_all() {
        let storage = setup();
        let results = AuditQuery::new().execute(&storage).unwrap();
        assert_eq!(results.len(), 4);
    }

    #[test]
    fn test_query_by_action() {
        let storage = setup();
        let results = AuditQuery::new()
            .action(ProxyActionSummary::Allow)
            .execute(&storage)
            .unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_by_plugin() {
        let storage = setup();
        let results = AuditQuery::new()
            .plugin("file-ops")
            .execute(&storage)
            .unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_by_min_score() {
        let storage = setup();
        let results = AuditQuery::new().min_score(5.0).execute(&storage).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_pagination() {
        let storage = setup();
        let results = AuditQuery::new().paginate(2, 0).execute(&storage).unwrap();
        assert_eq!(results.len(), 2);

        let page2 = AuditQuery::new().paginate(2, 2).execute(&storage).unwrap();
        assert_eq!(page2.len(), 2);
    }

    #[test]
    fn test_query_count() {
        let storage = setup();
        let count = AuditQuery::new()
            .action(ProxyActionSummary::Deny)
            .count(&storage)
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_query_by_call_type() {
        let storage = setup();
        let results = AuditQuery::new()
            .call_type("ShellExec")
            .execute(&storage)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tool_call_type, "ShellExec");
    }

    #[test]
    fn test_query_empty_result() {
        let storage = setup();
        let results = AuditQuery::new()
            .plugin("nonexistent")
            .execute(&storage)
            .unwrap();
        assert!(results.is_empty());
    }
}
