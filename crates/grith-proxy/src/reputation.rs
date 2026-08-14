// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Feature-Tuple Beta Reputation System (BRS).
//!
//! Replaces the coarse adaptive scoring engine with a fine-grained reputation
//! model that learns safe patterns from user behavior. Each operation is
//! described by a tuple of features (profile, action, process, destination,
//! path-class) at varying granularity levels. The system tracks Beta(α, β)
//! distributions per tuple and uses them to adjust proxy scores.
//!
//! Safety invariants:
//! - Safety ceilings prevent auto-allow when static filters score ≥ 5.0
//! - Deny signals carry 3× the weight of approvals
//! - Sensitive roots (`.ssh`, `.aws`, `.gnupg`, etc.) only get Level 0 (exact) entries
//! - Time decay ensures stale trust fades

use std::collections::HashMap;
use std::time::Instant;

use crate::types::{FilterResult, ToolCallType};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the reputation system.
#[derive(Debug, Clone)]
pub struct ReputationConfig {
    /// Whether the reputation system is enabled.
    pub enabled: bool,
    /// Per-hour exponential decay factor. 0.98 ≈ 61% after 24h.
    pub decay_lambda: f64,
    /// Weight multiplier for deny signals (default 3.0).
    pub deny_weight: f64,
    /// Trust score threshold for auto-allow (default 0.92).
    pub auto_allow_trust: f64,
    /// Minimum observations before auto-allow can trigger (default 8).
    pub auto_allow_min_observations: usize,
    /// Maximum score reduction from reputation (default 4.0).
    pub max_score_reduction: f64,
    /// Individual filter score threshold that triggers a safety ceiling (default 5.0).
    pub ceiling_filter_threshold: f64,
    /// Maximum raw score that reputation can auto-allow (default 7.0).
    /// Operations scoring above this are never auto-allowed by reputation.
    pub max_auto_allow_raw_score: f64,
    /// How often (in seconds) to save the reputation table during a session.
    pub save_interval_seconds: u64,
}

impl ReputationConfig {
    /// Get the save interval in seconds.
    pub fn save_interval_seconds(&self) -> u64 {
        self.save_interval_seconds
    }
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            decay_lambda: 0.98,
            deny_weight: 3.0,
            auto_allow_trust: 0.92,
            auto_allow_min_observations: 8,
            max_score_reduction: 4.0,
            ceiling_filter_threshold: 5.0,
            max_auto_allow_raw_score: 7.0,
            save_interval_seconds: 300,
        }
    }
}

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Outcome of a user action used as a reputation signal.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReputationOutcome {
    /// User approved (weight 1.0) or learned (weight 1.5).
    Approved(f64),
    /// User denied (weight 3.0), terminate-denied (5.0), or auto-denied (1.0).
    Denied(f64),
}

/// A single reputation entry tracking a Beta(α, β) distribution.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReputationEntry {
    pub alpha: f64,
    pub beta: f64,
    pub last_updated: String,
    #[serde(skip)]
    last_updated_instant: Option<Instant>,
}

const MIN_ALPHA: f64 = 0.5;
const MIN_BETA: f64 = 0.5;

impl ReputationEntry {
    /// Create a new entry with the given prior.
    pub fn new(alpha: f64, beta: f64) -> Self {
        Self {
            alpha: alpha.max(MIN_ALPHA),
            beta: beta.max(MIN_BETA),
            last_updated: chrono::Utc::now().to_rfc3339(),
            last_updated_instant: Some(Instant::now()),
        }
    }

    /// Trust score: α / (α + β).
    pub fn trust_score(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }

    /// Total observations (approximate, since decay reduces values).
    pub fn observation_count(&self) -> f64 {
        self.alpha + self.beta
    }

    /// Record an observation, applying time decay first.
    pub fn observe(&mut self, outcome: ReputationOutcome, decay_lambda: f64) {
        let now = Instant::now();
        self.apply_decay(now, decay_lambda);

        match outcome {
            ReputationOutcome::Approved(weight) => self.alpha += weight,
            ReputationOutcome::Denied(weight) => self.beta += weight,
        }

        self.alpha = self.alpha.max(MIN_ALPHA);
        self.beta = self.beta.max(MIN_BETA);
        self.last_updated = chrono::Utc::now().to_rfc3339();
        self.last_updated_instant = Some(now);
    }

    /// Apply exponential time decay based on elapsed hours.
    ///
    /// After deserialization, `last_updated_instant` is `None`. In that case,
    /// we compute elapsed hours from the persisted ISO `last_updated` string
    /// so that decay works correctly across restarts.
    fn apply_decay(&mut self, now: Instant, decay_lambda: f64) {
        let hours = if let Some(last) = self.last_updated_instant {
            now.duration_since(last).as_secs_f64() / 3600.0
        } else {
            // After deserialization: compute from the ISO timestamp.
            chrono::DateTime::parse_from_rfc3339(&self.last_updated)
                .ok()
                .map(|dt| {
                    let elapsed = chrono::Utc::now().signed_duration_since(dt);
                    (elapsed.num_seconds().max(0) as f64) / 3600.0
                })
                .unwrap_or(0.0)
        };

        if hours > 0.0 {
            let factor = decay_lambda.powf(hours);
            self.alpha = (self.alpha * factor).max(MIN_ALPHA);
            self.beta = (self.beta * factor).max(MIN_BETA);
        }

        // Set the instant so subsequent calls within this session use monotonic time.
        self.last_updated_instant = Some(now);
    }
}

// ---------------------------------------------------------------------------
// Path-class derivation
// ---------------------------------------------------------------------------

/// Sensitive roots where generalization is forbidden.
/// Only Level 0 (exact) entries are created for paths under these directories.
const SENSITIVE_ROOTS: &[&str] = &[
    "/.ssh/",
    "/.aws/",
    "/.gnupg/",
    "/.pki/",
    "/.config/gh/",
    "/.kube/",
    "/.docker/",
    "/.config/gcloud/",
    "/.azure/",
];

/// Check if a path is under a sensitive root that forbids generalization.
fn is_sensitive_root(path: &str) -> bool {
    SENSITIVE_ROOTS.iter().any(|root| path.contains(root))
}

/// Derive path classes at multiple granularity levels.
///
/// - Level 0: exact path
/// - Level 1: parent directory + `/*` (file-class)
///
/// Level 2 (grandparent) is intentionally omitted to prevent trust from
/// crossing sibling boundaries (e.g., `~/project/src/foo.rs` should not
/// build trust for `~/project/.env`).
///
/// Returns `Vec<(level, path_class)>`. Sensitive roots only get Level 0.
pub fn derive_path_classes(path: &str) -> Vec<(u8, String)> {
    let mut classes = vec![(0u8, path.to_string())];

    if is_sensitive_root(path) {
        return classes;
    }

    // Level 1: parent directory + /*
    if let Some(parent) = std::path::Path::new(path).parent() {
        if let Some(parent_str) = parent.to_str() {
            if !parent_str.is_empty() && parent_str != "/" {
                classes.push((1, format!("{parent_str}/*")));
            }
        }
    }

    classes
}

// ---------------------------------------------------------------------------
// Feature-tuple key generation
// ---------------------------------------------------------------------------

/// Build reputation keys at all applicable levels for a given operation.
///
/// Returns `Vec<(level, key_string)>` where level 0 is most specific
/// and level 3 is least specific (process-only).
pub fn build_reputation_keys(
    profile: &str,
    action: &str,
    process: &str,
    destination: &str,
    path: &str,
) -> Vec<(u8, String)> {
    let dest = if destination.is_empty() {
        "*"
    } else {
        destination
    };
    let proc = if process.is_empty() { "*" } else { process };

    let path_classes = derive_path_classes(path);

    let mut keys: Vec<(u8, String)> = path_classes
        .into_iter()
        .map(|(level, pc)| (level, format!("{profile}|{action}|{proc}|{dest}|{pc}")))
        .collect();

    // Level 3: process-only (no path specificity).
    // Only add if the path is not under a sensitive root.
    if !is_sensitive_root(path) {
        keys.push((3, format!("{profile}|{action}|{proc}|{dest}|*")));
    }

    keys
}

/// Extract a coarse action name from a ToolCallType for use in reputation keys.
pub fn action_name(call_type: &ToolCallType) -> &'static str {
    match call_type {
        ToolCallType::FileRead { .. } => "FileRead",
        ToolCallType::FileWrite { .. } => "FileWrite",
        ToolCallType::FileAppend { .. } => "FileAppend",
        ToolCallType::FileDelete { .. } => "FileDelete",
        ToolCallType::DirList { .. } => "DirList",
        ToolCallType::DirCreate { .. } => "DirCreate",
        ToolCallType::FileRename { .. } => "FileRename",
        ToolCallType::FileLink { .. } => "FileLink",
        ToolCallType::FileChmod { .. } => "FileChmod",
        ToolCallType::ShellExec { .. } => "ShellExec",
        ToolCallType::ProcessSpawn { .. } => "ProcessSpawn",
        ToolCallType::HttpRequest { .. } => "HttpRequest",
        ToolCallType::NetConnect { .. } => "NetConnect",
        ToolCallType::NetListen { .. } => "NetListen",
        ToolCallType::DnsQuery { .. } => "DnsQuery",
        // PR 6 Phase B: category-2 syscalls.
        ToolCallType::OwnershipChange { .. } => "OwnershipChange",
        ToolCallType::FilesystemMutation { .. } => "FilesystemMutation",
        ToolCallType::CrossProcessAccess { .. } => "CrossProcessAccess",
        ToolCallType::NamespaceOp { .. } => "NamespaceOp",
    }
}

// ---------------------------------------------------------------------------
// Safety ceilings
// ---------------------------------------------------------------------------

/// Check if a safety ceiling applies that prevents reputation-based auto-allow.
pub fn has_safety_ceiling(
    filter_results: &[FilterResult],
    call_type: &ToolCallType,
    config: &ReputationConfig,
) -> bool {
    // Any individual filter scoring above the ceiling threshold.
    let has_high_filter = filter_results
        .iter()
        .any(|r| r.matched && r.score >= config.ceiling_filter_threshold);
    if has_high_filter {
        return true;
    }

    // Secret-scanning filter matched.
    let secret_scan_matched = filter_results
        .iter()
        .any(|r| r.matched && r.filter_name == "secret-scan");
    if secret_scan_matched {
        return true;
    }

    // Write operations to sensitive directories.
    let is_write = matches!(
        call_type,
        ToolCallType::FileWrite { .. }
            | ToolCallType::FileAppend { .. }
            | ToolCallType::FileDelete { .. }
            | ToolCallType::FileRename { .. }
            | ToolCallType::FileChmod { .. }
            | ToolCallType::DirCreate { .. }
    );
    if is_write {
        let path = match call_type {
            ToolCallType::FileWrite { path, .. }
            | ToolCallType::FileAppend { path }
            | ToolCallType::FileDelete { path }
            | ToolCallType::FileChmod { path, .. }
            | ToolCallType::DirCreate { path } => Some(path.as_str()),
            ToolCallType::FileRename { old_path, .. } => Some(old_path.as_str()),
            _ => None,
        };
        if let Some(p) = path {
            if is_sensitive_root(p) {
                return true;
            }
        }
    }

    // Operations touching sensitive roots (even reads) for ceiling purposes.
    // Reputation can still provide bounded score reduction but not auto-allow.
    let op_path = match call_type {
        ToolCallType::FileRead { path }
        | ToolCallType::FileWrite { path, .. }
        | ToolCallType::FileAppend { path }
        | ToolCallType::FileDelete { path }
        | ToolCallType::FileChmod { path, .. }
        | ToolCallType::DirCreate { path }
        | ToolCallType::DirList { path } => Some(path.as_str()),
        ToolCallType::FileRename { old_path, .. } => Some(old_path.as_str()),
        _ => None,
    };
    if let Some(p) = op_path {
        if is_sensitive_root(p) {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Reputation table
// ---------------------------------------------------------------------------

/// The main reputation table: maps tuple keys to Beta entries.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ReputationTable {
    #[serde(default)]
    pub entries: HashMap<String, ReputationEntry>,
}

impl ReputationTable {
    /// Create an empty reputation table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an observation at all applicable tuple levels.
    pub fn observe(
        &mut self,
        keys: &[(u8, String)],
        outcome: ReputationOutcome,
        config: &ReputationConfig,
    ) {
        if !config.enabled {
            return;
        }
        for (_level, key) in keys {
            let entry = self
                .entries
                .entry(key.clone())
                .or_insert_with(|| ReputationEntry::new(1.0, 1.0));
            entry.observe(outcome, config.decay_lambda);
        }
    }

    /// Look up the trust score from the most specific level with sufficient data.
    ///
    /// Returns `Some((trust_score, level))` or `None` if no level has enough data.
    pub fn lookup(&self, keys: &[(u8, String)], config: &ReputationConfig) -> Option<(f64, u8)> {
        if !config.enabled {
            return None;
        }
        // Keys are ordered most-specific to least-specific.
        for (level, key) in keys {
            if let Some(entry) = self.entries.get(key) {
                if entry.observation_count() >= config.auto_allow_min_observations as f64 {
                    return Some((entry.trust_score(), *level));
                }
            }
        }
        None
    }

    /// Compute the score adjustment based on reputation.
    ///
    /// Returns the adjusted score. If auto-allow conditions are met
    /// (high trust, enough observations, no ceiling, raw score below max),
    /// returns 0.0 (auto-allow).
    pub fn adjust_score(
        &self,
        original_score: f64,
        keys: &[(u8, String)],
        ceiling_applies: bool,
        config: &ReputationConfig,
    ) -> f64 {
        if !config.enabled {
            return original_score;
        }
        let Some((trust, _level)) = self.lookup(keys, config) else {
            return original_score;
        };

        // Auto-allow check: high trust + enough observations + no ceiling + raw score within range.
        if !ceiling_applies
            && trust >= config.auto_allow_trust
            && original_score <= config.max_auto_allow_raw_score
        {
            return 0.0;
        }

        // Bounded score reduction based on trust.
        // trust 0.5 (uninformative) → 0.0 reduction
        // trust 1.0 (fully trusted) → max_score_reduction
        // trust 0.0 (fully distrusted) → -max_score_reduction (score increase)
        let reduction = (trust - 0.5) * 2.0 * config.max_score_reduction;
        (original_score - reduction).max(0.0)
    }

    /// Initialize reputation entries from profile priors.
    ///
    /// Only sets priors for entries that don't already exist with more data.
    pub fn seed_from_profile(
        &mut self,
        profile: &str,
        routine_paths: &[String],
        routine_commands: &[String],
        routine_destinations: &[String],
        readonly_paths: &[String],
    ) {
        for path in routine_paths {
            let key = format!("{profile}|FileRead|*|*|{path}");
            self.entries
                .entry(key)
                .or_insert_with(|| ReputationEntry::new(10.0, 0.5));
            let key = format!("{profile}|FileWrite|*|*|{path}");
            self.entries
                .entry(key)
                .or_insert_with(|| ReputationEntry::new(10.0, 0.5));
        }
        for cmd in routine_commands {
            let key = format!("{profile}|ProcessSpawn|*|*|{cmd}");
            self.entries
                .entry(key)
                .or_insert_with(|| ReputationEntry::new(10.0, 0.5));
        }
        for dest in routine_destinations {
            let key = format!("{profile}|NetConnect|*|*|{dest}");
            self.entries
                .entry(key)
                .or_insert_with(|| ReputationEntry::new(10.0, 0.5));
        }
        for path in readonly_paths {
            let key = format!("{profile}|FileRead|*|*|{path}");
            self.entries
                .entry(key)
                .or_insert_with(|| ReputationEntry::new(8.0, 0.5));
        }
    }

    /// Total number of entries in the table.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn reset(&mut self) {
        self.entries.clear();
    }

    /// Save the reputation table to a TOML file with merge-on-save.
    ///
    /// Before writing, reloads the existing file and merges entries using
    /// max(alpha, beta) per key. This prevents concurrent sessions from
    /// losing each other's observations (the last session to save merges
    /// rather than overwrites).
    pub fn save(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Merge with existing on-disk state to prevent data loss from
        // concurrent sessions.
        let mut merged = Self::load(path);
        for (key, entry) in &self.entries {
            match merged.entries.get_mut(key) {
                Some(existing) => {
                    // Take the higher values — more observations is more data.
                    if entry.alpha > existing.alpha {
                        existing.alpha = entry.alpha;
                    }
                    if entry.beta > existing.beta {
                        existing.beta = entry.beta;
                    }
                    // Use the more recent timestamp.
                    if entry.last_updated > existing.last_updated {
                        existing.last_updated = entry.last_updated.clone();
                    }
                }
                None => {
                    merged.entries.insert(key.clone(), entry.clone());
                }
            }
        }

        let content = toml::to_string_pretty(&merged).map_err(std::io::Error::other)?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, &content)?;
        if let Ok(f) = std::fs::File::open(&tmp) {
            let _ = f.sync_all();
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Load the reputation table from a TOML file.
    ///
    /// Returns an empty table if the file doesn't exist or can't be parsed.
    /// Entries with invalid invariants (negative alpha/beta, etc.) are dropped.
    pub fn load(path: impl AsRef<std::path::Path>) -> Self {
        let path = path.as_ref();
        if !path.exists() {
            return Self::new();
        }
        let mut table: Self = match std::fs::read_to_string(path) {
            Ok(content) => toml::from_str(&content).unwrap_or_default(),
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "failed to load reputation table");
                return Self::new();
            }
        };

        // Validate and sanitize loaded entries.
        let before = table.entries.len();
        table.entries.retain(|key, entry| {
            // Reject negative or NaN values.
            if entry.alpha < 0.0 || entry.beta < 0.0 || entry.alpha.is_nan() || entry.beta.is_nan()
            {
                tracing::warn!(key, "dropping reputation entry with invalid alpha/beta");
                return false;
            }
            // Clamp to reasonable bounds (prevent maliciously inflated values).
            entry.alpha = entry.alpha.clamp(MIN_ALPHA, 10000.0);
            entry.beta = entry.beta.clamp(MIN_BETA, 10000.0);
            true
        });
        let dropped = before - table.entries.len();
        if dropped > 0 {
            tracing::warn!(dropped, "dropped invalid reputation entries on load");
        }

        table
    }
}

/// Return the default path for the reputation persistence file.
///
/// Falls back to a temporary directory if `$HOME` is unset, but logs a warning
/// because `/tmp` is not a suitable persistence location.
pub fn default_reputation_path() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("GRITH_CONFIG_DIR") {
        return std::path::PathBuf::from(path).join("reputation.toml");
    }

    if let Some(home) = std::env::var_os("HOME") {
        return std::path::PathBuf::from(home)
            .join(".config/grith")
            .join("reputation.toml");
    }

    if let Some(profile) = std::env::var_os("USERPROFILE") {
        return std::path::PathBuf::from(profile)
            .join(".config/grith")
            .join("reputation.toml");
    }

    std::path::PathBuf::from(".grith").join("reputation.toml")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;

    fn matched_result(name: &str, score: f64) -> FilterResult {
        FilterResult::matched(name, "rule-1", score, Severity::Warning, "test")
    }

    // -- ReputationEntry tests --

    #[test]
    fn trust_score_uninformative_prior() {
        let entry = ReputationEntry::new(1.0, 1.0);
        assert!((entry.trust_score() - 0.5).abs() < 0.01);
    }

    #[test]
    fn trust_score_profile_prior() {
        let entry = ReputationEntry::new(10.0, 0.5);
        assert!(entry.trust_score() > 0.94);
    }

    #[test]
    fn observe_approved_increases_alpha() {
        let mut entry = ReputationEntry::new(1.0, 1.0);
        let before = entry.alpha;
        entry.observe(ReputationOutcome::Approved(1.0), 1.0); // no decay
        assert!(entry.alpha > before);
    }

    #[test]
    fn observe_denied_increases_beta() {
        let mut entry = ReputationEntry::new(1.0, 1.0);
        let before = entry.beta;
        entry.observe(ReputationOutcome::Denied(3.0), 1.0);
        assert!(entry.beta > before);
    }

    #[test]
    fn single_deny_drops_trust_significantly() {
        let mut entry = ReputationEntry::new(10.0, 0.5);
        let before = entry.trust_score();
        entry.observe(ReputationOutcome::Denied(3.0), 1.0);
        let after = entry.trust_score();
        assert!(after < 0.80, "trust should drop below 0.80: {after}");
        assert!(
            before - after > 0.10,
            "trust should drop by >0.10: {before} -> {after}"
        );
    }

    #[test]
    fn min_clamps_prevent_zero() {
        let mut entry = ReputationEntry::new(MIN_ALPHA, MIN_BETA);
        // Multiple denials shouldn't push alpha below min.
        for _ in 0..100 {
            entry.observe(ReputationOutcome::Denied(5.0), 0.5);
        }
        assert!(entry.alpha >= MIN_ALPHA);
        assert!(entry.trust_score() > 0.0);
        assert!(entry.trust_score() < 1.0);
    }

    // -- Path-class derivation tests --

    #[test]
    fn sensitive_root_only_level_0() {
        let classes = derive_path_classes("/home/dan/.ssh/id_rsa");
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].0, 0);
        assert_eq!(classes[0].1, "/home/dan/.ssh/id_rsa");
    }

    #[test]
    fn sensitive_aws_only_level_0() {
        let classes = derive_path_classes("/home/dan/.aws/credentials");
        assert_eq!(classes.len(), 1);
    }

    #[test]
    fn non_sensitive_path_gets_2_levels() {
        let classes = derive_path_classes("/home/dan/Pictures/Screenshots/shot.png");
        assert_eq!(classes.len(), 2);
        assert_eq!(classes[0].0, 0); // exact
        assert_eq!(classes[1].0, 1); // parent/*
        assert!(classes[1].1.ends_with("/*"));
        assert_eq!(classes[1].1, "/home/dan/Pictures/Screenshots/*");
    }

    #[test]
    fn exec_path_gets_levels() {
        let classes = derive_path_classes("/usr/bin/ssh");
        assert!(classes.len() >= 2);
        assert_eq!(classes[0].1, "/usr/bin/ssh");
        assert_eq!(classes[1].1, "/usr/bin/*");
    }

    // -- Key generation tests --

    #[test]
    fn keys_are_deterministic() {
        let k1 = build_reputation_keys("claude-code", "FileRead", "ssh", "github.com", "/tmp/f");
        let k2 = build_reputation_keys("claude-code", "FileRead", "ssh", "github.com", "/tmp/f");
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_profiles_produce_different_keys() {
        let k1 = build_reputation_keys("claude-code", "FileRead", "ssh", "*", "/tmp/f");
        let k2 = build_reputation_keys("codex", "FileRead", "ssh", "*", "/tmp/f");
        assert_ne!(k1[0].1, k2[0].1);
    }

    #[test]
    fn sensitive_path_no_level_3() {
        let keys =
            build_reputation_keys("claude-code", "FileRead", "ssh", "*", "/home/d/.ssh/id_rsa");
        assert!(
            !keys.iter().any(|(l, _)| *l == 3),
            "sensitive paths should not have Level 3 keys"
        );
    }

    #[test]
    fn non_sensitive_path_has_level_3() {
        let keys = build_reputation_keys("claude-code", "FileRead", "claude", "*", "/tmp/foo.txt");
        assert!(
            keys.iter().any(|(l, _)| *l == 3),
            "non-sensitive paths should have Level 3 keys"
        );
    }

    // -- Safety ceiling tests --

    #[test]
    fn ceiling_on_high_filter_score() {
        let config = ReputationConfig::default();
        let filters = vec![matched_result("path-match", 5.0)];
        let call = ToolCallType::FileRead {
            path: "/tmp/foo".into(),
        };
        assert!(has_safety_ceiling(&filters, &call, &config));
    }

    #[test]
    fn no_ceiling_on_low_filter_score() {
        let config = ReputationConfig::default();
        let filters = vec![matched_result("path-match", 4.9)];
        let call = ToolCallType::FileRead {
            path: "/tmp/foo".into(),
        };
        assert!(!has_safety_ceiling(&filters, &call, &config));
    }

    #[test]
    fn ceiling_on_secret_scan() {
        let config = ReputationConfig::default();
        let filters = vec![matched_result("secret-scan", 2.0)];
        let call = ToolCallType::FileRead {
            path: "/tmp/.env".into(),
        };
        assert!(has_safety_ceiling(&filters, &call, &config));
    }

    #[test]
    fn ceiling_on_sensitive_write() {
        let config = ReputationConfig::default();
        let filters = vec![];
        let call = ToolCallType::FileWrite {
            path: "/home/dan/.ssh/config".into(),
            content_hash: String::new(),
        };
        assert!(has_safety_ceiling(&filters, &call, &config));
    }

    #[test]
    fn ceiling_on_sensitive_read() {
        let config = ReputationConfig::default();
        let filters = vec![];
        let call = ToolCallType::FileRead {
            path: "/home/dan/.ssh/id_rsa".into(),
        };
        assert!(has_safety_ceiling(&filters, &call, &config));
    }

    #[test]
    fn no_ceiling_on_normal_read() {
        let config = ReputationConfig::default();
        let filters = vec![matched_result("behavioural", 2.0)];
        let call = ToolCallType::FileRead {
            path: "/home/dan/project/src/main.rs".into(),
        };
        assert!(!has_safety_ceiling(&filters, &call, &config));
    }

    // -- ReputationTable tests --

    #[test]
    fn lookup_returns_none_for_empty_table() {
        let table = ReputationTable::new();
        let config = ReputationConfig::default();
        let keys = build_reputation_keys("claude-code", "FileRead", "claude", "*", "/tmp/f");
        assert!(table.lookup(&keys, &config).is_none());
    }

    #[test]
    fn observe_and_lookup() {
        let mut table = ReputationTable::new();
        let config = ReputationConfig::default();
        let keys = build_reputation_keys("claude-code", "FileRead", "claude", "*", "/tmp/f");

        for _ in 0..10 {
            table.observe(&keys, ReputationOutcome::Approved(1.0), &config);
        }

        let result = table.lookup(&keys, &config);
        assert!(result.is_some());
        let (trust, _level) = result.unwrap();
        assert!(trust > 0.8);
    }

    #[test]
    fn auto_allow_with_high_trust_no_ceiling() {
        let mut table = ReputationTable::new();
        let config = ReputationConfig::default();
        let keys = build_reputation_keys("claude-code", "FileRead", "claude", "*", "/tmp/f");

        for _ in 0..20 {
            table.observe(&keys, ReputationOutcome::Approved(1.5), &config);
        }

        let adjusted = table.adjust_score(4.0, &keys, false, &config);
        assert_eq!(
            adjusted, 0.0,
            "should auto-allow with high trust and no ceiling"
        );
    }

    #[test]
    fn no_auto_allow_with_ceiling() {
        let mut table = ReputationTable::new();
        let config = ReputationConfig::default();
        let keys = build_reputation_keys("claude-code", "FileRead", "claude", "*", "/tmp/f");

        for _ in 0..20 {
            table.observe(&keys, ReputationOutcome::Approved(1.5), &config);
        }

        let adjusted = table.adjust_score(4.0, &keys, true, &config);
        assert!(adjusted > 0.0, "ceiling should prevent auto-allow");
        assert!(adjusted < 4.0, "should still get score reduction");
    }

    #[test]
    fn no_auto_allow_above_max_raw_score() {
        let mut table = ReputationTable::new();
        let config = ReputationConfig::default();
        let keys = build_reputation_keys("claude-code", "FileRead", "claude", "*", "/tmp/f");

        for _ in 0..20 {
            table.observe(&keys, ReputationOutcome::Approved(1.5), &config);
        }

        let adjusted = table.adjust_score(7.5, &keys, false, &config);
        assert!(
            adjusted > 0.0,
            "score above max_auto_allow_raw_score should not auto-allow"
        );
    }

    #[test]
    fn deny_drops_trust_below_auto_allow() {
        let mut table = ReputationTable::new();
        let config = ReputationConfig::default();
        let keys = build_reputation_keys("claude-code", "FileRead", "claude", "*", "/tmp/f");

        // Build high trust.
        for _ in 0..20 {
            table.observe(&keys, ReputationOutcome::Approved(1.5), &config);
        }
        // Verify auto-allow.
        assert_eq!(table.adjust_score(4.0, &keys, false, &config), 0.0);

        // One deny should drop trust.
        table.observe(&keys, ReputationOutcome::Denied(3.0), &config);
        let adjusted = table.adjust_score(4.0, &keys, false, &config);
        assert!(adjusted > 0.0, "single deny should revoke auto-allow");
    }

    #[test]
    fn cross_profile_isolation() {
        let mut table = ReputationTable::new();
        let config = ReputationConfig::default();

        let claude_keys = build_reputation_keys("claude-code", "FileRead", "claude", "*", "/tmp/f");
        let codex_keys = build_reputation_keys("codex", "FileRead", "claude", "*", "/tmp/f");

        for _ in 0..20 {
            table.observe(&claude_keys, ReputationOutcome::Approved(1.5), &config);
        }

        // Claude should auto-allow.
        assert_eq!(table.adjust_score(4.0, &claude_keys, false, &config), 0.0);
        // Codex should NOT auto-allow.
        assert!(table.lookup(&codex_keys, &config).is_none());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let mut table = ReputationTable::new();
        let config = ReputationConfig::default();
        let keys = build_reputation_keys("claude-code", "FileRead", "claude", "*", "/tmp/f");

        for _ in 0..10 {
            table.observe(&keys, ReputationOutcome::Approved(1.0), &config);
        }

        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("reputation.toml");
        table.save(&path).unwrap();

        let loaded = ReputationTable::load(&path);
        assert_eq!(loaded.len(), table.len());

        // Trust scores should be approximately equal.
        for (key, entry) in &table.entries {
            let loaded_entry = loaded.entries.get(key).unwrap();
            assert!(
                (entry.trust_score() - loaded_entry.trust_score()).abs() < 0.01,
                "trust scores should match after roundtrip"
            );
        }
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let table = ReputationTable::load("/nonexistent/path/reputation.toml");
        assert!(table.is_empty());
    }

    #[test]
    fn disabled_config_skips_observe_and_adjust() {
        let mut config = ReputationConfig::default();
        config.enabled = false;
        let keys = build_reputation_keys("claude-code", "FileRead", "claude", "*", "/tmp/f");
        let mut table = ReputationTable::new();
        table.observe(&keys, ReputationOutcome::Approved(1.0), &config);
        assert!(table.is_empty());
        assert_eq!(table.adjust_score(4.0, &keys, false, &config), 4.0);
        assert!(table.lookup(&keys, &config).is_none());
    }

    #[test]
    fn generalization_across_similar_files() {
        let mut table = ReputationTable::new();
        let config = ReputationConfig::default();

        // Learn several screenshots.
        for i in 0..6 {
            let path = format!("/home/dan/Pictures/Screenshots/shot{i}.png");
            let keys = build_reputation_keys("claude-code", "FileRead", "claude", "*", &path);
            table.observe(&keys, ReputationOutcome::Approved(1.5), &config);
        }

        // New screenshot should benefit from Level 1 generalization.
        let new_keys = build_reputation_keys(
            "claude-code",
            "FileRead",
            "claude",
            "*",
            "/home/dan/Pictures/Screenshots/shot_new.png",
        );

        let result = table.lookup(&new_keys, &config);
        assert!(
            result.is_some(),
            "generalization should provide trust for new file in same directory"
        );
        let (trust, level) = result.unwrap();
        assert!(level >= 1, "should match at Level 1 or higher");
        assert!(trust > 0.8, "trust should be high from repeated approvals");
    }

    #[test]
    fn no_generalization_for_sensitive_paths() {
        let mut table = ReputationTable::new();
        let config = ReputationConfig::default();

        // Learn several SSH key reads.
        for name in &["id_rsa", "id_rsa.pub", "id_rsa-cert.pub"] {
            let path = format!("/home/dan/.ssh/{name}");
            let keys = build_reputation_keys("claude-code", "FileRead", "ssh", "github.com", &path);
            table.observe(&keys, ReputationOutcome::Approved(1.5), &config);
        }

        // A different SSH file should NOT generalize (only exact matches).
        let new_keys = build_reputation_keys(
            "claude-code",
            "FileRead",
            "ssh",
            "github.com",
            "/home/dan/.ssh/id_ed25519",
        );
        assert!(
            table.lookup(&new_keys, &config).is_none(),
            "sensitive paths must not generalize"
        );
    }
}
