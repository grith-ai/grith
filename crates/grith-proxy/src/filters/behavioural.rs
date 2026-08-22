// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Behavioural profiling filter tracking session-level patterns.
//!
//! # Scoping (PR 1)
//!
//! Call histories key by `session_scope` — each supervised session builds its
//! own baseline. Unlike `taint`, this filter does NOT honour `conversation_id`:
//! a behavioural baseline is intrinsically per-process-lifetime, and an
//! OpenClaw conversation that crosses daemon sessions correctly cold-starts
//! a fresh baseline in each.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, SessionScopeKey, Severity, ToolCallContext, ToolCallType};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
// NOTE(M-4): std::sync::Mutex is intentionally used here instead of
// tokio::sync::Mutex because the lock is never held across .await points.
// All lock acquisitions are scoped to synchronous blocks within the async
// evaluate() method, making std::sync::Mutex the more efficient choice.
use std::sync::Mutex;

/// A record of a past tool call for behavioural profiling.
#[derive(Debug, Clone)]
pub struct CallRecord {
    pub call_type: String,
    pub timestamp: DateTime<Utc>,
}

/// Maximum number of call records retained in the sliding window.
/// When exceeded, the oldest entries are trimmed to maintain a bounded
/// memory footprint and ensure the baseline reflects recent behaviour
/// rather than degrading over long sessions (L-11).
const MAX_HISTORY_SIZE: usize = 1000;

/// The only categories the cold-start anomaly rules (`unseen-call-type` /
/// `rare-call-type` / `uncommon-call-type`) are allowed to score.
///
/// **This is an allowlist, inverted from PR 69 Change 2's denylist** of
/// "routine" categories (work/83 M9 / F9). The denylist shape was itself the
/// bug: it had to enumerate every ordinary file/net/process op, and be
/// extended by hand every time a `ToolCallType` variant was added. `file_link`
/// was simply never added, so the first symlink or hardlink of a session
/// scored `unseen-call-type` +3.0 — which, with `operation_risk`'s +0.5 link
/// baseline, is 3.5 and QUEUEs. Every `npm install` finishes with a burst of
/// `node_modules/.bin/*` symlinks and every rustc incremental build makes
/// hardlinks, so the omission spent a modal prompt (21 queues in the
/// 2026-08-20 audit morning) on the observation "this tool has not made a
/// symlink before" — not a security signal worth freezing a session over.
///
/// Inverted, a call type added later (or a platform-specific one) can never
/// silently start producing modal prompts because somebody forgot to extend a
/// list: it defaults to unscored and has to be named here deliberately.
///
/// **What suppressing `file_link` gives up, and what covers it.** Nothing an
/// attacker was constrained by. This rule scored the *novelty* of linking,
/// not the link: it fires on the first link of a session whatever that link
/// is, then decays through rare → uncommon → silent by about the seventh
/// (see `authority_category_traverses_all_three_anomaly_bands` for the walk).
/// Since any real workload makes hundreds of links, an attacker only had to
/// make theirs the eighth to pay nothing — so the signal taxed honest bursts
/// and never the adversary. What actually scores a link is what it *exposes*:
/// `ToolCallContext::paths` and `sensitive_path::path_operations` return the
/// target **and** the link path, and `sensitive_path`, `path_match` and
/// `allowlist` each evaluate both ends and take the worst, so
/// `ln -s ~/.ssh/id_rsa ./x` and `ln -s ./mine ~/.ssh/authorized_keys` both
/// still clear the QUEUE threshold on `operation_risk` + `sensitive_path`
/// alone. `credential_links_still_queue_without_the_behavioural_signal` pins
/// that; if a refactor drops either end, it fails.
///
/// **The residual, assessed — please read before re-litigating.** A link
/// whose ends match *no* name rule is now priced by `operation_risk` alone:
/// 0.5, an ALLOW. That was raised as a regression ("link-shaped
/// code-execution and credential-exposure paths no path rule covers"). It is
/// accepted deliberately, on four measured grounds:
///
/// 1. **Reach.** The signal was per-session *novelty*, so it priced the
///    **first** link of a session and progressively less thereafter. Measured
///    over one warmed session (100 reads, then 8 links) with the rule
///    restored, the addend walks 3.0, 2.0, 2.0, 1.0, 1.0, 1.0, 0, 0. For a
///    link no path rule names that is composites 3.5 QUEUE, 2.5, 2.5, 1.5,
///    1.5, 1.5, 0.5, 0.5 — one prompt per session, spent on whichever link
///    happens to arrive first (in the 2026-08-20 audit, a rustc incremental
///    hardlink or an npm `.bin/*` symlink in 96% of cases). It is not always
///    exactly one: a link whose path-derived score lands in the (0.5, 2.5]
///    band rides the decaying addend over the threshold for up to six. That
///    band is nearly empty in practice — measured, the only shape that hits it
///    is `ln -s /proc/self/environ ./x` (`kernel-interface-path`, 2.5 as a
///    read), which walked 6.0, 5.0, 5.0, 4.0, 4.0, 4.0 QUEUE and then 3.0
///    ALLOW from link #7, while *reading* the same target directly is 2.5 and
///    ALLOWs on call one. Either way the signal expires inside a single burst:
///    the same measurement put a malicious git-hook symlink arriving as link
///    #8 at 0.5 ALLOW *with* the rule. An attacker was never constrained by
///    it — theirs only had to be late.
/// 2. **Blindness.** It scored `node_modules/.bin/parser` and
///    `ln -s ./mine ~/.ssh/authorized_keys` identically (+3.0). All of the
///    discrimination between those two came from the path rules (0.0 vs 4.5),
///    which this change does not touch.
/// 3. **Parity.** What remains prices a link exactly as the operations it
///    stands in for. `path_operations` judges the target as a *read* and the
///    link path as a *write*, and `sensitive_path`, `path_match` and
///    `allowlist` each take the worst of both ends (pinned by
///    `credential_links_still_queue_without_the_behavioural_signal`, by
///    `path_match::tests::link_is_judged_at_both_ends`, and by
///    `allowlist::tests::denylist_blocks_a_link_planted_at_a_denied_path`).
///    Measured: the credential-store plant is 5.0 — identical to writing that
///    file directly; the key-material exposure is 4.5 where the plain write at
///    the same link path is 0.5. A link is never cheaper than its non-link
///    equivalent, pinned by `a_link_is_never_cheaper_than_what_it_replaces`.
///    Restoring a link-only surcharge would price `ln -s X P` *above*
///    `cp X P`, which an attacker would simply choose instead. work/83 F5's
///    session-allowlist key for `FileLink` is guarded on both ends for the
///    same reason, so project trust cannot short-circuit a link that reaches
///    into a credential store either.
/// 4. **Laundering is closed at use, not at creation.** A later read or write
///    *through* the new name is resolved before scoring — `resolve_follow`
///    via `ToolCallType::resolve_paths` on the LLM path,
///    `canonicalize_for_tracee` in the supervisor's `classify.rs` — so
///    `ln -s ~/.ssh /proj/keys` followed by reading `/proj/keys/id_rsa` is
///    scored as a read of `~/.ssh/id_rsa` at full strength. Link creation is
///    not the last chance to score the exposure.
///
/// If a link shape genuinely needs more score, the fix is a rule that *names*
/// it — in `sensitive_path` or `config/filters/paths.toml`, both of which
/// judge both ends — not a novelty tax that fires once per session on
/// whoever links first.
///
/// **What the inversion gives up, and what covers it.** The mirror-image risk
/// is a genuinely authority-changing category added later that gets no anomaly
/// signal until someone adds it here. That is the safer default because this
/// signal only ever *corroborates*: every category listed below is already
/// scored +5.0 on its own by `operation_risk` (`ownership-change-baseline`,
/// `filesystem-mutation-baseline`, `cross-process-access-baseline`,
/// `namespace-op-baseline`, `dbus-method-call-undeclared`), so each QUEUEs
/// with or without the behavioural rule. Losing the anomaly rule widens the
/// score, never the decision. A missing *denylist* entry, by contrast, turned
/// a routine op into a prompt — a decision change, in the wrong direction, and
/// the failure mode we actually observed.
///
/// `dbus_method_call` is here although work/83 F9 named only the four PR 6
/// categories: it was added to `classify_call` after that plan was written and
/// is likewise absent from the old denylist, so listing it keeps today's
/// behaviour for every existing category and makes `file_link` the single
/// intended behaviour change. It belongs on merit too — `operation_risk` scores
/// an undeclared bus method as "authority delegated to a peer outside
/// supervision", the same class as the other four.
const ANOMALY_SCORED_CATEGORIES: &[&str] = &[
    // PR 6 category-2/3 authority-changing syscall classes.
    "ownership_change",
    "filesystem_mutation",
    "cross_process_access",
    "namespace_op",
    // Authority delegated over the session bus to an unsupervised peer.
    "dbus_method_call",
];

fn is_anomaly_scored_category(category: &str) -> bool {
    ANOMALY_SCORED_CATEGORIES.contains(&category)
}

/// PR 69 Change 1: operator-tunable scoring parameters. The previous
/// daemon constructor hard-coded `min_calls_for_baseline = 20` while
/// `config/default.toml` advertised 200; this struct is the bridge that
/// makes the runtime match the declared config.
#[derive(Debug, Clone)]
pub struct BehaviouralConfig {
    /// Minimum per-session call count before any anomaly rule fires.
    pub min_calls_for_baseline: usize,
    /// Score assigned to `uncommon-call-type` matches (< 5% of baseline).
    pub mild_deviation_score: f64,
    /// Score assigned to `unseen-call-type` matches (never observed in
    /// baseline). `rare-call-type` (< 2% of baseline) keeps a fixed
    /// midpoint score of 2.0; making it operator-tunable was not part of
    /// the PR 69 work item.
    pub significant_deviation_score: f64,
}

impl Default for BehaviouralConfig {
    fn default() -> Self {
        Self {
            min_calls_for_baseline: 200,
            mild_deviation_score: 1.0,
            significant_deviation_score: 3.0,
        }
    }
}

/// Filter that profiles agent behaviour over time, detecting deviations
/// from established baselines.
///
/// Runs in Phase 3 (Context) because it depends on accumulated session state.
///
/// During the cold-start period (fewer than `min_calls_for_profiling` calls),
/// the filter records data but always returns a zero score. Once the baseline
/// is established, it compares the current call type distribution against
/// the historical baseline and flags significant deviations.
///
/// The call history is capped at `MAX_HISTORY_SIZE` entries, creating a
/// sliding window so the baseline reflects recent session behaviour and
/// does not degrade over long-running sessions.
///
/// Scoring (after warm-up):
/// - `mild_deviation_score` for uncommon call types (< 5% of baseline)
/// - `2.0` for rare call types (< 2% of baseline) — fixed midpoint
/// - `significant_deviation_score` for unseen call types
///
/// work/83 F9: all three rules are suppressed unless the current call's
/// category is in [`ANOMALY_SCORED_CATEGORIES`] — an allowlist of the
/// authority-changing categories the rules were built for, not a denylist
/// of ordinary ones. "This session has not made a symlink / read a file /
/// spawned a process before" is a cold-baseline artefact, not an attack
/// signal, and it arrives exactly when a package manager or compiler is
/// doing its noisiest work.
pub struct BehaviouralFilter {
    /// Per-session call history. PR 1 keys behavioural baselines by scope so
    /// one session cannot influence another's anomaly detector.
    call_history: Mutex<HashMap<SessionScopeKey, Vec<CallRecord>>>,
    min_calls_for_profiling: usize,
    mild_deviation_score: f64,
    significant_deviation_score: f64,
    max_history_size: usize,
}

impl BehaviouralFilter {
    pub fn new(min_calls_for_profiling: usize) -> Self {
        Self::from_config(&BehaviouralConfig {
            min_calls_for_baseline: min_calls_for_profiling,
            ..BehaviouralConfig::default()
        })
    }

    /// PR 69 Change 1: build the filter from an operator-supplied config.
    pub fn from_config(cfg: &BehaviouralConfig) -> Self {
        Self {
            call_history: Mutex::new(HashMap::new()),
            min_calls_for_profiling: cfg.min_calls_for_baseline,
            mild_deviation_score: cfg.mild_deviation_score,
            significant_deviation_score: cfg.significant_deviation_score,
            max_history_size: MAX_HISTORY_SIZE,
        }
    }

    /// Create a filter with the default warm-up period (200 calls).
    pub fn with_defaults() -> Self {
        Self::from_config(&BehaviouralConfig::default())
    }

    /// Whether *any* session has accumulated enough data to produce meaningful
    /// scores. For per-session readiness, use [`is_profiling_ready_for`].
    pub fn is_profiling_ready(&self) -> bool {
        let history = self.call_history.lock().expect("lock poisoned");
        history
            .values()
            .any(|v| v.len() >= self.min_calls_for_profiling)
    }

    /// Whether the specific session has accumulated enough data.
    pub fn is_profiling_ready_for(&self, scope: SessionScopeKey) -> bool {
        let history = self.call_history.lock().expect("lock poisoned");
        history
            .get(&scope)
            .map(|v| v.len() >= self.min_calls_for_profiling)
            .unwrap_or(false)
    }

    /// Total recorded calls across all sessions. For per-session counts, use
    /// [`call_count_for`].
    pub fn call_count(&self) -> usize {
        let history = self.call_history.lock().expect("lock poisoned");
        history.values().map(|v| v.len()).sum()
    }

    /// Per-session recorded call count.
    pub fn call_count_for(&self, scope: SessionScopeKey) -> usize {
        let history = self.call_history.lock().expect("lock poisoned");
        history.get(&scope).map(|v| v.len()).unwrap_or(0)
    }

    /// Classify a `ToolCallType` into a static string category for profiling.
    fn classify_call(call_type: &ToolCallType) -> &'static str {
        match call_type {
            ToolCallType::FileRead { .. } => "file_read",
            ToolCallType::FileWrite { .. } => "file_write",
            ToolCallType::FileAppend { .. } => "file_append",
            ToolCallType::FileDelete { .. } => "file_delete",
            ToolCallType::DirList { .. } => "dir_list",
            ToolCallType::ShellExec { .. } => "shell_exec",
            ToolCallType::HttpRequest { .. } => "http_request",
            ToolCallType::FileRename { .. } => "file_rename",
            ToolCallType::FileLink { .. } => "file_link",
            ToolCallType::FileChmod { .. } => "file_chmod",
            ToolCallType::DirCreate { .. } => "dir_create",
            ToolCallType::NetConnect { .. } => "net_connect",
            ToolCallType::NetListen { .. } => "net_listen",
            ToolCallType::ProcessSpawn { .. } => "process_spawn",
            ToolCallType::DnsQuery { .. } => "dns_query",
            // PR 6 Phase B: category-2 syscalls.
            ToolCallType::OwnershipChange { .. } => "ownership_change",
            ToolCallType::FilesystemMutation { .. } => "filesystem_mutation",
            ToolCallType::CrossProcessAccess { .. } => "cross_process_access",
            ToolCallType::NamespaceOp { .. } => "namespace_op",
            ToolCallType::DbusMethodCall { .. } => "dbus_method_call",
        }
    }

    /// Compute the baseline distribution from the call history.
    fn compute_baseline(history: &[CallRecord]) -> HashMap<String, f64> {
        let total = history.len() as f64;
        if total == 0.0 {
            return HashMap::new();
        }

        let mut counts: HashMap<String, usize> = HashMap::new();
        for record in history {
            *counts.entry(record.call_type.clone()).or_default() += 1;
        }

        counts
            .into_iter()
            .map(|(k, v)| (k, v as f64 / total))
            .collect()
    }
}

#[async_trait::async_trait]
impl SecurityFilter for BehaviouralFilter {
    fn name(&self) -> &str {
        "behavioural"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Context
    }

    /// Drop this session's per-scope call history. Used by the session-end
    /// hook and session-start sweep. Returns the number of records dropped
    /// for telemetry — useful for spotting unusually large session
    /// histories (e.g. an LLM that's been spamming calls).
    fn evict_session_state(&self, scope: crate::types::SessionScopeKey) -> usize {
        match self.call_history.lock() {
            Ok(mut history) => history.remove(&scope).map(|v| v.len()).unwrap_or(0),
            Err(_) => 0,
        }
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        let call_category = Self::classify_call(&ctx.call_type);
        let scope = ctx.scope_or_warn("behavioural");

        // Always record the call for future profiling, scoped to this session.
        // Trim oldest entries when the per-session history exceeds the max,
        // creating a sliding window that keeps the baseline fresh (M-1, L-11).
        {
            let mut history = self.call_history.lock().expect("lock poisoned");
            let entry = history.entry(scope).or_default();
            entry.push(CallRecord {
                call_type: call_category.to_string(),
                timestamp: ctx.timestamp,
            });
            if entry.len() > self.max_history_size {
                let excess = entry.len() - self.max_history_size;
                entry.drain(..excess);
            }
        }

        // work/83 F9: the anomaly rules only apply to the authority-changing
        // categories. Gate before touching the baseline at all — this is the
        // hot path (file_read/file_write/process_spawn are the overwhelming
        // majority of supervised traffic), and it saves both the second lock
        // acquisition and the O(history) `compute_baseline` HashMap build on
        // every one of them. The call has already been recorded above, so a
        // suppressed category still contributes to the baseline that the
        // scored categories are measured against.
        if !is_anomaly_scored_category(call_category) {
            return Ok(FilterResult::no_match("behavioural"));
        }

        // During cold-start (for this session), return no-match (zero score).
        let history = self.call_history.lock().expect("lock poisoned");
        let session_history = match history.get(&scope) {
            Some(h) => h,
            None => return Ok(FilterResult::no_match("behavioural")),
        };
        if session_history.len() < self.min_calls_for_profiling {
            return Ok(FilterResult::no_match("behavioural"));
        }

        // Compute baseline from this session's history except the current call.
        let baseline_history = &session_history[..session_history.len() - 1];
        let baseline = Self::compute_baseline(baseline_history);

        let baseline_proportion = baseline.get(call_category).copied().unwrap_or(0.0);

        // Score based on how unusual this call type is relative to baseline.
        if baseline_proportion == 0.0 {
            // Call type never seen before in baseline period - significant anomaly.
            Ok(FilterResult::matched(
                "behavioural",
                "unseen-call-type",
                self.significant_deviation_score,
                Severity::Warning,
                format!(
                    "Call type '{call_category}' never observed in baseline of {} calls",
                    baseline_history.len()
                ),
            ))
        } else if baseline_proportion < 0.02 {
            // Very rare call type (less than 2% of baseline) - moderate deviation.
            // Fixed midpoint score (operator-tunable scores cover only the
            // mild/significant ends; PR 69 Change 1 work-doc).
            Ok(FilterResult::matched(
                "behavioural",
                "rare-call-type",
                2.0,
                Severity::Warning,
                format!(
                    "Call type '{call_category}' is rare ({:.1}% of baseline)",
                    baseline_proportion * 100.0
                ),
            ))
        } else if baseline_proportion < 0.05 {
            // Uncommon call type (less than 5% of baseline) - mild deviation.
            Ok(FilterResult::matched(
                "behavioural",
                "uncommon-call-type",
                self.mild_deviation_score,
                Severity::Notice,
                format!(
                    "Call type '{call_category}' is uncommon ({:.1}% of baseline)",
                    baseline_proportion * 100.0
                ),
            ))
        } else {
            // Normal call type - no flag.
            Ok(FilterResult::no_match("behavioural"))
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

    /// Build a context that shares an existing session UUID. After PR 1 the
    /// behavioural baseline is keyed by session_scope, so warm-up calls must
    /// all share the same session_id to accumulate in one baseline.
    fn make_ctx_in_session(call_type: ToolCallType, session_id: Uuid) -> ToolCallContext {
        ToolCallContext::new("test", call_type, session_id)
    }

    #[tokio::test]
    async fn test_cold_start_returns_no_match() {
        let filter = BehaviouralFilter::new(10);
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/tmp/test.txt".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
        assert_eq!(result.score, 0.0);
    }

    #[tokio::test]
    async fn test_records_calls_during_cold_start() {
        let filter = BehaviouralFilter::new(100);
        let session = Uuid::new_v4();
        for _ in 0..5 {
            let ctx = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/test.txt".into(),
                },
                session,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }
        assert_eq!(filter.call_count(), 5);
        assert!(!filter.is_profiling_ready());
    }

    #[tokio::test]
    async fn test_normal_call_after_warmup() {
        let filter = BehaviouralFilter::new(10);
        let session = Uuid::new_v4();

        // Build a baseline of mostly file reads.
        for _ in 0..10 {
            let ctx = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/test.txt".into(),
                },
                session,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }

        // Another file read should be normal.
        let ctx = make_ctx_in_session(
            ToolCallType::FileRead {
                path: "/tmp/other.txt".into(),
            },
            session,
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    /// After warm-up, an allowlisted category (PR 6 authority-changing op
    /// such as `NamespaceOp`) that the baseline has never seen still fires
    /// `unseen-call-type`.
    #[tokio::test]
    async fn test_unseen_call_type_flagged() {
        let filter = BehaviouralFilter::new(10);
        let session = Uuid::new_v4();

        // Build a baseline of only file reads.
        for _ in 0..10 {
            let ctx = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/test.txt".into(),
                },
                session,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }

        // A namespace op has never been seen and IS in
        // ANOMALY_SCORED_CATEGORIES — should fire as unseen.
        let ctx = make_ctx_in_session(
            ToolCallType::NamespaceOp {
                syscall: "unshare".into(),
                flags: 0,
            },
            session,
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 3.0);
        assert_eq!(result.rule_id, "unseen-call-type");
    }

    /// After warm-up, an allowlisted category at <2% of baseline still
    /// fires `rare-call-type`.
    #[tokio::test]
    async fn test_rare_call_type_flagged() {
        let filter = BehaviouralFilter::new(100);
        let session = Uuid::new_v4();

        // Build a baseline: 99 file reads, 1 ownership change.
        for _ in 0..99 {
            let ctx = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/test.txt".into(),
                },
                session,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }
        let ctx = make_ctx_in_session(
            ToolCallType::OwnershipChange {
                target: "/etc/passwd".into(),
                new_uid: 0,
                new_gid: 0,
            },
            session,
        );
        let _ = filter.evaluate(&ctx).await.unwrap();

        // Now ownership_change is ~1% of baseline and IS allowlisted —
        // should fire as rare.
        let ctx = make_ctx_in_session(
            ToolCallType::OwnershipChange {
                target: "/tmp/foo".into(),
                new_uid: 1000,
                new_gid: 1000,
            },
            session,
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.score, 2.0);
        assert_eq!(result.rule_id, "rare-call-type");
    }

    /// Ordinary categories (FileRead/Write/Rename, etc.) must NOT fire any
    /// of the anomaly rules even after warm-up, regardless of whether the
    /// baseline has seen them. This is the fix for the codex prompt-flood —
    /// the first FileWrite/FileRead in a session should not score
    /// behaviourally. Post-work/83-F9 they are suppressed by absence from
    /// ANOMALY_SCORED_CATEGORIES rather than presence in a routine denylist.
    #[tokio::test]
    async fn test_routine_category_never_fires_after_warmup() {
        let filter = BehaviouralFilter::new(10);
        let session = Uuid::new_v4();

        // Warm baseline with shell_exec (also routine, but the point is
        // that file_write never appears in the baseline).
        for _ in 0..15 {
            let ctx = make_ctx_in_session(
                ToolCallType::ShellExec {
                    command: "ls".into(),
                    args: vec![],
                },
                session,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }

        // First file_write — would be `unseen-call-type` without the
        // allowlist gate. With it, no_match.
        let ctx = make_ctx_in_session(
            ToolCallType::FileWrite {
                path: "/var/tmp/etilqs_abc".into(),
                content_hash: "abc".into(),
            },
            session,
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched, "ordinary FileWrite must not fire");

        // First file_rename — same story.
        let ctx = make_ctx_in_session(
            ToolCallType::FileRename {
                old_path: "/tmp/node-compile-cache/v22/abc.tmp".into(),
                new_path: "/tmp/node-compile-cache/v22/abc".into(),
            },
            session,
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched, "ordinary FileRename must not fire");
    }

    /// PR 6 authority-changing categories must STILL fire the anomaly
    /// rules — they are the reason ANOMALY_SCORED_CATEGORIES exists.
    #[tokio::test]
    async fn test_pr6_categories_still_fire_after_warmup() {
        let filter = BehaviouralFilter::new(10);
        let session = Uuid::new_v4();

        for _ in 0..15 {
            let ctx = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/x".into(),
                },
                session,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }

        for (call, label) in [
            (
                ToolCallType::OwnershipChange {
                    target: "/etc/x".into(),
                    new_uid: 0,
                    new_gid: 0,
                },
                "OwnershipChange",
            ),
            (
                ToolCallType::FilesystemMutation {
                    op: "mount".into(),
                    source: None,
                    target: "/mnt/x".into(),
                    fstype: Some("tmpfs".into()),
                },
                "FilesystemMutation",
            ),
            (
                ToolCallType::CrossProcessAccess {
                    op: "ptrace".into(),
                    target_pid: 999,
                },
                "CrossProcessAccess",
            ),
            (
                ToolCallType::NamespaceOp {
                    syscall: "unshare".into(),
                    flags: 0,
                },
                "NamespaceOp",
            ),
        ] {
            let ctx = make_ctx_in_session(call, session);
            let result = filter.evaluate(&ctx).await.unwrap();
            assert!(
                result.matched,
                "{label} must still fire (in ANOMALY_SCORED_CATEGORIES)"
            );
            assert_eq!(result.rule_id, "unseen-call-type", "{label}");
        }
    }

    /// Drive `count` successive calls of one kind through a warmed session
    /// and return the rule id each produced (`""` for no_match). Lets a test
    /// assert what happened as the category's share of the baseline walks up
    /// through the unseen → rare → uncommon → normal bands.
    async fn rule_ids_for_repeated(
        filter: &BehaviouralFilter,
        session: Uuid,
        count: usize,
        make: impl Fn() -> ToolCallType,
    ) -> Vec<String> {
        let mut ids = Vec::with_capacity(count);
        for _ in 0..count {
            let ctx = make_ctx_in_session(make(), session);
            let result = filter.evaluate(&ctx).await.unwrap();
            ids.push(if result.matched {
                result.rule_id.clone()
            } else {
                String::new()
            });
        }
        ids
    }

    /// Warm a session with `n` file reads so the baseline is established and
    /// dominated by one ordinary category.
    async fn warm_with_reads(filter: &BehaviouralFilter, session: Uuid, n: usize) {
        for _ in 0..n {
            let ctx = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/warm.txt".into(),
                },
                session,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }
    }

    fn a_symlink() -> ToolCallType {
        ToolCallType::FileLink {
            target: "/proj/node_modules/@babel/parser/bin/babel-parser.js".into(),
            link_path: "/proj/node_modules/.bin/parser".into(),
            symbolic: true,
        }
    }

    fn an_ownership_change() -> ToolCallType {
        ToolCallType::OwnershipChange {
            target: "/tmp/owned".into(),
            new_uid: 1000,
            new_gid: 1000,
        }
    }

    /// work/83 M9: this is the regression the inversion exists for. Before
    /// F9, `file_link` was missing from the routine denylist, so the first
    /// link of a session scored `unseen-call-type` +3.0 — 3.5 with
    /// `operation_risk`'s link baseline, i.e. a QUEUE — and the next few
    /// scored `rare`/`uncommon` on the way to normal. An `npm install`'s
    /// closing burst of `node_modules/.bin/*` symlinks landed squarely in
    /// that window. No proportion of the baseline may produce a match.
    #[tokio::test]
    async fn link_calls_never_score_at_any_baseline_proportion() {
        let filter = BehaviouralFilter::new(100);
        let session = Uuid::new_v4();
        warm_with_reads(&filter, session, 100).await;

        // Seven successive links walk file_link's share of the baseline from
        // 0% (unseen) through ~1-2% (rare) and ~3-5% (uncommon) to >5%
        // (normal) — see the companion test for the same walk on an
        // allowlisted category, which proves the bands are really traversed.
        let ids = rule_ids_for_repeated(&filter, session, 7, a_symlink).await;
        assert_eq!(
            ids,
            vec![""; 7],
            "file_link must never fire an anomaly rule, at any baseline share"
        );
    }

    /// Companion to the test above and the guard that keeps it honest: the
    /// identical call sequence on an allowlisted category really does walk
    /// unseen → rare → uncommon → normal. Without this, the `file_link` test
    /// could pass for the wrong reason (e.g. a broken baseline computation).
    #[tokio::test]
    async fn authority_category_traverses_all_three_anomaly_bands() {
        let filter = BehaviouralFilter::new(100);
        let session = Uuid::new_v4();
        warm_with_reads(&filter, session, 100).await;

        let ids = rule_ids_for_repeated(&filter, session, 7, an_ownership_change).await;
        assert_eq!(
            ids,
            vec![
                "unseen-call-type",
                "rare-call-type",
                "rare-call-type",
                "uncommon-call-type",
                "uncommon-call-type",
                "uncommon-call-type",
                "",
            ],
            "allowlisted category must still traverse every anomaly band"
        );
    }

    /// Regression guard for the PR 6 signal the inversion must preserve: all
    /// four authority-changing categories still fire `unseen-call-type`, and
    /// at the operator-configured `significant_deviation_score` rather than a
    /// hard-coded 3.0.
    #[tokio::test]
    async fn pr6_categories_score_unseen_at_configured_score() {
        for (call, label) in [
            (
                ToolCallType::OwnershipChange {
                    target: "/etc/x".into(),
                    new_uid: 0,
                    new_gid: 0,
                },
                "ownership_change",
            ),
            (
                ToolCallType::FilesystemMutation {
                    op: "mount".into(),
                    source: None,
                    target: "/mnt/x".into(),
                    fstype: Some("tmpfs".into()),
                },
                "filesystem_mutation",
            ),
            (
                ToolCallType::CrossProcessAccess {
                    op: "process_vm_readv".into(),
                    target_pid: 999,
                },
                "cross_process_access",
            ),
            (
                ToolCallType::NamespaceOp {
                    syscall: "setns".into(),
                    flags: 0,
                },
                "namespace_op",
            ),
        ] {
            // A fresh filter per category so each one is genuinely unseen.
            let filter = BehaviouralFilter::from_config(&BehaviouralConfig {
                min_calls_for_baseline: 10,
                mild_deviation_score: 0.25,
                significant_deviation_score: 4.25,
            });
            let session = Uuid::new_v4();
            warm_with_reads(&filter, session, 10).await;

            let ctx = make_ctx_in_session(call, session);
            let result = filter.evaluate(&ctx).await.unwrap();
            assert!(result.matched, "{label} must still fire");
            assert_eq!(result.rule_id, "unseen-call-type", "{label}");
            assert_eq!(
                result.score, 4.25,
                "{label} must score the configured significant_deviation_score"
            );
        }
    }

    /// `dbus_method_call` is allowlisted deliberately (work/83 F9 named only
    /// the four PR 6 categories, but this one was added to `classify_call`
    /// after that plan was written and was likewise absent from the old
    /// denylist). Keeping it scored means `file_link` is the only category
    /// whose behaviour the inversion changes.
    #[tokio::test]
    async fn dbus_method_call_still_scores_unseen() {
        let filter = BehaviouralFilter::new(10);
        let session = Uuid::new_v4();
        warm_with_reads(&filter, session, 10).await;

        let ctx = make_ctx_in_session(
            ToolCallType::DbusMethodCall {
                socket: "/run/user/1000/bus".into(),
                destination: Some("org.freedesktop.systemd1".into()),
                interface: Some("org.freedesktop.systemd1.Manager".into()),
                member: Some("StartTransientUnit".into()),
            },
            session,
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched, "dbus_method_call must still fire");
        assert_eq!(result.rule_id, "unseen-call-type");
    }

    /// The point of the inversion: a category string this filter does not
    /// know about is suppressed by default, so a `ToolCallType` variant added
    /// later cannot silently start producing modal prompts because somebody
    /// forgot to extend a list. Opting a new category *in* is a deliberate,
    /// reviewable edit to ANOMALY_SCORED_CATEGORIES.
    #[test]
    fn unknown_category_is_suppressed_by_default() {
        for unknown in [
            "file_lock",
            "process_inject",
            "windows_registry_write",
            "",
            "file_link",
        ] {
            assert!(
                !is_anomaly_scored_category(unknown),
                "'{unknown}' must not be anomaly-scored without an explicit opt-in"
            );
        }
    }

    /// Tripwire: the allowlist is a security-relevant set, so adding to or
    /// removing from it should require touching this assertion and saying why
    /// in the commit. Every member here is independently scored +5.0 by
    /// `operation_risk`, which is why the anomaly rule is corroborating only.
    #[test]
    fn anomaly_allowlist_membership_is_pinned() {
        assert_eq!(
            ANOMALY_SCORED_CATEGORIES,
            [
                "ownership_change",
                "filesystem_mutation",
                "cross_process_access",
                "namespace_op",
                "dbus_method_call",
            ]
        );
    }

    /// The `file_link` suppression above is only safe because a link is still
    /// scored by **what it exposes**, not by the novelty of linking. Pin that
    /// compensating control here, in the file that depends on it: with the
    /// behavioural signal gone, a symlink whose *target* is key material and
    /// a symlink planted *at* a credential store each still QUEUE on
    /// `operation_risk` + `sensitive_path` alone.
    ///
    /// Both ends matter. `ToolCallContext::paths` and
    /// `sensitive_path::path_operations` deliberately return the target *and*
    /// the link path, so `ln -s ./mine ~/.ssh/authorized_keys` cannot be a
    /// cheaper way to plant a file than writing it. If a refactor ever drops
    /// one of those ends this test fails, and the suppression must be
    /// revisited rather than silently losing coverage.
    ///
    /// **The bar is the router, not a number.** `route_decision` allows on
    /// `score > allow_threshold`, so a composite of *exactly* 3.0 is ALLOWED.
    /// An earlier version of this test asserted `total >= 3.0`, which would
    /// have passed for a call that is not queued — the assertion could go
    /// green while the compensating control it exists to prove had failed.
    /// Asking `route_decision` itself removes any chance of restating that
    /// boundary wrongly here or in a copy of this test, and the exact
    /// composites are pinned alongside so a *narrowing* of either path rule
    /// has to be acknowledged here rather than silently eating the margin.
    #[tokio::test]
    async fn credential_links_still_queue_without_the_behavioural_signal() {
        use crate::filters::operation_risk::OperationRiskFilter;
        use crate::filters::sensitive_path::SensitivePathHeuristicFilter;
        use crate::scoring::{aggregate, route_decision, ScoringConfig};
        use crate::types::ProxyAction;
        use std::time::Duration;

        let behavioural = BehaviouralFilter::new(10);
        let op_risk = OperationRiskFilter::new();
        let sensitive = SensitivePathHeuristicFilter::new();
        let (allow_threshold, deny_threshold) = ScoringConfig::default().thresholds();

        for (call, label, expected_total) in [
            (
                // Target is key material: the link exposes it under a benign name.
                ToolCallType::FileLink {
                    target: "/home/dev/.ssh/id_rsa".into(),
                    link_path: "/proj/build/artifact".into(),
                    symbolic: true,
                },
                "link exposing key material",
                // 0.5 symlink-create-baseline + 4.0 key-material-file.
                4.5_f64,
            ),
            (
                // Link path plants INTO a credential store; the target is benign.
                ToolCallType::FileLink {
                    target: "/proj/mine.pub".into(),
                    link_path: "/home/dev/.ssh/authorized_keys".into(),
                    symbolic: true,
                },
                "link planted at a credential store",
                // 0.5 symlink-create-baseline + 4.5 credential-directory.
                5.0_f64,
            ),
        ] {
            let session = Uuid::new_v4();
            warm_with_reads(&behavioural, session, 10).await;
            let ctx = make_ctx_in_session(call, session);

            let b = behavioural.evaluate(&ctx).await.unwrap();
            assert!(
                !b.matched,
                "{label}: behavioural must contribute nothing post-F9"
            );

            // The additive pipeline still reaches QUEUE without it. Let the
            // real router decide — `score > allow_threshold`, so 3.0 exactly
            // would ALLOW.
            let results = vec![
                op_risk.evaluate(&ctx).await.unwrap(),
                sensitive.evaluate(&ctx).await.unwrap(),
            ];
            let total = aggregate(&results);
            let action = route_decision(
                total,
                results,
                allow_threshold,
                deny_threshold,
                Duration::from_millis(1),
            )
            .action;
            assert!(
                !matches!(action, ProxyAction::Allow),
                "{label}: must still QUEUE on path-derived rules alone, \
                 got {total} -> {action:?}"
            );
            assert_eq!(
                total, expected_total,
                "{label}: composite changed; confirm the margin over the \
                 {allow_threshold} allow threshold is still intended"
            );
        }
    }

    /// The invariant that makes the `file_link` suppression above safe, and
    /// the answer to "a link no path rule covers is only 0.5": so is the
    /// operation it substitutes for.
    ///
    /// With the novelty signal gone, a link is priced as the read of its
    /// target plus the write of its new name — `path_operations` judges both
    /// ends and every path filter takes the worst. So for every shape, the
    /// link's composite is at least that of writing the link path directly
    /// and at least that of reading the target directly. Nothing is made
    /// cheaper by expressing it as a link, which is the property that matters:
    /// a surcharge on links alone would just push an attacker to `cp`.
    ///
    /// The two benign rows are also the false positive the suppression exists
    /// to remove — the npm `.bin/*` symlink and the rustc incremental
    /// hardlink — so their measured composites are pinned here too: the npm
    /// one is 0.5 and ALLOWs, where before the suppression the first of the
    /// burst was 3.5 and QUEUEd.
    #[tokio::test]
    async fn a_link_is_never_cheaper_than_what_it_replaces() {
        use crate::filters::operation_risk::OperationRiskFilter;
        use crate::filters::sensitive_path::SensitivePathHeuristicFilter;

        let behavioural = BehaviouralFilter::new(10);
        let op_risk = OperationRiskFilter::new();
        let sensitive = SensitivePathHeuristicFilter::new();

        // Composite of `operation_risk` + `sensitive_path` for one call, with
        // the behavioural contribution asserted to be zero.
        async fn composite(
            behavioural: &BehaviouralFilter,
            op_risk: &OperationRiskFilter,
            sensitive: &SensitivePathHeuristicFilter,
            call: ToolCallType,
        ) -> f64 {
            let session = Uuid::new_v4();
            warm_with_reads(behavioural, session, 10).await;
            let ctx = make_ctx_in_session(call, session);
            assert!(
                !behavioural.evaluate(&ctx).await.unwrap().matched,
                "behavioural must contribute nothing to this comparison"
            );
            op_risk.evaluate(&ctx).await.unwrap().score
                + sensitive.evaluate(&ctx).await.unwrap().score
        }

        for (target, link_path, symbolic, label, expected_link) in [
            (
                "/proj/node_modules/@babel/parser/bin/babel-parser.js",
                "/proj/node_modules/.bin/parser",
                true,
                "npm .bin symlink (the false positive F9 removes)",
                Some(0.5_f64),
            ),
            (
                "/proj/target/debug/deps/x-abc.rcgu.o",
                "/proj/target/debug/incremental/773v9mxq3ohs6twiwt1rzauth.o",
                false,
                "rustc incremental hardlink",
                // MERGE-ORDER DEPENDENT, so it is pinned as a range rather
                // than a number. On this branch alone it is 4.0 — 0.5
                // hardlink-create-baseline plus 3.5 from `secretish-filename`
                // firing on the coincidental "auth" at the end of the hash.
                // Once work/83 F1 (whole-token matching) and F7 (a `target/`
                // tree is name-opaque) land it is 0.5, which is the point:
                // this exact shape was 511 of the recorded prompts. Either
                // value is correct; what must hold in BOTH worlds is the
                // invariant this test exists for — a link is never cheaper
                // than the write or read it stands in for.
                None,
            ),
            (
                "/tmp/payload.sh",
                "/proj/.git/hooks/pre-commit",
                true,
                "code-execution link no name rule covers",
                Some(0.5),
            ),
            (
                // The one shape whose path-derived score lands in the
                // (0.5, 2.5] band, where the removed novelty addend used to
                // carry links #1-#6 over the threshold. It now sits exactly on
                // the allow threshold, so `route_decision` (`score >
                // allow_threshold`) ALLOWs it — as it already did for the
                // plain read of the same target, which is 2.5. Pinned because
                // it is the boundary: any rule that nudges it either way must
                // be a decision someone made on purpose.
                "/proc/self/environ",
                "/proj/build/x",
                true,
                "link to a kernel-interface path (exactly on the allow threshold)",
                Some(3.0),
            ),
            (
                "/home/dev/.ssh/id_rsa",
                "/proj/build/artifact",
                true,
                "link exposing key material",
                Some(4.5),
            ),
            (
                "/proj/mine.pub",
                "/home/dev/.ssh/authorized_keys",
                true,
                "link planted at a credential store",
                Some(5.0),
            ),
        ] {
            let link = composite(
                &behavioural,
                &op_risk,
                &sensitive,
                ToolCallType::FileLink {
                    target: target.into(),
                    link_path: link_path.into(),
                    symbolic,
                },
            )
            .await;
            let write = composite(
                &behavioural,
                &op_risk,
                &sensitive,
                ToolCallType::FileWrite {
                    path: link_path.into(),
                    content_hash: String::new(),
                },
            )
            .await;
            let read = composite(
                &behavioural,
                &op_risk,
                &sensitive,
                ToolCallType::FileRead {
                    path: target.into(),
                },
            )
            .await;

            if let Some(expected) = expected_link {
                assert_eq!(link, expected, "{label}: link composite");
            }
            assert!(
                link >= write,
                "{label}: linking must not be cheaper than writing the link \
                 path ({link} < {write})"
            );
            assert!(
                link >= read,
                "{label}: linking must not be cheaper than reading the target \
                 ({link} < {read})"
            );
        }
    }

    /// PR 69 Change 1: `from_config` honours operator-supplied scores.
    #[tokio::test]
    async fn test_from_config_overrides_scores() {
        let cfg = BehaviouralConfig {
            min_calls_for_baseline: 10,
            mild_deviation_score: 0.25,
            significant_deviation_score: 1.75,
        };
        let filter = BehaviouralFilter::from_config(&cfg);
        let session = Uuid::new_v4();

        for _ in 0..10 {
            let ctx = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/x".into(),
                },
                session,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }

        let ctx = make_ctx_in_session(
            ToolCallType::NamespaceOp {
                syscall: "unshare".into(),
                flags: 0,
            },
            session,
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert_eq!(result.score, 1.75, "significant_deviation_score honoured");
    }

    #[tokio::test]
    async fn test_is_profiling_ready() {
        let filter = BehaviouralFilter::new(5);
        let session = Uuid::new_v4();
        assert!(!filter.is_profiling_ready());

        for _ in 0..5 {
            let ctx = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/test.txt".into(),
                },
                session,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }
        assert!(filter.is_profiling_ready());
        assert!(filter.is_profiling_ready_for(SessionScopeKey::from_session_id(session)));
    }

    /// PR 1 Phase F: `evict_session_state(scope)` drops the per-session
    /// history vector entirely. Other sessions' histories remain.
    #[tokio::test]
    async fn test_evict_drops_only_matching_session() {
        let filter = BehaviouralFilter::new(10);
        let session_a = Uuid::new_v4();
        let session_b = Uuid::new_v4();

        for _ in 0..5 {
            let ctx_a = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/a.txt".into(),
                },
                session_a,
            );
            let _ = filter.evaluate(&ctx_a).await.unwrap();

            let ctx_b = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/b.txt".into(),
                },
                session_b,
            );
            let _ = filter.evaluate(&ctx_b).await.unwrap();
        }
        assert_eq!(filter.call_count(), 10);

        let removed = filter.evict_session_state(SessionScopeKey::from_session_id(session_a));
        assert_eq!(removed, 5, "session A had 5 entries");
        assert_eq!(filter.call_count(), 5, "session B's 5 entries remain");
        assert_eq!(
            filter.call_count_for(SessionScopeKey::from_session_id(session_b)),
            5
        );
        assert_eq!(
            filter.call_count_for(SessionScopeKey::from_session_id(session_a)),
            0
        );
    }

    /// PR 1 isolation: warming session A's baseline must not make session B
    /// look "ready", and an anomaly in session B (where the baseline is cold)
    /// must not fire — there's no baseline to deviate from yet.
    #[tokio::test]
    async fn test_cross_session_isolation() {
        let filter = BehaviouralFilter::new(10);
        let session_a = Uuid::new_v4();
        let session_b = Uuid::new_v4();

        // Warm session A with 10 file reads.
        for _ in 0..10 {
            let ctx = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/test.txt".into(),
                },
                session_a,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }

        // First call in session B (HTTP) — would have fired "unseen-call-type"
        // under the old global-state behaviour. Under PR 1 the session B
        // baseline is empty, so cold-start returns no-match.
        let ctx = make_ctx_in_session(
            ToolCallType::HttpRequest {
                method: "POST".into(),
                url: "https://evil.com".into(),
            },
            session_b,
        );
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(
            !result.matched,
            "session B should be in cold-start despite session A being warm"
        );
        assert!(!filter.is_profiling_ready_for(SessionScopeKey::from_session_id(session_b)));
        assert!(filter.is_profiling_ready_for(SessionScopeKey::from_session_id(session_a)));
    }

    #[tokio::test]
    async fn test_classify_call_categories() {
        assert_eq!(
            BehaviouralFilter::classify_call(&ToolCallType::FileRead {
                path: "/tmp".into()
            }),
            "file_read"
        );
        assert_eq!(
            BehaviouralFilter::classify_call(&ToolCallType::FileWrite {
                path: "/tmp".into(),
                content_hash: "abc".into()
            }),
            "file_write"
        );
        assert_eq!(
            BehaviouralFilter::classify_call(&ToolCallType::ShellExec {
                command: "ls".into(),
                args: vec![]
            }),
            "shell_exec"
        );
        assert_eq!(
            BehaviouralFilter::classify_call(&ToolCallType::HttpRequest {
                method: "GET".into(),
                url: "https://x.com".into()
            }),
            "http_request"
        );
    }

    #[tokio::test]
    async fn test_history_trimmed_at_max_size() {
        // M-1 & L-11: Verify that the call history is bounded and acts
        // as a sliding window rather than growing unboundedly. After PR 1
        // the cap applies per-session, so all 25 calls share one session.
        let mut filter = BehaviouralFilter::new(5);
        filter.max_history_size = 20; // Small cap for testing
        let session = Uuid::new_v4();

        // Push 25 calls — history should be trimmed to 20.
        for _ in 0..25 {
            let ctx = make_ctx_in_session(
                ToolCallType::FileRead {
                    path: "/tmp/test.txt".into(),
                },
                session,
            );
            let _ = filter.evaluate(&ctx).await.unwrap();
        }

        assert_eq!(filter.call_count(), 20);
    }
}
