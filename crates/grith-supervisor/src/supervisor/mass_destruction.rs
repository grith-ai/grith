// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Target-aware mass-destruction signal — step 2 of the rate-limit-burst
//! redesign (`work/futurework/rate-limit-burst-redesign.md`).
//!
//! The proxy's per-op score is blind to *volume*: each `unlink` of a single
//! file is individually allowed, so a ransomware-style delete spree never
//! crosses the QUEUE threshold on per-op score alone. The legacy `rate_limit`
//! burst counter caught this only incidentally — and floods on benign churn
//! (`cargo clean`, `git gc`, `~/.cache`) because it counts *frequency* blind
//! to *what* is being destroyed.
//!
//! This module is the precise replacement: a post-decision aggregator (the doc
//! calls volume detection's "proper home" the supervisor, since only the
//! supervisor knows the session's working-set context) that counts **distinct**
//! destructive targets — `unlink`/`rename` — falling *outside* the session's
//! working tree and the profile's routine/scratch roots, i.e. the user's
//! valuable files the tool has no business mass-deleting. Build/VCS/cache churn
//! is in-tree or ephemeral, so it never counts. When the distinct-target count
//! crosses a threshold within a short window, the caller escalates the current
//! op Allow→QUEUE so the operator is prompted before the spree continues.
//!
//! **Scope of this first cut:** deletes and renames only. Distinguishing an
//! overwrite-write (destruction, e.g. encrypt-in-place) from a create-write
//! (benign — every build writes many files) needs a pre-existence `stat` the
//! supervisor does not do on the hot path; that overwrite-spread case is
//! deferred. Deletes and renames unambiguously remove or relocate existing
//! data, giving a low-false-positive signal.
//!
//! **Gating:** ON by default (rollout step 4) — it is the coverage that makes
//! `proxy.rate_limit.risk_gated_burst` (also default-on) safe, backfilling the
//! single case risk-gating drops: an *untainted* destructive spree.
//! `GRITH_SUPERVISOR_MASS_DESTRUCTION_SIGNAL` is a kill-switch override
//! (set `0`/`false`/`no`/`off` to disable; `OnceLock`-cached — the documented
//! PR 4 env-override precedent). The window/threshold below are conservative
//! first-cut values pending on-box tuning.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use grith_proxy::types::{ProxyAction, ProxyDecision, QueuePriority, ToolCallType};

/// Sliding window over which distinct destructive targets are counted.
pub(super) const WINDOW: Duration = Duration::from_secs(10);

/// Distinct out-of-tree destructive targets within [`WINDOW`] that trip the
/// signal. Deliberately conservative — incidental out-of-tree deletes during
/// normal agent work are well below this, while a genuine spree (ransomware,
/// `rm -rf ~/somewhere`) blows past it. Escalation only *prompts*; a false trip
/// costs a prompt, not lost authority.
pub(super) const THRESHOLD: usize = 25;

/// Whether the mass-destruction signal is enabled for this process. ON by
/// default; `GRITH_SUPERVISOR_MASS_DESTRUCTION_SIGNAL` is a kill-switch
/// (`0`/`false`/`no`/`off` disables; any other value, or unset, leaves it on).
/// Read once via `OnceLock` so the supervisor's 50µs/syscall budget pays a
/// single atomic load on the hot path rather than an env lookup per event.
pub(super) fn signal_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("GRITH_SUPERVISOR_MASS_DESTRUCTION_SIGNAL")
            .map(|v| !matches!(v.trim(), "0" | "false" | "no" | "off"))
            .unwrap_or(true)
    })
}

/// Per-session sliding-window tracker of distinct out-of-tree destructive
/// targets. One per `SupervisorLoopContext` (which is one per session), so no
/// cross-session keying is needed.
#[derive(Debug)]
pub(super) struct MassDestructionTracker {
    /// Distinct target → most recent observation. Deduped so re-touching the
    /// same path doesn't inflate the count; pruned to the window on each
    /// record so size stays bounded by distinct targets in the window.
    seen: HashMap<PathBuf, Instant>,
    window: Duration,
    threshold: usize,
}

impl MassDestructionTracker {
    pub(super) fn new(window: Duration, threshold: usize) -> Self {
        Self {
            seen: HashMap::new(),
            window,
            threshold,
        }
    }

    pub(super) fn with_defaults() -> Self {
        Self::new(WINDOW, THRESHOLD)
    }

    /// Record a distinct out-of-tree destructive target observed at `now`.
    /// Returns `Some(distinct_count)` once the count of distinct targets within
    /// the window has reached the threshold (caller escalates), else `None`.
    pub(super) fn record(&mut self, target: PathBuf, now: Instant) -> Option<usize> {
        // Prune anything older than the window. `checked_sub` is `None` only
        // very early in the process (now < window since boot) — then we keep
        // everything, which is correct (nothing has aged out yet).
        if let Some(cutoff) = now.checked_sub(self.window) {
            self.seen.retain(|_, seen_at| *seen_at >= cutoff);
        }
        self.seen.insert(target, now);
        let distinct = self.seen.len();
        (distinct >= self.threshold).then_some(distinct)
    }

    #[cfg(test)]
    pub(super) fn distinct_len(&self) -> usize {
        self.seen.len()
    }
}

/// The path a destructive op targets, if the op removes or relocates existing
/// data. Returns `None` for every other op (including writes/appends — see the
/// module docs for why overwrite-spread is deferred).
pub(super) fn destructive_target(call_type: &ToolCallType) -> Option<&str> {
    match call_type {
        ToolCallType::FileDelete { path } => Some(path.as_str()),
        ToolCallType::FileRename { old_path, .. } => Some(old_path.as_str()),
        _ => None,
    }
}

/// True when `target` is a *valuable out-of-tree* path that should count toward
/// the signal: an absolute path that is NOT under the session working root or
/// any of the session's other trusted workspace roots, NOT under any profile
/// routine/scratch root, and NOT under an ephemeral system root (temp / cache
/// / pseudo-filesystem). Relative paths can't be classified and never count.
///
/// `workspace_roots` (work/83 F4) are the launch repository's linked git
/// worktrees plus operator-declared project roots. They are passed separately
/// from `routine_roots` rather than folded into it because `routine_roots` is
/// the session's `routine_exec_roots` — the *executable* provenance roots that
/// PR 4's routine-spawn signal, the PR 6 namespace carveout and the
/// routine-agent connect check all read. Appending trees there to fix a
/// deletion-count false positive would silently widen three unrelated spawn
/// and namespace decisions. Semantically they belong here anyway: a linked
/// worktree is part of the session's working set, which is what the in-tree
/// test is about. Deleting a whole worktree is exactly the operation that
/// produced 692 escalations of `FileDelete` calls scored 1.0.
pub(super) fn is_valuable_out_of_tree(
    target: &str,
    working_root: Option<&Path>,
    workspace_roots: &[String],
    routine_roots: &[String],
    scratch_roots: &[String],
) -> bool {
    if !target.starts_with('/') {
        return false;
    }
    if let Some(root) = working_root {
        if path_under(target, &root.to_string_lossy()) {
            return false;
        }
    }
    if workspace_roots.iter().any(|r| path_under(target, r)) {
        return false;
    }
    if routine_roots.iter().any(|r| path_under(target, r)) {
        return false;
    }
    if scratch_roots.iter().any(|r| path_under(target, r)) {
        return false;
    }
    !is_ephemeral(target)
}

/// Ephemeral / pseudo-filesystem roots whose contents are never the user's
/// valuable data. Deleting many files here (build temp, caches) is routine.
const EPHEMERAL_ROOTS: &[&str] = &[
    "/tmp/",
    "/var/tmp/",
    "/var/cache/",
    "/dev/",
    "/proc/",
    "/sys/",
    "/run/",
];

/// Regenerable build-artifact directory segments, matched as whole path
/// components anywhere in the target. A deletion under one of these is
/// toolchain-owned churn (compiler caches, package installs), not the user's
/// valuable data - even when it happens outside the session's working tree.
/// Incident: a session rooted in one repo ran `cargo` in a sibling repo and
/// tripped the signal on hundreds of incremental artifacts under the
/// sibling's `target/debug/` (see `work/findings/mass-destruction-cargo-
/// churn-prompt-flood-2026-08-17.md`).
///
/// Deliberately narrow: unambiguous, toolchain-owned names only. Generic
/// output dirs (`build/`, `dist/`, `out/`) hold real deliverables in some
/// projects and must NOT be listed. Staging valuable files INTO one of
/// these directories before deleting them does not evade the signal: the
/// staging renames count their `old_path` (see [`destructive_target`]),
/// which still sits in the valuable tree.
const BUILD_ARTIFACT_SEGMENTS: &[&str] = &[
    "/target/debug/",
    "/target/release/",
    "/node_modules/",
    "/__pycache__/",
    "/.git/objects/",
    "/.next/",
];

fn is_ephemeral(target: &str) -> bool {
    if EPHEMERAL_ROOTS.iter().any(|p| target.starts_with(p)) {
        return true;
    }
    // Absolute paths make `contains` boundary-safe here: every segment is
    // wrapped in `/`, so `/home/u/mytarget/debug/x` does not match
    // `/target/debug/` and `/repo/node_modules_backup/x` does not match
    // `/node_modules/`.
    if BUILD_ARTIFACT_SEGMENTS
        .iter()
        .any(|seg| target.contains(seg))
    {
        return true;
    }
    if let Some(cache) = home_cache_prefix() {
        if target.starts_with(cache) {
            return true;
        }
    }
    false
}

/// `$HOME/.cache/`, cached once. `None` when `HOME` is unset.
fn home_cache_prefix() -> Option<&'static str> {
    static CACHE: OnceLock<Option<String>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            std::env::var_os("HOME").map(|home| {
                let mut s = home.to_string_lossy().into_owned();
                if !s.ends_with('/') {
                    s.push('/');
                }
                s.push_str(".cache/");
                s
            })
        })
        .as_deref()
}

/// Boundary-safe path containment: `target` equals `root` or sits beneath it
/// with a `/` separator. Tolerates a trailing slash on `root` (the profile
/// roots are stored trailing-slashed; the working root is not).
fn path_under(target: &str, root: &str) -> bool {
    let root = root.strip_suffix('/').unwrap_or(root);
    if root.is_empty() {
        return false;
    }
    target == root
        || target
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Record `call_type`'s target (when it is a valuable out-of-tree
/// deletion/rename) into `tracker`, and — if that pushes the distinct-target
/// window to the threshold AND `decision` is currently `Allow` — escalate
/// `decision` to a high-priority QUEUE in place. Returns the distinct count
/// when it escalated, else `None`.
///
/// Recording happens for every qualifying op (so the window is accurate even
/// when the proxy already QUEUE'd/DENY'd it); escalation only rewrites an
/// `Allow`. Pure given the injected `tracker` + `now`, so the caller's
/// `OnceLock` env gate stays out of the unit-tested path.
pub(super) fn maybe_escalate(
    decision: &mut ProxyDecision,
    call_type: &ToolCallType,
    working_root: Option<&Path>,
    workspace_roots: &[String],
    routine_roots: &[String],
    scratch_roots: &[String],
    tracker: &Mutex<MassDestructionTracker>,
    now: Instant,
) -> Option<usize> {
    let target = destructive_target(call_type)?;
    if !is_valuable_out_of_tree(
        target,
        working_root,
        workspace_roots,
        routine_roots,
        scratch_roots,
    ) {
        return None;
    }
    let count = tracker.lock().ok()?.record(target.into(), now)?;
    if !matches!(decision.action, ProxyAction::Allow) {
        return None;
    }
    decision.action = ProxyAction::Queue {
        priority: QueuePriority::High,
    };
    decision.decision_reason = format!(
        "mass-destruction signal: {count} distinct out-of-tree deletions within {}s",
        WINDOW.as_secs()
    );
    Some(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delete(path: &str) -> ToolCallType {
        ToolCallType::FileDelete {
            path: path.to_string(),
        }
    }

    #[test]
    fn destructive_target_covers_delete_and_rename_only() {
        assert_eq!(destructive_target(&delete("/home/u/x")), Some("/home/u/x"));
        assert_eq!(
            destructive_target(&ToolCallType::FileRename {
                old_path: "/home/u/a".into(),
                new_path: "/home/u/b".into(),
            }),
            Some("/home/u/a")
        );
        // Writes/appends are intentionally NOT destructive targets (create vs
        // overwrite is indistinguishable without a stat — deferred).
        assert_eq!(
            destructive_target(&ToolCallType::FileWrite {
                path: "/home/u/x".into(),
                content_hash: String::new(),
            }),
            None
        );
    }

    #[test]
    fn in_tree_and_routine_and_scratch_and_ephemeral_never_count() {
        let working = Path::new("/home/u/project");
        let routine = vec!["/usr/lib/node/".to_string()];
        let scratch = vec!["/home/u/project/.cache/".to_string()];

        // In the working tree — the agent's job, never flagged.
        assert!(!is_valuable_out_of_tree(
            "/home/u/project/src/main.rs",
            Some(working),
            &[],
            &routine,
            &scratch
        ));
        // Working-root boundary is exact: a sibling that shares the prefix as a
        // substring (…/project-old) is NOT in-tree.
        assert!(is_valuable_out_of_tree(
            "/home/u/project-old/data.db",
            Some(working),
            &[],
            &routine,
            &scratch
        ));
        // Routine root.
        assert!(!is_valuable_out_of_tree(
            "/usr/lib/node/x.js",
            Some(working),
            &[],
            &routine,
            &scratch
        ));
        // Scratch root.
        assert!(!is_valuable_out_of_tree(
            "/home/u/project/.cache/blob",
            Some(working),
            &[],
            &routine,
            &scratch
        ));
        // Ephemeral system roots.
        for p in ["/tmp/etilqs_x", "/var/cache/foo", "/proc/1/maps"] {
            assert!(!is_valuable_out_of_tree(
                p,
                Some(working),
                &[],
                &routine,
                &scratch
            ));
        }
        // Relative path can't be classified.
        assert!(!is_valuable_out_of_tree(
            "relative/x",
            Some(working),
            &[],
            &routine,
            &scratch
        ));
    }

    #[test]
    fn out_of_tree_user_data_counts() {
        let working = Path::new("/home/u/project");
        assert!(is_valuable_out_of_tree(
            "/home/u/Documents/taxes.pdf",
            Some(working),
            &[],
            &[],
            &[]
        ));
    }

    /// The 2026-08-17 incident shape: cargo (or npm/python/git) churn in a
    /// SIBLING repo - outside the working root, so the in-tree exclusion
    /// misses it - must classify as ephemeral, not valuable.
    #[test]
    fn sibling_repo_build_artifacts_never_count() {
        let working = Path::new("/home/u/proj-website");
        for p in [
            "/home/u/proj/target/debug/incremental/net-9a598f.rcgu.o",
            "/home/u/proj/target/release/deps/libfoo.rlib",
            "/home/u/proj/node_modules/.cache/esbuild/x.js",
            "/home/u/proj/src/__pycache__/mod.cpython-312.pyc",
            "/home/u/proj/.git/objects/ab/cdef0123",
            "/home/u/proj/.next/cache/webpack/chunk.js",
        ] {
            assert!(
                !is_valuable_out_of_tree(p, Some(working), &[], &[], &[]),
                "build artifact counted as valuable: {p}"
            );
        }
    }

    /// The build-dir exemption must match whole directory components only -
    /// look-alike names that merely share a prefix or suffix still count.
    #[test]
    fn build_segment_lookalikes_still_count() {
        let working = Path::new("/home/u/proj-website");
        for p in [
            "/home/u/mytarget/debug/data.db",
            "/home/u/proj/targets/debug/data.db",
            "/home/u/proj/target/debugged/data.db",
            "/home/u/proj/node_modules_backup/real-code.js",
            "/home/u/proj/.gitlab/objects/data.db",
        ] {
            assert!(
                is_valuable_out_of_tree(p, Some(working), &[], &[], &[]),
                "look-alike wrongly exempted: {p}"
            );
        }
    }

    /// work/83 F4: the 2026-08-20 incident shape. `git worktree remove` on a
    /// sibling worktree of the launch repository produced 692 escalations of
    /// `FileDelete` calls that individually scored 1.0, because the worktree
    /// sat outside the launch cwd and every deletion in it looked like a
    /// spree. A resolved workspace root makes those deletions in-tree —
    /// while a delete outside every trusted root still counts, so the signal
    /// is narrowed to the session's real working set, not disabled.
    #[test]
    fn deletions_inside_a_trusted_worktree_never_count() {
        let working = Path::new("/home/u/proj");
        let workspace = vec!["/home/u/worktrees/analytics-local".to_string()];

        for p in [
            "/home/u/worktrees/analytics-local/work/todos/a.md",
            "/home/u/worktrees/analytics-local/src/main.rs",
            "/home/u/worktrees/analytics-local",
        ] {
            assert!(
                !is_valuable_out_of_tree(p, Some(working), &workspace, &[], &[]),
                "deletion inside a trusted worktree must not count: {p}"
            );
        }

        // The user's own files are untouched by the widening.
        assert!(is_valuable_out_of_tree(
            "/home/u/Documents/taxes.pdf",
            Some(working),
            &workspace,
            &[],
            &[]
        ));
        // Boundary safety: a sibling directory that merely shares the prefix
        // is NOT inside the trusted worktree.
        assert!(is_valuable_out_of_tree(
            "/home/u/worktrees/analytics-local-backup/data.db",
            Some(working),
            &workspace,
            &[],
            &[]
        ));
    }

    /// End-to-end through `maybe_escalate`: a bulk delete inside a trusted
    /// worktree does not mass-escalate, while a bulk delete of `~/Documents`
    /// still does.
    #[test]
    fn bulk_delete_escalates_outside_the_workspace_only() {
        let working = Path::new("/home/u/proj");
        let workspace = vec!["/home/u/worktrees/wt".to_string()];
        let now = Instant::now();
        let run = |paths: Vec<String>| {
            let tracker = Mutex::new(MassDestructionTracker::new(WINDOW, 3));
            let mut escalations = 0;
            for path in paths {
                let mut d = ProxyDecision {
                    action: ProxyAction::Allow,
                    composite_score: 1.0,
                    filter_results: vec![],
                    decision_reason: "allowed".into(),
                    evaluation_time: Duration::from_millis(1),
                };
                if maybe_escalate(
                    &mut d,
                    &delete(&path),
                    Some(working),
                    &workspace,
                    &[],
                    &[],
                    &tracker,
                    now,
                )
                .is_some()
                {
                    escalations += 1;
                }
            }
            escalations
        };

        assert_eq!(
            run((0..10)
                .map(|i| format!("/home/u/worktrees/wt/work/todos/{i}.md"))
                .collect()),
            0,
            "removing a trusted worktree must not mass-escalate"
        );
        assert!(
            run((0..10)
                .map(|i| format!("/home/u/Documents/{i}.pdf"))
                .collect())
                > 0,
            "a spree through the user's documents must still escalate"
        );
    }

    #[test]
    fn distinct_targets_trip_threshold_repeats_do_not() {
        let mut t = MassDestructionTracker::new(WINDOW, 3);
        let now = Instant::now();
        assert!(t.record("/a".into(), now).is_none());
        // Re-touching the same path does not advance the distinct count.
        assert!(t.record("/a".into(), now).is_none());
        assert!(t.record("/b".into(), now).is_none());
        assert_eq!(t.record("/c".into(), now), Some(3));
    }

    #[test]
    fn maybe_escalate_flips_allow_to_queue_at_threshold_and_bypasses_otherwise() {
        let tracker = Mutex::new(MassDestructionTracker::new(WINDOW, 3));
        let working = Path::new("/home/u/project");
        let now = Instant::now();
        let esc = |path: &str, action: ProxyAction| {
            let mut d = ProxyDecision {
                action,
                composite_score: 0.5,
                filter_results: vec![],
                decision_reason: "allowed".into(),
                evaluation_time: Duration::from_millis(1),
            };
            let r = maybe_escalate(
                &mut d,
                &delete(path),
                Some(working),
                &[],
                &[],
                &[],
                &tracker,
                now,
            );
            (r, d.action)
        };

        // First two distinct out-of-tree deletes are recorded but below the
        // threshold of 3 — Allow is preserved.
        assert!(matches!(
            esc("/home/u/a", ProxyAction::Allow),
            (None, ProxyAction::Allow)
        ));
        assert!(matches!(
            esc("/home/u/b", ProxyAction::Allow),
            (None, ProxyAction::Allow)
        ));
        // Third distinct target trips it: Allow → high-priority QUEUE.
        let (count, action) = esc("/home/u/c", ProxyAction::Allow);
        assert_eq!(count, Some(3));
        assert!(matches!(
            action,
            ProxyAction::Queue {
                priority: QueuePriority::High
            }
        ));

        // In-tree deletes never count, even past the threshold.
        let (count, action) = esc("/home/u/project/src/lib.rs", ProxyAction::Allow);
        assert_eq!(count, None);
        assert!(matches!(action, ProxyAction::Allow));

        // A non-Allow decision is recorded (window stays accurate) but its
        // action is left untouched — we don't downgrade a Deny to a Queue.
        let (count, action) = esc("/home/u/d", ProxyAction::Deny { reason: "x".into() });
        assert_eq!(count, None);
        assert!(matches!(action, ProxyAction::Deny { .. }));
    }

    #[test]
    fn targets_outside_window_age_out_before_tripping() {
        let mut t = MassDestructionTracker::new(Duration::from_secs(10), 3);
        let base = Instant::now();
        assert!(t.record("/a".into(), base).is_none());
        assert!(t.record("/b".into(), base).is_none());
        // 11s later, /a and /b have aged out; only /c and /d are in-window, so
        // the threshold of 3 is never reached.
        let later = base + Duration::from_secs(11);
        assert!(t.record("/c".into(), later).is_none());
        assert!(t.record("/d".into(), later).is_none());
        assert_eq!(t.distinct_len(), 2);
    }
}
