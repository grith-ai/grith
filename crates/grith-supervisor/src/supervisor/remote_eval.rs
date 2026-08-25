// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Shared transport for daemon-backed policy evaluation.
//!
//! Two callers evaluate against the daemon's `/api/proxy/evaluate`: the ptrace
//! event loop ([`super::event_handler`]) and the connected DNS proxy's policy
//! adapter ([`super::dns_decision`]). Both must recognise an IPC-token
//! rejection so they can reload the rotated token and retry rather than
//! failing the call.
//!
//! That recognition used to be a substring match on each caller's own error
//! text, and the two texts had drifted: the event loop emitted `daemon
//! returned 403 …` while the DNS adapter emitted `remote DNS policy returned
//! 403 …`. Only the former was matched, so a daemon restart left DNS denying
//! every query until some unrelated syscall happened to heal the shared token.
//! Classifying the status once, here, in a type both callers share is what
//! stops the two from drifting apart again.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use grith_proxy::types::ToolCallContext;

/// How long a single evaluate call may take before it is treated as a
/// transport failure. Matches the previous per-caller timeouts.
const EVALUATE_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a daemon-backed evaluation did not produce a decision.
///
/// [`RemoteEvalError::AuthRejected`] is split out from the other HTTP statuses
/// deliberately: it is the only variant a caller can recover from, by
/// reloading the token and retrying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteEvalError {
    /// The request never reached the daemon, or the response never arrived.
    Transport(String),
    /// The daemon rejected our credentials (401/403). Recoverable: the daemon
    /// has almost certainly restarted and rotated its IPC token, and the
    /// current one is already on disk.
    AuthRejected { status: u16, body: String },
    /// The daemon answered, with a status that is not success and not an auth
    /// rejection.
    HttpStatus { status: u16, body: String },
    /// The daemon answered 2xx with a body we could not read as a decision.
    Parse(String),
}

impl RemoteEvalError {
    /// Whether this is the daemon rejecting our credentials, as opposed to
    /// being unreachable or answering unusably.
    ///
    /// Callers use this to decide whether reloading the IPC token and retrying
    /// could help. Every other variant is terminal for the call.
    pub fn is_auth_rejection(&self) -> bool {
        matches!(self, Self::AuthRejected { .. })
    }
}

impl std::fmt::Display for RemoteEvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(detail) => write!(f, "request failed: {detail}"),
            Self::AuthRejected { status, body } | Self::HttpStatus { status, body } => {
                write!(f, "daemon returned {status}: {body}")
            }
            Self::Parse(detail) => write!(f, "response parse failed: {detail}"),
        }
    }
}

impl std::error::Error for RemoteEvalError {}

/// POST a tool-call context to the daemon's evaluate endpoint and return the
/// raw JSON body.
///
/// Decision parsing stays with the caller: the two callers build a
/// `ProxyDecision` differently and neither should inherit the other's
/// tolerance for missing fields. What is shared is the part that had drifted -
/// issuing the request and classifying the status.
pub async fn post_evaluate(
    client: &reqwest::Client,
    base_url: &str,
    token: &str,
    ctx: &ToolCallContext,
) -> Result<serde_json::Value, RemoteEvalError> {
    post_evaluate_with_observations(client, base_url, token, ctx, Vec::new()).await
}

/// As [`post_evaluate`], but carrying the outcomes of earlier calls so the
/// daemon can commit them BEFORE scoring this one.
///
/// That ordering is the whole point: it guarantees call N's commit lands ahead
/// of call N+1's evaluate, at zero extra round trips.
pub async fn post_evaluate_with_observations(
    client: &reqwest::Client,
    base_url: &str,
    token: &str,
    ctx: &ToolCallContext,
    observations: Vec<WireObservation>,
) -> Result<serde_json::Value, RemoteEvalError> {
    let response = client
        .post(format!("{base_url}/api/proxy/evaluate"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "context": ctx, "observations": observations }))
        .timeout(EVALUATE_TIMEOUT)
        .send()
        .await
        .map_err(|error| RemoteEvalError::Transport(error.to_string()))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        let status = status.as_u16();
        return Err(
            if status == reqwest::StatusCode::UNAUTHORIZED.as_u16()
                || status == reqwest::StatusCode::FORBIDDEN.as_u16()
            {
                RemoteEvalError::AuthRejected { status, body }
            } else {
                RemoteEvalError::HttpStatus { status, body }
            },
        );
    }

    response
        .json()
        .await
        .map_err(|error| RemoteEvalError::Parse(error.to_string()))
}

/// Flush pending outcome observations that have no evaluate to ride along
/// with - at session end, where the session's last calls would otherwise never
/// be committed.
///
/// Best-effort: on failure the batch goes back in the outbox. At session end
/// nothing will drain it, which is the safe direction - a lost commit
/// under-counts, and the daemon's state for the scope is about to be dropped
/// anyway.
pub async fn flush_observations(
    client: &reqwest::Client,
    base_url: &str,
    token: &str,
    outbox: &ObservationOutbox,
) {
    let batch = outbox.take();
    if batch.is_empty() {
        return;
    }
    let count = batch.len();
    let response = client
        .post(format!("{base_url}/api/proxy/observe"))
        .bearer_auth(token)
        .json(&ObservationOutbox::to_wire(&batch))
        .timeout(EVALUATE_TIMEOUT)
        .send()
        .await;
    match response {
        Ok(r) if r.status().is_success() => {
            tracing::debug!(count, "flushed pending outcome observations at session end");
        }
        Ok(r) => {
            tracing::warn!(status = %r.status(), count, "observation flush rejected");
            outbox.restore(batch);
        }
        Err(error) => {
            tracing::warn!(%error, count, "observation flush failed");
            outbox.restore(batch);
        }
    }
}

/// Reload the IPC token from disk after an auth rejection, updating the shared
/// token so every holder (the event loop and the DNS decision service) heals
/// together.
///
/// Returns the fresh token only when it differs from the one just rejected -
/// retrying with an identical token cannot succeed, and returning it anyway
/// would turn every rejection into a second wasted round trip.
pub fn reload_rotated_token(
    token_path: &Path,
    shared: &Arc<Mutex<String>>,
    just_used: &str,
) -> Option<String> {
    let fresh = std::fs::read_to_string(token_path).ok()?.trim().to_string();
    if fresh.is_empty() || fresh == just_used {
        return None;
    }
    if let Ok(mut guard) = shared.lock() {
        *guard = fresh.clone();
    }
    tracing::info!(
        event = "ipc_token_refreshed",
        "daemon IPC token reloaded from disk after auth rejection"
    );
    Some(fresh)
}

// ---------------------------------------------------------------------------
// Observation outbox (daemon mode)
// ---------------------------------------------------------------------------

/// One call's final outcome, in the form the daemon needs to commit it.
///
/// Carries the fields a stateful filter actually reads rather than the whole
/// `ToolCallContext`: the daemon reconstitutes a minimal context from these.
///
/// `age_ms` rather than a timestamp because the two processes share no
/// `Instant` epoch, and a wall clock would import clock-adjustment bugs into
/// windows that are deliberately monotonic.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WireObservation {
    pub call_id: uuid::Uuid,
    pub scope: uuid::Uuid,
    pub session_id: uuid::Uuid,
    pub call_type: grith_proxy::types::ToolCallType,
    /// Needed for profile-trusted destination matching. Without it a routine
    /// destination commits as non-routine and inflates the volumetric counters.
    pub profile_name: Option<String>,
    /// Carries the unix-socket class label. Without it a Control-class connect
    /// (session D-Bus, X11) commits as egress even though `evaluate` correctly
    /// ignored it - the exact false-positive class the class labelling exists
    /// to suppress.
    ///
    /// The daemon already receives the full `arguments` on every evaluate, so
    /// this discloses nothing new to it.
    pub arguments: serde_json::Value,
    pub outcome: grith_proxy::types::CallOutcome,
    /// Filled in at SEND time from `attempted_at`, never at push time: an
    /// observation can sit in the outbox across many calls, and stamping the
    /// age when it was queued would re-date it to the moment it finally left.
    pub age_ms: u64,
}

/// An observation plus the local instant its call was attempted.
///
/// The instant stays supervisor-side because the two processes share no
/// `Instant` epoch; it is converted to an age only as the request is built.
#[derive(Debug, Clone)]
pub struct PendingObservation {
    pub observation: WireObservation,
    pub attempted_at: std::time::Instant,
}

/// Cap on unsent observations. Dropping the oldest is the safe direction: a
/// lost commit can only under-count, whereas an unbounded queue in a
/// supervisor is a memory leak with a security consequence.
const OUTBOX_CAP: usize = 256;

/// Outcomes waiting to ride along with the next daemon evaluate request.
///
/// In daemon mode the filters live in the daemon, so an outcome observed in
/// the supervisor has to cross the IPC boundary. Piggybacking on the next
/// evaluate is what guarantees call N's commit is applied before call N+1's
/// evaluate, at zero extra round trips - ordering the fire-and-forget
/// reputation path does not provide.
#[derive(Debug, Default)]
pub struct ObservationOutbox {
    pending: Mutex<Vec<PendingObservation>>,
    dropped: std::sync::atomic::AtomicU64,
}

impl ObservationOutbox {
    pub fn push(&self, observation: PendingObservation) {
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        if pending.len() >= OUTBOX_CAP {
            pending.remove(0);
            let dropped = self
                .dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            tracing::warn!(
                dropped,
                cap = OUTBOX_CAP,
                "observation outbox full; dropped the oldest unsent outcome"
            );
        }
        pending.push(observation);
    }

    /// Take everything pending, for attaching to an outbound request.
    pub fn take(&self) -> Vec<PendingObservation> {
        match self.pending.lock() {
            Ok(mut pending) => std::mem::take(&mut *pending),
            Err(_) => Vec::new(),
        }
    }

    /// Stamp each pending observation with its age as of now.
    pub fn to_wire(batch: &[PendingObservation]) -> Vec<WireObservation> {
        batch
            .iter()
            .map(|p| {
                let mut wire = p.observation.clone();
                wire.age_ms = p
                    .attempted_at
                    .elapsed()
                    .as_millis()
                    .min(u128::from(u64::MAX)) as u64;
                wire
            })
            .collect()
    }

    /// Put a failed batch back at the front, preserving order.
    pub fn restore(&self, mut batch: Vec<PendingObservation>) {
        if batch.is_empty() {
            return;
        }
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        batch.append(&mut pending);
        *pending = batch;
        if pending.len() > OUTBOX_CAP {
            let excess = pending.len() - OUTBOX_CAP;
            pending.drain(0..excess);
        }
    }

    /// Unsent observations dropped because the outbox was full. Non-zero means
    /// the daemon has been unreachable long enough to lose commits.
    #[allow(dead_code)] // read by diagnostics; kept so the loss is countable
    pub fn dropped(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_statuses_are_recoverable() {
        for status in [401, 403] {
            let error = RemoteEvalError::AuthRejected {
                status,
                body: "Invalid IPC token".into(),
            };
            assert!(
                error.is_auth_rejection(),
                "{status} must be treated as recoverable"
            );
        }
    }

    #[test]
    fn other_failures_are_terminal() {
        let cases = [
            RemoteEvalError::Transport("connection refused".into()),
            RemoteEvalError::HttpStatus {
                status: 500,
                body: "boom".into(),
            },
            RemoteEvalError::Parse("expected object".into()),
        ];
        for error in cases {
            assert!(
                !error.is_auth_rejection(),
                "{error} must not trigger a token reload"
            );
        }
    }

    /// The DNS adapter and the event loop must agree on what an auth rejection
    /// looks like. This is the regression that let a daemon restart leave DNS
    /// failing closed: the two paths classified the same 403 differently
    /// because each matched on its own error string.
    #[test]
    fn both_callers_classify_the_same_status_identically() {
        let from_dns = RemoteEvalError::AuthRejected {
            status: 403,
            body: "Invalid IPC token".into(),
        };
        let from_event_loop = RemoteEvalError::AuthRejected {
            status: 403,
            body: "Invalid IPC token".into(),
        };
        assert_eq!(from_dns, from_event_loop);
        assert!(from_dns.is_auth_rejection() && from_event_loop.is_auth_rejection());
    }

    #[test]
    fn reload_returns_none_when_the_token_is_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("daemon.token");
        std::fs::write(&path, "same-token\n").expect("write token");

        let shared = Arc::new(Mutex::new("same-token".to_string()));
        assert_eq!(reload_rotated_token(&path, &shared, "same-token"), None);
    }

    #[test]
    fn reload_returns_none_when_the_token_file_is_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("daemon.token");
        std::fs::write(&path, "   \n").expect("write token");

        let shared = Arc::new(Mutex::new("old-token".to_string()));
        assert_eq!(reload_rotated_token(&path, &shared, "old-token"), None);
    }

    #[test]
    fn reload_returns_none_when_the_token_file_is_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("absent.token");

        let shared = Arc::new(Mutex::new("old-token".to_string()));
        assert_eq!(reload_rotated_token(&path, &shared, "old-token"), None);
    }

    #[test]
    fn reload_publishes_a_rotated_token_to_every_holder() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("daemon.token");
        std::fs::write(&path, "rotated-token\n").expect("write token");

        let shared = Arc::new(Mutex::new("old-token".to_string()));
        // A second holder of the same Arc stands in for the DNS decision
        // service, which is handed the same shared token as the event loop.
        let dns_view = Arc::clone(&shared);

        assert_eq!(
            reload_rotated_token(&path, &shared, "old-token"),
            Some("rotated-token".to_string())
        );
        assert_eq!(dns_view.lock().expect("lock").as_str(), "rotated-token");
    }

    fn pending(age: std::time::Duration) -> PendingObservation {
        PendingObservation {
            attempted_at: std::time::Instant::now() - age,
            observation: WireObservation {
                call_id: uuid::Uuid::new_v4(),
                scope: uuid::Uuid::new_v4(),
                session_id: uuid::Uuid::new_v4(),
                call_type: grith_proxy::types::ToolCallType::NetConnect {
                    address: "example.net".into(),
                    port: 443,
                },
                profile_name: None,
                arguments: serde_json::Value::Null,
                outcome: grith_proxy::types::CallOutcome::Denied,
                age_ms: 0,
            },
        }
    }

    /// An observation can wait in the outbox across many calls. Stamping its
    /// age when it was queued would re-date it to the moment it finally left,
    /// landing a queued-then-approved call after the events it should have
    /// correlated with.
    #[test]
    fn age_is_stamped_at_send_not_at_push() {
        let outbox = ObservationOutbox::default();
        outbox.push(pending(std::time::Duration::from_secs(30)));
        let batch = outbox.take();
        let wire = ObservationOutbox::to_wire(&batch);
        assert_eq!(wire.len(), 1);
        assert!(
            wire[0].age_ms >= 30_000,
            "expected the real dwell time, got {}ms",
            wire[0].age_ms
        );
    }

    #[test]
    fn restore_preserves_order_and_respects_the_cap() {
        let outbox = ObservationOutbox::default();
        let first = pending(std::time::Duration::ZERO);
        let first_id = first.observation.call_id;
        outbox.push(first);
        let batch = outbox.take();
        assert!(outbox.take().is_empty(), "take must drain");

        outbox.push(pending(std::time::Duration::ZERO));
        outbox.restore(batch);
        let after = outbox.take();
        assert_eq!(after.len(), 2);
        assert_eq!(
            after[0].observation.call_id, first_id,
            "a restored batch goes back in front of what arrived meanwhile"
        );
    }

    #[test]
    fn outbox_drops_oldest_at_capacity_and_counts_it() {
        let outbox = ObservationOutbox::default();
        for _ in 0..(OUTBOX_CAP + 5) {
            outbox.push(pending(std::time::Duration::ZERO));
        }
        assert_eq!(outbox.take().len(), OUTBOX_CAP);
        assert_eq!(outbox.dropped(), 5);
    }
}
