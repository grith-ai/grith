// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Daemon initialization, health checking, and lifecycle management.
//!
//! This module owns the [`Daemon`] struct which holds all initialized subsystem
//! handles and coordinates their startup, health monitoring, and shutdown.

pub(crate) mod background;
#[allow(dead_code)]
pub mod client;
pub(crate) mod config_loader;
mod filter_registry;
mod health;
pub mod identity;
mod notifications;
pub(crate) mod pid;
pub mod readiness;
#[cfg(test)]
mod scoring_latency_bench;
#[allow(dead_code)]
pub mod token;

// Re-export public items so external `use crate::daemon::*` paths remain valid.
pub use health::format_health_report;
pub use pid::{
    dashboard_already_opened, is_dashboard_running, mark_dashboard_opened, remove_dashboard_opened,
    remove_dashboard_pid, write_dashboard_pid,
};

use crate::config::GrithConfig;
use crate::error::Error;
use config_loader::{expand_path, resolve_api_key, to_supervisor_config};
use filter_registry::{build_filter_registry_with_config_result, build_meta_rule_engine_result};
use grith_audit::AuditStorage;
use grith_audit::CorrelationTracker as AuditCorrelationTracker;
use grith_digest::DigestQueue;
use grith_proxy::engine::SecurityProxy;
use grith_proxy::filters::dlp_gate::DlpRedactor;
use grith_proxy::filters::session_containment::ContainmentTracker;
use grith_proxy::scoring::ScoringConfig;
use grith_supervisor::supervisor::SupervisorRegistry;
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::broadcast;

/// Subsystem health status.
#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded(String),
    Unhealthy(String),
}

/// Individual subsystem health.
#[derive(Debug, Clone)]
pub struct SubsystemHealth {
    pub name: String,
    pub status: HealthStatus,
}

/// Overall daemon health report.
#[derive(Debug, Clone)]
pub struct HealthReport {
    pub subsystems: Vec<SubsystemHealth>,
}

impl HealthReport {
    pub fn is_healthy(&self) -> bool {
        self.subsystems
            .iter()
            .all(|s| s.status == HealthStatus::Healthy)
    }

    pub fn is_degraded(&self) -> bool {
        self.subsystems
            .iter()
            .any(|s| matches!(s.status, HealthStatus::Degraded(_)))
            && !self
                .subsystems
                .iter()
                .any(|s| matches!(s.status, HealthStatus::Unhealthy(_)))
    }
}

/// Outcome of startup audit-chain verification.
///
/// work/74 Phase 5. Startup never rewrites the chain; it either proves the
/// chain is usable or refuses to write to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStatus {
    /// Verified. Normal operation.
    Ready,
    /// The archive boundary anchor was missing and has been re-derived from
    /// cold storage. No record was modified.
    Recovered {
        /// Sequence of the archived record the active segment continues from.
        boundary_sequence: i64,
    },
    /// The active segment verifies, but it does not continue the archived
    /// history — it restarts from sequence 1 while cold archives hold
    /// earlier records (B12 item 7).
    ///
    /// Writable: the discontinuity is historical, and the local chain from
    /// this point on is sound. It is surfaced rather than hidden because
    /// "one unbroken chain" is not a true statement about this database.
    SegmentDiscontinuity {
        /// Highest sequence held in cold archives.
        archive_terminal_sequence: i64,
        /// Lowest sequence in the active segment.
        active_genesis_sequence: i64,
    },
    /// Integrity could not be established. Audit writes must be refused and
    /// every byte preserved for the operator to inspect.
    Quarantined {
        /// Operator-facing explanation of what failed.
        reason: String,
    },
}

impl ChainStatus {
    /// True when the daemon may accept new audit writes and admit sessions.
    #[must_use]
    pub fn is_writable(&self) -> bool {
        !matches!(self, Self::Quarantined { .. })
    }
}

/// Whether cloud sync has credentials to transmit with.
///
/// Mirrors the check `background::flush_audit_batch` makes before sending
/// anything: without stored credentials sync is inert, so no row will ever
/// be acknowledged and sync-safe retention has nothing to wait for.
fn has_sync_credentials() -> bool {
    matches!(crate::license::load_credentials(), Ok(Some(_)))
}

/// Detect an active segment that restarted at sequence 1 while cold
/// archives hold earlier history, and record the fact durably.
///
/// Returns the marker when the database is (or already was) classified as
/// multi-segment, `None` when the history is a single continuous chain.
/// Writing is idempotent — an already-marked database is re-reported from
/// its stored marker rather than re-derived.
fn classify_active_regenesis(
    storage: &AuditStorage,
    cold_dir: &std::path::Path,
) -> anyhow::Result<Option<grith_audit::SegmentHistory>> {
    if let Some(existing) = storage.load_segment_history()? {
        return Ok(Some(existing));
    }

    let Some((first_sequence, _)) = storage.first_chained_row()? else {
        return Ok(None);
    };
    // Only a re-genesis is in question here. A segment starting above 1 is
    // the anchored/unanchored case, handled by the boundary logic.
    if first_sequence > 1 {
        return Ok(None);
    }
    // An archive boundary means the operator's history was already
    // reconciled deliberately; that is not a discontinuity.
    if storage.load_archive_boundary()?.is_some() {
        return Ok(None);
    }

    let archives = grith_audit::retention::list_archive_files(cold_dir);
    if archives.is_empty() {
        return Ok(None);
    }
    let Some((terminal_sequence, terminal_hash)) =
        grith_audit::retention::archive_terminal_record(cold_dir)?
    else {
        return Ok(None);
    };

    let history = grith_audit::SegmentHistory {
        archive_terminal_sequence: terminal_sequence,
        archive_terminal_hash: terminal_hash,
        active_genesis_sequence: first_sequence,
        cause: "active_regenesis_with_archives".to_string(),
        reason: format!(
            "cold archives end at sequence {terminal_sequence}, but the active audit \
             database restarts at sequence {first_sequence} with no link to it. Local \
             history therefore consists of two segments that cannot be joined without \
             rewriting records. Both segments are retained and independently verifiable."
        ),
        classified_at: chrono::Utc::now(),
    };
    storage.store_segment_history(&history)?;
    tracing::warn!(
        archive_terminal_sequence = terminal_sequence,
        active_genesis_sequence = first_sequence,
        "audit history spans two segments; recorded segment-history marker"
    );
    Ok(Some(history))
}

/// Decide what to do about a verification outcome, without ever rewriting.
///
/// The only "repair" performed here is re-deriving a missing archive boundary
/// from cold storage, which changes no audit record — it restores a lost
/// bookkeeping row. Anything that could be genuine tampering quarantines.
fn resolve_chain_status(
    storage: &AuditStorage,
    verification: &grith_audit::ChainVerification,
    cold_dir: &std::path::Path,
) -> ChainStatus {
    use grith_audit::retention::{resolve_boundary_from_archives, BoundaryResolution};
    use grith_audit::ChainVerification as V;

    match verification {
        // A valid active segment still leaves one honest question open: does
        // it *continue* the archived history, or did it restart? A segment
        // that begins at sequence 1 while cold archives hold earlier history
        // is a re-genesis — 0.1.4's automatic repair could produce exactly
        // that (work/74:203-232). Verification calls it Valid, which is true
        // of the segment but silent about the discontinuity.
        //
        // This classifies and warns rather than quarantining. Quarantine
        // would brick every machine that ever ran the old auto-repair,
        // including ones with no recovery command yet, and the fault being
        // described is historical and unfixable without rewriting evidence.
        // The marker is durable so diagnose and compliance reporting can
        // state plainly that local history has two segments.
        V::Valid { .. } => {
            match classify_active_regenesis(storage, cold_dir) {
                Ok(Some(history)) => ChainStatus::SegmentDiscontinuity {
                    archive_terminal_sequence: history.archive_terminal_sequence,
                    active_genesis_sequence: history.active_genesis_sequence,
                },
                // Classification is best-effort bookkeeping; failing to read
                // archives must not deny a healthy chain.
                Ok(None) => ChainStatus::Ready,
                Err(e) => {
                    tracing::warn!(error = %e, "could not classify audit segment history");
                    ChainStatus::Ready
                }
            }
        }

        // An empty active DB is only a legitimate genesis when no archived
        // history claims otherwise (work/74 §11). Archives plus an empty
        // active database means the active segment was deleted or truncated.
        V::Empty => {
            let archives = grith_audit::retention::list_archive_files(cold_dir);
            if archives.is_empty() {
                ChainStatus::Ready
            } else {
                ChainStatus::Quarantined {
                    reason: format!(
                        "active audit database is empty but {} cold archive(s) exist — \
                         history is missing, refusing to start a new genesis chain",
                        archives.len()
                    ),
                }
            }
        }

        // Recoverable: the anchor is missing, not the data. Re-derive it from
        // the archives, which are the source of truth.
        V::Unanchored { first_sequence } => {
            let first_prev = storage
                .first_chained_row()
                .ok()
                .flatten()
                .and_then(|(_, prev)| prev);
            match resolve_boundary_from_archives(cold_dir, *first_sequence, first_prev.as_deref()) {
                Ok(BoundaryResolution::Resolved(boundary)) => {
                    let sequence = boundary.last_archived_sequence;
                    match storage.store_archive_boundary(&boundary) {
                        Ok(()) => ChainStatus::Recovered {
                            boundary_sequence: sequence,
                        },
                        Err(e) => ChainStatus::Quarantined {
                            reason: format!("could not persist recovered archive boundary: {e}"),
                        },
                    }
                }
                Ok(BoundaryResolution::Mismatch {
                    boundary_sequence,
                    archived_hash,
                    found_prev_hash,
                }) => ChainStatus::Quarantined {
                    reason: format!(
                        "archived record {boundary_sequence} hashes to {archived_hash} but the \
                         active segment claims prev_hash {found_prev_hash:?} — the archived and \
                         active histories do not join"
                    ),
                },
                Ok(BoundaryResolution::TamperedArchive {
                    boundary_sequence,
                    stored_hash,
                    recomputed_hash,
                    archive,
                }) => ChainStatus::Quarantined {
                    reason: if stored_hash.is_empty() {
                        format!(
                            "cold archive {archive} fails its own internal chain check at \
                             sequence {boundary_sequence} — refusing to derive a boundary from it"
                        )
                    } else {
                        format!(
                            "archived record {boundary_sequence} in {archive} stores hash \
                             {stored_hash} but its content hashes to {recomputed_hash} — the \
                             archive has been modified, refusing to anchor to it"
                        )
                    },
                },
                Ok(BoundaryResolution::Unresolved) => ChainStatus::Quarantined {
                    reason: format!(
                        "active segment starts at sequence {first_sequence} with no archive \
                         boundary, and no cold archive contains record {}",
                        first_sequence - 1
                    ),
                },
                Ok(BoundaryResolution::NotNeeded) => ChainStatus::Ready,
                Err(e) => ChainStatus::Quarantined {
                    reason: format!("could not read cold archives to recover the boundary: {e}"),
                },
            }
        }

        V::AnchorMismatch {
            boundary_sequence,
            expected_prev_hash,
            found_prev_hash,
            ..
        } => ChainStatus::Quarantined {
            reason: format!(
                "archive boundary at sequence {boundary_sequence} expects prev_hash \
                 {expected_prev_hash} but the active segment carries {found_prev_hash:?}"
            ),
        },

        V::Broken {
            at_sequence,
            reason,
            ..
        } => ChainStatus::Quarantined {
            reason: format!("chain broken at sequence {at_sequence}: {reason}"),
        },
    }
}

/// Holds all initialized subsystem handles.
pub struct Daemon {
    pub config: GrithConfig,
    pub account_id: String,
    pub audit_storage: Arc<Mutex<AuditStorage>>,
    pub digest_queue: Arc<DigestQueue>,
    pub proxy: Arc<SecurityProxy>,
    pub supervisor_registry: Arc<Mutex<SupervisorRegistry>>,
    pub dlp_redactor: Arc<DlpRedactor>,
    pub containment_tracker: Arc<ContainmentTracker>,
    pub correlation_tracker: Arc<AuditCorrelationTracker>,
    pub canary_registry: Arc<grith_proxy::filters::canary::CanaryRegistry>,
    pub notification_dispatcher: Arc<grith_notify::NotificationDispatcher>,
    pub feature_gate: Arc<RwLock<crate::license::FeatureGate>>,
    /// License renewal date (YYYY-MM-DD) when a Pro/Enterprise license is active.
    pub license_valid_until: Option<String>,
    /// Billing portal URL from license metadata, if provided.
    pub billing_portal_url: Option<String>,
    // Retained for runtime diagnostics and future refresh logic.
    #[allow(dead_code)]
    pub license_status: crate::license::LicenseStatus,
    /// Live licence-refresh state shared with the API/CLI.
    pub refresh_state: Arc<RwLock<crate::license::RefreshState>>,
    /// Shared reputation table — owned by the daemon, shared across all
    /// supervisor sessions. Loaded from disk on startup, saved periodically
    /// and on shutdown.
    pub reputation_table: Arc<Mutex<grith_proxy::reputation::ReputationTable>>,
    /// Mtime of the provider-keys directory at last load, for rotation detection.
    provider_keys_mtime: Option<std::time::SystemTime>,
    /// Outcome of startup audit-chain verification (work/74 Phase 5). When
    /// quarantined the daemon must refuse audit writes and session admission
    /// rather than rewrite the chain.
    pub chain_status: ChainStatus,
    /// Whether this process owns the audit database (work/74 Phase 4).
    pub audit_role: AuditRole,
    /// Held for the process lifetime when this daemon is the audit owner;
    /// dropping it releases the exclusive lock.
    #[allow(dead_code)]
    audit_writer_lock: Option<grith_audit::writer_lock::AuditWriterLock>,
    pub(crate) shutdown_tx: broadcast::Sender<()>,
    // Held to keep the broadcast channel alive; receivers are created via subscribe_shutdown().
    #[allow(dead_code)]
    shutdown_rx: broadcast::Receiver<()>,
}

/// Whether this process may write to the audit database (work/74 Phase 4,
/// go-live review B12 item 3).
///
/// Exactly one process — the daemon holding the exclusive writer lock — is
/// the `Owner`. Every other command is a `Reader`: it opens SQLite read-only,
/// runs no backfill, writes no verification checkpoints or archive
/// boundaries, and starts no retention thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditRole {
    /// This process holds the writer lock and owns the database.
    Owner,
    /// Another process owns it; this one may only read.
    Reader,
}

impl AuditRole {
    /// Whether this role may modify the audit database.
    #[must_use]
    pub const fn can_write(self) -> bool {
        matches!(self, Self::Owner)
    }
}

/// Initialization result with optional warnings.
pub struct InitResult {
    pub daemon: Daemon,
    pub warnings: Vec<String>,
}

/// How long a starting daemon waits for a shutting-down predecessor to
/// release the audit writer lock. A restarting predecessor releases its port
/// early in shutdown but holds the lock until process exit (after connection
/// drain and the final audit sync flush), so the successor routinely starts
/// inside that window.
const DAEMON_WRITER_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// How [`Daemon::start_with`] treats the exclusive audit-writer lock.
#[derive(Debug, Clone, Copy, Default)]
pub struct StartOptions {
    /// When set, this process intends to be the serving daemon: writer-lock
    /// acquisition is retried for up to this long, and startup FAILS instead
    /// of degrading to a read-only [`AuditRole::Reader`] if the lock never
    /// frees. A serving daemon that cannot write audit records breaks every
    /// session it admits, so it has no working state to degrade to.
    ///
    /// `None` (the default) keeps CLI-command behaviour: one non-blocking
    /// attempt, degrading to Reader immediately.
    pub own_audit_within: Option<std::time::Duration>,
}

impl StartOptions {
    /// Options for the process that will serve as the grith daemon,
    /// admitting supervised sessions over IPC.
    #[must_use]
    pub fn serving_daemon() -> Self {
        Self {
            own_audit_within: Some(DAEMON_WRITER_LOCK_WAIT),
        }
    }
}

impl Daemon {
    /// Initialize all subsystems in dependency order.
    pub fn start(mut config: GrithConfig, options: StartOptions) -> Result<InitResult, Error> {
        let mut warnings = Vec::new();

        tracing::info!("initializing subsystems");

        // 0. License check -- plan tier is always derived from the signed license status.
        // The daemon's background `spawn_license_revalidation()` task is the
        // single place that contacts grith.ai for refresh; startup just reads
        // the cached signed licence so init stays fast and offline-tolerant.
        let license_status = crate::license::load_license(&crate::license::license_path());

        let derived_tier = crate::license::plan_tier_from_status(&license_status);
        config.general.plan_tier = derived_tier.to_string();
        match &license_status {
            crate::license::LicenseStatus::Valid(lic) => {
                tracing::info!(
                    plan = %lic.plan,
                    expires = %lic.valid_until.format("%Y-%m-%d"),
                    "pro license active"
                );
            }
            crate::license::LicenseStatus::GracePeriod { expired_days, .. } => {
                tracing::warn!(
                    expired_days,
                    "license expired -- grace period active, run `grith pro refresh`"
                );
            }
            crate::license::LicenseStatus::ExtendedGrace { expired_days, .. } => {
                let renew_url = format!("{}/dashboard/settings", crate::license::web_base_url());
                tracing::warn!(
                    expired_days,
                    %renew_url,
                    "license expired -- extended grace window, renew in dashboard"
                );
            }
            crate::license::LicenseStatus::Expired => {
                tracing::warn!(
                    "license expired beyond grace window, falling back to community tier"
                );
            }
            crate::license::LicenseStatus::Invalid(reason) => {
                tracing::warn!(
                    reason,
                    "invalid license file, falling back to community tier"
                );
            }
            crate::license::LicenseStatus::NotFound => {
                tracing::debug!("no license file found, using community tier");
            }
        }
        let initial_feature_gate = crate::license::feature_gate_from_status(&license_status);
        let account_id = resolve_account_id(&license_status);

        // Build initial refresh state, seeded from credentials' last_validated.
        let mut initial_refresh_state = crate::license::RefreshState::default();
        if let Ok(Some(creds)) = crate::license::load_credentials() {
            if !creds.last_validated.is_empty() {
                initial_refresh_state.last_success = Some(creds.last_validated.clone());
            }
        }
        if let crate::license::LicenseStatus::Valid(ref lic)
        | crate::license::LicenseStatus::GracePeriod {
            license: ref lic, ..
        }
        | crate::license::LicenseStatus::ExtendedGrace {
            license: ref lic, ..
        } = license_status
        {
            initial_refresh_state.air_gapped = lic.air_gapped;
            if lic.air_gapped {
                tracing::info!(
                    license_id = %lic.license_id,
                    "air-gapped licence active — scheduled refresh disabled"
                );
            }
        }

        // Extract license renewal date for API responses.
        let license_valid_until = match &license_status {
            crate::license::LicenseStatus::Valid(lic)
            | crate::license::LicenseStatus::GracePeriod { license: lic, .. }
            | crate::license::LicenseStatus::ExtendedGrace { license: lic, .. } => {
                Some(lic.valid_until.format("%Y-%m-%d").to_string())
            }
            _ => None,
        };
        let billing_portal_url = crate::license::billing_portal_url_from_status(&license_status);

        // 1. Resolve paths
        let audit_dir = expand_path(&config.general.audit_dir);

        // 2. Create directories
        if let Err(e) = std::fs::create_dir_all(&audit_dir) {
            warnings.push(format!(
                "could not create audit dir {}: {e}",
                audit_dir.display()
            ));
        }

        // 3 & 4. Open audit and digest databases in parallel — both are
        // independent SQLite files so there is no ordering constraint.
        let audit_db_path = audit_dir.join("audit.db");
        let digest_db_path = audit_dir.join("digest.db");

        // work/74 Phase 4: exactly one process may write the audit database.
        // Whoever takes the exclusive lock is the owner; everyone else opens
        // read-only and skips backfill, verification writes and retention.
        // Concurrent writers are what forked the chain, and a second process
        // pruning and checkpointing the same file is a hazard no amount of
        // per-insert care removes.
        //
        // A process that intends to BE the daemon (`own_audit_within` set)
        // waits out a restart handover — the predecessor holds the lock until
        // process exit, well after it releases the port — and refuses to
        // start if the lock never frees, rather than serving as a Reader that
        // fails every audit write it is asked to perform.
        let lock_outcome = match options.own_audit_within {
            Some(wait) => grith_audit::writer_lock::acquire_with_wait(&audit_dir, wait),
            None => grith_audit::writer_lock::try_acquire(&audit_dir),
        };
        let (audit_role, audit_writer_lock) = match lock_outcome {
            Ok(grith_audit::writer_lock::LockOutcome::Acquired(lock)) => {
                (AuditRole::Owner, Some(lock))
            }
            Ok(grith_audit::writer_lock::LockOutcome::HeldByAnother) => {
                if let Some(wait) = options.own_audit_within {
                    let holder = grith_audit::writer_lock::holder_hint(&audit_dir);
                    tracing::error!(
                        event = "audit_writer_lock_timeout",
                        waited_secs = wait.as_secs_f32(),
                        holder = holder.as_deref().unwrap_or("unknown"),
                        "another process still owns the audit database; \
                         refusing to start a daemon that cannot record sessions"
                    );
                    let holder_note = holder
                        .map(|h| format!(" The lock is held by {h}."))
                        .unwrap_or_default();
                    return Err(Error::Config(format!(
                        "another process still owned the audit database after \
                         {:.0}s, and a daemon that cannot record sessions must \
                         not serve.{holder_note} If a previous daemon is still \
                         shutting down, retry in a few seconds; otherwise stop \
                         the holding process and retry.",
                        wait.as_secs_f32()
                    )));
                }
                // Normal steady state for a CLI command while the background
                // daemon owns the database — not worth a user-visible warning.
                tracing::debug!(
                    event = "audit_writer_lock_held_elsewhere",
                    "another process owns the audit database; opening read-only"
                );
                (AuditRole::Reader, None)
            }
            Err(e) => {
                if options.own_audit_within.is_some() {
                    tracing::error!(
                        event = "audit_writer_lock_unusable",
                        error = %e,
                        "audit writer lock file is unusable; refusing to start \
                         a daemon that cannot prove audit ownership"
                    );
                    return Err(Error::Config(format!(
                        "could not acquire the audit writer lock ({e}), and a \
                         daemon that cannot prove exclusive ownership of the \
                         audit database must not serve"
                    )));
                }
                // The lock file itself is unusable. Degrade to read-only:
                // assuming ownership we could not prove is how two writers
                // happen.
                warnings.push(format!(
                    "could not acquire the audit writer lock ({e}); \
                     opening the audit database read-only"
                ));
                (AuditRole::Reader, None)
            }
        };

        let (audit_result, digest_result) = std::thread::scope(|s| {
            let t_audit = s.spawn(|| match audit_role {
                AuditRole::Owner => AuditStorage::open(&audit_db_path),
                // B12 #78: a Reader must NEVER open read-write. On a fresh
                // machine with no daemon, `try_acquire` succeeds and this
                // process is the Owner — so the only way to reach here as a
                // Reader is that another process already holds the writer lock
                // (or the lock file itself was unusable). Opening read-write in
                // that state — which the previous `AuditRole::Reader =>
                // AuditStorage::open(..)` fallback did whenever the database
                // did not yet exist — creates a second writer against the very
                // chain this lock exists to keep single-writer, and would
                // bring a competing database into existence during the window
                // before the owner has created its own. Open read-only; a
                // missing database then fails closed rather than being created
                // by a non-owner.
                AuditRole::Reader => AuditStorage::open_read_only(&audit_db_path),
            });
            let t_digest = s.spawn(|| DigestQueue::open(&digest_db_path));
            (
                t_audit.join().expect("audit open thread panicked"),
                t_digest.join().expect("digest open thread panicked"),
            )
        });

        let audit_storage =
            Arc::new(Mutex::new(audit_result.map_err(|e| {
                Error::Config(format!("failed to open audit database: {e}"))
            })?));
        let digest_queue = Arc::new(
            digest_result
                .map_err(|e| Error::Config(format!("failed to open digest database: {e}")))?,
        );

        // Backfill legacy unchained rows, then VERIFY the chain.
        //
        // work/74 Phase 5: startup must never rewrite audit hashes. It used to
        // call `repair_chain()` on any `Broken` result, which renumbered
        // records and nulled the link to archived history — destroying the
        // evidence it was reacting to. Worse, the break it reacted to was
        // usually false: verification assumed the active DB begins at
        // sequence 1, which stops being true after the first retention
        // archive (§9).
        //
        // The state machine is now:
        //   Valid / Empty  -> ready
        //   Unanchored     -> re-derive the boundary from cold archives; ready
        //                     if it links, quarantine if it cannot be resolved
        //   AnchorMismatch -> quarantine (genuine discontinuity)
        //   Broken         -> quarantine (genuine tampering/corruption)
        // Quarantine preserves every byte and requires explicit operator
        // recovery; it never rewrites.
        // Only the owner verifies. Backfill and `incremental_verify_chain`
        // both WRITE (chained hashes, verification checkpoints), and
        // `resolve_chain_status` can persist an archive boundary — none of
        // which a read-only process may do. A reader inherits the owner's
        // conclusion instead: the daemon that owns the chain is the one that
        // gates admission on it (work/74 Phase 4).
        let chain_status = if !audit_role.can_write() {
            tracing::debug!(
                event = "audit_verification_skipped_reader",
                "not the audit owner; skipping chain verification and backfill"
            );
            ChainStatus::Ready
        } else {
            let storage = Arc::clone(&audit_storage);
            let cold_dir = audit_dir.join("cold");
            let verify_result: Result<(usize, ChainStatus), String> = std::thread::scope(|scope| {
                let worker = scope.spawn(move || match storage.lock() {
                    Ok(s) => {
                        let backfilled = s
                            .backfill_chain_for_legacy_rows()
                            .map_err(|e| format!("backfill: {e}"))?;
                        let verification = s
                            .incremental_verify_chain()
                            .map_err(|e| format!("verify: {e}"))?;
                        let status = resolve_chain_status(&s, &verification, &cold_dir);
                        Ok((backfilled, status))
                    }
                    Err(_) => Err("audit storage lock poisoned".to_string()),
                });

                // Spinner while the (bounded) verification walk runs.
                let frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
                let mut i = 0;
                while !worker.is_finished() {
                    eprint!("\r  {} Verifying audit chain...", frames[i % frames.len()]);
                    i += 1;
                    std::thread::sleep(std::time::Duration::from_millis(80));
                }
                if i > 0 {
                    eprint!("\r{}\r", " ".repeat(40));
                }

                worker
                    .join()
                    .expect("audit chain verification thread panicked")
            });

            match verify_result {
                Ok((backfilled, status)) => {
                    if backfilled > 0 {
                        tracing::info!(count = backfilled, "backfilled legacy audit chain rows");
                    }
                    match &status {
                        ChainStatus::Ready => {}
                        ChainStatus::Recovered { boundary_sequence } => {
                            tracing::info!(
                                event = "audit_boundary_recovered",
                                boundary_sequence,
                                "re-derived the archive boundary from cold storage; \
                                 no records were modified"
                            );
                        }
                        ChainStatus::SegmentDiscontinuity {
                            archive_terminal_sequence,
                            active_genesis_sequence,
                        } => {
                            warnings.push(format!(
                                "audit history spans two segments: archived records end at \
                                 {archive_terminal_sequence} and the active database restarts \
                                 at {active_genesis_sequence}. Both are preserved and verify \
                                 independently. Run `grith audit diagnose` for detail."
                            ));
                            tracing::warn!(
                                event = "audit_segment_discontinuity",
                                archive_terminal_sequence,
                                active_genesis_sequence,
                                "audit history is not one continuous chain"
                            );
                        }
                        ChainStatus::Quarantined { reason } => {
                            warnings.push(format!(
                                "audit chain quarantined: {reason}. Records are preserved \
                                 unmodified. Run `grith audit diagnose` to inspect."
                            ));
                            tracing::error!(
                                event = "audit_chain_quarantined",
                                reason = %reason,
                                "audit chain failed verification — writes quarantined, \
                                 nothing rewritten"
                            );
                        }
                    }
                    status
                }
                Err(e) => {
                    // We could not establish integrity either way. Fail closed:
                    // an unverifiable audit log is not a usable one.
                    warnings.push(format!("audit chain verification failed: {e}"));
                    tracing::error!(error = %e, "audit chain verification failed");
                    ChainStatus::Quarantined {
                        reason: format!("verification error: {e}"),
                    }
                }
            }
        };

        tracing::info!(path = %audit_db_path.display(), "audit storage initialized");
        tracing::info!(path = %digest_db_path.display(), "digest queue initialized");

        // Audit retention thread — prunes the active DB to `retain_full_days`
        // and writes archives to `<audit_dir>/cold/`. Runs once on startup,
        // then every `prune_interval_hours`. retain_full_days = 0 disables.
        // Plain std::thread so this works whether or not the caller has a
        // tokio runtime at Daemon::start time (main constructs one after).
        //
        // Owner only (work/74 Phase 4). Every non-thin command used to spawn
        // its own retention thread, so several processes could prune, archive
        // and checkpoint the same database concurrently.
        if config.audit.retain_full_days > 0 && audit_role.can_write() {
            let storage = Arc::clone(&audit_storage);
            let cold_dir = audit_dir.join("cold");
            let retain_days = config.audit.retain_full_days;
            let cold_enabled = config.audit.cold_storage_enabled;
            let interval_hours = config.audit.prune_interval_hours;
            // When cloud sync is on, retention must not delete rows the
            // server hasn't acknowledged. See audit-completeness-scaling.md
            // Stage 2 — sync-safe guard.
            //
            // H-19: the guard must track whether sync can *actually happen*,
            // not merely whether it is configured. `audit_sync` defaults to
            // true, so a logged-out user had the guard on while nothing ever
            // acknowledged a row; retention then found no synced prefix and
            // returned early on every pass, forever. Local retention was
            // silently disabled on exactly the installs with no cloud
            // component — which is how the active database reached ~1.4 GiB.
            //
            // Sync only transmits with credentials (see
            // `background::flush_audit_batch`), so no credentials means no
            // acknowledgement is coming and there is nothing to protect.
            let audit_sync = config.general.audit_sync;
            // One-time startup note reflecting the state at boot. The loop
            // below re-evaluates credentials every pass (B12 #73), so a later
            // login or logout re-arms or relaxes the guard without a restart.
            if audit_sync && !has_sync_credentials() {
                tracing::info!(
                    "audit sync is enabled but no account is signed in; retention will \
                     prune on age alone until an account signs in"
                );
            }
            std::thread::Builder::new()
                .name("grith-audit-retention".into())
                .spawn(move || loop {
                    let Some(cutoff) = grith_audit::retention::cutoff_for_retention(retain_days)
                    else {
                        return;
                    };
                    // B12 #73: recompute the sync guard on every pass.
                    // `has_sync_credentials()` reads the on-disk credential
                    // state, which changes when the user logs in or out during
                    // the daemon's lifetime. Freezing it at startup meant a
                    // user who signed in after boot kept pruning on age alone —
                    // deleting rows the server had not yet acknowledged — while
                    // a user who signed out kept the guard on and stalled
                    // retention (the unbounded-growth mode H-19 addressed).
                    let respect_sync_state = audit_sync && has_sync_credentials();
                    let outcome = match storage.lock() {
                        Ok(mut s) => grith_audit::retention::prune_and_archive(
                            &mut s,
                            cutoff,
                            &cold_dir,
                            cold_enabled,
                            respect_sync_state,
                        )
                        .map_err(|e| e.to_string()),
                        Err(_) => Err("audit storage lock poisoned".to_string()),
                    };
                    match outcome {
                        Ok(stats) if stats.archived_rows > 0 => {
                            tracing::info!(
                                rows = stats.archived_rows,
                                files = stats.archive_files,
                                max_seq = stats.max_pruned_sequence,
                                "audit retention: pruned + archived"
                            );
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "audit retention failed"),
                    }

                    // H-19: bound the physical footprint on the same
                    // schedule that bounds row count, and report it so
                    // unbounded growth is visible before it becomes an
                    // incident. Checkpointing can lose a race with an
                    // active reader; that is benign — the next pass
                    // retries.
                    if let Ok(s) = storage.lock() {
                        if let Err(e) = s.checkpoint_wal() {
                            tracing::debug!(error = %e, "audit WAL checkpoint deferred");
                        }
                        match s.footprint() {
                            Ok(f) => tracing::info!(
                                live_bytes = f.live_bytes,
                                free_bytes = f.free_bytes,
                                db_file_bytes = f.db_file_bytes,
                                wal_file_bytes = f.wal_file_bytes,
                                "audit storage footprint"
                            ),
                            Err(e) => {
                                tracing::debug!(error = %e, "could not measure audit footprint");
                            }
                        }
                    }
                    if interval_hours == 0 {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_secs(
                        interval_hours.saturating_mul(3600),
                    ));
                })
                .map_err(|e| Error::Config(format!("failed to spawn retention thread: {e}")))?;
        }

        // 5. Initialize security proxy
        let (registry, containment_tracker, canary_registry, dlp_redactor) =
            build_filter_registry_with_config_result(&config.proxy)?;
        let scoring = ScoringConfig {
            auto_allow_threshold: config.proxy.auto_allow_threshold,
            auto_deny_threshold: config.proxy.auto_deny_threshold,
        };
        let meta_rules = build_meta_rule_engine_result()?;
        let filter_count = registry.count();
        let proxy = Arc::new(SecurityProxy::new(registry, scoring, meta_rules));
        tracing::info!(
            allow = config.proxy.auto_allow_threshold,
            deny = config.proxy.auto_deny_threshold,
            filters = filter_count,
            "security proxy initialized"
        );

        // 6. Initialize supervisor registry
        let supervisor_config = to_supervisor_config(&config.supervisor);
        if config.supervisor.enabled {
            if let Err(msg) = supervisor_config.validate() {
                return Err(Error::Config(format!(
                    "supervisor config validation: {msg}"
                )));
            }
        }
        let mut registry_inner = SupervisorRegistry::new(supervisor_config);
        let license_max = initial_feature_gate.max_sessions();
        let config_max = config.supervisor.max_concurrent_sessions;
        let effective_max = config_max.min(license_max);
        registry_inner.set_max_sessions(effective_max);
        // A Reader process cannot write audit records, so admitting a
        // supervised session would break every recording path mid-session —
        // worst of all the required DNS audit records, whose failure denies
        // the session's DNS fail-closed. Refuse admission up front, exactly
        // like the quarantine gate below. (With `StartOptions::serving_daemon`
        // a Reader daemon fails startup before reaching here; this gate
        // covers every other process that serves sessions from this
        // registry, such as the in-process server fallback.)
        if !audit_role.can_write() {
            registry_inner.set_audit_read_only(Some(
                "another grith process owns the audit database, so this one \
                 cannot record supervised sessions"
                    .to_string(),
            ));
        }
        // work/74 Phase 5: a quarantined audit chain must refuse session
        // admission. Both admission paths funnel through
        // `SupervisorRegistry::register`, so setting it here covers the
        // in-process path and the daemon IPC route alike.
        if let ChainStatus::Quarantined { reason } = &chain_status {
            registry_inner.set_audit_quarantine(Some(reason.clone()));
            // B-CORE-1: the registry gate above refuses new supervised-session
            // admission, but the built-in-agent (`grith run`/REPL) and the daemon
            // IPC ingest route write records directly through this shared
            // `AuditStorage` with no admission step — a quarantined chain would
            // otherwise keep accepting their appends onto broken evidence. All
            // three writers hold clones of this same Arc, so arming the storage
            // flag here (after startup verification/recovery writes have already
            // run) gates every ingest path in one place.
            if let Ok(mut storage) = audit_storage.lock() {
                storage.set_quarantined(Some(reason.clone()));
            }
        }
        let supervisor_registry = Arc::new(Mutex::new(registry_inner));
        if config.supervisor.enabled {
            tracing::info!(
                max_sessions = effective_max,
                config_max,
                license_max,
                profile = %config.supervisor.default_profile,
                "supervisor subsystem initialized"
            );
        } else {
            tracing::info!("supervisor subsystem disabled");
        }

        // 7. Correlation tracker for source->sink evidence chaining
        let correlation_tracker = Arc::new(AuditCorrelationTracker::with_defaults());

        // 8. Initialize notification dispatcher
        let notification_dispatcher = {
            use grith_digest::notification::CallbackNonceStore;
            use grith_notify::{ChannelRegistry, RoutingEngine};

            let plan_tier = initial_feature_gate.tier;
            let nonce_store = Arc::new(CallbackNonceStore::new(std::time::Duration::from_secs(
                config.proxy.review_timeout_seconds,
            )));

            let routing = if config.notifications.routing.severity_routes.is_empty() {
                RoutingEngine::default()
            } else {
                RoutingEngine::from_config(
                    config.notifications.routing.severity_routes.clone(),
                    config.notifications.routing.escalation_channels.clone(),
                    // Normalised so pre-rename snake_case override keys
                    // (e.g. "dlp_gate") keep routing against live kebab-case
                    // filter names.
                    config.notifications.routing.canonical_filter_overrides(),
                )
            };

            let mut rate_limiter = grith_notify::rate_limiter::RateLimiter::new(
                config.notifications.rate_limits.max_per_window,
                std::time::Duration::from_secs(config.notifications.rate_limits.window_seconds),
            );
            if config.notifications.rate_limits.quiet_hours_start != 0
                || config.notifications.rate_limits.quiet_hours_end != 0
            {
                rate_limiter.set_quiet_hours(
                    config.notifications.rate_limits.quiet_hours_start,
                    config.notifications.rate_limits.quiet_hours_end,
                );
            }

            let batcher = grith_notify::batcher::Batcher::new(
                std::time::Duration::from_secs(
                    config.notifications.escalation.batch_window_seconds,
                ),
                config.notifications.escalation.max_batch_size,
            );

            let registry = ChannelRegistry::new();
            // Note: channels are registered later when the server starts and ws_tx is available.

            let auto_escalate_timeout = std::time::Duration::from_secs(
                config
                    .notifications
                    .escalation
                    .auto_escalate_timeout_seconds,
            );
            let auto_escalate_min_severity = match config
                .notifications
                .escalation
                .auto_escalate_min_severity
                .to_lowercase()
                .as_str()
            {
                "low" => grith_digest::types::ScoreSeverity::Low,
                "medium" => grith_digest::types::ScoreSeverity::Medium,
                "critical" => grith_digest::types::ScoreSeverity::Critical,
                _ => grith_digest::types::ScoreSeverity::High,
            };

            let dispatcher = grith_notify::NotificationDispatcher::new(
                registry,
                routing,
                nonce_store,
                plan_tier,
                digest_queue.clone(),
                rate_limiter,
                batcher,
                auto_escalate_timeout,
                auto_escalate_min_severity,
            );
            Arc::new(dispatcher)
        };
        if config.notifications.enabled {
            tracing::info!("notification dispatcher initialized");
        }

        // 9. Shutdown channel
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        {
            let enabled_count = initial_feature_gate
                .feature_list()
                .iter()
                .filter(|(_, enabled)| *enabled)
                .count();
            tracing::info!(
                tier = %initial_feature_gate.tier,
                seats = initial_feature_gate.seats,
                enabled_features = enabled_count,
                max_sessions = effective_max,
                "feature gating active"
            );
        }

        let feature_gate = Arc::new(RwLock::new(initial_feature_gate));

        // Load shared reputation table from disk.
        let reputation_table = {
            let rep_path = grith_proxy::reputation::default_reputation_path();
            let table = grith_proxy::reputation::ReputationTable::load(&rep_path);
            tracing::info!(
                entries = table.len(),
                path = %rep_path.display(),
                "loaded shared reputation table"
            );
            Arc::new(Mutex::new(table))
        };

        tracing::info!("all subsystems initialized");

        let daemon = Daemon {
            chain_status,
            audit_role,
            audit_writer_lock,
            config,
            account_id,
            audit_storage,
            digest_queue,
            proxy,
            supervisor_registry,
            dlp_redactor,
            containment_tracker,
            correlation_tracker,
            canary_registry,
            notification_dispatcher,
            feature_gate,
            license_valid_until,
            billing_portal_url,
            license_status,
            refresh_state: Arc::new(RwLock::new(initial_refresh_state)),
            reputation_table,
            provider_keys_mtime: config_loader::provider_keys_dir_mtime(),
            shutdown_tx,
            shutdown_rx,
        };

        Ok(InitResult { daemon, warnings })
    }

    /// Perform a health check across all subsystems.
    pub fn health_check(&self) -> HealthReport {
        let mut subsystems = Vec::new();

        // Audit storage
        subsystems.push(SubsystemHealth {
            name: "audit".to_string(),
            status: health::check_audit_health(&self.audit_storage),
        });

        // Digest queue
        subsystems.push(SubsystemHealth {
            name: "digest".to_string(),
            status: health::check_digest_health(&self.digest_queue),
        });

        // Security proxy
        subsystems.push(SubsystemHealth {
            name: "proxy".to_string(),
            status: HealthStatus::Healthy, // proxy is in-memory, always healthy if constructed
        });

        // Supervisor
        subsystems.push(SubsystemHealth {
            name: "supervisor".to_string(),
            status: if self.config.supervisor.enabled {
                if grith_supervisor::platform::is_supported() {
                    HealthStatus::Healthy
                } else {
                    HealthStatus::Degraded("platform not supported".to_string())
                }
            } else {
                HealthStatus::Degraded("disabled in config".to_string())
            },
        });

        HealthReport { subsystems }
    }

    /// Get a receiver for the shutdown signal.
    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        tracing::info!("initiating graceful shutdown");
        let _ = self.shutdown_tx.send(());
    }

    /// Get the filter count from the proxy.
    pub fn filter_count(&self) -> usize {
        self.proxy.filter_count()
    }

    /// Create an LLM router from the current configuration.
    pub fn create_llm_router(&self) -> anyhow::Result<grith_llm::LlmRouter> {
        // Check if provider keys have been rotated since last load.
        let current_mtime = config_loader::provider_keys_dir_mtime();
        if current_mtime != self.provider_keys_mtime && current_mtime.is_some() {
            tracing::info!("provider key files updated — loading rotated keys");
        }

        let provider_name = &self.config.llm.default_provider;
        let provider: Arc<dyn grith_llm::LlmProvider> = match provider_name.as_str() {
            "ollama" => Arc::new(grith_llm::ollama::OllamaProvider::new(
                &self.config.llm.ollama.base_url,
                &self.config.llm.ollama.model,
            )?),
            "anthropic" => {
                let api_key = resolve_api_key(
                    "Anthropic",
                    self.config.llm.anthropic.api_key.as_deref(),
                    &self.config.llm.anthropic.api_key_env,
                )?;
                Arc::new(grith_llm::anthropic::AnthropicProvider::new(
                    api_key,
                    &self.config.llm.anthropic.model,
                )?)
            }
            "openai" => {
                let api_key = resolve_api_key(
                    "OpenAI",
                    self.config.llm.openai.api_key.as_deref(),
                    &self.config.llm.openai.api_key_env,
                )?;
                Arc::new(
                    grith_llm::openai_compat::OpenAiCompatProvider::new(
                        "https://api.openai.com",
                        &self.config.llm.openai.model,
                        Some(api_key),
                    )?
                    .with_name("openai"),
                )
            }
            "openrouter" => {
                let api_key = resolve_api_key(
                    "OpenRouter",
                    self.config.llm.openrouter.api_key.as_deref(),
                    &self.config.llm.openrouter.api_key_env,
                )?;
                Arc::new(
                    grith_llm::openai_compat::OpenAiCompatProvider::new(
                        "https://openrouter.ai/api",
                        &self.config.llm.openrouter.model,
                        Some(api_key),
                    )?
                    .with_name("openrouter"),
                )
            }
            other => anyhow::bail!("unsupported LLM provider: {other}"),
        };
        tracing::info!(provider = %provider_name, "LLM router created");
        Ok(grith_llm::LlmRouter::fixed(provider_name, provider))
    }

    /// Get the model name from config.
    pub fn model_name(&self) -> &str {
        match self.config.llm.default_provider.as_str() {
            "ollama" => &self.config.llm.ollama.model,
            "openai" => &self.config.llm.openai.model,
            "anthropic" => &self.config.llm.anthropic.model,
            "openrouter" => &self.config.llm.openrouter.model,
            _ => &self.config.llm.ollama.model,
        }
    }
}

/// Set up signal handlers for graceful shutdown.
///
/// PR 1 Phase E: signal receipts are logged at `warn` level with a stable
/// `event = "shutdown_signal_received"` field so the audit pipeline can
/// pick them out. Most receipts are user-initiated (Ctrl+C or `systemctl
/// stop`) but the LLM-attempt case (a supervised tool somehow signalling
/// the supervisor) is the security-interesting one — surfacing every
/// signal receipt at high severity gives the operator a clean audit trail
/// to investigate after the fact.
pub async fn wait_for_shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = ctrl_c => {
                        tracing::warn!(
                            event = "shutdown_signal_received",
                            signal = "SIGINT",
                            "supervisor received SIGINT (Ctrl+C); shutting down"
                        );
                    }
                    _ = sigterm.recv() => {
                        tracing::warn!(
                            event = "shutdown_signal_received",
                            signal = "SIGTERM",
                            "supervisor received SIGTERM; shutting down"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to register SIGTERM handler, falling back to Ctrl+C only");
                if let Err(e) = ctrl_c.await {
                    tracing::error!(error = %e, "failed to listen for Ctrl+C signal");
                } else {
                    tracing::warn!(
                        event = "shutdown_signal_received",
                        signal = "SIGINT",
                        "supervisor received SIGINT (Ctrl+C); shutting down"
                    );
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        match ctrl_c.await {
            Ok(()) => tracing::warn!(
                event = "shutdown_signal_received",
                signal = "SIGINT",
                "supervisor received Ctrl+C; shutting down"
            ),
            Err(e) => tracing::error!(error = %e, "failed to listen for Ctrl+C signal"),
        }
    }
}

fn resolve_account_id(status: &crate::license::LicenseStatus) -> String {
    let from_status = match status {
        crate::license::LicenseStatus::Valid(lic)
        | crate::license::LicenseStatus::GracePeriod { license: lic, .. }
        | crate::license::LicenseStatus::ExtendedGrace { license: lic, .. } => {
            let user_id = lic.user_id.trim();
            if user_id.is_empty() {
                None
            } else {
                Some(user_id.to_string())
            }
        }
        _ => None,
    };
    if let Some(user_id) = from_status {
        return format!("user:{user_id}");
    }

    if let Ok(Some(creds)) = crate::license::load_credentials() {
        let user_id = creds.user_id.trim();
        if !user_id.is_empty() {
            return format!("user:{user_id}");
        }
    }

    "local:community".to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// B12 item 7: a database whose active segment restarts at sequence 1
    /// while cold archives hold earlier history is classified, recorded and
    /// reported — but stays writable. Quarantining it would brick every
    /// machine that ever ran the 0.1.4 automatic repair.
    ///
    /// The archive is produced by the real retention path, and the
    /// re-genesis by dropping the boundary anchor the way that repair did,
    /// so the fixture is the incident's shape rather than a hand-built
    /// approximation of it.
    #[test]
    fn active_regenesis_with_archives_is_classified_not_quarantined() {
        let dir = tempfile::tempdir().unwrap();
        let cold = dir.path().join("cold");

        // Archive sequences 1..=3 to cold storage through the real
        // retention path.
        {
            let mut original = AuditStorage::open(dir.path().join("audit.db")).unwrap();
            for _ in 0..3 {
                original.insert_record(&sample_record()).unwrap();
            }
            let stats = grith_audit::retention::prune_and_archive(
                &mut original,
                chrono::Utc::now() + chrono::Duration::days(1),
                &cold,
                true,
                false,
            )
            .unwrap();
            assert_eq!(stats.archived_rows, 3);
        }

        // The 0.1.4 repair path left a *fresh* active database beside the
        // surviving archives, so writes begin again at sequence 1 with no
        // anchor linking them to the archived history.
        let storage = AuditStorage::open(dir.path().join("audit-new.db")).unwrap();
        storage.insert_record(&sample_record()).unwrap();
        storage.insert_record(&sample_record()).unwrap();
        assert_eq!(storage.first_chained_row().unwrap().unwrap().0, 1);

        let verification = storage.verify_chain().unwrap();
        assert!(
            matches!(verification, grith_audit::ChainVerification::Valid { .. }),
            "the active segment alone verifies — that is what makes this silent"
        );

        let status = resolve_chain_status(&storage, &verification, &cold);
        assert_eq!(
            status,
            ChainStatus::SegmentDiscontinuity {
                archive_terminal_sequence: 3,
                active_genesis_sequence: 1,
            }
        );
        assert!(
            status.is_writable(),
            "a historical discontinuity must not stop the daemon writing"
        );

        // The marker is durable, and re-classifying is idempotent.
        let stored = storage.load_segment_history().unwrap().expect("marker");
        assert_eq!(stored.archive_terminal_sequence, 3);
        assert_eq!(stored.cause, "active_regenesis_with_archives");
        assert_eq!(resolve_chain_status(&storage, &verification, &cold), status);
    }

    /// The common case must stay silent: no archives means a segment
    /// starting at 1 is simply the beginning of history.
    #[test]
    fn regenesis_classification_does_not_fire_without_archives() {
        let dir = tempfile::tempdir().unwrap();
        let storage = AuditStorage::open_in_memory().unwrap();
        storage.insert_record(&sample_record()).unwrap();

        let verification = storage.verify_chain().unwrap();
        assert_eq!(
            resolve_chain_status(&storage, &verification, dir.path()),
            ChainStatus::Ready
        );
        assert!(storage.load_segment_history().unwrap().is_none());
    }

    fn sample_record() -> grith_audit::AuditRecord {
        grith_audit::AuditRecord::new(
            uuid::Uuid::new_v4(),
            "test".into(),
            "FileRead".into(),
            &serde_json::json!({"path": "/tmp/x"}),
            1.0,
            grith_audit::ProxyActionSummary::Allow,
            vec![],
            0.5,
            None,
        )
    }

    #[test]
    fn test_daemon_start() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = GrithConfig::default();
        config.supervisor.default_profile = "generic".to_string();
        config.general.audit_dir = dir.path().join("audit").to_string_lossy().to_string();

        let result = Daemon::start(config, StartOptions::default()).unwrap();
        assert!(result.warnings.is_empty());

        let health = result.daemon.health_check();
        let audit_health = health
            .subsystems
            .iter()
            .find(|s| s.name == "audit")
            .unwrap();
        assert_eq!(audit_health.status, HealthStatus::Healthy);
    }

    /// A serving daemon must not degrade to a Reader: when another process
    /// still owns the writer lock at the end of the wait, startup fails
    /// instead of coming up unable to record sessions.
    #[test]
    fn serving_daemon_fails_startup_when_the_writer_lock_never_frees() {
        let dir = tempfile::tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        let _held = match grith_audit::writer_lock::try_acquire(&audit_dir).unwrap() {
            grith_audit::writer_lock::LockOutcome::Acquired(lock) => lock,
            grith_audit::writer_lock::LockOutcome::HeldByAnother => {
                panic!("uncontended lock must be acquired")
            }
        };

        let mut config = GrithConfig::default();
        config.supervisor.default_profile = "generic".to_string();
        config.general.audit_dir = audit_dir.to_string_lossy().to_string();

        let Err(err) = Daemon::start(
            config,
            StartOptions {
                own_audit_within: Some(std::time::Duration::from_millis(300)),
            },
        ) else {
            panic!("a daemon that cannot own the audit database must not start");
        };
        assert!(
            err.to_string().contains("audit database"),
            "unexpected error: {err}"
        );
    }

    /// The restart handover: the predecessor releases the lock while the
    /// successor is waiting, and the successor becomes the owner.
    #[test]
    fn serving_daemon_acquires_the_lock_released_mid_wait() {
        let dir = tempfile::tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        let held = match grith_audit::writer_lock::try_acquire(&audit_dir).unwrap() {
            grith_audit::writer_lock::LockOutcome::Acquired(lock) => lock,
            grith_audit::writer_lock::LockOutcome::HeldByAnother => {
                panic!("uncontended lock must be acquired")
            }
        };
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(400));
            drop(held);
        });

        let mut config = GrithConfig::default();
        config.supervisor.default_profile = "generic".to_string();
        config.general.audit_dir = audit_dir.to_string_lossy().to_string();

        let result = Daemon::start(
            config,
            StartOptions {
                own_audit_within: Some(std::time::Duration::from_secs(10)),
            },
        )
        .expect("the successor must acquire the lock the predecessor released");
        releaser.join().unwrap();
        assert_eq!(result.daemon.audit_role, AuditRole::Owner);
    }

    /// A CLI process (default options) still degrades to a Reader — and that
    /// Reader refuses supervised-session admission, because it could not
    /// record the session it admitted.
    #[test]
    fn reader_process_refuses_session_admission() {
        let dir = tempfile::tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        // The owner must have created the database first; a Reader never does.
        drop(grith_audit::AuditStorage::open(audit_dir.join("audit.db")).unwrap());
        let _held = match grith_audit::writer_lock::try_acquire(&audit_dir).unwrap() {
            grith_audit::writer_lock::LockOutcome::Acquired(lock) => lock,
            grith_audit::writer_lock::LockOutcome::HeldByAnother => {
                panic!("uncontended lock must be acquired")
            }
        };

        let mut config = GrithConfig::default();
        config.supervisor.default_profile = "generic".to_string();
        config.general.audit_dir = audit_dir.to_string_lossy().to_string();

        let result = Daemon::start(config, StartOptions::default()).unwrap();
        assert_eq!(result.daemon.audit_role, AuditRole::Reader);

        let mut registry = result.daemon.supervisor_registry.lock().unwrap();
        match registry.reserve("claude", None).unwrap_err() {
            grith_supervisor::Error::AuditReadOnly(reason) => {
                assert!(reason.contains("owns the audit database"));
            }
            other => panic!("expected AuditReadOnly, got: {other}"),
        }
    }

    #[test]
    fn test_daemon_model_name() {
        let mut config = GrithConfig::default();
        config.supervisor.default_profile = "generic".to_string();
        config.llm.default_provider = "ollama".to_string();
        config.llm.ollama.model = "llama3.1:8b".to_string();

        let dir = tempfile::tempdir().unwrap();
        config.general.audit_dir = dir.path().join("audit").to_string_lossy().to_string();

        let result = Daemon::start(config, StartOptions::default()).unwrap();
        assert_eq!(result.daemon.model_name(), "llama3.1:8b");
    }

    #[test]
    fn test_daemon_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = GrithConfig::default();
        config.supervisor.default_profile = "generic".to_string();
        config.general.audit_dir = dir.path().join("audit").to_string_lossy().to_string();

        let result = Daemon::start(config, StartOptions::default()).unwrap();
        let mut rx = result.daemon.subscribe_shutdown();

        result.daemon.shutdown();
        // The receiver should get the signal
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn test_daemon_filter_count() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = GrithConfig::default();
        config.supervisor.default_profile = "generic".to_string();
        config.general.audit_dir = dir.path().join("audit").to_string_lossy().to_string();

        let result = Daemon::start(config, StartOptions::default()).unwrap();
        // Default proxy has the built-in filters
        let count = result.daemon.filter_count();
        assert!(
            count >= 6,
            "expected default proxy to register filters, got {count}"
        );
    }

    #[test]
    fn test_daemon_ignores_config_plan_tier_override_and_uses_license_tier() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = GrithConfig::default();
        config.supervisor.default_profile = "generic".to_string();
        config.general.audit_dir = dir.path().join("audit").to_string_lossy().to_string();
        config.general.plan_tier = "enterprise".to_string();

        let status = crate::license::load_license(&crate::license::license_path());
        let expected_tier = crate::license::plan_tier_from_status(&status).to_string();

        let result = Daemon::start(config, StartOptions::default()).unwrap();
        assert_eq!(result.daemon.config.general.plan_tier, expected_tier);

        let gate = result.daemon.feature_gate.read().unwrap();
        let expected_gate_tier = match result.daemon.config.general.plan_tier.as_str() {
            "enterprise" => crate::license::PlanTier::Enterprise,
            "pro" => crate::license::PlanTier::Pro,
            _ => crate::license::PlanTier::Community,
        };
        assert_eq!(gate.tier, expected_gate_tier);
    }
}
