// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! REST and WebSocket handlers for supervisor session management.
//!
//! Provides endpoints for listing, inspecting, creating, and terminating
//! supervised CLI tool sessions, as well as a per-session WebSocket stream
//! for live syscall interception events.

use crate::AppState;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use grith_supervisor::process_tree::ProcessTree;
use grith_supervisor::supervisor::{run_supervisor_loop, SupervisorSession};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[cfg(unix)]
struct ServerPtyKeepAlive {
    _forwarder: grith_supervisor::pty::PtyForwarder,
    _stdin_writer: Box<dyn std::io::Write + Send>,
}

#[cfg(not(unix))]
struct ServerPtyKeepAlive;

/// Build the supervisor sub-router, nested under `/api/supervisor`.
pub fn supervisor_router() -> Router<AppState> {
    Router::new()
        .route("/sessions", get(list_sessions))
        .route("/sessions", post(create_session))
        .route("/sessions/:id", get(get_session))
        .route("/sessions/:id/kill", post(kill_session))
        .route("/sessions/:id", delete(terminate_session))
}

/// Build the supervisor WebSocket router, merged at the top level.
pub fn supervisor_ws_router() -> Router<AppState> {
    Router::new().route("/ws/supervisor/:id", get(ws_session_handler))
}

// ---------------------------------------------------------------------------
// JSON response / request types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ApiError {
    error: String,
    code: String,
}

fn api_error(
    status: StatusCode,
    message: impl Into<String>,
    code: impl Into<String>,
) -> impl IntoResponse {
    (
        status,
        Json(ApiError {
            error: message.into(),
            code: code.into(),
        }),
    )
}

#[derive(Deserialize)]
struct CreateSessionRequest {
    /// The name of the tool to supervise (e.g. "claude-code", "codex", "aider").
    tool_name: String,
    /// Attach to this PID. Required unless `command` is provided.
    #[serde(default)]
    root_pid: Option<u32>,
    /// Optional command to spawn under supervision. If present, this is used
    /// when `root_pid` is omitted.
    #[serde(default)]
    command: Vec<String>,
    /// Extra environment variables passed to `spawn_supervised`.
    #[serde(default)]
    environment: Vec<(String, String)>,
    /// Whether to start the interception loop immediately.
    #[serde(default = "default_true")]
    start_interception: bool,
}

#[derive(Serialize)]
struct CreateSessionResponse {
    id: String,
    tool_name: String,
    root_pid: u32,
    interception_started: bool,
}

#[derive(Serialize)]
struct SessionDetailResponse {
    id: String,
    tool_name: String,
    root_pid: u32,
    uptime_seconds: u64,
    process_tree_pids: Vec<u32>,
    stats: grith_supervisor::supervisor::SessionStats,
    #[serde(skip_serializing_if = "Option::is_none")]
    containment_remaining_seconds: Option<u64>,
}

#[derive(Serialize)]
struct TerminateSessionResponse {
    id: String,
    status: String,
    tool_name: String,
    final_stats: grith_supervisor::supervisor::SessionStats,
    interception_stopped: bool,
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn session_registry_view(session: &SupervisorSession) -> SupervisorSession {
    SupervisorSession {
        id: session.id,
        tool_name: session.tool_name.clone(),
        profile_name: session.profile_name.clone(),
        policy_scope: session.policy_scope.clone(),
        launcher_overlay_name: session.launcher_overlay_name.clone(),
        provider_overlay_name: session.provider_overlay_name.clone(),
        root_pid: session.root_pid,
        process_tree: ProcessTree::new(session.root_pid, &session.tool_name),
        started_at: session.started_at,
        last_synced_at: session.last_synced_at,
        last_activity_at: session.last_activity_at,
        stats: session.stats.clone(),
        project_name: session.project_name.clone(),
        cwd: session.cwd.clone(),
        tty: session.tty.clone(),
        wedge_reported_tids: std::collections::HashSet::new(),
        spawn_recorded: std::collections::HashSet::new(),
        controlling_pts: std::sync::OnceLock::new(),
        recent_denials: std::collections::HashMap::new(),
        recent_approvals: std::collections::HashMap::new(),
    }
}

async fn launch_supervisor_task(
    state: AppState,
    mut interceptor: Box<dyn grith_supervisor::interceptor::SyscallInterceptor>,
    mut session: SupervisorSession,
    config: grith_supervisor::config::SupervisorConfig,
    pty_keepalive: Option<ServerPtyKeepAlive>,
) -> bool {
    let (stop_tx, stop_rx) = tokio::sync::broadcast::channel(1);
    {
        let mut tasks = state.supervisor_tasks.lock().await;
        tasks.insert(session.id, stop_tx);
    }

    let session_id = session.id;
    let proxy = state.proxy.clone();
    let registry = state.supervisor_registry.clone();
    let tasks = state.supervisor_tasks.clone();
    let event_tx = Some(state.ws_tx.clone());

    tokio::spawn(async move {
        // Keep PTY resources alive for the entire supervised session when
        // PTY forwarding is enabled.
        let _pty_keepalive = pty_keepalive;

        let dlp_redactor = grith_proxy::filters::dlp_gate::DlpRedactor::with_defaults();
        let audit_sink: Arc<dyn grith_supervisor::AuditSink> = Arc::new(
            grith_supervisor::StorageAuditSink::new(state.audit_storage.clone()),
        );
        let digest_store: Arc<dyn grith_supervisor::DigestStore> = Arc::new(
            grith_supervisor::LocalDigestStore::new(state.digest_queue.clone()),
        );
        let session_sync: Arc<dyn grith_supervisor::SessionSync> = Arc::new(
            grith_supervisor::RegistrySessionSync::new(state.supervisor_registry.clone()),
        );

        if let Err(e) = refresh_team_learned_rules_cache(&state).await {
            tracing::warn!(
                session_id = %session_id,
                error = %e,
                "failed to refresh team learned-rules cache, falling back to cached copy"
            );
        }

        // Build session allowlist from the TOML profile. Dashboard sessions
        // must go through the same profile-driven allowlist as CLI sessions —
        // there is no hardcoded fallback.
        let session_allowed = {
            let profile_name = session.profile_name.as_deref().unwrap_or("generic");
            let config = match grith_supervisor::profiles::SupervisorProfile::load_config() {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "supervisor profiles config unavailable — session cannot start"
                    );
                    let mut task_map = tasks.lock().await;
                    task_map.remove(&session_id);
                    return;
                }
            };
            match config.build_effective_policy(
                profile_name,
                session.launcher_overlay_name.as_deref(),
                session.provider_overlay_name.as_deref(),
            ) {
                Ok(policy) => {
                    let scope = session.scope_name().unwrap_or(policy.scope_key.as_str());
                    let mut allowlist = policy.merged_profile.build_session_allowlist();
                    let (local_count, team_count) =
                        grith_supervisor::learned_rules::merge_default_cached_rules_for_profile(
                            &mut allowlist,
                            scope,
                        );
                    if local_count > 0 {
                        tracing::info!(
                            session_id = %session_id,
                            count = local_count,
                            scope,
                            "loaded persistent learned rules into dashboard session allowlist"
                        );
                    }
                    if team_count > 0 {
                        tracing::info!(
                            session_id = %session_id,
                            count = team_count,
                            scope,
                            "loaded team learned rules into dashboard session allowlist"
                        );
                    }
                    allowlist
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        profile = profile_name,
                        "failed to resolve effective policy — session cannot start without a valid TOML policy"
                    );
                    let mut task_map = tasks.lock().await;
                    task_map.remove(&session_id);
                    return;
                }
            }
        };

        let run_result = run_supervisor_loop(
            &mut interceptor,
            &mut session,
            proxy,
            audit_sink,
            digest_store,
            &dlp_redactor,
            state.correlation_tracker.clone(),
            state.containment_tracker.clone(),
            &config,
            stop_rx,
            event_tx,
            None, // Dashboard sessions use polling (reviews via HTTP API)
            Some(session_sync),
            &state.dns_seed_domains,
            session_allowed,
            Some(state.reputation_table.clone()),
            None, // Dashboard sessions use in-process proxy (they ARE the daemon)
            None,
            None,
            None, // Dashboard sessions ARE the daemon; SessionStateRegistry is shared in-process
        )
        .await;

        if let Err(e) = run_result {
            tracing::warn!(session_id = %session_id, error = %e, "supervisor loop exited with error");
        }

        match registry.lock() {
            Ok(mut reg) => {
                reg.remove(&session_id);
            }
            Err(e) => {
                tracing::error!(session_id = %session_id, error = %e, "supervisor registry mutex poisoned during cleanup");
            }
        }

        let mut task_map = tasks.lock().await;
        task_map.remove(&session_id);
    });

    true
}

async fn refresh_team_learned_rules_cache(state: &AppState) -> anyhow::Result<()> {
    let Some(api_key) = state.sync_api_key.as_deref() else {
        return Ok(());
    };
    let Some(base_url) = state.sync_api_base_url.as_deref() else {
        return Ok(());
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(format!("grith-server/{}", env!("CARGO_PKG_VERSION")))
        .build()?;
    let resp = client
        .get(format!(
            "{}/api/sync/learned-rules",
            base_url.trim_end_matches('/')
        ))
        .header("x-grith-api-key", api_key)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("{}: {}", status, body);
    }

    #[derive(Deserialize)]
    struct SyncRule {
        pattern: String,
        profile: String,
        scope: String,
        reason: String,
        created_by: String,
        created_at: String,
    }

    let rules = resp.json::<Vec<SyncRule>>().await?;
    let cache_rules: Vec<grith_supervisor::learned_rules::TeamLearnedRule> = rules
        .into_iter()
        .map(|rule| grith_supervisor::learned_rules::TeamLearnedRule {
            pattern: rule.pattern,
            profile: rule.profile,
            scope: rule.scope,
            reason: rule.reason,
            created_by: rule.created_by,
            created_at: rule.created_at,
        })
        .collect();

    grith_supervisor::learned_rules::write_team_learned_rules_cache(
        grith_supervisor::learned_rules::team_learned_rules_cache_path(),
        &cache_rules,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(())
}

/// GET /api/supervisor/sessions
///
/// Returns all active supervisor sessions as lightweight summaries,
/// enriched with containment state from the shared tracker.
async fn list_sessions(State(state): State<AppState>) -> impl IntoResponse {
    let registry = match state.supervisor_registry.lock() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "supervisor registry mutex poisoned in list_sessions");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "supervisor registry unavailable (mutex poisoned)",
                "LOCK_ERROR",
            )
            .into_response();
        }
    };
    let mut sessions = registry.list();
    let count = registry.count();

    // Enrich each summary with containment state
    for s in &mut sessions {
        s.containment_remaining_seconds = state.containment_tracker.remaining_seconds(s.id);
    }

    Json(serde_json::json!({
        "sessions": sessions,
        "total": count,
    }))
    .into_response()
}

/// GET /api/supervisor/sessions/:id
///
/// Returns detailed information about a single supervisor session, including
/// its process tree PIDs and cumulative statistics.
async fn get_session(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return api_error(StatusCode::BAD_REQUEST, "invalid UUID", "INVALID_ID").into_response()
        }
    };

    let registry = match state.supervisor_registry.lock() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "supervisor registry mutex poisoned in get_session");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "supervisor registry unavailable (mutex poisoned)",
                "LOCK_ERROR",
            )
            .into_response();
        }
    };
    match registry.get(&uuid) {
        Some(session) => {
            let containment = state.containment_tracker.remaining_seconds(session.id);
            let detail = SessionDetailResponse {
                id: session.id.to_string(),
                tool_name: session.tool_name.clone(),
                root_pid: session.root_pid,
                uptime_seconds: session.uptime().as_secs(),
                process_tree_pids: session.process_tree.all_pids(),
                stats: session.stats.clone(),
                containment_remaining_seconds: containment,
            };
            Json(detail).into_response()
        }
        None => api_error(
            StatusCode::NOT_FOUND,
            "session not found",
            "SESSION_NOT_FOUND",
        )
        .into_response(),
    }
}

/// POST /api/supervisor/sessions
///
/// Register a new supervised session. The caller provides the tool name and
/// root PID. The session is created and registered in the supervisor registry.
/// Returns the newly assigned session UUID.
async fn create_session(
    State(state): State<AppState>,
    Json(body): Json<CreateSessionRequest>,
) -> impl IntoResponse {
    let supervisor_config = {
        let registry = match state.supervisor_registry.lock() {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "supervisor registry mutex poisoned in create_session config read");
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "supervisor registry unavailable (mutex poisoned)",
                    "LOCK_ERROR",
                )
                .into_response();
            }
        };
        // Refuse audit-unrecordable admission BEFORE anything is attached or
        // spawned. The registry gate at registration time still backstops
        // this, but by then the target process exists — refused registration
        // there would abandon a frozen, unmanaged, unauditable process
        // (work/74 Phase 1: the refusal must happen while there is still
        // nothing running).
        if let Some(reason) = registry.audit_quarantine() {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("audit chain quarantined, refusing new sessions: {reason}"),
                "AUDIT_QUARANTINED",
            )
            .into_response();
        }
        if let Some(reason) = registry.audit_read_only() {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "audit database is read-only for this process, refusing new sessions: {reason}"
                ),
                "AUDIT_READ_ONLY",
            )
            .into_response();
        }
        registry.config().clone()
    };

    if body.start_interception {
        if let Err(msg) = supervisor_config.validate() {
            return api_error(
                StatusCode::BAD_REQUEST,
                format!("invalid supervisor configuration: {msg}"),
                "INVALID_SUPERVISOR_CONFIG",
            )
            .into_response();
        }
    }

    let tool_name = body.tool_name.trim();
    if tool_name.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "tool_name must not be empty",
            "INVALID_REQUEST",
        )
        .into_response();
    }

    if body.start_interception && body.root_pid.is_none() && body.command.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "provide either root_pid or command when start_interception=true",
            "INVALID_REQUEST",
        )
        .into_response();
    }

    if let Some(pid) = body.root_pid {
        if pid == 0 {
            return api_error(
                StatusCode::BAD_REQUEST,
                "root_pid must be a positive integer",
                "INVALID_REQUEST",
            )
            .into_response();
        }
    }

    let mut interceptor = if body.start_interception {
        match grith_supervisor::platform::create_interceptor() {
            Ok(interceptor) => Some(interceptor),
            Err(e) => {
                return api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("supervisor interceptor unavailable: {e}"),
                    "INTERCEPTOR_UNAVAILABLE",
                )
                .into_response();
            }
        }
    } else {
        None
    };
    let mut pty_keepalive: Option<ServerPtyKeepAlive> = None;

    let root_pid = if let Some(pid) = body.root_pid {
        if let Some(ref mut active_interceptor) = interceptor {
            if let Err(e) = active_interceptor.attach(pid).await {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    format!("failed to attach to pid {pid}: {e}"),
                    "ATTACH_FAILED",
                )
                .into_response();
            }
        }
        pid
    } else {
        let command = &body.command;
        if command.is_empty() {
            return api_error(
                StatusCode::BAD_REQUEST,
                "command must not be empty",
                "INVALID_REQUEST",
            )
            .into_response();
        }

        let Some(ref mut active_interceptor) = interceptor else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "root_pid is required when start_interception=false",
                "INVALID_REQUEST",
            )
            .into_response();
        };

        let command_name = command[0].clone();
        let command_args = command.iter().skip(1).cloned().collect::<Vec<_>>();

        #[cfg(unix)]
        {
            if supervisor_config.pty_forwarding {
                let (forwarder, mut reader, writer) =
                    match grith_supervisor::pty::PtyForwarder::spawn(
                        &command_name,
                        &command_args,
                        80,
                        24,
                    ) {
                        Ok(parts) => parts,
                        Err(e) => {
                            return api_error(
                                StatusCode::BAD_REQUEST,
                                format!("failed to spawn PTY command: {e}"),
                                "SPAWN_FAILED",
                            )
                            .into_response();
                        }
                    };
                let pid = match forwarder.child_pid() {
                    Some(pid) => pid,
                    None => {
                        return api_error(
                            StatusCode::BAD_REQUEST,
                            "failed to resolve PTY child pid",
                            "SPAWN_FAILED",
                        )
                        .into_response();
                    }
                };
                if let Err(e) = active_interceptor.attach(pid).await {
                    return api_error(
                        StatusCode::BAD_REQUEST,
                        format!("failed to attach to PTY child pid {pid}: {e}"),
                        "ATTACH_FAILED",
                    )
                    .into_response();
                }

                // Drain PTY output in the background to avoid blocking the
                // child process on a full PTY buffer in API-managed sessions.
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    loop {
                        match std::io::Read::read(&mut reader, &mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                });

                pty_keepalive = Some(ServerPtyKeepAlive {
                    _forwarder: forwarder,
                    _stdin_writer: writer,
                });
                pid
            } else {
                match active_interceptor
                    .spawn_supervised(&command_name, &command_args, &body.environment)
                    .await
                {
                    Ok(pid) => pid,
                    Err(e) => {
                        return api_error(
                            StatusCode::BAD_REQUEST,
                            format!("failed to spawn supervised command: {e}"),
                            "SPAWN_FAILED",
                        )
                        .into_response();
                    }
                }
            }
        }

        #[cfg(not(unix))]
        {
            match active_interceptor
                .spawn_supervised(&command_name, &command_args, &body.environment)
                .await
            {
                Ok(pid) => pid,
                Err(e) => {
                    return api_error(
                        StatusCode::BAD_REQUEST,
                        format!("failed to spawn supervised command: {e}"),
                        "SPAWN_FAILED",
                    )
                    .into_response();
                }
            }
        }
    };

    let mut session = SupervisorSession::new(tool_name, root_pid);
    session.profile_name =
        grith_supervisor::profiles::SupervisorProfile::detect_profile(&session.tool_name)
            .or_else(|| Some("generic".to_string()));
    let response = CreateSessionResponse {
        id: session.id.to_string(),
        tool_name: session.tool_name.clone(),
        root_pid: session.root_pid,
        interception_started: body.start_interception,
    };

    {
        let mut registry = match state.supervisor_registry.lock() {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "supervisor registry mutex poisoned in create_session");
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "supervisor registry unavailable (mutex poisoned)",
                    "LOCK_ERROR",
                )
                .into_response();
            }
        };
        match registry.register(session_registry_view(&session)) {
            Ok(()) => {}
            // Audit refusals are not capacity problems: rendering them as a
            // 429 would show the dashboard a bogus "session limit" message
            // for a condition no upgrade or retry fixes.
            Err(
                e @ (grith_supervisor::Error::AuditQuarantined(_)
                | grith_supervisor::Error::AuditReadOnly(_)),
            ) => {
                let code = match e {
                    grith_supervisor::Error::AuditQuarantined(_) => "AUDIT_QUARANTINED",
                    _ => "AUDIT_READ_ONLY",
                };
                return api_error(StatusCode::SERVICE_UNAVAILABLE, e.to_string(), code)
                    .into_response();
            }
            Err(e) => {
                return api_error(
                    StatusCode::TOO_MANY_REQUESTS,
                    e.to_string(),
                    "SESSION_LIMIT_REACHED",
                )
                .into_response();
            }
        }
    }

    if body.start_interception {
        if let Some(active_interceptor) = interceptor {
            let _ = launch_supervisor_task(
                state.clone(),
                active_interceptor,
                session,
                supervisor_config,
                pty_keepalive,
            )
            .await;
        }
    }

    (StatusCode::CREATED, Json(response)).into_response()
}

/// DELETE /api/supervisor/sessions/:id
///
/// Terminate and remove a supervised session. Returns the final session
/// statistics before removal.
async fn terminate_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    terminate_session_by_id(state, &id).await
}

/// POST /api/supervisor/sessions/:id/kill
///
/// Terminate and remove a supervised session. Kept for compatibility with
/// the Phase 15 API contract.
async fn kill_session(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    terminate_session_by_id(state, &id).await
}

pub(crate) async fn terminate_session_by_id(state: AppState, id: &str) -> axum::response::Response {
    let uuid = match Uuid::parse_str(id) {
        Ok(u) => u,
        Err(e) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                format!("invalid UUID: {e}"),
                "INVALID_ID",
            )
            .into_response();
        }
    };

    let shutdown = {
        let mut tasks = state.supervisor_tasks.lock().await;
        tasks.remove(&uuid)
    };
    let stopped = if let Some(stop_tx) = shutdown {
        let _ = stop_tx.send(());
        true
    } else {
        false
    };

    let mut registry = match state.supervisor_registry.lock() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "supervisor registry mutex poisoned in terminate_session");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "supervisor registry unavailable (mutex poisoned)",
                "LOCK_ERROR",
            )
            .into_response();
        }
    };
    match registry.remove(&uuid) {
        Some(session) => {
            if !stopped {
                #[cfg(unix)]
                {
                    let ret = unsafe { libc::kill(session.root_pid as libc::pid_t, libc::SIGTERM) };
                    if ret != 0 {
                        let err = std::io::Error::last_os_error();
                        tracing::warn!(
                            session_id = %session.id,
                            pid = session.root_pid,
                            error = %err,
                            "failed to send SIGTERM to externally registered session"
                        );
                    }
                }
                #[cfg(not(unix))]
                {
                    tracing::warn!(
                        session_id = %session.id,
                        pid = session.root_pid,
                        "externally registered session removed but process signaling is unsupported on this platform"
                    );
                }
            }
            let response = TerminateSessionResponse {
                id: session.id.to_string(),
                status: "terminated".into(),
                tool_name: session.tool_name.clone(),
                final_stats: session.stats.clone(),
                interception_stopped: stopped,
            };
            Json(response).into_response()
        }
        None => api_error(
            StatusCode::NOT_FOUND,
            "session not found",
            "SESSION_NOT_FOUND",
        )
        .into_response(),
    }
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

/// GET /ws/supervisor/:id
///
/// Upgrades to a WebSocket connection that streams live supervisor events for
/// the given session. Events are received from the global broadcast channel
/// and filtered to only include those matching the requested session ID.
async fn ws_session_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Authorization (Origin-vs-Host + dashboard token) is enforced by the
    // `ws_auth::require_ws_auth` middleware layered on this route, so an
    // unauthorized caller cannot even reach the session-existence probe below.
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return api_error(StatusCode::BAD_REQUEST, "invalid UUID", "INVALID_ID")
                .into_response();
        }
    };

    // Verify the session exists before upgrading.
    {
        let registry = match state.supervisor_registry.lock() {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "supervisor registry mutex poisoned in ws_session_handler");
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "supervisor registry unavailable (mutex poisoned)",
                    "LOCK_ERROR",
                )
                .into_response();
            }
        };
        if registry.get(&uuid).is_none() {
            return api_error(
                StatusCode::NOT_FOUND,
                "session not found",
                "SESSION_NOT_FOUND",
            )
            .into_response();
        }
    }

    let rx = state.ws_tx.subscribe();
    let session_id = uuid.to_string();

    ws.on_upgrade(move |socket| handle_supervisor_ws(socket, rx, session_id))
        .into_response()
}

/// Handle a supervisor WebSocket connection, forwarding only events whose
/// `session_id` field matches the requested session.
async fn handle_supervisor_ws(
    mut socket: WebSocket,
    mut rx: tokio::sync::broadcast::Receiver<String>,
    session_id: String,
) {
    tracing::info!(session_id = %session_id, "supervisor WebSocket client connected");

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Ok(text) => {
                        // Filter: only forward events for this session.
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                            if parsed.get("session_id").and_then(|v| v.as_str()) == Some(&session_id)
                                && socket.send(Message::Text(text)).await.is_err()
                            {
                                break;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(
                            session_id = %session_id,
                            skipped = n,
                            "supervisor WebSocket client lagged"
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Ping(data))) => match socket.send(Message::Pong(data)).await {
                        Ok(()) => {}
                        Err(_) => break,
                    },
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }

    tracing::info!(session_id = %session_id, "supervisor WebSocket client disconnected");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::Request;
    use chrono::Utc;
    use grith_audit::{AuditStorage, ChainVerification};
    use grith_proxy::engine::SecurityProxy;
    use grith_proxy::filters::FilterRegistry;
    use grith_proxy::meta_rules::MetaRuleEngine;
    use grith_proxy::scoring::ScoringConfig;
    use grith_supervisor::config::SupervisorConfig;
    use grith_supervisor::interceptor::{OpenFlags, SyscallEvent, SyscallInterceptor, SyscallKind};
    use grith_supervisor::supervisor::SupervisorRegistry;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::broadcast;
    use tower::util::ServiceExt;

    fn make_state() -> AppState {
        let audit_db_path = std::env::temp_dir()
            .join(format!("grith-test-{}", uuid::Uuid::new_v4()))
            .join("audit.db");
        if let Some(parent) = audit_db_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let audit = Arc::new(Mutex::new(
            grith_audit::AuditStorage::open(&audit_db_path).unwrap(),
        ));
        let digest = Arc::new(grith_digest::DigestQueue::open_in_memory().unwrap());
        let proxy = Arc::new(SecurityProxy::new(
            FilterRegistry::new(),
            ScoringConfig::default(),
            MetaRuleEngine::new(vec![]),
        ));
        let registry = Arc::new(Mutex::new(SupervisorRegistry::new(
            SupervisorConfig::default(),
        )));
        let containment = Arc::new(
            grith_proxy::filters::session_containment::ContainmentTracker::with_defaults(),
        );
        let correlation = Arc::new(grith_audit::CorrelationTracker::with_defaults());
        let canary_registry = Arc::new(grith_proxy::filters::canary::CanaryRegistry::empty());
        let notification_dispatcher = Arc::new(grith_notify::NotificationDispatcher::new(
            grith_notify::ChannelRegistry::new(),
            grith_notify::RoutingEngine::default(),
            Arc::new(grith_digest::notification::CallbackNonceStore::new(
                std::time::Duration::from_secs(300),
            )),
            grith_digest::notification::PlanTier::Community,
            digest.clone(),
            grith_notify::rate_limiter::RateLimiter::default(),
            grith_notify::batcher::Batcher::default(),
            std::time::Duration::from_secs(300),
            grith_digest::types::ScoreSeverity::High,
        ));
        let (ws_tx, _) = broadcast::channel(16);
        let supervisor_tasks = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        AppState {
            audit_storage: audit,
            digest_queue: digest,
            proxy,
            supervisor_registry: registry,
            supervisor_tasks,
            containment_tracker: containment,
            correlation_tracker: correlation,
            canary_registry,
            notification_dispatcher,
            start_time: std::time::Instant::now(),
            instance_id: None,
            protocol_version: None,
            version: "0.1.0-test".into(),
            ws_tx,
            shutdown_tx: None,
            plan_tier: "community".into(),
            config_dir: std::env::temp_dir().join(format!("grith-test-{}", uuid::Uuid::new_v4())),
            audit_db_path,
            account_id: "local:test".into(),
            auth_config: crate::auth::AuthConfig::default(),
            feature_gate: std::sync::Arc::new(std::sync::RwLock::new(
                grith_digest::notification::FeatureGate {
                    tier: grith_digest::notification::PlanTier::Community,
                    seats: 1,
                },
            )),
            license_valid_until: None,
            billing_portal_url: None,
            refresh_state: std::sync::Arc::new(std::sync::RwLock::new(
                grith_digest::notification::RefreshState::default(),
            )),
            dns_seed_domains: vec![],
            reputation_table: std::sync::Arc::new(std::sync::Mutex::new(
                grith_proxy::reputation::ReputationTable::new(),
            )),
            reputation_config: grith_proxy::reputation::ReputationConfig::default(),
            sync_api_key: None,
            sync_api_base_url: None,
            ipc_token: String::new(),
            dashboard_token: String::new(),
            dashboard_pair_code: std::sync::Arc::new(std::sync::Mutex::new(None)),
            session_limit_rejections: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    fn make_router() -> Router {
        let state = make_state();
        supervisor_router().with_state(state)
    }

    struct ScriptedInterceptor {
        events: VecDeque<SyscallEvent>,
    }

    impl ScriptedInterceptor {
        fn new(events: Vec<SyscallEvent>) -> Self {
            Self {
                events: VecDeque::from(events),
            }
        }
    }

    #[async_trait]
    impl SyscallInterceptor for ScriptedInterceptor {
        async fn attach(&mut self, pid: u32) -> grith_supervisor::error::Result<()> {
            Err(grith_supervisor::error::Error::AttachFailed {
                pid,
                reason: "scripted interceptor does not support attach".into(),
            })
        }

        async fn spawn_supervised(
            &mut self,
            _command: &str,
            _args: &[String],
            _env: &[(String, String)],
        ) -> grith_supervisor::error::Result<u32> {
            Err(grith_supervisor::error::Error::SpawnFailed(
                "scripted interceptor does not support spawn".into(),
            ))
        }

        async fn next_event(&mut self) -> grith_supervisor::error::Result<Option<SyscallEvent>> {
            Ok(self.events.pop_front())
        }

        async fn allow(&mut self, _pid: u32) -> grith_supervisor::error::Result<()> {
            Ok(())
        }

        async fn deny(&mut self, _pid: u32) -> grith_supervisor::error::Result<()> {
            Ok(())
        }

        async fn kill(&mut self, _pid: u32) -> grith_supervisor::error::Result<()> {
            Ok(())
        }

        async fn freeze(&mut self, _pid: u32) -> grith_supervisor::error::Result<()> {
            Ok(())
        }

        async fn thaw(&mut self, _pid: u32) -> grith_supervisor::error::Result<()> {
            Ok(())
        }

        async fn detach(&mut self, _pid: u32) -> grith_supervisor::error::Result<()> {
            Ok(())
        }

        async fn detach_all(&mut self) -> grith_supervisor::error::Result<()> {
            Ok(())
        }

        fn supervised_pids(&self) -> Vec<u32> {
            vec![]
        }

        fn is_available() -> bool
        where
            Self: Sized,
        {
            true
        }

        fn mechanism_name(&self) -> &str {
            "scripted"
        }
    }

    fn sample_file_open_event(pid: u32, path: &str) -> SyscallEvent {
        SyscallEvent {
            pid,
            tid: pid,
            timestamp: Utc::now(),
            kind: SyscallKind::FileOpen {
                path: path.to_string(),
                flags: OpenFlags::ReadOnly,
            },
            raw_syscall_nr: 257,
        }
    }

    #[test]
    fn session_registry_view_preserves_policy_metadata() {
        let mut session = SupervisorSession::new("grith-repl", 1234);
        session.profile_name = Some("grith-repl".into());
        session.policy_scope = Some("grith-repl+provider:openai+launcher:vscode-terminal".into());
        session.launcher_overlay_name = Some("vscode-terminal".into());
        session.provider_overlay_name = Some("openai".into());

        let cloned = session_registry_view(&session);

        assert_eq!(cloned.profile_name, session.profile_name);
        assert_eq!(cloned.policy_scope, session.policy_scope);
        assert_eq!(cloned.launcher_overlay_name, session.launcher_overlay_name);
        assert_eq!(cloned.provider_overlay_name, session.provider_overlay_name);
    }

    async fn wait_for_task_completion(state: &AppState, session_id: Uuid) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let running = state
                    .supervisor_tasks
                    .lock()
                    .await
                    .contains_key(&session_id);
                if !running {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("supervisor task should complete");
    }

    #[tokio::test]
    async fn test_list_sessions_empty() {
        let router = make_router();
        let response = router
            .oneshot(Request::get("/sessions").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["total"], 0);
        assert!(json["sessions"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_create_session() {
        let router = make_router();
        let response = router
            .oneshot(
                Request::post("/sessions")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"tool_name": "claude-code", "root_pid": 12345, "start_interception": false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["tool_name"], "claude-code");
        assert_eq!(json["root_pid"], 12345);
        assert!(json["id"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_create_session_empty_tool_name() {
        let router = make_router();
        let response = router
            .oneshot(
                Request::post("/sessions")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"tool_name": "", "root_pid": 100, "start_interception": false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_session_zero_pid() {
        let router = make_router();
        let response = router
            .oneshot(
                Request::post("/sessions")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"tool_name": "codex", "root_pid": 0, "start_interception": false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_session_not_found() {
        let router = make_router();
        let id = Uuid::new_v4();
        let response = router
            .oneshot(
                Request::get(format!("/sessions/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_session_invalid_id() {
        let router = make_router();
        let response = router
            .oneshot(
                Request::get("/sessions/not-a-uuid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_and_get_session() {
        let state = make_state();
        let router = supervisor_router().with_state(state.clone());

        // Create a session.
        let create_resp = router
            .clone()
            .oneshot(
                Request::post("/sessions")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"tool_name": "aider", "root_pid": 9876, "start_interception": false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(create_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let session_id = create_json["id"].as_str().unwrap();

        // Get the session.
        let get_resp = router
            .oneshot(
                Request::get(format!("/sessions/{session_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(get_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let get_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(get_json["tool_name"], "aider");
        assert_eq!(get_json["root_pid"], 9876);
        assert!(get_json["uptime_seconds"].is_number());
        assert!(get_json["process_tree_pids"].is_array());
        assert!(get_json["stats"].is_object());
    }

    #[tokio::test]
    async fn test_terminate_session() {
        let state = make_state();
        let router = supervisor_router().with_state(state.clone());

        // Create a session.
        let create_resp = router
            .clone()
            .oneshot(
                Request::post("/sessions")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"tool_name": "codex", "root_pid": 5555, "start_interception": false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(create_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let session_id = create_json["id"].as_str().unwrap();

        // Terminate the session.
        let del_resp = router
            .clone()
            .oneshot(
                Request::delete(format!("/sessions/{session_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(del_resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(del_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let del_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(del_json["status"], "terminated");
        assert_eq!(del_json["tool_name"], "codex");

        // Verify it's gone.
        let get_resp = router
            .oneshot(
                Request::get(format!("/sessions/{session_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_terminate_session_via_post_kill() {
        let state = make_state();
        let router = supervisor_router().with_state(state.clone());

        let create_resp = router
            .clone()
            .oneshot(
                Request::post("/sessions")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"tool_name": "codex", "root_pid": 5555, "start_interception": false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(create_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let session_id = create_json["id"].as_str().unwrap();

        let kill_resp = router
            .clone()
            .oneshot(
                Request::post(format!("/sessions/{session_id}/kill"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(kill_resp.status(), StatusCode::OK);

        let get_resp = router
            .oneshot(
                Request::get(format!("/sessions/{session_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_terminate_session_not_found() {
        let router = make_router();
        let id = Uuid::new_v4();
        let response = router
            .oneshot(
                Request::delete(format!("/sessions/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_sessions_after_create() {
        let state = make_state();
        let router = supervisor_router().with_state(state.clone());

        // Create two sessions.
        for (name, pid) in [("claude-code", 100), ("aider", 200)] {
            let _ = router
                .clone()
                .oneshot(
                    Request::post("/sessions")
                        .header("content-type", "application/json")
                        .body(Body::from(format!(
                            r#"{{"tool_name": "{name}", "root_pid": {pid}, "start_interception": false}}"#
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
        }

        // List sessions.
        let list_resp = router
            .oneshot(Request::get("/sessions").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(list_resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(list_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["total"], 2);
        assert_eq!(json["sessions"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_supervisor_audit_persists_across_reopen() {
        let state = make_state();
        let session = SupervisorSession::new("mock-tool", 9001);
        let session_id = session.id;
        {
            let mut registry = state.supervisor_registry.lock().unwrap();
            registry.register(session_registry_view(&session)).unwrap();
        }

        let interceptor: Box<dyn SyscallInterceptor> =
            Box::new(ScriptedInterceptor::new(vec![sample_file_open_event(
                9001,
                "/tmp/server-persist-1.txt",
            )]));
        let mut config = SupervisorConfig::default();
        config.noise_reduction.ignore_read_only = false;
        let started =
            launch_supervisor_task(state.clone(), interceptor, session, config, None).await;
        assert!(started);
        wait_for_task_completion(&state, session_id).await;

        let storage = AuditStorage::open(&state.audit_db_path).unwrap();
        let records = storage.get_recent(128).unwrap();
        assert!(
            records.iter().any(|r| r.session_id == session_id),
            "expected persisted supervisor audit record for session {session_id}"
        );
        drop(storage);

        let reopened = AuditStorage::open(&state.audit_db_path).unwrap();
        let reopened_records = reopened.get_recent(128).unwrap();
        assert!(
            reopened_records.iter().any(|r| r.session_id == session_id),
            "expected persisted records after reopening audit storage"
        );
    }

    #[tokio::test]
    async fn test_supervisor_concurrent_sessions_audit_integrity() {
        let state = make_state();
        let session_a = SupervisorSession::new("tool-a", 9101);
        let session_b = SupervisorSession::new("tool-b", 9102);
        let session_a_id = session_a.id;
        let session_b_id = session_b.id;
        {
            let mut registry = state.supervisor_registry.lock().unwrap();
            registry
                .register(session_registry_view(&session_a))
                .unwrap();
            registry
                .register(session_registry_view(&session_b))
                .unwrap();
        }

        let interceptor_a: Box<dyn SyscallInterceptor> = Box::new(ScriptedInterceptor::new(vec![
            sample_file_open_event(9101, "/tmp/server-concurrent-a1.txt"),
            sample_file_open_event(9101, "/tmp/server-concurrent-a2.txt"),
        ]));
        let interceptor_b: Box<dyn SyscallInterceptor> = Box::new(ScriptedInterceptor::new(vec![
            sample_file_open_event(9102, "/tmp/server-concurrent-b1.txt"),
            sample_file_open_event(9102, "/tmp/server-concurrent-b2.txt"),
        ]));

        let mut config_a = SupervisorConfig::default();
        config_a.noise_reduction.ignore_read_only = false;
        let mut config_b = SupervisorConfig::default();
        config_b.noise_reduction.ignore_read_only = false;
        assert!(
            launch_supervisor_task(state.clone(), interceptor_a, session_a, config_a, None,).await
        );
        assert!(
            launch_supervisor_task(state.clone(), interceptor_b, session_b, config_b, None,).await
        );

        wait_for_task_completion(&state, session_a_id).await;
        wait_for_task_completion(&state, session_b_id).await;

        let storage = AuditStorage::open(&state.audit_db_path).unwrap();
        let records = storage.get_recent(256).unwrap();
        assert!(records.iter().any(|r| r.session_id == session_a_id));
        assert!(records.iter().any(|r| r.session_id == session_b_id));

        match storage.verify_chain().unwrap() {
            ChainVerification::Valid { record_count } => {
                assert!(
                    record_count >= 4,
                    "expected chained records from both sessions"
                );
            }
            other => panic!("expected valid chain, got {other:?}"),
        }
    }
}
