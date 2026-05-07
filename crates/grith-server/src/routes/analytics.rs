// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Usage analytics endpoints (Pro feature).
//!
//! Provides summary, cost, and compliance analytics computed from the local
//! audit database. All endpoints are gated behind the `usage_analytics`
//! feature (Pro+).

use super::api_error;
use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use grith_audit::stats::AuditStats;
use serde::Serialize;

// --- Shared error helper ---

macro_rules! lock_audit {
    ($state:expr) => {
        match $state.audit_storage.lock() {
            Ok(s) => s,
            Err(_) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to acquire audit storage lock",
                    "INTERNAL_ERROR",
                )
                .into_response();
            }
        }
    };
}

macro_rules! try_audit {
    ($expr:expr, $label:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to compute {}: {e}", $label),
                    "INTERNAL_ERROR",
                )
                .into_response();
            }
        }
    };
}

// --- GET /api/analytics/summary ---

#[derive(Serialize)]
struct LatencyResponse {
    avg_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
}

#[derive(Serialize)]
struct FilterTriggerCount {
    name: String,
    trigger_count: usize,
}

#[derive(Serialize)]
struct TimeRange {
    earliest: Option<String>,
    latest: Option<String>,
}

#[derive(Serialize)]
struct AnalyticsSummaryResponse {
    total_evaluations: usize,
    allow_count: usize,
    queue_count: usize,
    deny_count: usize,
    avg_score: f64,
    latency: LatencyResponse,
    top_filters: Vec<FilterTriggerCount>,
    time_range: TimeRange,
}

pub(crate) async fn analytics_summary(State(state): State<AppState>) -> impl IntoResponse {
    if let Some(resp) = super::require_feature(&state, "usage_analytics", "Pro") {
        return resp;
    }

    let storage = lock_audit!(state);
    let stats = try_audit!(AuditStats::compute(&storage), "stats");
    let percentiles = try_audit!(AuditStats::latency_percentiles(&storage), "percentiles");
    let top_filters = try_audit!(
        AuditStats::top_triggered_filters(&storage, 10),
        "top filters"
    );
    let (earliest, latest) = try_audit!(AuditStats::time_range(&storage), "time range");

    Json(AnalyticsSummaryResponse {
        total_evaluations: stats.total_calls,
        allow_count: stats.allow_count,
        queue_count: stats.queue_count,
        deny_count: stats.deny_count,
        avg_score: stats.avg_score,
        latency: LatencyResponse {
            avg_ms: stats.avg_latency_ms,
            p50_ms: percentiles.p50_ms,
            p95_ms: percentiles.p95_ms,
            p99_ms: percentiles.p99_ms,
        },
        top_filters: top_filters
            .into_iter()
            .map(|(name, count)| FilterTriggerCount {
                name,
                trigger_count: count,
            })
            .collect(),
        time_range: TimeRange { earliest, latest },
    })
    .into_response()
}

// --- GET /api/analytics/cost ---

#[derive(Serialize)]
struct CostResponse {
    total_cost_usd: f64,
    total_prompt_tokens: usize,
    total_completion_tokens: usize,
    by_provider: Vec<grith_audit::stats::ProviderCost>,
}

pub(crate) async fn analytics_cost(State(state): State<AppState>) -> impl IntoResponse {
    if let Some(resp) = super::require_feature(&state, "usage_analytics", "Pro") {
        return resp;
    }

    let storage = lock_audit!(state);
    let providers = try_audit!(AuditStats::cost_by_provider(&storage), "cost by provider");

    let total_cost: f64 = providers.iter().map(|p| p.total_cost_usd).sum();
    let total_prompt: usize = providers.iter().map(|p| p.prompt_tokens).sum();
    let total_completion: usize = providers.iter().map(|p| p.completion_tokens).sum();

    Json(CostResponse {
        total_cost_usd: total_cost,
        total_prompt_tokens: total_prompt,
        total_completion_tokens: total_completion,
        by_provider: providers,
    })
    .into_response()
}

// --- GET /api/analytics/activity ---

#[derive(Serialize)]
struct ActivityResponse {
    days: usize,
    daily: Vec<grith_audit::stats::DailyCount>,
    top_tool_call_types: Vec<ToolCallTypeCount>,
}

#[derive(Serialize)]
struct ToolCallTypeCount {
    tool_call_type: String,
    count: usize,
}

pub(crate) async fn analytics_activity(State(state): State<AppState>) -> impl IntoResponse {
    if let Some(resp) = super::require_feature(&state, "usage_analytics", "Pro") {
        return resp;
    }

    let storage = lock_audit!(state);
    let daily = try_audit!(AuditStats::daily_activity(&storage, 30), "daily activity");
    let top_types = try_audit!(
        AuditStats::top_tool_call_types(&storage, 10),
        "top tool call types"
    );

    Json(ActivityResponse {
        days: 30,
        daily,
        top_tool_call_types: top_types
            .into_iter()
            .map(|(name, count)| ToolCallTypeCount {
                tool_call_type: name,
                count,
            })
            .collect(),
    })
    .into_response()
}

// --- GET /api/analytics/compliance ---

#[derive(Serialize)]
struct ComplianceResponse {
    score_distribution: grith_audit::stats::ScoreDistribution,
    total_evaluations: usize,
    deny_rate: f64,
    queue_rate: f64,
    allow_rate: f64,
    avg_score: f64,
    time_range: TimeRange,
}

pub(crate) async fn analytics_compliance(State(state): State<AppState>) -> impl IntoResponse {
    if let Some(resp) = super::require_feature(&state, "usage_analytics", "Pro") {
        return resp;
    }

    let storage = lock_audit!(state);
    let stats = try_audit!(AuditStats::compute(&storage), "stats");
    let dist = try_audit!(
        AuditStats::score_distribution(&storage),
        "score distribution"
    );
    let (earliest, latest) = try_audit!(AuditStats::time_range(&storage), "time range");

    let total = stats.total_calls.max(1) as f64;
    Json(ComplianceResponse {
        score_distribution: dist,
        total_evaluations: stats.total_calls,
        deny_rate: stats.deny_count as f64 / total,
        queue_rate: stats.queue_count as f64 / total,
        allow_rate: stats.allow_count as f64 / total,
        avg_score: stats.avg_score,
        time_range: TimeRange { earliest, latest },
    })
    .into_response()
}
