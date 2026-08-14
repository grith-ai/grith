// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Production policy adapter for inspected DNS queries.
//!
//! The connected UDP proxy runs outside the ptrace scheduling domain. This
//! adapter consequently owns every dependency needed to make a DNS decision;
//! it never borrows [`SupervisorSession`] or sends work back through the
//! supervisor event loop.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use grith_audit::types::AuditRecord;
use grith_digest::types::{DigestItem, DigestStatus, FilterBreakdown, ScoreSeverity};
use grith_proxy::audit_bridge;
use grith_proxy::engine::SecurityProxy;
use grith_proxy::filters::dlp_gate::DlpRedactor;
use grith_proxy::filters::egress_policy::dns_tunneling_signal;
use grith_proxy::filters::session_containment::ContainmentTracker;
use grith_proxy::session_state::SessionStateRegistry;
use grith_proxy::types::{
    FilterResult, ProxyAction, ProxyDecision, QueuePriority, SessionScopeKey, Severity,
    ToolCallContext, ToolCallType,
};
use uuid::Uuid;

use crate::audit_sink::AuditSink;
use crate::config::DnsProxyQueueAction;
use crate::connected_dns_proxy::{DnsDecision, DnsDecisionRequest, DnsDecisionService};
use crate::reviewer::DigestStore;

use super::session_state::SupervisorSession;

/// Session fields needed by DNS policy, audit, and digest output.
///
/// This is deliberately a value snapshot. The proxy worker must not retain a
/// reference to the mutable ptrace-loop session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsDecisionSession {
    pub session_id: Uuid,
    pub tool_name: String,
    pub profile_name: Option<String>,
    pub project_name: Option<String>,
    pub root_pid: u32,
}

impl From<&SupervisorSession> for DnsDecisionSession {
    fn from(session: &SupervisorSession) -> Self {
        Self {
            session_id: session.id,
            tool_name: session.tool_name.clone(),
            profile_name: session.profile_name.clone(),
            project_name: session.project_name.clone(),
            root_pid: session.root_pid,
        }
    }
}

/// Owned production implementation of the transport-neutral DNS policy
/// boundary.
pub struct ProductionDnsDecisionService {
    proxy: Arc<SecurityProxy>,
    audit_sink: Arc<dyn AuditSink>,
    digest_store: Arc<dyn DigestStore>,
    session_allowed: Arc<Mutex<HashSet<String>>>,
    containment_tracker: Arc<ContainmentTracker>,
    session: DnsDecisionSession,
    daemon_proxy_url: Option<String>,
    daemon_proxy_token: Option<Arc<Mutex<String>>>,
    dlp_redactor: DlpRedactor,
    http_client: reqwest::Client,
    call_sequence: AtomicU64,
}

impl ProductionDnsDecisionService {
    /// Construct a local-policy service with the default DLP redactor.
    pub fn new(
        proxy: Arc<SecurityProxy>,
        audit_sink: Arc<dyn AuditSink>,
        digest_store: Arc<dyn DigestStore>,
        session_allowed: Arc<Mutex<HashSet<String>>>,
        containment_tracker: Arc<ContainmentTracker>,
        session: DnsDecisionSession,
    ) -> Self {
        Self {
            proxy,
            audit_sink,
            digest_store,
            session_allowed,
            containment_tracker,
            session,
            daemon_proxy_url: None,
            daemon_proxy_token: None,
            dlp_redactor: DlpRedactor::with_defaults(),
            http_client: reqwest::Client::new(),
            call_sequence: AtomicU64::new(0),
        }
    }

    /// Use the daemon's shared proxy state instead of the local proxy.
    ///
    /// The token remains behind an `Arc<Mutex<_>>` so an owning supervisor can
    /// atomically replace refreshed credentials without rebuilding the DNS
    /// worker.
    pub fn with_daemon(mut self, url: impl Into<String>, token: Arc<Mutex<String>>) -> Self {
        self.daemon_proxy_url = Some(url.into());
        self.daemon_proxy_token = Some(token);
        self
    }

    /// Use the session's configured redactor rather than the default patterns.
    pub fn with_dlp_redactor(mut self, redactor: &DlpRedactor) -> Self {
        self.dlp_redactor = redactor.clone();
        self
    }

    async fn evaluate_request(&self, request: &DnsDecisionRequest) -> DnsDecision {
        let ctx = self.context_for(request);

        let containment_active = self
            .containment_tracker
            .remaining_seconds(self.session.session_id)
            .is_some()
            || SessionStateRegistry::global()
                .is_containment_active(SessionScopeKey::from_session_id(self.session.session_id));
        let allowlisted = match self.session_allowed.lock() {
            Ok(allowed) => !containment_active && dns_allowlist_matches(&request.domain, &allowed),
            Err(_) => {
                return DnsDecision::InfrastructureFailure {
                    reason: "DNS session allowlist lock is poisoned".into(),
                };
            }
        };

        // W4: an allowlisted parent zone trusts the *destination* for
        // resolution, but must not become a blind spot for DNS tunnelling — a
        // query like `<base32-payload>.example.com` resolves the trusted
        // `example.com` while smuggling data in the subdomain labels. Before
        // blind-allowing, shape-check the query; only when it looks like an
        // encoded payload do we defer to the full proxy (which scores the
        // `dns-tunneling` signal and queues/denies as its composite dictates).
        // A normal query under the parent still short-circuits — no new prompts.
        if allowlisted && dns_tunneling_signal(&request.domain, &request.query_type).is_none() {
            let mut decision = ProxyDecision::allow(0.0, Vec::new(), Duration::ZERO);
            decision.decision_reason = "DNS destination is allowed for this session".into();
            return self.finish_decision(&ctx, &decision, request).await;
        }

        let decision = match self.evaluate_proxy(&ctx).await {
            Ok(decision) => decision,
            Err(reason) => {
                return DnsDecision::InfrastructureFailure {
                    reason: self.dlp_redactor.redact(&reason),
                };
            }
        };
        self.finish_decision(&ctx, &decision, request).await
    }

    fn context_for(&self, request: &DnsDecisionRequest) -> ToolCallContext {
        let call_type = ToolCallType::DnsQuery {
            domain: request.domain.clone(),
            query_type: request.query_type.clone(),
        };
        let mut ctx = ToolCallContext::new(
            format!("supervisor:{}", self.session.tool_name),
            call_type,
            self.session.session_id,
        );
        ctx.profile_name = self.session.profile_name.clone();
        ctx.task_context = self.session.project_name.clone();
        ctx.call_sequence_number = self
            .call_sequence
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        ctx.arguments = if request.route_id.get() == 0 {
            serde_json::json!({
                "domain": request.domain,
                "query_type": request.query_type,
                "inspection_owner": "inline",
                "transport": "inline",
                "tgid": request.provenance.tgid,
                "tid": request.provenance.creator_tid,
            })
        } else {
            serde_json::json!({
                "domain": request.domain,
                "query_type": request.query_type,
                "inspection_owner": "connected_proxy",
                "transport": "connected_udp_proxy",
                "route_id": request.route_id.get(),
                "original_resolver": request.original_resolver.to_string(),
                "transaction_id": request.transaction_id,
                "tgid": request.provenance.tgid,
                "creator_tid": request.provenance.creator_tid,
                "socket_id": request.provenance.socket_id,
            })
        };
        ctx
    }

    async fn evaluate_proxy(&self, ctx: &ToolCallContext) -> Result<ProxyDecision, String> {
        match (&self.daemon_proxy_url, &self.daemon_proxy_token) {
            (None, None) => Ok(self.proxy.evaluate(ctx).await),
            (Some(url), Some(token)) => {
                let token = token
                    .lock()
                    .map_err(|_| "daemon proxy token lock is poisoned".to_string())?
                    .clone();
                self.remote_proxy_evaluate(url, &token, ctx).await
            }
            _ => Err("daemon proxy configuration requires both URL and token".to_string()),
        }
    }

    async fn remote_proxy_evaluate(
        &self,
        base_url: &str,
        token: &str,
        ctx: &ToolCallContext,
    ) -> Result<ProxyDecision, String> {
        let response = self
            .http_client
            .post(format!("{base_url}/api/proxy/evaluate"))
            .bearer_auth(token)
            .json(&serde_json::json!({ "context": ctx }))
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|error| format!("remote DNS policy request failed: {error}"))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("remote DNS policy returned {status}: {body}"));
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|error| format!("remote DNS policy response parse failed: {error}"))?;
        parse_remote_decision(&body)
    }

    async fn finish_decision(
        &self,
        ctx: &ToolCallContext,
        decision: &ProxyDecision,
        request: &DnsDecisionRequest,
    ) -> DnsDecision {
        match &decision.action {
            ProxyAction::Allow => {
                let record = self.build_audit_record(ctx, decision, request);
                match self.audit_sink.log_required(record).await {
                    Ok(()) => DnsDecision::Allow,
                    Err(error) => DnsDecision::InfrastructureFailure {
                        reason: self
                            .dlp_redactor
                            .redact(&format!("required DNS audit enqueue failed: {error}")),
                    },
                }
            }
            ProxyAction::Deny { reason } => {
                self.log_non_forwarding_audit(ctx, decision, request).await;
                DnsDecision::Deny {
                    reason: self
                        .dlp_redactor
                        .redact(&non_empty_reason(reason, &decision.decision_reason)),
                }
            }
            ProxyAction::Queue { .. } => {
                let item = self.build_digest_item(ctx, decision);
                if let Err(error) = self.digest_store.enqueue(&item).await {
                    return DnsDecision::InfrastructureFailure {
                        reason: self
                            .dlp_redactor
                            .redact(&format!("DNS review digest enqueue failed: {error}")),
                    };
                }
                let record = self.build_audit_record(ctx, decision, request);
                if let Err(error) = self.audit_sink.log_required(record).await {
                    return DnsDecision::InfrastructureFailure {
                        reason: self
                            .dlp_redactor
                            .redact(&format!("required DNS queue audit enqueue failed: {error}")),
                    };
                }
                DnsDecision::Queue {
                    reason: self.dlp_redactor.redact(&non_empty_reason(
                        &decision.decision_reason,
                        "DNS query requires review",
                    )),
                }
            }
        }
    }

    async fn log_non_forwarding_audit(
        &self,
        ctx: &ToolCallContext,
        decision: &ProxyDecision,
        request: &DnsDecisionRequest,
    ) {
        let record = self.build_audit_record(ctx, decision, request);
        if let Err(error) = self.audit_sink.log(record).await {
            tracing::warn!(
                error = %error,
                session_id = %self.session.session_id,
                route_id = request.route_id.get(),
                "failed to enqueue non-forwarding DNS audit record"
            );
        }
    }

    fn build_audit_record(
        &self,
        ctx: &ToolCallContext,
        decision: &ProxyDecision,
        request: &DnsDecisionRequest,
    ) -> AuditRecord {
        let filter_results = audit_bridge::to_filter_summaries(&decision.filter_results)
            .into_iter()
            .map(|mut result| {
                result.message = self.dlp_redactor.redact(&result.message);
                result
            })
            .collect();
        let mut record = AuditRecord::new(
            self.session.session_id,
            self.dlp_redactor.redact(&ctx.plugin_id),
            self.dlp_redactor.redact(&ctx.call_type.to_string()),
            &ctx.arguments,
            decision.composite_score,
            audit_bridge::to_action_summary(&decision.action),
            filter_results,
            decision.evaluation_time.as_secs_f64() * 1000.0,
            ctx.task_context
                .as_deref()
                .map(|task| self.dlp_redactor.redact(task)),
        )
        .with_supervisor_source(
            self.dlp_redactor.redact(&self.session.tool_name),
            request.provenance.tgid,
        )
        .with_project_name(
            self.session
                .project_name
                .as_deref()
                .map(|project| self.dlp_redactor.redact(project)),
        );
        record.arguments_summary = self.dlp_redactor.redact(&record.arguments_summary);
        let decision_reason = (!decision.decision_reason.is_empty())
            .then(|| self.dlp_redactor.redact(&decision.decision_reason));
        let enforcement_outcome = match (&decision.action, request.queue_action) {
            (ProxyAction::Queue { .. }, DnsProxyQueueAction::Forward) => "dns_queue_forward",
            (ProxyAction::Queue { .. }, DnsProxyQueueAction::Refuse) => "dns_queue_refuse",
            (ProxyAction::Deny { .. }, _) => "dns_deny",
            (ProxyAction::Allow, _) => "dns_allow",
        };
        record = record.with_decision_enforcement(decision_reason.clone(), enforcement_outcome);
        // Keep the outcome and redacted reason durable even on installations
        // whose audit database predates the optional dedicated columns.
        record.execution_result = Some(format!(
            "dns_enforcement={enforcement_outcome};decision_reason={}",
            decision_reason.as_deref().unwrap_or("unspecified")
        ));
        record
    }

    fn build_digest_item(&self, ctx: &ToolCallContext, decision: &ProxyDecision) -> DigestItem {
        DigestItem {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            session_id: Some(self.session.session_id),
            tool_call_type: self.dlp_redactor.redact(&ctx.call_type.to_string()),
            arguments_summary: self
                .dlp_redactor
                .redact(&grith_audit::types::summarize_arguments(&ctx.arguments)),
            decision_reason: (!decision.decision_reason.is_empty())
                .then(|| self.dlp_redactor.redact(&decision.decision_reason)),
            composite_score: decision.composite_score,
            severity: ScoreSeverity::from_score(decision.composite_score),
            filter_breakdown: digest_filter_breakdowns(
                &decision.filter_results,
                &self.dlp_redactor,
            ),
            task_context: ctx
                .task_context
                .as_deref()
                .map(|task| self.dlp_redactor.redact(task)),
            plugin_id: self.dlp_redactor.redact(&ctx.plugin_id),
            status: DigestStatus::Pending,
            reviewed_at: None,
            review_action: None,
            reviewer_notes: None,
            informational_only: false,
            escalated_at: None,
            escalated_by: None,
        }
    }
}

#[async_trait]
impl DnsDecisionService for ProductionDnsDecisionService {
    async fn evaluate(&self, request: DnsDecisionRequest) -> DnsDecision {
        self.evaluate_request(&request).await
    }
}

fn dns_allowlist_matches(domain: &str, allowed: &HashSet<String>) -> bool {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return false;
    }
    allowed.iter().any(|entry| {
        entry
            .strip_prefix("net:")
            .or_else(|| entry.strip_prefix("dns:"))
            .is_some_and(|suffix| domain_suffix_matches(domain, suffix))
    })
}

fn domain_suffix_matches(domain: &str, suffix: &str) -> bool {
    let suffix = suffix.trim_end_matches('.');
    if domain.eq_ignore_ascii_case(suffix) {
        return true;
    }
    let Some(boundary) = domain.len().checked_sub(suffix.len()) else {
        return false;
    };
    domain
        .get(boundary..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
        && domain
            .as_bytes()
            .get(boundary.wrapping_sub(1))
            .is_some_and(|byte| *byte == b'.')
}

fn digest_filter_breakdowns(
    results: &[FilterResult],
    redactor: &DlpRedactor,
) -> Vec<FilterBreakdown> {
    results
        .iter()
        .filter(|result| result.matched)
        .map(|result| FilterBreakdown {
            filter_name: result.filter_name.clone(),
            score: result.score,
            rule_id: result.rule_id.clone(),
            message: redactor.redact(&result.message),
        })
        .collect()
}

fn non_empty_reason(preferred: &str, fallback: &str) -> String {
    if preferred.is_empty() {
        fallback.to_string()
    } else {
        preferred.to_string()
    }
}

fn parse_remote_decision(body: &serde_json::Value) -> Result<ProxyDecision, String> {
    let composite_score = body["composite_score"]
        .as_f64()
        .ok_or_else(|| "remote DNS policy omitted composite_score".to_string())?;
    let action_text = body["action"]
        .as_str()
        .ok_or_else(|| "remote DNS policy omitted action".to_string())?;
    let action = if action_text == "allow" {
        ProxyAction::Allow
    } else if let Some(reason) = action_text.strip_prefix("deny:") {
        ProxyAction::Deny {
            reason: reason.to_string(),
        }
    } else if action_text.starts_with("queue:") {
        ProxyAction::Queue {
            priority: parse_queue_priority(action_text),
        }
    } else {
        return Err(format!(
            "remote DNS policy returned unknown action: {action_text}"
        ));
    };

    let filter_results = match body["filter_results"].as_array() {
        Some(items) => items
            .iter()
            .map(parse_remote_filter_result)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| "remote DNS policy returned a malformed filter result".to_string())?,
        None => Vec::new(),
    };
    let evaluation_time_ms = body["evaluation_time_ms"].as_f64().unwrap_or_default();
    if !evaluation_time_ms.is_finite() || evaluation_time_ms < 0.0 {
        return Err("remote DNS policy returned invalid evaluation_time_ms".into());
    }

    Ok(ProxyDecision {
        action,
        composite_score,
        filter_results,
        evaluation_time: Duration::from_secs_f64(evaluation_time_ms / 1000.0),
        decision_reason: body["decision_reason"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    })
}

fn parse_queue_priority(action: &str) -> QueuePriority {
    if action.contains("Critical") {
        QueuePriority::Critical
    } else if action.contains("High") {
        QueuePriority::High
    } else if action.contains("Medium") {
        QueuePriority::Medium
    } else {
        QueuePriority::Low
    }
}

fn parse_remote_filter_result(value: &serde_json::Value) -> Option<FilterResult> {
    let severity = match value["severity"].as_str().unwrap_or("Notice") {
        "Critical" | "critical" => Severity::Critical,
        "Error" | "error" => Severity::Error,
        "Warning" | "warning" => Severity::Warning,
        _ => Severity::Notice,
    };
    Some(FilterResult {
        filter_name: value["filter_name"].as_str()?.to_string(),
        matched: value["matched"].as_bool()?,
        score: value["score"].as_f64()?,
        rule_id: value["rule_id"].as_str().unwrap_or_default().to_string(),
        severity,
        message: value["message"].as_str().unwrap_or_default().to_string(),
        metadata: std::collections::HashMap::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DnsProxyQueueAction;
    use std::sync::atomic::{AtomicBool, Ordering};

    use grith_proxy::filters::{FilterPhase, FilterRegistry, SecurityFilter};
    use grith_proxy::meta_rules::MetaRuleEngine;
    use grith_proxy::scoring::ScoringConfig;
    use grith_proxy::types::{FilterResult, QueuePriority};

    use crate::connected_dns_proxy::{ConnectedDnsRouteId, DnsRouteProvenance};

    struct FixedFilter {
        result: FilterResult,
    }

    #[async_trait]
    impl SecurityFilter for FixedFilter {
        fn name(&self) -> &str {
            "dns-decision-test"
        }

        fn phase(&self) -> FilterPhase {
            FilterPhase::Static
        }

        async fn evaluate(
            &self,
            _ctx: &ToolCallContext,
        ) -> grith_proxy::error::Result<FilterResult> {
            Ok(self.result.clone())
        }
    }

    #[derive(Default)]
    struct FakeAuditSink {
        records: Mutex<Vec<AuditRecord>>,
        fail_required: AtomicBool,
    }

    #[async_trait]
    impl AuditSink for FakeAuditSink {
        async fn log(&self, record: AuditRecord) -> Result<(), String> {
            self.records.lock().unwrap().push(record);
            Ok(())
        }

        async fn log_required(&self, record: AuditRecord) -> Result<(), String> {
            if self.fail_required.load(Ordering::Relaxed) {
                return Err("full".into());
            }
            self.records.lock().unwrap().push(record);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeDigestStore {
        items: Mutex<Vec<DigestItem>>,
        fail_enqueue: AtomicBool,
    }

    #[async_trait]
    impl DigestStore for FakeDigestStore {
        async fn enqueue(&self, item: &DigestItem) -> Result<(), String> {
            if self.fail_enqueue.load(Ordering::Relaxed) {
                return Err("closed".into());
            }
            self.items.lock().unwrap().push(item.clone());
            Ok(())
        }

        async fn get(&self, _item_id: Uuid) -> Result<Option<DigestItem>, String> {
            Ok(None)
        }

        async fn update_status(
            &self,
            _item_id: Uuid,
            _status: DigestStatus,
            _review_action: Option<&str>,
            _reviewer_notes: Option<&str>,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    fn proxy_with_score(score: Option<f64>) -> Arc<SecurityProxy> {
        let mut registry = FilterRegistry::new();
        if let Some(score) = score {
            registry.register(Box::new(FixedFilter {
                result: FilterResult::matched(
                    "dns-decision-test",
                    "fixed",
                    score,
                    if score > 8.0 {
                        Severity::Critical
                    } else {
                        Severity::Warning
                    },
                    "fixed DNS decision",
                ),
            }));
        }
        Arc::new(SecurityProxy::new(
            registry,
            ScoringConfig::default(),
            MetaRuleEngine::new(Vec::new()),
        ))
    }

    fn session() -> DnsDecisionSession {
        DnsDecisionSession {
            session_id: Uuid::new_v4(),
            tool_name: "test-tool".into(),
            profile_name: Some("test-profile".into()),
            project_name: Some("test-project".into()),
            root_pid: 123,
        }
    }

    fn request(domain: &str) -> DnsDecisionRequest {
        DnsDecisionRequest {
            route_id: ConnectedDnsRouteId(7),
            provenance: DnsRouteProvenance {
                tgid: 123,
                creator_tid: 124,
                socket_id: 9,
            },
            original_resolver: "127.0.0.53:53".parse().unwrap(),
            transaction_id: 42,
            domain: domain.into(),
            query_type: "A".into(),
            queue_action: DnsProxyQueueAction::Refuse,
        }
    }

    fn service(
        score: Option<f64>,
        audit: Arc<FakeAuditSink>,
        digest: Arc<FakeDigestStore>,
        allowed: HashSet<String>,
    ) -> ProductionDnsDecisionService {
        ProductionDnsDecisionService::new(
            proxy_with_score(score),
            audit,
            digest,
            Arc::new(Mutex::new(allowed)),
            Arc::new(ContainmentTracker::with_defaults()),
            session(),
        )
    }

    #[tokio::test]
    async fn allow_requires_successful_required_audit_enqueue() {
        let audit = Arc::new(FakeAuditSink::default());
        audit.fail_required.store(true, Ordering::Relaxed);
        let digest = Arc::new(FakeDigestStore::default());
        let decision = service(None, audit, digest, HashSet::new())
            .evaluate(request("safe.example"))
            .await;
        assert!(matches!(
            decision,
            DnsDecision::InfrastructureFailure { .. }
        ));
    }

    #[tokio::test]
    async fn allow_is_returned_only_after_audit_is_recorded() {
        let audit = Arc::new(FakeAuditSink::default());
        let digest = Arc::new(FakeDigestStore::default());
        let decision = service(None, Arc::clone(&audit), digest, HashSet::new())
            .evaluate(request("safe.example"))
            .await;
        assert_eq!(decision, DnsDecision::Allow);
        let records = audit.records.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].proxy_action.to_string(), "allow");
        assert!(records[0]
            .arguments_summary
            .contains("\"transport\":\"connected_udp_proxy\""));
    }

    #[tokio::test]
    async fn allowlist_uses_label_boundary_and_bypasses_deny_filter() {
        let audit = Arc::new(FakeAuditSink::default());
        let digest = Arc::new(FakeDigestStore::default());
        let allowed = HashSet::from(["net:example.com".to_string()]);
        let service = service(Some(9.0), Arc::clone(&audit), digest, allowed);

        assert_eq!(
            service.evaluate(request("api.example.com.")).await,
            DnsDecision::Allow
        );
        assert!(matches!(
            service.evaluate(request("example.com.evil")).await,
            DnsDecision::Deny { .. }
        ));
        assert_eq!(audit.records.lock().unwrap().len(), 2);
    }

    /// W4: an allowlisted parent zone must not blind-allow a tunnelling-shaped
    /// subdomain. A normal label short-circuits to Allow (proxy not consulted,
    /// even though the fake proxy would deny); an encoded high-entropy label
    /// under the SAME parent defers to the proxy and is denied.
    #[tokio::test]
    async fn allowlisted_parent_still_scores_dns_tunnelling_subdomain() {
        let audit = Arc::new(FakeAuditSink::default());
        let digest = Arc::new(FakeDigestStore::default());
        let allowed = HashSet::from(["net:example.com".to_string()]);
        let service = service(Some(9.0), Arc::clone(&audit), digest, allowed);

        // Routine label under the allowlisted parent → short-circuit Allow.
        assert_eq!(
            service.evaluate(request("api.example.com.")).await,
            DnsDecision::Allow
        );
        // Encoded 34-char label under the same allowlisted parent → the gate
        // defers to the proxy (score 9.0) instead of blind-allowing → Deny.
        assert!(matches!(
            service
                .evaluate(request("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7.example.com."))
                .await,
            DnsDecision::Deny { .. }
        ));
    }

    #[tokio::test]
    async fn containment_disables_dns_session_allowlist_shortcut() {
        let audit = Arc::new(FakeAuditSink::default());
        let digest = Arc::new(FakeDigestStore::default());
        let containment = Arc::new(ContainmentTracker::with_defaults());
        let session = session();
        containment.register(session.session_id, std::time::Instant::now());
        let service = ProductionDnsDecisionService::new(
            proxy_with_score(Some(9.0)),
            audit.clone(),
            digest,
            Arc::new(Mutex::new(HashSet::from(["net:example.com".to_string()]))),
            containment,
            session,
        );

        assert!(matches!(
            service.evaluate(request("api.example.com")).await,
            DnsDecision::Deny { .. }
        ));
        assert_eq!(audit.records.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn queue_must_enqueue_digest_before_returning_queue() {
        let audit = Arc::new(FakeAuditSink::default());
        let digest = Arc::new(FakeDigestStore::default());
        let decision = service(Some(5.0), audit, Arc::clone(&digest), HashSet::new())
            .evaluate(request("review.example"))
            .await;

        assert!(matches!(decision, DnsDecision::Queue { .. }));
        assert_eq!(digest.items.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn digest_enqueue_failure_is_infrastructure_failure() {
        let audit = Arc::new(FakeAuditSink::default());
        let digest = Arc::new(FakeDigestStore::default());
        digest.fail_enqueue.store(true, Ordering::Relaxed);
        let decision = service(Some(5.0), Arc::clone(&audit), digest, HashSet::new())
            .evaluate(request("review.example"))
            .await;

        assert!(matches!(
            decision,
            DnsDecision::InfrastructureFailure { .. }
        ));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn queue_requires_audit_enqueue_after_digest_enqueue() {
        let audit = Arc::new(FakeAuditSink::default());
        audit.fail_required.store(true, Ordering::Relaxed);
        let digest = Arc::new(FakeDigestStore::default());
        let decision = service(
            Some(5.0),
            Arc::clone(&audit),
            Arc::clone(&digest),
            HashSet::new(),
        )
        .evaluate(request("review.example"))
        .await;

        assert!(matches!(
            decision,
            DnsDecision::InfrastructureFailure { .. }
        ));
        assert_eq!(digest.items.lock().unwrap().len(), 1);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn audit_and_digest_fields_are_redacted() {
        let audit = Arc::new(FakeAuditSink::default());
        let digest = Arc::new(FakeDigestStore::default());
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let decision = service(
            Some(5.0),
            Arc::clone(&audit),
            Arc::clone(&digest),
            HashSet::new(),
        )
        .evaluate(request(&format!("{secret}.example")))
        .await;

        assert!(matches!(decision, DnsDecision::Queue { .. }));
        let records = audit.records.lock().unwrap();
        let record = &records[0];
        assert!(!record.tool_call_type.contains(secret));
        assert!(!record.arguments_summary.contains(secret));
        drop(records);
        let items = digest.items.lock().unwrap();
        let item = &items[0];
        assert!(!item.tool_call_type.contains(secret));
        assert!(!item.arguments_summary.contains(secret));
    }

    #[test]
    fn remote_queue_priority_parser_matches_daemon_protocol() {
        let body = serde_json::json!({
            "composite_score": 6.0,
            "action": "queue:High",
            "decision_reason": "review",
            "filter_results": [],
            "evaluation_time_ms": 1.0
        });
        let parsed = parse_remote_decision(&body).unwrap();
        assert_eq!(
            parsed.action,
            ProxyAction::Queue {
                priority: QueuePriority::High
            }
        );
    }

    #[test]
    fn malformed_remote_filter_result_fails_closed() {
        let body = serde_json::json!({
            "composite_score": 0.0,
            "action": "allow",
            "decision_reason": "safe",
            "filter_results": [{
                "filter_name": "broken",
                "matched": true
            }],
            "evaluation_time_ms": 1.0
        });
        assert!(parse_remote_decision(&body).is_err());
    }
}
