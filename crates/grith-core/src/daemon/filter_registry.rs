// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Security filter registry construction.
//!
//! Builds the [`FilterRegistry`] with all built-in filters (Phase 1 static,
//! Phase 2 pattern, Phase 3 context) and the [`MetaRuleEngine`] for composite
//! score adjustments.

use grith_proxy::filters::allowlist::AllowlistFilter;
use grith_proxy::filters::argument::ArgumentFilter;
use grith_proxy::filters::behavioural::BehaviouralFilter;
use grith_proxy::filters::canary::{CanaryFilter, CanaryRegistry};
use grith_proxy::filters::capability::CapabilityFilter;
use grith_proxy::filters::command::CommandFilter;
use grith_proxy::filters::destructive_action::DestructiveActionFilter;
use grith_proxy::filters::dlp_gate::{DlpGateFilter, DlpRedactor};
use grith_proxy::filters::egress_policy::EgressPolicyFilter;
use grith_proxy::filters::egress_rate::EgressRateFilter;
use grith_proxy::filters::operation_risk::OperationRiskFilter;
use grith_proxy::filters::path_match::PathMatchFilter;
use grith_proxy::filters::rate_limit::RateLimitFilter;
use grith_proxy::filters::reputation::ReputationFilter;
use grith_proxy::filters::secret_scan::SecretScanFilter;
use grith_proxy::filters::sensitive_path::SensitivePathHeuristicFilter;
use grith_proxy::filters::session_containment::{ContainmentTracker, SessionContainmentFilter};
use grith_proxy::filters::taint::TaintFilter;
use grith_proxy::filters::FilterRegistry;
use grith_proxy::meta_rules::MetaRuleEngine;
use std::sync::Arc;

use super::config_loader;
use crate::config::{FilterGroupConfig, ProxyConfig};

/// Build the complete security filter registry with all phases.
///
/// Returns the registry, the session containment tracker, the canary registry,
/// and the DLP redactor -- all of which are needed by the daemon for various
/// subsystems beyond the proxy itself.
///
pub(crate) fn build_filter_registry_with_config_result(
    proxy_cfg: &ProxyConfig,
) -> Result<
    (
        FilterRegistry,
        Arc<ContainmentTracker>,
        Arc<CanaryRegistry>,
        Arc<DlpRedactor>,
    ),
    crate::error::Error,
> {
    let filter_cfg: &FilterGroupConfig = &proxy_cfg.filters;
    let mut registry = FilterRegistry::new();

    // Phase 1 (Static)
    // PR 4 Phase H: pass the routine_provenance_signal config flag.
    // Default is false until operators flip it via `proxy.spawn.
    // routine_provenance_signal = true`. See PR 4 work-doc rollout.
    registry.register(Box::new(OperationRiskFilter::with_routine_signal(
        proxy_cfg.spawn.routine_provenance_signal,
    )));
    registry.register(Box::new(PathMatchFilter::new(
        config_loader::load_path_rules()?,
    )));
    registry.register(Box::new(SensitivePathHeuristicFilter::new()));
    registry.register(Box::new(AllowlistFilter::new(
        config_loader::load_allowlist_config(),
    )));
    registry.register(Box::new(ArgumentFilter::new()));
    match config_loader::load_capability_grants() {
        config_loader::CapabilityGrantsLoad::Grants(grants) => {
            registry.register(Box::new(CapabilityFilter::new(grants)));
        }
        config_loader::CapabilityGrantsLoad::ConfigError(err) => {
            return Err(crate::error::Error::Config(format!(
                "required config/filters/capabilities.toml unavailable: {err}"
            )));
        }
    }

    // Phase 2 (Pattern) — load configs and build filters in parallel since
    // each is independent (different TOML files, separate regex compilation).
    // SecretScanFilter dominates: 1600+ patterns → single RegexSet compile pass.
    let (secret_filter, command_filter, egress_config, dlp_config, canary_config) =
        std::thread::scope(|s| {
            let t_secret = s.spawn(config_loader::load_secret_patterns);
            let t_command = s.spawn(config_loader::load_command_rules);
            let t_egress = s.spawn(|| {
                let mut cfg = config_loader::load_egress_policy_config()?;
                if cfg.profile_trusted_domains.is_empty() {
                    cfg.profile_trusted_domains = config_loader::build_profile_trusted_domains()?;
                }
                Ok::<_, crate::error::Error>(cfg)
            });
            let t_dlp = s.spawn(config_loader::load_dlp_gate_config);
            let t_canary = s.spawn(config_loader::load_canary_config);
            (
                t_secret.join().expect("secret filter thread panicked"),
                t_command.join().expect("command filter thread panicked"),
                t_egress.join().expect("egress config thread panicked"),
                t_dlp.join().expect("dlp config thread panicked"),
                t_canary.join().expect("canary config thread panicked"),
            )
        });

    registry.register(Box::new(SecretScanFilter::new(secret_filter?)));
    registry.register(Box::new(CommandFilter::new(command_filter?)));
    // Work item 68: destructive-action coverage. Default-on; hard-denies
    // catastrophic host/storage destruction and escalates
    // destructive-against-production to DENY.
    if proxy_cfg.destructive_action.enabled {
        registry.register(Box::new(DestructiveActionFilter::new()));
    }
    let egress_config = egress_config?;
    // Share the egress-policy trust sets with the egress-rate filter so routine/
    // allowlisted destinations are excluded from its volumetric burst/rate
    // counters (A#2). Cloned before `egress_config` is moved into the policy
    // filter below.
    let egress_rate_trusted_domains = egress_config.trusted_domains.clone();
    let egress_rate_profile_trusted = egress_config.profile_trusted_domains.clone();
    if egress_config.enabled {
        registry.register(Box::new(EgressPolicyFilter::from_config(egress_config)));
    }
    let dlp_config = dlp_config?;
    let dlp_filter = DlpGateFilter::from_config(dlp_config.clone());
    let dlp_redactor = Arc::new(dlp_filter.redactor());
    if dlp_config.enabled {
        registry.register(Box::new(dlp_filter));
    }
    let canary_config = canary_config?;
    let canary_registry = Arc::new(CanaryRegistry::new(canary_config.tokens));
    if canary_config.enabled {
        registry.register(Box::new(CanaryFilter::new(canary_registry.clone())));
    }

    // Phase 3 (Context) — respect per-filter enable/disable toggles
    if filter_cfg.reputation.enabled {
        let (malicious, safe) = config_loader::load_reputation_domains()?;
        registry.register(Box::new(ReputationFilter::new(malicious, safe)));
    }
    if filter_cfg.behavioural.enabled {
        // PR 69 Change 1: honour the operator-supplied min_calls_for_baseline
        // and deviation scores from `[proxy.filters.behavioural]` instead
        // of the previous hard-coded `BehaviouralFilter::new(20)`.
        registry.register(Box::new(BehaviouralFilter::from_config(
            &filter_cfg.behavioural.to_proxy_config(),
        )));
    }
    if filter_cfg.taint.enabled {
        registry.register(Box::new(
            TaintFilter::with_defaults()
                .with_spawn_data_flow_only(proxy_cfg.spawn.taint_data_flow_only)
                .with_outbound_taint_requires_data_flow(
                    proxy_cfg.spawn.taint_outbound_requires_data_flow,
                ),
        ));
    }
    let containment_config = config_loader::load_session_containment_config()?;
    let containment_tracker =
        if containment_config.enabled && filter_cfg.session_containment.enabled {
            let (filter, tracker) = SessionContainmentFilter::from_config(containment_config);
            registry.register(Box::new(filter));
            tracker
        } else {
            Arc::new(ContainmentTracker::with_defaults())
        };
    if filter_cfg.rate_limit.enabled {
        // Default is false until operators flip it via `proxy.rate_limit.
        // risk_gated_burst` — and only after the target-aware delete-spread
        // signal lands (see work/futurework/rate-limit-burst-redesign.md).
        registry.register(Box::new(
            RateLimitFilter::with_defaults()
                .with_risk_gated_burst(proxy_cfg.rate_limit.risk_gated_burst),
        ));
    }
    // Operator-tunable since the egress-rate knobs were plumbed through; this
    // used to be `EgressRateConfig::default()`, so nothing an operator wrote
    // could reach the filter.
    let egress_rate_config = filter_cfg.egress_rate.to_proxy_config();
    if filter_cfg.egress_rate.enabled && !filter_cfg.egress.enabled {
        tracing::warn!(
            "[proxy.filters.egress_rate] enabled = true has no effect while \
             [proxy.filters.egress] enabled = false - the latter is the master \
             switch for both egress filters"
        );
    }
    if egress_rate_config.enabled && filter_cfg.egress.enabled {
        registry.register(Box::new(EgressRateFilter::from_config_with_trust(
            egress_rate_config,
            egress_rate_trusted_domains,
            egress_rate_profile_trusted,
        )));
    }
    // SemanticFilter is intentionally not registered — it requires an embedding
    // model integration that is not yet implemented. See work/todos/semantic-filter-roadmap.md.

    Ok((registry, containment_tracker, canary_registry, dlp_redactor))
}

pub(crate) fn build_meta_rule_engine_result() -> Result<MetaRuleEngine, crate::error::Error> {
    let rules = config_loader::load_meta_rules()?;
    Ok(MetaRuleEngine::new(rules))
}
