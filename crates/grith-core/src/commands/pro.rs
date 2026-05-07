// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! `grith pro` subcommand — license authentication, status, and plan management.

use crate::daemon::background::{run_license_refresh, RefreshOutcome};
use crate::{daemon, license};

const DEFAULT_BILLING_PORTAL_URL: &str = "https://grith.ai/dashboard/settings/billing";

pub fn cmd_pro_login(api_key: Option<&str>) -> anyhow::Result<()> {
    let base_url = license::api_base_url();
    if let Some(key) = api_key {
        println!("Authenticating with {base_url}...");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let signed = runtime.block_on(async { license::fetch_license(key).await })?;
        return complete_login_from_license(key, signed);
    }

    println!("Starting browser-based device authorization with {base_url}...");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let start = runtime.block_on(async { license::start_device_authorization().await })?;

    println!();
    println!("Open this URL in your browser and sign in:");
    println!("  {}", start.verification_url);
    println!();
    println!("Enter this code on the webpage:");
    println!("  {}", start.user_code);
    println!();
    println!("Waiting for authorization...");

    if let Err(e) = open::that(&start.verification_url) {
        println!("Could not open browser automatically: {e}");
    }

    let expires_at = std::time::Instant::now() + std::time::Duration::from_secs(start.expires_in);
    let poll_interval = std::time::Duration::from_secs(start.interval.max(1));

    loop {
        if std::time::Instant::now() >= expires_at {
            anyhow::bail!(
                "device authorization timed out; run `grith pro login` again for a new code"
            );
        }

        let (status, payload) = runtime
            .block_on(async { license::poll_device_authorization(&start.device_code).await })?;

        match status {
            license::DeviceAuthPollStatus::Pending => {
                std::thread::sleep(poll_interval);
            }
            license::DeviceAuthPollStatus::Expired => {
                anyhow::bail!("device code expired; run `grith pro login` to generate a new code");
            }
            license::DeviceAuthPollStatus::Approved => {
                let Some(payload) = payload else {
                    anyhow::bail!("authorization completed but no device payload was returned");
                };
                println!("Authorization complete.");
                return complete_login_from_license(&payload.api_key, payload.license);
            }
        }
    }
}

pub(crate) fn persist_team_learned_rules_cache(
    rules: &[crate::license::LearnedRuleResponse],
) -> anyhow::Result<std::path::PathBuf> {
    let cache_path = grith_supervisor::learned_rules::team_learned_rules_cache_path();
    let cache_rules: Vec<grith_supervisor::learned_rules::TeamLearnedRule> = rules
        .iter()
        .map(|rule| grith_supervisor::learned_rules::TeamLearnedRule {
            pattern: rule.pattern.clone(),
            profile: rule.profile.clone(),
            scope: rule.scope.clone(),
            reason: rule.reason.clone(),
            created_by: rule.created_by.clone(),
            created_at: rule.created_at.clone(),
        })
        .collect();

    grith_supervisor::learned_rules::write_team_learned_rules_cache(&cache_path, &cache_rules)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(cache_path)
}

fn complete_login_from_license(
    api_key: &str,
    signed: license::SignedLicense,
) -> anyhow::Result<()> {
    let license_bytes = serde_json::to_vec(&signed)?;
    let verified = license::verify_license(&license_bytes)
        .map_err(|e| anyhow::anyhow!("license verification failed: {e}"))?;

    let lic_path = license::save_license(&signed)
        .map_err(|e| anyhow::anyhow!("failed to save license: {e}"))?;

    let creds = license::Credentials {
        user_id: verified.user_id.clone(),
        api_key: api_key.to_string(),
        team_id: verified.team_id.clone(),
        license_file: lic_path.display().to_string(),
        activated_at: chrono::Utc::now().to_rfc3339(),
        last_validated: chrono::Utc::now().to_rfc3339(),
        last_synced: None,
    };
    license::save_credentials(&creds)
        .map_err(|e| anyhow::anyhow!("failed to save credentials: {e}"))?;

    println!("Logged in successfully.");
    println!("  Plan:    {}", verified.plan);
    println!("  Email:   {}", verified.email);
    println!("  Team:    {}", verified.team_id);
    println!("  Expires: {}", verified.valid_until.format("%Y-%m-%d"));
    println!("  License: {}", lic_path.display());
    Ok(())
}

pub fn cmd_pro_status() -> anyhow::Result<()> {
    let creds = license::load_credentials().map_err(|e| anyhow::anyhow!("{e}"))?;

    let Some(creds) = creds else {
        println!("Not logged in.");
        println!("  Run: grith pro login");
        println!("       or: grith pro login --api-key <key>");
        return Ok(());
    };

    let status = license::load_license(&license::license_path());
    let tier = license::plan_tier_from_status(&status);
    let dashboard_url = format!("{}/dashboard/settings", license::api_base_url());
    let billing_url = license::billing_portal_url_from_status(&status)
        .unwrap_or_else(|| DEFAULT_BILLING_PORTAL_URL.to_string());

    let air_gapped = matches!(
        status,
        license::LicenseStatus::Valid(ref l)
        | license::LicenseStatus::GracePeriod { license: ref l, .. }
        | license::LicenseStatus::ExtendedGrace { license: ref l, .. }
            if l.air_gapped
    );

    match &status {
        license::LicenseStatus::Valid(lic) => {
            let days = license::days_until_expiry(lic);
            println!("Plan:       {} ({})", lic.plan, tier);
            println!("Email:      {}", lic.email);
            println!("Team:       {}", lic.team_id);
            println!("Seats:      {}", lic.seats);
            println!(
                "Renewal:    {} ({days} days remaining)",
                lic.valid_until.format("%Y-%m-%d")
            );
            println!("Status:     Active");
            println!("Billing:    {billing_url}");
            if !lic.features.is_empty() {
                println!("Features:   {}", lic.features.join(", "));
            }
        }
        license::LicenseStatus::GracePeriod {
            license: lic,
            expired_days,
        } => {
            println!("Plan:       {} ({})", lic.plan, tier);
            println!("Email:      {}", lic.email);
            println!("Seats:      {}", lic.seats);
            println!("Status:     Grace period ({expired_days} day(s) past expiry)");
            println!("Billing:    {billing_url}");
            println!("            Run: grith pro refresh");
        }
        license::LicenseStatus::ExtendedGrace {
            license: lic,
            expired_days,
        } => {
            println!("Plan:       {} ({})", lic.plan, tier);
            println!("Email:      {}", lic.email);
            println!("Seats:      {}", lic.seats);
            println!("Status:     Extended grace ({expired_days} day(s) past expiry)");
            println!("Billing:    {billing_url}");
            println!("            Renew at {dashboard_url}");
        }
        license::LicenseStatus::Expired => {
            println!("Plan:       community (expired)");
            println!("Status:     License expired beyond grace window. Pro features disabled.");
            println!("            Renew at {dashboard_url}");
        }
        license::LicenseStatus::NotFound => {
            println!("Plan:       community");
            println!("Status:     No license file found.");
            println!("            Run: grith pro activate");
        }
        license::LicenseStatus::Invalid(reason) => {
            println!("Plan:       community");
            println!("Status:     Invalid license: {reason}");
            println!("            Run: grith pro activate");
        }
    }

    let validated = creds.last_validated.clone();
    let validated_dt = chrono::DateTime::parse_from_rfc3339(&validated)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc));
    let hours_since = validated_dt.map(|dt| (chrono::Utc::now() - dt).num_hours());
    if let Some(hours) = hours_since {
        println!("Validated:  {validated} ({hours}h ago)");
    } else {
        println!("Validated:  {validated}");
    }

    if air_gapped {
        println!("Refresh:    disabled (air-gapped contract licence)");
    } else if let Some(daemon_state) = fetch_remote_refresh_state() {
        if let Some(next) = daemon_state.refresh.next_attempt.as_ref() {
            println!("Next refresh: {next}");
        }
        if let (Some(when), Some(kind)) = (
            daemon_state.refresh.last_failure.as_ref(),
            daemon_state.refresh.last_failure_kind.as_ref(),
        ) {
            let reason = daemon_state
                .refresh
                .last_failure_reason
                .as_deref()
                .unwrap_or("");
            println!("Last failure: {when} [{kind}] {reason}");
        }
    } else {
        println!("Refresh:    daemon not running (start with `grith run` to schedule refreshes)");
    }

    if let Some(synced) = &creds.last_synced {
        println!("Last sync:  {synced}");
    }

    Ok(())
}

#[derive(serde::Deserialize)]
struct RemoteRefreshSnapshot {
    refresh: RemoteRefresh,
}

#[derive(serde::Deserialize)]
struct RemoteRefresh {
    next_attempt: Option<String>,
    last_failure: Option<String>,
    last_failure_kind: Option<String>,
    last_failure_reason: Option<String>,
}

fn fetch_remote_refresh_state() -> Option<RemoteRefreshSnapshot> {
    let (_pid, port) = daemon::is_dashboard_running()?;
    let url = format!("http://127.0.0.1:{port}/api/license/status");
    let resp = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .ok()?
        .get(url)
        .send()
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<RemoteRefreshSnapshot>().ok()
}

pub fn cmd_pro_upgrade() -> anyhow::Result<()> {
    let status = license::load_license(&license::license_path());
    if matches!(status, license::LicenseStatus::Valid(_)) {
        println!("Already on Pro plan.");
        return Ok(());
    }

    let url = "https://grith.ai/pricing";
    println!("Opening grith.ai/pricing in your browser...");
    if let Err(e) = open::that(url) {
        println!("Could not open browser: {e}");
        println!("Visit: {url}");
    }
    Ok(())
}

pub fn cmd_pro_billing() -> anyhow::Result<()> {
    let creds = license::load_credentials().map_err(|e| anyhow::anyhow!("{e}"))?;
    let Some(_creds) = creds else {
        anyhow::bail!("Not logged in. Run: grith pro login");
    };

    let status = license::load_license(&license::license_path());
    let tier = license::plan_tier_from_status(&status);
    let url = license::billing_portal_url_from_status(&status)
        .unwrap_or_else(|| DEFAULT_BILLING_PORTAL_URL.to_string());

    match &status {
        license::LicenseStatus::Valid(lic)
        | license::LicenseStatus::GracePeriod { license: lic, .. }
        | license::LicenseStatus::ExtendedGrace { license: lic, .. } => {
            println!("Plan:       {} ({})", lic.plan, tier);
            println!("Seats:      {}", lic.seats);
            println!("Renewal:    {}", lic.valid_until.format("%Y-%m-%d"));
            println!("Team:       {}", lic.team_id);
        }
        _ => {
            println!("Plan:       community");
        }
    }

    println!();
    println!("Opening billing portal in your browser...");
    if let Err(e) = open::that(&url) {
        println!("Could not open browser: {e}");
        println!("Visit: {url}");
    }
    Ok(())
}

pub fn cmd_pro_activate() -> anyhow::Result<()> {
    let creds = license::load_credentials().map_err(|e| anyhow::anyhow!("{e}"))?;
    let Some(mut creds) = creds else {
        anyhow::bail!("Not logged in. Run: grith pro login");
    };

    println!("Fetching license from {}...", license::api_base_url());

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let signed = runtime
        .block_on(async { license::fetch_license(&creds.api_key).await })
        .map_err(|e| anyhow::anyhow!("failed to fetch license: {e}"))?;

    let license_bytes = serde_json::to_vec(&signed)?;
    let verified = license::verify_license(&license_bytes)
        .map_err(|e| anyhow::anyhow!("license verification failed: {e}"))?;
    let lic_path = license::save_license(&signed)
        .map_err(|e| anyhow::anyhow!("failed to save license: {e}"))?;

    creds.last_validated = chrono::Utc::now().to_rfc3339();
    creds.license_file = lic_path.display().to_string();
    license::save_credentials(&creds)
        .map_err(|e| anyhow::anyhow!("failed to save credentials: {e}"))?;

    let days = license::days_until_expiry(&verified);
    println!("License activated.");
    println!("  Plan:    {}", verified.plan);
    println!(
        "  Expires: {} ({days} days remaining)",
        verified.valid_until.format("%Y-%m-%d")
    );

    Ok(())
}

pub fn cmd_pro_refresh() -> anyhow::Result<()> {
    let creds = license::load_credentials().map_err(|e| anyhow::anyhow!("{e}"))?;
    let Some(creds) = creds else {
        anyhow::bail!("Not logged in. Run: grith pro login");
    };

    println!("Refreshing license against {}...", license::api_base_url());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    match runtime.block_on(async { run_license_refresh(&creds).await }) {
        RefreshOutcome::Replaced => {
            println!("License refreshed.");
            print_post_refresh_summary();
            Ok(())
        }
        RefreshOutcome::Hard(kind, reason) => {
            println!("Refresh rejected ({kind}): {reason}.", kind = kind.as_str());
            println!("Cached license is retained until natural expiry.");
            anyhow::bail!("license refresh hard failure");
        }
        RefreshOutcome::Transient(reason) => {
            println!("Refresh failed (transient): {reason}.");
            println!("Cached license is retained; the daemon will retry automatically.");
            anyhow::bail!("license refresh transient failure");
        }
    }
}

fn print_post_refresh_summary() {
    let status = license::load_license(&license::license_path());
    if let license::LicenseStatus::Valid(lic) = &status {
        let days = license::days_until_expiry(lic);
        println!("  Plan:    {}", lic.plan);
        println!(
            "  Expires: {} ({days} days remaining)",
            lic.valid_until.format("%Y-%m-%d")
        );
        if lic.air_gapped {
            println!("  Mode:    air-gapped (scheduled refresh disabled)");
        }
    }
}

pub fn cmd_pro_logout() -> anyhow::Result<()> {
    license::remove_credentials().map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("Logged out. Pro features disabled on next start.");
    Ok(())
}

pub fn cmd_pro_sync(daemon: &daemon::Daemon) -> anyhow::Result<()> {
    let creds = license::load_credentials().map_err(|e| anyhow::anyhow!("{e}"))?;
    let Some(mut creds) = creds else {
        anyhow::bail!("Not logged in. Run: grith pro login");
    };

    let status = license::load_license(&license::license_path());
    let tier = license::plan_tier_from_status(&status);
    if tier == "community" {
        anyhow::bail!("Sync requires an active Pro license. Run: grith pro activate");
    }

    let since = creds
        .last_synced
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|| chrono::Utc::now() - chrono::Duration::days(30));

    let storage = daemon
        .audit_storage
        .lock()
        .map_err(|_| anyhow::anyhow!("audit storage lock poisoned"))?;
    let records = grith_audit::AuditQuery::new()
        .since(since)
        .paginate(1000, 0)
        .execute(&storage)
        .map_err(|e| anyhow::anyhow!("audit query failed: {e}"))?;
    drop(storage);

    let sync_records: Vec<license::SyncRecord> = records
        .iter()
        .map(|r| license::SyncRecord {
            tool_call_type: r.tool_call_type.clone(),
            composite_score: r.composite_score,
            proxy_action: format!("{:?}", r.proxy_action).to_lowercase(),
            filter_scores: r.filter_scores.clone(),
            timestamp: r.timestamp.to_rfc3339(),
            session_id: Some(r.session_id.to_string()),
            project_name: r.task_context.clone(),
            llm_provider: r.llm_provider.clone(),
            llm_model: r.llm_model.clone(),
            prompt_tokens: r.prompt_tokens,
            completion_tokens: r.completion_tokens,
            estimated_cost_usd: r.estimated_cost_usd,
        })
        .collect();

    let record_count = sync_records.len();

    if record_count == 0 {
        println!("No new audit records to sync.");
    } else {
        println!("Syncing {record_count} audit records...");

        /// Maximum records per sync API call (stays under CloudFront WAF body size limits).
        const AUDIT_SYNC_BATCH_LIMIT: usize = 25;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let mut synced = 0usize;
        for chunk in sync_records.chunks(AUDIT_SYNC_BATCH_LIMIT) {
            runtime
                .block_on(async { license::sync_records(&creds, chunk.to_vec()).await })
                .map_err(|e| anyhow::anyhow!("sync failed: {e}"))?;
            synced += chunk.len();
            if synced < record_count {
                print!("\r  {synced}/{record_count} synced...");
                std::io::Write::flush(&mut std::io::stdout()).ok();
            }
        }

        println!("\rSynced {record_count} records.     ");
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    match runtime.block_on(async { license::fetch_policies(&creds).await }) {
        Ok(policy) => {
            let dir = license::policies_dir();
            std::fs::create_dir_all(&dir)?;
            if let Some(safe_name) = license::sanitize_sync_name(&policy.name) {
                let policy_path = dir.join(format!("{safe_name}.json"));
                std::fs::write(&policy_path, serde_json::to_string_pretty(&policy.content)?)?;
                println!(
                    "Policy: {} v{} -> {}",
                    policy.name,
                    policy.version,
                    policy_path.display()
                );
            } else {
                tracing::warn!(name = %policy.name, "skipping policy with unsafe name");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to fetch team policies");
        }
    }

    match runtime.block_on(async { license::fetch_configs(&creds).await }) {
        Ok(configs) => {
            if configs.is_empty() {
                println!("No shared configs to pull.");
            } else {
                let dir = license::configs_dir();
                std::fs::create_dir_all(&dir)?;
                for config in &configs {
                    let Some(safe_name) = license::sanitize_sync_name(&config.name) else {
                        tracing::warn!(name = %config.name, "skipping config with unsafe name");
                        continue;
                    };
                    let config_path = dir.join(format!("{safe_name}.json"));
                    std::fs::write(&config_path, serde_json::to_string_pretty(&config.config)?)?;
                    println!("Config: {} -> {}", config.name, config_path.display());
                }
                println!("Pulled {} shared config(s).", configs.len());
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to fetch shared configs");
        }
    }

    match runtime.block_on(async { license::fetch_provider_keys(&creds).await }) {
        Ok(keys) => {
            let report = license::reconcile_provider_key_files(
                &creds.api_key,
                &license::provider_keys_dir(),
                &keys,
            )
            .map_err(|e| anyhow::anyhow!("sync provider keys: {e}"))?;

            if report.written.is_empty() {
                if report.revoked.is_empty() {
                    println!("No provider keys to pull.");
                } else {
                    println!("Removed {} revoked provider key(s).", report.revoked.len());
                }
            } else {
                for entry in &report.written {
                    println!(
                        "Provider key: {} ({}) -> {} [encrypted]",
                        entry.provider,
                        entry.label,
                        entry.path.display()
                    );
                }
                println!("Pulled {} provider key(s).", report.written.len());
                if !report.revoked.is_empty() {
                    println!("Removed {} revoked provider key(s).", report.revoked.len());
                }
            }
            if report.skipped_unsafe > 0 {
                println!(
                    "Skipped {} provider key(s) with unsafe names.",
                    report.skipped_unsafe
                );
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to fetch provider keys");
        }
    }

    // ---- Push reputation data ----
    {
        let rep_path = grith_proxy::reputation::default_reputation_path();
        let table = grith_proxy::reputation::ReputationTable::load(&rep_path);
        let entries: Vec<serde_json::Value> = table
            .entries
            .iter()
            .filter(|(_, entry)| entry.observation_count() >= 3.0)
            .map(|(key, entry)| {
                // Infer level from the path segment of the key.
                // Key format: profile|action|process|destination|path
                let parts: Vec<&str> = key.split('|').collect();
                let level = if parts.len() >= 5 {
                    let path_seg = parts[4];
                    if path_seg == "*" {
                        3 // process-only wildcard
                    } else if path_seg.ends_with("/*") {
                        1 // parent directory class
                    } else {
                        0 // exact path
                    }
                } else {
                    0
                };
                let profile = parts.first().unwrap_or(&"unknown");
                serde_json::json!({
                    "key": key,
                    "level": level,
                    "profile": profile,
                    "alpha": entry.alpha,
                    "beta": entry.beta,
                    "trust_score": entry.trust_score(),
                    "observation_count": entry.observation_count() as i64,
                    "auto_allowed": entry.trust_score() >= 0.92 && entry.observation_count() >= 8.0,
                    "last_updated": entry.last_updated,
                })
            })
            .collect();

        if entries.is_empty() {
            println!("No reputation data to push.");
        } else {
            // Batch uploads to stay under the 500-entry API limit.
            const REPUTATION_SYNC_BATCH_LIMIT: usize = 400;
            let total = entries.len();
            let mut synced = 0usize;
            for chunk in entries.chunks(REPUTATION_SYNC_BATCH_LIMIT) {
                match runtime
                    .block_on(async { license::sync_reputation(&creds, chunk.to_vec()).await })
                {
                    Ok(n) => synced += n,
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to push reputation batch");
                        break;
                    }
                }
                if synced < total {
                    print!("\r  {synced}/{total} reputation entries synced...");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                }
            }
            if total > REPUTATION_SYNC_BATCH_LIMIT {
                println!();
            }
            println!("Pushed {synced} reputation entries.");
        }
    }

    // ---- Sync learned rules ----
    match runtime.block_on(async { license::fetch_learned_rules(&creds).await }) {
        Ok(rules) => {
            // Always write the cache — even if empty — so revoked rules are cleared.
            let cache_path = persist_team_learned_rules_cache(&rules)?;
            println!(
                "Learned rules: {} rule(s) -> {}",
                rules.len(),
                cache_path.display()
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to fetch team learned rules");
        }
    }

    creds.last_synced = Some(chrono::Utc::now().to_rfc3339());
    license::save_credentials(&creds)
        .map_err(|e| anyhow::anyhow!("failed to update credentials: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::license::{provider_file_name, sanitize_sync_name};

    #[test]
    fn sanitize_sync_name_rejects_empty() {
        assert_eq!(sanitize_sync_name("   "), None);
    }

    #[test]
    fn sanitize_sync_name_replaces_path_separators() {
        assert_eq!(
            sanitize_sync_name("../../etc/passwd"),
            Some("etc-passwd".to_string())
        );
    }

    #[test]
    fn provider_file_name_uses_legacy_name_for_first_key() {
        assert_eq!(
            provider_file_name("openai", "production", 1),
            Some("openai.json".to_string())
        );
    }

    #[test]
    fn provider_file_name_generates_unique_suffixes() {
        assert_eq!(
            provider_file_name("openai", "production key", 2),
            Some("openai--production-key-2.json".to_string())
        );
    }
}
