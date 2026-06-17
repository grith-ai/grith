import { useState, useEffect } from "react";
import { getTier } from "@/lib/api";
import type { RefreshState, TierResponse } from "@/types/api";

const TIER_COLORS: Record<string, string> = {
  community: "bg-grith-muted/20 text-grith-muted border-grith-border",
  pro: "bg-green/15 text-green border-green/40",
  enterprise: "bg-purple-500/15 text-purple-400 border-purple-500/40",
};

const TIER_LABELS: Record<string, string> = {
  community: "Community",
  pro: "Pro",
  enterprise: "Enterprise",
};

interface FeatureRow {
  name: string;
  key: string;
  community: boolean;
  pro: boolean;
  enterprise: boolean;
}

const FEATURE_MATRIX: FeatureRow[] = [
  { name: "Security Proxy", key: "proxy", community: true, pro: true, enterprise: true },
  { name: "Audit Logging", key: "audit", community: true, pro: true, enterprise: true },
  { name: "Digest Review", key: "digest", community: true, pro: true, enterprise: true },
  { name: "Dashboard", key: "dashboard", community: true, pro: true, enterprise: true },
  { name: "Supervisor", key: "supervisor", community: true, pro: true, enterprise: true },
  { name: "Adaptive Scoring", key: "adaptive_scoring", community: false, pro: true, enterprise: true },
  { name: "Notification Channels", key: "notification_channels", community: false, pro: true, enterprise: true },
  { name: "Usage Analytics", key: "usage_analytics", community: false, pro: true, enterprise: true },
  { name: "Cloud Sync", key: "cloud_sync", community: false, pro: true, enterprise: true },
  { name: "Policy Editor", key: "policy_editor", community: false, pro: true, enterprise: true },
  { name: "PagerDuty", key: "pagerduty", community: false, pro: false, enterprise: true },
  { name: "Team Scope", key: "team_scope", community: false, pro: false, enterprise: true },
];

export function BillingPage() {
  const [tier, setTier] = useState<TierResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getTier()
      .then(setTier)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center">
        <div className="text-grith-muted text-sm">Loading billing info...</div>
      </div>
    );
  }

  if (error || !tier) {
    return (
      <div className="p-6">
        <div className="bg-status-deny-red/10 border border-status-deny-red/30 rounded-xl px-4 py-3 text-xs text-status-deny-red">
          Failed to load billing information: {error ?? "unknown error"}
        </div>
      </div>
    );
  }

  const tierKey = tier.tier.toLowerCase();
  const colorClass = TIER_COLORS[tierKey] ?? TIER_COLORS.community;
  const label = TIER_LABELS[tierKey] ?? tier.tier;
  const billingUrl = tier.billing_portal_url ?? "https://grith.ai/dashboard/settings/billing";

  return (
    <div className="p-6 max-w-4xl">
      <h1 className="text-xl font-semibold text-grith-text mb-6">
        Plan &amp; Billing
      </h1>

      <RefreshBanner refresh={tier.refresh ?? null} />

      <SessionLimitNudge tier={tier} />

      {/* Current plan card */}
      <div className="bg-white border border-grith-border rounded-xl p-5 mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <span className={`inline-flex items-center px-2.5 py-1 rounded text-xs font-semibold border ${colorClass}`}>
              {label}
            </span>
            <span className="text-sm text-grith-text">Current Plan</span>
          </div>
          {tierKey === "community" ? (
            <a
              href="https://grith.ai/pricing"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-green text-white text-xs font-medium hover:bg-green-dark transition-colors"
            >
              Upgrade to Pro
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 0 0 3 8.25v10.5A2.25 2.25 0 0 0 5.25 21h10.5A2.25 2.25 0 0 0 18 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
              </svg>
            </a>
          ) : (
            <a
              href={billingUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-grith-border text-grith-muted text-xs hover:text-grith-text hover:border-grith-text/30 transition-colors"
            >
              Manage Subscription
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 0 0 3 8.25v10.5A2.25 2.25 0 0 0 5.25 21h10.5A2.25 2.25 0 0 0 18 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
              </svg>
            </a>
          )}
        </div>

        <div className="grid grid-cols-3 gap-4">
          <div>
            <div className="text-xs text-grith-muted mb-1">Seats</div>
            <div className="text-sm text-grith-text font-mono">{tier.seats}</div>
          </div>
          <div>
            <div className="text-xs text-grith-muted mb-1">Max Sessions</div>
            <div className="text-sm text-grith-text font-mono">{tier.max_sessions}</div>
          </div>
          <div>
            <div className="text-xs text-grith-muted mb-1">Renewal Date</div>
            <div className="text-sm text-grith-text font-mono">
              {tier.renewal_date ?? "—"}
            </div>
          </div>
        </div>
      </div>

      {/* Feature comparison table */}
      <div className="bg-white border border-grith-border rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-grith-border">
          <h2 className="text-xs text-grith-muted uppercase tracking-wider">
            Feature Comparison
          </h2>
        </div>
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-grith-border">
              <th className="text-left px-5 py-2.5 text-grith-muted font-medium">Feature</th>
              <th className="text-center px-3 py-2.5 text-grith-muted font-medium">Community</th>
              <th className="text-center px-3 py-2.5 text-green font-medium">Pro</th>
              <th className="text-center px-3 py-2.5 text-purple-400 font-medium">Enterprise</th>
            </tr>
          </thead>
          <tbody>
            {FEATURE_MATRIX.map((row) => (
              <tr key={row.key} className="border-b border-grith-border/50 last:border-b-0">
                <td className="px-5 py-2 text-grith-text">{row.name}</td>
                <td className="text-center px-3 py-2">
                  <FeatureCheck enabled={row.community} active={tierKey === "community" && tier.features[row.key]} />
                </td>
                <td className="text-center px-3 py-2">
                  <FeatureCheck enabled={row.pro} active={tierKey === "pro" && tier.features[row.key]} />
                </td>
                <td className="text-center px-3 py-2">
                  <FeatureCheck enabled={row.enterprise} active={tierKey === "enterprise" && tier.features[row.key]} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* CLI hint */}
      <div className="mt-6 bg-white border border-grith-border rounded-xl p-5 text-center">
        <p className="text-grith-muted text-xs">
          Manage your subscription from the CLI:{" "}
          <code className="font-mono text-green">grith pro billing</code>
          {" | "}
          <code className="font-mono text-green">grith pro status</code>
          {" | "}
          <code className="font-mono text-green">grith pro upgrade</code>
        </p>
      </div>
    </div>
  );
}

/**
 * Upgrade nudge shown when the user has recently hit their concurrent-session
 * cap. The 429 is the highest-intent upgrade moment, so surface it here.
 * Hidden for Enterprise (already top tier) and when there are no recent
 * rejections.
 */
function SessionLimitNudge({ tier }: { tier: TierResponse }) {
  const count = tier.session_limit_rejections ?? 0;
  const windowDays = tier.session_limit_rejection_window_days ?? 7;
  const tierKey = tier.tier.toLowerCase();
  if (count <= 0 || tierKey === "enterprise") return null;

  const headline =
    tierKey === "pro"
      ? `You hit your ${tier.max_sessions}-session limit ${count} time${count !== 1 ? "s" : ""} in the last ${windowDays} days.`
      : `You hit your ${tier.max_sessions}-session limit ${count} time${count !== 1 ? "s" : ""} in the last ${windowDays} days.`;
  const remediation =
    tierKey === "pro"
      ? "Add seats to run more concurrent supervised sessions."
      : "Upgrade to Pro to run more concurrent supervised sessions (4× seats).";
  const cta = tierKey === "pro" ? "Add seats" : "Upgrade to Pro";
  const ctaUrl =
    tier.billing_portal_url ??
    (tierKey === "pro"
      ? "https://grith.ai/dashboard/settings/billing"
      : "https://grith.ai/pricing");

  return (
    <div className="mb-4 border border-status-queue-amber/40 bg-status-queue-amber/10 rounded-xl px-4 py-3 flex items-center justify-between gap-4">
      <div className="text-xs text-grith-text">
        <div className="font-semibold text-status-queue-amber">{headline}</div>
        <div className="opacity-80 mt-0.5">{remediation}</div>
      </div>
      <a
        href={ctaUrl}
        target="_blank"
        rel="noopener noreferrer"
        className="flex-shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-green text-white text-xs font-medium hover:bg-green-dark transition-colors"
      >
        {cta}
      </a>
    </div>
  );
}

function RefreshBanner({ refresh }: { refresh: RefreshState | null }) {
  if (!refresh) return null;
  if (refresh.air_gapped) {
    return (
      <div className="mb-4 bg-grith-muted/10 border border-grith-border rounded-xl px-4 py-3 text-xs text-grith-muted">
        Air-gapped contract licence: scheduled refresh is disabled. Renewal is
        delivered out-of-band.
      </div>
    );
  }
  if (!refresh.last_failure || !refresh.last_failure_kind) {
    return null;
  }
  const days = refresh.last_failure
    ? Math.max(
        0,
        Math.floor(
          (Date.now() - new Date(refresh.last_failure).getTime()) /
            (1000 * 60 * 60 * 24),
        ),
      )
    : null;
  const isHard =
    refresh.last_failure_kind === "revoked" ||
    refresh.last_failure_kind === "unauthorized";
  const colorClass = isHard
    ? "bg-status-deny-red/10 border-status-deny-red/30 text-status-deny-red"
    : "bg-status-queue-yellow/10 border-status-queue-yellow/30 text-status-queue-yellow";
  const remediation =
    refresh.last_failure_kind === "unauthorized"
      ? "Run `grith pro login` to refresh credentials."
      : refresh.last_failure_kind === "revoked"
        ? "Renew your subscription in the dashboard."
        : "Network failure — the daemon will retry automatically.";
  return (
    <div className={`mb-4 border rounded-xl px-4 py-3 text-xs ${colorClass}`}>
      <div className="font-semibold">
        Licence refresh failed {days !== null ? `${days} day(s) ago` : "recently"}
        {" "}
        <span className="font-normal opacity-80">
          ({refresh.last_failure_kind})
        </span>
      </div>
      <div className="opacity-80 mt-1">
        {refresh.last_failure_reason ?? "no details provided"}. {remediation}
      </div>
    </div>
  );
}

function FeatureCheck({ enabled, active }: { enabled: boolean; active?: boolean }) {
  if (!enabled) {
    return <span className="text-grith-muted/40">—</span>;
  }
  if (active) {
    return (
      <svg className="w-4 h-4 mx-auto text-status-allow-green" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
      </svg>
    );
  }
  return (
    <svg className="w-4 h-4 mx-auto text-grith-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
    </svg>
  );
}
