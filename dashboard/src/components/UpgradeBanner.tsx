/**
 * Persistent, always-visible upgrade banner shown on the dashboard for
 * non-paid tiers. Frames the upsell around real limits (retention window,
 * alerting, anomaly detection) rather than a generic nag.
 */

import type { TierState } from "@/hooks/useTier";

const PERKS = [
  "90-day audit retention",
  "Anomaly detection",
  "Slack / email alerts",
  "Team policies",
];

export function UpgradeBanner({ tierState }: { tierState: TierState }) {
  // Enterprise is already top-tier; nothing to upsell.
  if (tierState.tierKey === "enterprise") return null;

  const isPro = tierState.tierKey === "pro";
  const headline = isPro
    ? "You're on Pro - unlock org-wide policy & SSO with Enterprise"
    : "You're seeing the last 24 hours. Pro keeps 90 days and watches for anomalies.";
  const cta = isPro ? "Talk to sales" : "Upgrade to Pro";

  return (
    <a
      href={tierState.billingUrl}
      className="group relative block overflow-hidden rounded-card border border-green-border bg-green-light px-5 py-4 mb-8 transition-colors hover:border-green"
    >
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-3 min-w-0">
          <span className="flex-shrink-0 inline-flex h-9 w-9 items-center justify-center rounded-lg bg-green-light text-accent-text">
            <svg className="h-5 w-5" viewBox="0 0 24 24" fill="none" aria-hidden>
              <path
                d="M12 3l2.5 5.2 5.7.8-4.1 4 1 5.7L12 21l-5.1 2.5 1-5.7-4.1-4 5.7-.8L12 3z"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinejoin="round"
              />
            </svg>
          </span>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-text truncate">
              {headline}
            </p>
            <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1">
              {PERKS.map((p) => (
                <span
                  key={p}
                  className="inline-flex items-center gap-1 text-[11px] text-text-secondary"
                >
                  <svg
                    className="h-3 w-3 text-accent-text"
                    viewBox="0 0 24 24"
                    fill="none"
                    aria-hidden
                  >
                    <path
                      d="M5 13l4 4L19 7"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                  {p}
                </span>
              ))}
            </div>
          </div>
        </div>
        <span className="flex-shrink-0 inline-flex items-center gap-1.5 rounded-btn bg-green px-4 py-2 text-xs font-heading font-semibold text-accent-ink transition-transform group-hover:translate-x-0.5">
          {cta}
          <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" aria-hidden>
            <path
              d="M5 12h14M13 6l6 6-6 6"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </span>
      </div>
    </a>
  );
}
