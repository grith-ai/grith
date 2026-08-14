/**
 * A locked, blurred-teaser card for a Pro/Enterprise-only insight. Renders a
 * faux preview (passed as children) behind a frosted overlay with an upgrade
 * CTA, so the value of the feature is visible but not usable on Community.
 *
 * When `unlocked` is true the overlay is dropped and children render live.
 */

import type { ReactNode } from "react";

interface Props {
  title: string;
  /** One-line description of what the locked feature delivers. */
  description: string;
  /** Short tier tag shown on the lock pill, e.g. "Pro" or "Enterprise". */
  tier?: string;
  billingUrl: string;
  unlocked?: boolean;
  children: ReactNode;
}

export function LockedProCard({
  title,
  description,
  tier = "Pro",
  billingUrl,
  unlocked = false,
  children,
}: Props) {
  return (
    <div className="relative overflow-hidden rounded-card border border-border bg-surface p-5">
      <div className="flex items-baseline justify-between mb-3">
        <h2 className="font-heading text-[15px] font-semibold text-text">{title}</h2>
        {!unlocked && (
          <span className="inline-flex items-center gap-1 rounded-pill border border-green-border bg-green-light px-2.5 py-0.5 font-label text-[10px] font-medium uppercase tracking-[0.08em] text-accent-text">
            <svg className="h-3 w-3" viewBox="0 0 24 24" fill="none" aria-hidden>
              <path
                d="M6 10V8a6 6 0 1112 0v2m-13 0h14v9a1 1 0 01-1 1H6a1 1 0 01-1-1v-9z"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinejoin="round"
              />
            </svg>
            {tier}
          </span>
        )}
      </div>

      {/* Preview surface — blurred & non-interactive when locked. */}
      <div
        className={unlocked ? "" : "pointer-events-none select-none blur-[3px] opacity-60"}
        aria-hidden={!unlocked}
      >
        {children}
      </div>

      {!unlocked && (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 bg-gradient-to-b from-surface/40 to-surface/90 px-6 text-center">
          <p className="max-w-xs text-xs text-text-secondary">{description}</p>
          <a
            href={billingUrl}
            className="inline-flex items-center gap-1.5 rounded-btn bg-green px-4 py-2 text-xs font-heading font-semibold text-accent-ink transition-colors hover:bg-green-dark"
          >
            Unlock with {tier}
            <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" aria-hidden>
              <path
                d="M5 12h14M13 6l6 6-6 6"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </a>
        </div>
      )}
    </div>
  );
}
