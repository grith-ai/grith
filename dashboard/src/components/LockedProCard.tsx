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
    <div className="relative overflow-hidden rounded-xl border border-grith-border bg-white p-5">
      <div className="flex items-baseline justify-between mb-3">
        <h2 className="text-sm font-medium text-grith-text">{title}</h2>
        {!unlocked && (
          <span className="inline-flex items-center gap-1 rounded-full border border-green/30 bg-green-light px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-green-dark">
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
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 bg-gradient-to-b from-white/40 to-white/85 px-6 text-center">
          <p className="max-w-xs text-xs text-grith-muted">{description}</p>
          <a
            href={billingUrl}
            className="inline-flex items-center gap-1.5 rounded-lg bg-green px-4 py-2 text-xs font-semibold text-white shadow-sm transition-colors hover:bg-green-dark"
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
