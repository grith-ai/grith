/**
 * Dismissible "Get started" checklist shown on the dashboard home until the
 * user has set things up (or dismisses it). Doubles as a useful empty-state
 * and a re-entry point for anyone who skipped the CLI onboarding flow.
 *
 * State comes from `GET /api/onboarding/status` (non-secret). Dismissal is
 * dashboard-specific (`POST /api/onboarding/dismiss`) — separate from the CLI's
 * `general.onboarded` flag.
 */

import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import type { OnboardingStatus } from "@/types/api";
import { getOnboardingStatus, dismissOnboarding } from "@/lib/api";

interface ChecklistItem {
  label: string;
  hint: string;
  done: boolean;
  to?: string;
}

function buildItems(s: OnboardingStatus): ChecklistItem[] {
  return [
    {
      label: "Finish first-run setup",
      hint: s.onboarded
        ? `Built-in provider: ${s.default_provider}`
        : "Run `grith setup` in your terminal",
      done: s.onboarded,
    },
    {
      label: "Supervise your first tool",
      hint: "grith exec -- claude-code \"…\"",
      done: s.active_sessions > 0,
      to: "/sessions",
    },
    {
      label: "Start a free Pro trial",
      hint: "Unlock team & automation features for 14 days",
      done: s.trial_active,
      to: "/billing",
    },
    {
      label: "Set up notifications",
      hint: "Get alerted when grith pauses a risky call",
      done: s.notifications_configured,
      to: "/notifications",
    },
  ];
}

export function GetStartedCard() {
  const [status, setStatus] = useState<OnboardingStatus | null>(null);
  const [hidden, setHidden] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getOnboardingStatus()
      .then((s) => {
        if (!cancelled) setStatus(s);
      })
      .catch(() => {
        // Non-fatal: if the endpoint is unavailable, just don't show the card.
        if (!cancelled) setHidden(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (hidden || !status || status.dismissed) return null;

  const items = buildItems(status);
  // Nothing left to nudge → don't show the card at all.
  if (items.every((i) => i.done)) return null;

  const doneCount = items.filter((i) => i.done).length;

  const onDismiss = () => {
    setHidden(true);
    void dismissOnboarding().catch(() => {
      /* best-effort; the card is already hidden for this session */
    });
  };

  return (
    <section
      className="relative mb-8 rounded-card border border-green-border bg-green-light px-5 py-4"
      aria-label="Get started checklist"
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="font-heading text-[15px] font-semibold text-text">
            Get started with grith
          </h2>
          <p className="mt-0.5 text-xs text-text-secondary">
            {doneCount} of {items.length} done
          </p>
        </div>
        <button
          type="button"
          onClick={onDismiss}
          className="flex-shrink-0 rounded-md px-2 py-1 text-xs text-text-secondary transition-colors hover:bg-green/10 hover:text-text"
          aria-label="Dismiss get-started checklist"
        >
          Dismiss
        </button>
      </div>

      <ul className="mt-3 space-y-2">
        {items.map((item) => {
          const row = (
            <div className="flex items-start gap-3">
              <span
                className={
                  item.done
                    ? "mt-0.5 flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full bg-green text-accent-ink"
                    : "mt-0.5 flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full border border-border text-transparent"
                }
                aria-hidden
              >
                <svg className="h-3 w-3" viewBox="0 0 24 24" fill="none">
                  <path
                    d="M5 13l4 4L19 7"
                    stroke="currentColor"
                    strokeWidth="2.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </span>
              <div className="min-w-0">
                <p
                  className={
                    item.done
                      ? "text-sm text-text-secondary line-through"
                      : "text-sm font-medium text-text"
                  }
                >
                  {item.label}
                </p>
                <p className="text-xs text-text-secondary">{item.hint}</p>
              </div>
            </div>
          );
          return (
            <li key={item.label}>
              {item.to && !item.done ? (
                <Link
                  to={item.to}
                  className="block rounded-btn px-2 py-1 -mx-2 transition-colors hover:bg-green/10"
                >
                  {row}
                </Link>
              ) : (
                <div className="px-2 py-1 -mx-2">{row}</div>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
