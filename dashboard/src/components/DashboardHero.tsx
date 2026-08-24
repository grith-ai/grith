/**
 * The dashboard's shareable centerpiece: a dark, branded hero band that tells
 * the security story at a glance — how much agent activity grith has inspected
 * under Zero Trust, and how it split across allow / review / deny.
 *
 * Deliberately dark (grith's terminal palette) to contrast the light data
 * sections below and read as a single, screenshot-worthy "posture" panel.
 */

import { ShareMenu } from "@/components/ShareMenu";
import { chartColors } from "@/lib/chartPalette";
import type { ShareStats } from "@/lib/shareCard";
import type { SummaryWindow } from "@/types/api";

/** Selector label and headline phrasing for each window the hero offers. */
export const HERO_WINDOWS: Array<{
  value: SummaryWindow;
  label: string;
  phrase: string;
}> = [
  { value: "today", label: "Today", phrase: "today" },
  { value: "7d", label: "7d", phrase: "in the last 7 days" },
  { value: "30d", label: "30d", phrase: "in the last 30 days" },
  { value: "all", label: "All", phrase: "under Zero Trust" },
];

export function heroWindowPhrase(window: SummaryWindow): string {
  return HERO_WINDOWS.find((w) => w.value === window)?.phrase ?? "in the last 7 days";
}

/**
 * Step the headline down a size as it gets longer.
 *
 * A bounded window keeps this from ever being the primary defence, but a busy
 * month can still reach eight digits and the number must not wrap or overrun
 * the stat rail beside it.
 */
function headlineSize(formatted: string): string {
  if (formatted.length >= 12) return "text-3xl sm:text-4xl";
  if (formatted.length >= 10) return "text-4xl sm:text-5xl";
  return "text-5xl sm:text-6xl";
}

/** Segmented control scoping every number in the hero to one time window. */
function WindowPicker({
  value,
  onChange,
}: {
  value: SummaryWindow;
  onChange: (next: SummaryWindow) => void;
}) {
  return (
    <div
      role="group"
      aria-label="Time window"
      className="inline-flex items-center rounded-lg border border-white/10 bg-white/[0.04] p-0.5"
    >
      {HERO_WINDOWS.map((w) => {
        const active = w.value === value;
        return (
          <button
            key={w.value}
            type="button"
            onClick={() => onChange(w.value)}
            aria-pressed={active}
            className={`rounded-md px-2.5 py-1 font-code text-[11px] uppercase tracking-[0.08em] transition-colors ${
              active
                ? "bg-white/[0.10] text-white"
                : "text-white/45 hover:text-white/75"
            }`}
          >
            {w.label}
          </button>
        );
      })}
    </div>
  );
}

interface HeroProps {
  totalEvals: number;
  allow: number;
  queue: number;
  deny: number;
  /** Live supervised agents right now. */
  liveSessions: number;
  uptime: string;
  filtersActive: number;
  /** grith version (e.g. "0.1.4"). */
  version?: string;
  /** Whether the daemon is reachable/healthy. */
  online: boolean;
  /** Display label for the current license tier, e.g. "Community". */
  planLabel?: string;
  /** Whether the current tier is a paid one (changes the badge styling). */
  planPaid?: boolean;
  /** Where the plan badge links to. */
  billingUrl?: string;
  /** Open the existing share menu from an explicit CLI deep link. */
  shareOnOpen?: boolean;
  /** Time window every number in the hero is scoped to. Named `timeWindow`
   *  rather than `window` so it cannot shadow the global inside this file. */
  timeWindow: SummaryWindow;
  /** Called when the operator picks a different window. */
  onWindowChange: (next: SummaryWindow) => void;
}

function HeroMark() {
  return (
    <svg className="w-7 h-7" viewBox="0 0 24 26" fill="none" aria-hidden>
      <path
        d="M12 1.5L22 7v11L12 23.5 2 18V7L12 1.5z"
        stroke={chartColors.accent}
        strokeWidth="1.5"
      />
      <circle cx="12" cy="12.5" r="2.5" fill={chartColors.accent} />
    </svg>
  );
}

/** A labelled secondary metric in the hero's stat rail. */
function HeroStat({
  value,
  label,
  tone = "default",
  delay,
}: {
  value: string | number;
  label: string;
  tone?: "default" | "green" | "amber" | "red";
  delay: number;
}) {
  const toneColor =
    tone === "green"
      ? chartColors.accent
      : tone === "amber"
        ? chartColors.warning
        : tone === "red"
          ? chartColors.danger
          : undefined;
  return (
    <div
      className="grith-fade-up"
      style={{ animationDelay: `${delay}ms` }}
    >
      <div
        className={`font-code text-xl sm:text-2xl font-semibold tabular-nums ${toneColor ? "" : "text-white"}`}
        style={toneColor ? { color: toneColor } : undefined}
      >
        {value}
      </div>
      <div className="text-[11px] uppercase tracking-[0.12em] text-white/45 mt-0.5">
        {label}
      </div>
    </div>
  );
}

export function DashboardHero({
  totalEvals,
  allow,
  queue,
  deny,
  liveSessions,
  uptime,
  filtersActive,
  version,
  online,
  planLabel,
  planPaid = false,
  billingUrl = "/billing",
  shareOnOpen = false,
  timeWindow,
  onWindowChange,
}: HeroProps) {
  const decided = allow + queue + deny;
  const pct = (n: number) => (decided > 0 ? (n / decided) * 100 : 0);
  // "Held back" = everything grith did NOT silently allow (queued for review +
  // denied) — the value proposition, surfaced as one number.
  const heldBack = queue + deny;

  const windowPhrase = heroWindowPhrase(timeWindow);
  const formattedTotal = totalEvals.toLocaleString();

  const shareStats: ShareStats = {
    totalEvals,
    allow,
    queue,
    deny,
    liveSessions,
    uptime,
    filtersActive,
    version,
    windowPhrase,
  };

  return (
    <section className="grith-hero rounded-card px-6 py-7 sm:px-8 sm:py-8 mb-8 border border-white/10">
      {/* Top rail: brand + live status. `relative z-30` lifts it (and the
          share dropdown it contains) above the later headline / stat-rail
          sections, which would otherwise paint over the open menu. */}
      <div className="relative z-30 flex items-center justify-between mb-7">
        <div
          className="flex items-center gap-2.5 grith-fade-up"
          style={{ animationDelay: "0ms" }}
        >
          <HeroMark />
          <span className="text-white font-semibold tracking-tight text-[15px]">
            grith
          </span>
          {version && (
            <span className="font-code text-[11px] text-white/35">
              v{version}
            </span>
          )}
          <span className="hidden sm:inline text-white/20 mx-1">/</span>
          <span className="hidden sm:inline text-[12px] text-white/45 tracking-wide">
            Zero Trust for AI Agents
          </span>
        </div>
        <div
          className="flex items-center gap-4 grith-fade-up"
          style={{ animationDelay: "80ms" }}
        >
          <div className="flex items-center gap-2">
            <span className="relative flex">
              <span
                className={`grith-pulse-ring relative w-2 h-2 rounded-full ${
                  online ? "" : "text-white/30"
                }`}
                style={online ? { color: chartColors.accent } : undefined}
              >
                <span
                  className={`block w-2 h-2 rounded-full ${
                    online ? "" : "bg-white/30"
                  }`}
                  style={online ? { backgroundColor: chartColors.accent } : undefined}
                />
              </span>
            </span>
            <span className="hidden sm:inline text-[12px] text-white/60 font-medium">
              {online ? "Supervising live" : "Offline"}
            </span>
          </div>
          {planLabel && (
            <a
              href={billingUrl}
              title={planPaid ? "Manage your plan" : "Upgrade your plan"}
              className={`group inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-[11px] font-semibold uppercase tracking-wide transition-colors ${
                planPaid
                  ? "border-[#00e5a0]/40 bg-[#00e5a0]/10 text-[#00e5a0] hover:bg-[#00e5a0]/20"
                  : "border-white/15 bg-white/[0.06] text-white/70 hover:border-[#00e5a0]/40 hover:text-white"
              }`}
            >
              {!planPaid && (
                <svg className="h-3 w-3" viewBox="0 0 24 24" fill="none" aria-hidden>
                  <path d="M6 10V8a6 6 0 1112 0v2m-13 0h14v9a1 1 0 01-1 1H6a1 1 0 01-1-1v-9z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
                </svg>
              )}
              {planLabel}
              {!planPaid && (
                <span className="text-[#00e5a0] group-hover:translate-x-0.5 transition-transform">↑</span>
              )}
            </a>
          )}
          <ShareMenu stats={shareStats} autoOpen={shareOnOpen} />
        </div>
      </div>

      {/* Headline metric */}
      <div className="flex flex-col lg:flex-row lg:items-end lg:justify-between gap-6">
        <div className="grith-fade-up" style={{ animationDelay: "120ms" }}>
          <div className="flex items-baseline gap-3">
            <span
              className={`font-code ${headlineSize(formattedTotal)} font-bold text-white tabular-nums leading-none`}
              title={`${formattedTotal} tool calls inspected ${windowPhrase}`}
            >
              {formattedTotal}
            </span>
          </div>
          <p className="text-white/55 text-sm mt-3 max-w-md">
            tool calls inspected {windowPhrase} -{" "}
            <span className="text-white/90 font-medium">
              {heldBack.toLocaleString()}
            </span>{" "}
            queued for review or denied.
          </p>
          <div className="mt-4">
            <WindowPicker value={timeWindow} onChange={onWindowChange} />
          </div>
        </div>

        {/* Secondary stat rail */}
        <div className="grid grid-cols-3 sm:grid-cols-4 gap-x-7 gap-y-4">
          <HeroStat
            value={liveSessions}
            label="Agents live"
            tone="green"
            delay={180}
          />
          <HeroStat value={queue.toLocaleString()} label="Queued" tone="amber" delay={220} />
          <HeroStat value={deny.toLocaleString()} label="Denied" tone="red" delay={260} />
          <HeroStat value={filtersActive} label="Filters" delay={300} />
        </div>
      </div>

      {/* Posture bar — allow / queue / deny, full-bleed and legible on dark */}
      <div
        className="mt-7 grith-fade-up"
        style={{ animationDelay: "340ms" }}
      >
        <div className="h-2 rounded-full bg-white/[0.06] overflow-hidden flex">
          {pct(allow) > 0 && (
            <div
              className="h-full transition-all duration-700"
              style={{ width: `${pct(allow)}%`, backgroundColor: chartColors.accent }}
            />
          )}
          {pct(queue) > 0 && (
            <div
              className="h-full transition-all duration-700"
              style={{ width: `${pct(queue)}%`, backgroundColor: chartColors.warning }}
            />
          )}
          {pct(deny) > 0 && (
            <div
              className="h-full transition-all duration-700"
              style={{ width: `${pct(deny)}%`, backgroundColor: chartColors.danger }}
            />
          )}
        </div>
        <div className="flex flex-wrap items-center gap-x-6 gap-y-1 mt-3 text-[12px]">
          <Legend color={chartColors.accent} label="Allowed" value={allow} pct={pct(allow)} />
          <Legend color={chartColors.warning} label="Queued" value={queue} pct={pct(queue)} />
          <Legend color={chartColors.danger} label="Denied" value={deny} pct={pct(deny)} />
          <span className="ml-auto text-white/35 font-code text-[11px]">
            uptime {uptime}
          </span>
        </div>
      </div>
    </section>
  );
}

function Legend({
  color,
  label,
  value,
  pct,
}: {
  color: string;
  label: string;
  value: number;
  pct: number;
}) {
  return (
    <span className="flex items-center gap-1.5 text-white/55">
      <span
        className="w-2 h-2 rounded-sm"
        style={{ backgroundColor: color }}
      />
      <span className="text-white/80">{label}</span>
      <span className="font-code text-white/45">
        {value.toLocaleString()}
        <span className="text-white/25"> · {pct.toFixed(0)}%</span>
      </span>
    </span>
  );
}
