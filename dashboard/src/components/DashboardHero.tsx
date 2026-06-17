/**
 * The dashboard's shareable centerpiece: a dark, branded hero band that tells
 * the security story at a glance — how much agent activity grith has inspected
 * under Zero Trust, and how it split across allow / review / deny.
 *
 * Deliberately dark (grith's terminal palette) to contrast the light data
 * sections below and read as a single, screenshot-worthy "posture" panel.
 */

import { ShareMenu } from "@/components/ShareMenu";
import type { ShareStats } from "@/lib/shareCard";

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
}

function HeroMark() {
  return (
    <svg className="w-7 h-7" viewBox="0 0 24 26" fill="none" aria-hidden>
      <path
        d="M12 1.5L22 7v11L12 23.5 2 18V7L12 1.5z"
        stroke="#00e5a0"
        strokeWidth="1.5"
      />
      <circle cx="12" cy="12.5" r="2.5" fill="#00e5a0" />
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
  const toneClass =
    tone === "green"
      ? "text-[#00e5a0]"
      : tone === "amber"
        ? "text-[#f0b429]"
        : tone === "red"
          ? "text-[#ff5c69]"
          : "text-white";
  return (
    <div
      className="grith-fade-up"
      style={{ animationDelay: `${delay}ms` }}
    >
      <div className={`font-mono text-xl sm:text-2xl font-semibold tabular-nums ${toneClass}`}>
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
}: HeroProps) {
  const decided = allow + queue + deny;
  const pct = (n: number) => (decided > 0 ? (n / decided) * 100 : 0);
  // "Held back" = everything grith did NOT silently allow (queued for review +
  // denied) — the value proposition, surfaced as one number.
  const heldBack = queue + deny;

  const shareStats: ShareStats = {
    totalEvals,
    allow,
    queue,
    deny,
    liveSessions,
    uptime,
    filtersActive,
    version,
  };

  return (
    <section className="grith-hero rounded-2xl px-6 py-7 sm:px-8 sm:py-8 mb-8 border border-white/10 shadow-[0_8px_40px_-12px_rgba(0,0,0,0.5)]">
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
            <span className="font-mono text-[11px] text-white/35">
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
                  online ? "text-[#00e5a0]" : "text-white/30"
                }`}
              >
                <span
                  className={`block w-2 h-2 rounded-full ${
                    online ? "bg-[#00e5a0]" : "bg-white/30"
                  }`}
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
          <ShareMenu stats={shareStats} />
        </div>
      </div>

      {/* Headline metric */}
      <div className="flex flex-col lg:flex-row lg:items-end lg:justify-between gap-6">
        <div className="grith-fade-up" style={{ animationDelay: "120ms" }}>
          <div className="flex items-baseline gap-3">
            <span className="font-mono text-5xl sm:text-6xl font-bold text-white tabular-nums leading-none">
              {totalEvals.toLocaleString()}
            </span>
          </div>
          <p className="text-white/55 text-sm mt-3 max-w-md">
            tool calls inspected under Zero Trust —{" "}
            <span className="text-white/90 font-medium">
              {heldBack.toLocaleString()}
            </span>{" "}
            held back for review or denied.
          </p>
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
              className="bg-[#00e5a0] h-full transition-all duration-700"
              style={{ width: `${pct(allow)}%` }}
            />
          )}
          {pct(queue) > 0 && (
            <div
              className="bg-[#f0b429] h-full transition-all duration-700"
              style={{ width: `${pct(queue)}%` }}
            />
          )}
          {pct(deny) > 0 && (
            <div
              className="bg-[#ff5c69] h-full transition-all duration-700"
              style={{ width: `${pct(deny)}%` }}
            />
          )}
        </div>
        <div className="flex flex-wrap items-center gap-x-6 gap-y-1 mt-3 text-[12px]">
          <Legend color="#00e5a0" label="Allowed" value={allow} pct={pct(allow)} />
          <Legend color="#f0b429" label="Queued" value={queue} pct={pct(queue)} />
          <Legend color="#ff5c69" label="Denied" value={deny} pct={pct(deny)} />
          <span className="ml-auto text-white/35 font-mono text-[11px]">
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
      <span className="font-mono text-white/45">
        {value.toLocaleString()}
        <span className="text-white/25"> · {pct.toFixed(0)}%</span>
      </span>
    </span>
  );
}
