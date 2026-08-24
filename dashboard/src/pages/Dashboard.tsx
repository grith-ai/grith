import { useEffect, useState } from "react";
import type {
  AuditRecord,
  AuditSummaryResponse,
  ExfilStatsResponse,
  HealthResponse,
  ProxyStatusResponse,
  SessionSummary,
  SummaryWindow,
} from "@/types/api";
import {
  getHealth,
  getProxyStatus,
  getExfilStats,
  getAuditRecords,
  getAuditSummary,
  getSessions,
} from "@/lib/api";
import { InteractiveScoreScatter } from "@/components/charts/InteractiveScoreScatter";
import { ActivityArea } from "@/components/charts/ActivityArea";
import { LatencyHistogram } from "@/components/charts/LatencyHistogram";
import { ThreatSignals } from "@/components/charts/ThreatSignals";
import { SessionComparison } from "@/components/charts/SessionComparison";
import { MiniDonut } from "@/components/charts/MiniDonut";
import { CallTypeBar } from "@/components/charts/CallTypeBar";
import { DashboardHero } from "@/components/DashboardHero";
import { GetStartedCard } from "@/components/GetStartedCard";
import { AuditDetailModal } from "@/components/AuditDetailModal";
import { LiveTicker } from "@/components/LiveTicker";
import { UpgradeBanner } from "@/components/UpgradeBanner";
import { LockedProCard } from "@/components/LockedProCard";
import {
  AnomalyPreview,
  RetentionTrendPreview,
  MultiSessionPreview,
} from "@/components/charts/ProPreviews";
import { useTier } from "@/hooks/useTier";

function ScoreDistributionBar({
  allow,
  queue,
  deny,
}: {
  allow: number;
  queue: number;
  deny: number;
}) {
  const total = allow + queue + deny;
  if (total === 0) {
    return (
      <div className="h-3 rounded-full bg-border overflow-hidden" />
    );
  }
  const pctAllow = (allow / total) * 100;
  const pctQueue = (queue / total) * 100;
  const pctDeny = (deny / total) * 100;

  return (
    <div className="h-3 rounded-full bg-border overflow-hidden flex">
      {pctAllow > 0 && (
        <div
          className="bg-green transition-all"
          style={{ width: `${pctAllow}%` }}
        />
      )}
      {pctQueue > 0 && (
        <div
          className="bg-warning transition-all"
          style={{ width: `${pctQueue}%` }}
        />
      )}
      {pctDeny > 0 && (
        <div
          className="bg-danger transition-all"
          style={{ width: `${pctDeny}%` }}
        />
      )}
    </div>
  );
}

/** Three-phase filter pipeline visualization (Static → Pattern → Context). */
function FilterPipeline({
  filters,
}: {
  filters: ProxyStatusResponse["filters"];
}) {
  const ready = filters.filter((f) => f.is_ready).length;
  const phases = [
    {
      key: "static",
      label: "Static",
      sub: "<0.1ms",
      count: filters.filter((f) => f.phase === "static").length,
    },
    {
      key: "pattern",
      label: "Pattern",
      sub: "1–3ms",
      count: filters.filter((f) => f.phase === "pattern").length,
    },
    {
      key: "context",
      label: "Context",
      sub: "behavioural",
      count: filters.filter((f) => f.phase === "context").length,
    },
  ];
  return (
    <div className="bg-surface border border-border rounded-card p-5">
      <div className="flex items-baseline justify-between mb-4">
        <h2 className="font-heading text-[15px] font-semibold text-text">Filter Pipeline</h2>
        <span className="text-xs text-text-secondary">
          <span className="font-code font-semibold text-accent-text">
            {ready}
          </span>{" "}
          active
        </span>
      </div>
      <div className="flex items-stretch gap-2">
        {phases.map((p, i) => (
          <div key={p.key} className="flex items-stretch flex-1 gap-2">
            <div className="flex-1 rounded-btn bg-surface-2 border border-border px-3 py-3 text-center">
              <div className="font-heading text-2xl font-semibold tracking-[-0.02em] text-text tabular-nums">
                {p.count}
              </div>
              <div className="text-xs text-text mt-0.5">{p.label}</div>
              <div className="text-[10px] text-text-dim font-code mt-0.5">
                {p.sub}
              </div>
            </div>
            {i < phases.length - 1 && (
              <div className="flex items-center text-text-dim">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
                  <path
                    d="M9 6l6 6-6 6"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </div>
            )}
          </div>
        ))}
      </div>
      <p className="text-xs text-text-secondary mt-4 leading-relaxed">
        Every tool call flows through {ready} parallel filters across three
        phases before grith decides{" "}
        <span className="text-accent-text font-medium">allow</span>,{" "}
        <span className="text-warning-text font-medium">queue</span>, or{" "}
        <span className="text-danger-text font-medium">deny</span>.
      </p>
    </div>
  );
}

/** A small "you're on the free window" hint shown under time-series charts for
 *  non-paid tiers — the honest retention upsell. */
function RetentionNote({ billingUrl }: { billingUrl: string }) {
  return (
    <a
      href={billingUrl}
      className="mt-3 flex items-center justify-between gap-2 rounded-lg border border-green-border bg-green-light px-3 py-2 text-[11px] transition-colors hover:bg-green/15"
    >
      <span className="text-text-secondary">
        Showing the last <span className="font-medium text-text">24 hours</span>. Pro retains{" "}
        <span className="font-medium text-text">90 days</span> for trend &amp; incident review.
      </span>
      <span className="flex-shrink-0 font-semibold text-accent-text">Upgrade →</span>
    </a>
  );
}

function PlanLabel(tierKey: string): string {
  if (tierKey === "pro") return "Pro";
  if (tierKey === "enterprise") return "Enterprise";
  return "Community";
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m ${s}s`;
}

/** Compute decision counts from audit records. */
/** localStorage key remembering the operator's chosen hero window. */
const HERO_WINDOW_KEY = "grith-hero-window";

const HERO_WINDOW_VALUES: SummaryWindow[] = ["today", "7d", "30d", "all"];

/**
 * Default to the last 7 days: large enough to look substantial on a quiet
 * morning, recent enough to reflect current usage, and — unlike all-time —
 * bounded in both display width and query cost as the audit database grows.
 */
function readHeroWindow(): SummaryWindow {
  try {
    const stored = localStorage.getItem(HERO_WINDOW_KEY) as SummaryWindow | null;
    if (stored && HERO_WINDOW_VALUES.includes(stored)) return stored;
  } catch {
    // Private windows and blocked site data throw on access; fall through.
  }
  return "7d";
}

function persistHeroWindow(next: SummaryWindow): void {
  try {
    localStorage.setItem(HERO_WINDOW_KEY, next);
  } catch {
    // Non-fatal: the choice just won't survive a reload.
  }
}

/** Derive per-session stats from audit records. */
interface AuditSession {
  session_id: string;
  name: string;
  allowed: number;
  queued: number;
  denied: number;
  total: number;
  last_seen: string;
  /** Project name (from the live supervisor session), when still running. */
  project_name?: string | null;
  cwd?: string | null;
  uptime_seconds?: number;
  is_live?: boolean;
}

/** Derive a human project label from a cwd when the daemon didn't set one. */
function projectFromCwd(cwd?: string | null): string | null {
  if (!cwd) return null;
  const parts = cwd.replace(/\/+$/, "").split("/").filter(Boolean);
  return parts[parts.length - 1] ?? null;
}

/** Enrich audit-derived sessions with live supervisor data (project, uptime),
 *  and surface any live session that has no audit rows yet. */
function mergeSessions(
  audit: AuditSession[],
  live: SessionSummary[],
): AuditSession[] {
  const liveById = new Map(live.map((s) => [s.id, s]));
  const out = audit.map((s) => {
    const l = liveById.get(s.session_id);
    if (!l) return s;
    return {
      ...s,
      project_name: l.project_name ?? projectFromCwd(l.cwd) ?? s.project_name,
      cwd: l.cwd,
      uptime_seconds: l.uptime_seconds,
      is_live: true,
    };
  });
  // Live sessions with no audit rows yet (just started) — show them too.
  const seen = new Set(audit.map((s) => s.session_id));
  for (const l of live) {
    if (seen.has(l.id)) continue;
    out.unshift({
      session_id: l.id,
      name: l.tool_name,
      allowed: l.stats.total_allowed,
      queued: l.stats.total_queued,
      denied: l.stats.total_denied,
      total: l.stats.total_intercepted,
      last_seen: new Date().toISOString(),
      project_name: l.project_name ?? projectFromCwd(l.cwd),
      cwd: l.cwd,
      uptime_seconds: l.uptime_seconds,
      is_live: true,
    });
  }
  return out;
}

function deriveSessionsFromAudit(records: AuditRecord[]): AuditSession[] {
  const map = new Map<string, AuditSession>();
  for (const r of records) {
    let s = map.get(r.session_id);
    if (!s) {
      s = {
        session_id: r.session_id,
        name: r.supervised_tool ?? r.source,
        allowed: 0,
        queued: 0,
        denied: 0,
        total: 0,
        last_seen: r.timestamp,
        // Persisted on supervisor records, so ended sessions keep their label.
        project_name: r.project_name ?? null,
      };
      map.set(r.session_id, s);
    }
    if (!s.project_name && r.project_name) s.project_name = r.project_name;
    s.total++;
    switch (r.proxy_action) {
      case "allow":
        s.allowed++;
        break;
      case "queue":
        s.queued++;
        break;
      case "deny":
        s.denied++;
        break;
    }
    if (r.timestamp > s.last_seen) s.last_seen = r.timestamp;
  }
  // Sort by most recent activity first.
  return [...map.values()].sort((a, b) => b.last_seen.localeCompare(a.last_seen));
}

export function DashboardPage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [proxy, setProxy] = useState<ProxyStatusResponse | null>(null);
  const [exfil, setExfil] = useState<ExfilStatsResponse | null>(null);
  // Server-aggregated hero figures. Previously the headline was a
  // whole-database count while allow/queue/deny were tallied from whatever
  // records this page had fetched — two different populations in one panel.
  // One windowed query now supplies all four.
  const [summary, setSummary] = useState<AuditSummaryResponse | null>(null);
  const [heroWindow, setHeroWindow] = useState<SummaryWindow>(readHeroWindow);
  const [auditSessions, setAuditSessions] = useState<AuditSession[]>([]);
  const [auditRecords, setAuditRecords] = useState<AuditRecord[]>([]);
  // Currently-live supervisor sessions (registry) — carry project name, cwd,
  // and uptime. Distinct from `auditSessions` (distinct session_ids in the
  // recent audit window, which includes already-ended sessions).
  const [liveSessions, setLiveSessions] = useState<SessionSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [selectedRecord, setSelectedRecord] = useState<AuditRecord | null>(null);
  const tierState = useTier();
  const shareRequested =
    new URLSearchParams(window.location.search).get("share") === "1";

  useEffect(() => {
    async function load() {
      // Fetch each endpoint independently so one failure doesn't blank
      // the entire dashboard.
      const results = await Promise.allSettled([
        getHealth(),
        getProxyStatus(),
        getExfilStats(),
        getAuditRecords({ limit: 500, offset: 0 }),
        getSessions(),
        getAuditSummary(heroWindow),
      ]);

      const [h, p, e, audit, sessions, heroSummary] = results;

      if (h.status === "fulfilled") setHealth(h.value);
      if (p.status === "fulfilled") setProxy(p.value);
      if (e.status === "fulfilled") setExfil(e.value);
      if (heroSummary.status === "fulfilled") setSummary(heroSummary.value);
      if (audit.status === "fulfilled") {
        setAuditSessions(deriveSessionsFromAudit(audit.value.records));
        setAuditRecords(audit.value.records);
      }
      if (sessions.status === "fulfilled" && sessions.value?.sessions) {
        setLiveSessions(sessions.value.sessions);
      }

      const allFailed = results.every((r) => r.status === "rejected");
      if (allFailed) {
        setHealth(null);
        setProxy(null);
        setExfil(null);
        setSummary(null);
        setAuditSessions([]);
        setLiveSessions([]);
        setError("grith daemon has stopped. Restart with grith exec or grith run.");
      } else {
        setError(null);
      }
    }
    void load();
    const interval = setInterval(() => void load(), 5_000);
    return () => clearInterval(interval);
  }, [heroWindow]);

  // Prefer the audit summary (durable, covers thin-client evaluations) over
  // the proxy's in-memory counters, which reset with the daemon and only see
  // in-process work.
  const totalEvals = summary?.total ?? proxy?.total_evaluations ?? 0;
  const allowCount = summary?.allow ?? proxy?.allow_count ?? 0;
  const queueCount = summary?.queue ?? proxy?.queue_count ?? 0;
  const denyCount = summary?.deny ?? proxy?.deny_count ?? 0;
  const filtersActive = proxy?.filters.filter((f) => f.is_ready).length ?? 0;
  const displaySessions = mergeSessions(auditSessions, liveSessions);
  // session_id → human project label, for naming Live Decisions rows by
  // project rather than the supervised tool.
  const sessionProjects = new Map<string, string>();
  for (const s of displaySessions) {
    if (s.project_name) sessionProjects.set(s.session_id, s.project_name);
  }

  return (
    <div className="p-6 max-w-6xl">
      {error && (
        <div className="bg-danger-light border border-danger-border rounded-card p-3 mb-6 text-sm text-danger-text">
          {error}
        </div>
      )}

      {/* Hero — the shareable security-posture centerpiece */}
      <DashboardHero
        totalEvals={totalEvals}
        allow={allowCount}
        queue={queueCount}
        deny={denyCount}
        liveSessions={liveSessions.length}
        uptime={health ? formatUptime(health.uptime_seconds) : "--"}
        filtersActive={filtersActive}
        version={health?.version}
        online={!error && health !== null}
        planLabel={PlanLabel(tierState.tierKey)}
        planPaid={tierState.isPaid}
        billingUrl={tierState.billingUrl}
        shareOnOpen={shareRequested && (summary !== null || proxy !== null)}
        timeWindow={heroWindow}
        onWindowChange={(next) => {
          setHeroWindow(next);
          persistHeroWindow(next);
        }}
      />

      {/* Persistent upgrade banner — hidden only for Enterprise. */}
      <UpgradeBanner tierState={tierState} />

      {/* First-run "Get started" checklist — self-hides when done/dismissed. */}
      <GetStartedCard />

      {/* Interactive score scatter — the hero visualization */}
      {auditRecords.length > 0 && (
        <div className="bg-surface border border-border rounded-card p-5 mb-8">
          <h2 className="font-heading text-[15px] font-semibold text-text mb-2">
            Evaluation Scores
          </h2>
          <InteractiveScoreScatter
            records={auditRecords}
            onSelect={setSelectedRecord}
          />
          {!tierState.isPaid && <RetentionNote billingUrl={tierState.billingUrl} />}
        </div>
      )}

      {/* Activity over time (stacked) + live decision ticker */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-8">
        {auditRecords.length > 0 && (
          <div className="bg-surface border border-border rounded-card p-5">
            <h2 className="font-heading text-[15px] font-semibold text-text mb-2">
              Activity Over Time
            </h2>
            <ActivityArea records={auditRecords} />
          </div>
        )}
        <LiveTicker
          records={auditRecords}
          online={!error && health !== null}
          projects={sessionProjects}
          onSelect={setSelectedRecord}
        />
      </div>

      {/* Threat signals (filter contribution) — the security story */}
      {auditRecords.length > 0 && (
        <div className="bg-surface border border-border rounded-card p-5 mb-8">
          <div className="flex items-baseline justify-between mb-3">
            <h2 className="font-heading text-[15px] font-semibold text-text">
              Threat Signals
            </h2>
            <span className="text-xs text-text-secondary">which filters fired</span>
          </div>
          <ThreatSignals records={auditRecords} />
        </div>
      )}

      {/* Call types + latency, side by side */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
        {auditRecords.length > 0 && (
          <div className="bg-surface border border-border rounded-card p-5">
            <h2 className="font-heading text-[15px] font-semibold text-text mb-2">
              Call Types
            </h2>
            <CallTypeBar records={auditRecords} />
          </div>
        )}
        {auditRecords.length > 0 && (
          <div className="bg-surface border border-border rounded-card p-5">
            <h2 className="font-heading text-[15px] font-semibold text-text mb-2">
              Evaluation Latency
            </h2>
            <LatencyHistogram records={auditRecords} />
          </div>
        )}
      </div>

      {/* Filter pipeline (full width) */}
      {proxy && proxy.filters.length > 0 && (
        <div className="mb-8">
          <FilterPipeline filters={proxy.filters} />
        </div>
      )}

      {/* Locked premium insights — prominent, persistent upsell surfaces. */}
      {!tierState.isPaid && (
        <div className="mb-8">
          <div className="flex items-baseline justify-between mb-3">
            <h2 className="font-heading text-[15px] font-semibold text-text">
              Premium Insights
            </h2>
            <span className="text-xs text-text-secondary">available on Pro</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <LockedProCard
              title="Anomaly Detection"
              description="Get alerted when an agent's behaviour deviates from its learned baseline."
              billingUrl={tierState.billingUrl}
            >
              <AnomalyPreview />
            </LockedProCard>
            <LockedProCard
              title="90-Day Trends"
              description="Keep three months of audit history to spot drift and prove compliance."
              billingUrl={tierState.billingUrl}
            >
              <RetentionTrendPreview />
            </LockedProCard>
            <LockedProCard
              title="Session Comparison"
              description="Compare security posture across tools and sessions side by side."
              tier="Enterprise"
              billingUrl={tierState.billingUrl}
            >
              <MultiSessionPreview />
            </LockedProCard>
          </div>
        </div>
      )}

      {/* Unlocked Session Comparison — real data for paid tiers. */}
      {tierState.isPaid && displaySessions.length > 1 && (
        <div className="bg-surface border border-border rounded-card p-5 mb-8">
          <div className="flex items-baseline justify-between mb-3">
            <h2 className="font-heading text-[15px] font-semibold text-text">
              Session Comparison
            </h2>
            <span className="text-xs text-text-secondary">posture by session</span>
          </div>
          <SessionComparison
            sessions={displaySessions.map((s) => ({
              id: s.session_id,
              label: s.project_name ?? s.name,
              allow: s.allowed,
              queue: s.queued,
              deny: s.denied,
              total: s.total,
            }))}
          />
        </div>
      )}

      {/* Exfiltration attempts */}
      {exfil && (exfil.total_blocked > 0 || exfil.total_queued > 0) && (
        <div className="bg-surface border border-border rounded-card p-5 mb-8">
          <h2 className="font-heading text-[15px] font-semibold text-text mb-4">
            Exfiltration Attempts
          </h2>
          <div className="grid grid-cols-3 gap-4 mb-4">
            <div className="text-center">
              <p className="font-label text-[11px] text-text-dim uppercase tracking-[0.08em]">Denied</p>
              <p className="font-heading text-xl font-semibold text-danger-text">
                {exfil.total_blocked}
              </p>
            </div>
            <div className="text-center">
              <p className="font-label text-[11px] text-text-dim uppercase tracking-[0.08em]">Queued</p>
              <p className="font-heading text-xl font-semibold text-warning-text">
                {exfil.total_queued}
              </p>
            </div>
            <div className="text-center">
              <p className="font-label text-[11px] text-text-dim uppercase tracking-[0.08em]">Redacted (DLP)</p>
              <p className="font-heading text-xl font-semibold text-text">
                {exfil.total_redacted}
              </p>
            </div>
          </div>

          {/* Contextual upsell — only fires when there's a real number to act on. */}
          {tierState.tierKey !== "enterprise" && exfil.total_blocked > 0 && (
            <a
              href={tierState.billingUrl}
              className="group mb-4 flex items-center justify-between gap-3 rounded-lg border border-danger-border bg-danger-light px-4 py-3 transition-colors hover:border-danger/50"
            >
              <div className="flex items-center gap-3 min-w-0">
                <span className="flex-shrink-0 inline-flex h-8 w-8 items-center justify-center rounded-lg bg-danger-light text-danger-text">
                  <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" aria-hidden>
                    <path d="M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
                  </svg>
                </span>
                <p className="text-xs text-text min-w-0">
                  grith denied{" "}
                  <span className="font-semibold">
                    {exfil.total_blocked.toLocaleString()}
                  </span>{" "}
                  exfiltration attempt{exfil.total_blocked !== 1 ? "s" : ""}.{" "}
                  <span className="text-text-secondary">
                    Get a real-time Slack &amp; email alert the moment it happens with Pro.
                  </span>
                </p>
              </div>
              <span className="flex-shrink-0 inline-flex items-center gap-1 rounded-btn bg-green px-3 py-1.5 text-[11px] font-heading font-semibold text-accent-ink transition-transform group-hover:translate-x-0.5">
                Enable alerts →
              </span>
            </a>
          )}

          {Object.keys(exfil.by_protocol).length > 0 && (
            <div className="mb-4">
              <h3 className="font-label text-[11px] text-text-dim uppercase tracking-[0.08em] mb-2">By Protocol</h3>
              <div className="flex flex-wrap gap-2">
                {Object.entries(exfil.by_protocol).map(([protocol, count]) => (
                  <span
                    key={protocol}
                    className="inline-flex items-center gap-1.5 px-2 py-1 rounded-lg bg-surface-2 text-xs"
                  >
                    <span className="text-text">{protocol}</span>
                    <span className="text-text-secondary font-code">{count}</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {exfil.top_blocked_destinations.length > 0 && (
            <div>
              <h3 className="font-label text-[11px] text-text-dim uppercase tracking-[0.08em] mb-2">
                Top Denied Destinations
              </h3>
              <div className="space-y-1">
                {exfil.top_blocked_destinations.map((d) => (
                  <div
                    key={d.domain}
                    className="flex items-center justify-between py-1 px-3 rounded-md"
                  >
                    <span className="text-xs text-text font-code truncate max-w-[300px]">
                      {d.domain}
                    </span>
                    <span className="text-xs text-danger-text font-code">
                      {d.count}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Sessions — live supervisor sessions enriched with audit stats */}
      {displaySessions.length > 0 && (
        <div className="mb-8 space-y-4">
          <div className="flex items-baseline justify-between">
            <h2 className="font-heading text-[15px] font-semibold text-text">Sessions</h2>
            <span className="text-xs text-text-secondary">
              {liveSessions.length > 0 ? (
                <>
                  <span className="font-code font-semibold text-accent-text">
                    {liveSessions.length}
                  </span>{" "}
                  live
                </>
              ) : (
                "recent"
              )}
            </span>
          </div>
          {displaySessions.map((s) => (
            <div
              key={s.session_id}
              className="bg-surface border border-border rounded-card p-5 transition-colors hover:border-border-dark"
            >
              <div className="flex gap-5">
                {/* Donut */}
                <div className="flex-shrink-0 flex items-center">
                  <MiniDonut allow={s.allowed} queue={s.queued} deny={s.denied} size={56} />
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  {/* Session header — project name leads, tool is secondary */}
                  <div className="flex items-center justify-between mb-3 gap-3">
                    <div className="flex items-center gap-2.5 min-w-0">
                      {s.is_live && (
                        <span className="relative flex flex-shrink-0">
                          <span className="grith-pulse-ring relative w-2 h-2 rounded-full text-green">
                            <span className="block w-2 h-2 rounded-full bg-green" />
                          </span>
                        </span>
                      )}
                      <span className="text-sm font-semibold text-text truncate">
                        {s.project_name ?? s.name}
                      </span>
                      <span className="flex-shrink-0 inline-flex items-center px-1.5 py-0.5 rounded-md bg-surface-2 text-[11px] font-medium text-text-secondary">
                        {s.name}
                      </span>
                      <span className="hidden sm:inline text-[11px] text-text-dim font-code flex-shrink-0">
                        {s.session_id.slice(0, 8)}
                      </span>
                    </div>
                    <span className="text-xs text-text-secondary flex-shrink-0">
                      {s.is_live && s.uptime_seconds !== undefined
                        ? `${formatUptime(s.uptime_seconds)} up`
                        : new Date(s.last_seen).toLocaleTimeString()}
                    </span>
                  </div>

                  {/* cwd path, when known */}
                  {s.cwd && (
                    <p className="text-[11px] text-text-dim font-code truncate mb-3 -mt-1">
                      {s.cwd}
                    </p>
                  )}

                  {/* Session stats */}
                  <div className="flex gap-6 text-xs mb-3">
                    <span>
                      <span className="text-text-secondary">Total </span>
                      <span className="font-semibold text-text font-code">
                        {s.total.toLocaleString()}
                      </span>
                    </span>
                    <span>
                      <span className="text-text-secondary">Allow </span>
                      <span className="font-semibold text-accent-text font-code">
                        {s.allowed.toLocaleString()}
                      </span>
                    </span>
                    <span>
                      <span className="text-text-secondary">Queue </span>
                      <span className="font-semibold text-warning-text font-code">
                        {s.queued.toLocaleString()}
                      </span>
                    </span>
                    <span>
                      <span className="text-text-secondary">Deny </span>
                      <span className="font-semibold text-danger-text font-code">
                        {s.denied.toLocaleString()}
                      </span>
                    </span>
                  </div>

                  {/* Score bar */}
                  {s.total > 0 && (
                    <ScoreDistributionBar
                      allow={s.allowed}
                      queue={s.queued}
                      deny={s.denied}
                    />
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Subsystems */}
      {health && Object.keys(health.subsystems).length > 0 && (
        <div className="bg-surface border border-border rounded-card p-5">
          <h2 className="font-heading text-[15px] font-semibold text-text mb-4">
            Subsystems
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {Object.entries(health.subsystems).map(([name, sub]) => (
              <div
                key={name}
                className="flex items-center justify-between py-2 px-3 rounded-md"
              >
                <div className="flex items-center gap-2">
                  <span
                    className={`w-2 h-2 rounded-full ${
                      sub.status === "ok"
                        ? "bg-green"
                        : sub.status === "degraded"
                          ? "bg-warning"
                          : "bg-danger"
                    }`}
                  />
                  <span className="text-sm text-text capitalize">
                    {name}
                  </span>
                </div>
                {sub.latency_ms !== undefined && (
                  <span className="text-xs text-text-secondary">
                    {sub.latency_ms.toFixed(1)}ms
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {selectedRecord && (
        <AuditDetailModal
          record={selectedRecord}
          onClose={() => setSelectedRecord(null)}
        />
      )}
    </div>
  );
}
