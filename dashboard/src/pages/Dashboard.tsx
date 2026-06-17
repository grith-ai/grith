import { useEffect, useState } from "react";
import type {
  AuditRecord,
  ExfilStatsResponse,
  HealthResponse,
  ProxyStatusResponse,
  SessionSummary,
} from "@/types/api";
import {
  getHealth,
  getProxyStatus,
  getExfilStats,
  getAuditRecords,
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
      <div className="h-3 rounded-full bg-grith-surface overflow-hidden" />
    );
  }
  const pctAllow = (allow / total) * 100;
  const pctQueue = (queue / total) * 100;
  const pctDeny = (deny / total) * 100;

  return (
    <div className="h-3 rounded-full bg-grith-surface overflow-hidden flex">
      {pctAllow > 0 && (
        <div
          className="bg-status-allow-green transition-all"
          style={{ width: `${pctAllow}%` }}
        />
      )}
      {pctQueue > 0 && (
        <div
          className="bg-status-queue-amber transition-all"
          style={{ width: `${pctQueue}%` }}
        />
      )}
      {pctDeny > 0 && (
        <div
          className="bg-status-deny-red transition-all"
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
    <div className="bg-white border border-grith-border rounded-xl p-5">
      <div className="flex items-baseline justify-between mb-4">
        <h2 className="text-sm font-medium text-grith-text">Filter Pipeline</h2>
        <span className="text-xs text-grith-muted">
          <span className="font-mono font-semibold text-status-allow-green">
            {ready}
          </span>{" "}
          active
        </span>
      </div>
      <div className="flex items-stretch gap-2">
        {phases.map((p, i) => (
          <div key={p.key} className="flex items-stretch flex-1 gap-2">
            <div className="flex-1 rounded-lg bg-grith-surface border border-grith-border px-3 py-3 text-center">
              <div className="font-mono text-2xl font-semibold text-grith-text tabular-nums">
                {p.count}
              </div>
              <div className="text-xs text-grith-text mt-0.5">{p.label}</div>
              <div className="text-[10px] text-grith-dim font-mono mt-0.5">
                {p.sub}
              </div>
            </div>
            {i < phases.length - 1 && (
              <div className="flex items-center text-grith-dim">
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
      <p className="text-xs text-grith-muted mt-4 leading-relaxed">
        Every tool call flows through {ready} parallel filters across three
        phases before grith decides{" "}
        <span className="text-status-allow-green font-medium">allow</span>,{" "}
        <span className="text-status-queue-amber font-medium">review</span>, or{" "}
        <span className="text-status-deny-red font-medium">deny</span>.
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
      className="mt-3 flex items-center justify-between gap-2 rounded-lg border border-dashed border-green/40 bg-green-light/50 px-3 py-2 text-[11px] transition-colors hover:bg-green-light"
    >
      <span className="text-grith-muted">
        Showing the last <span className="font-medium text-grith-text">24 hours</span>. Pro retains{" "}
        <span className="font-medium text-grith-text">90 days</span> for trend &amp; incident review.
      </span>
      <span className="flex-shrink-0 font-semibold text-green-dark">Upgrade →</span>
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
function computeStats(records: AuditRecord[], dbTotal: number) {
  let allow = 0;
  let queue = 0;
  let deny = 0;
  for (const r of records) {
    switch (r.proxy_action) {
      case "allow":
        allow++;
        break;
      case "queue":
        queue++;
        break;
      case "deny":
        deny++;
        break;
    }
  }
  return { dbTotal, allow, queue, deny };
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
  const [auditStats, setAuditStats] = useState<{
    dbTotal: number;
    allow: number;
    queue: number;
    deny: number;
  } | null>(null);
  const [auditSessions, setAuditSessions] = useState<AuditSession[]>([]);
  const [auditRecords, setAuditRecords] = useState<AuditRecord[]>([]);
  // Currently-live supervisor sessions (registry) — carry project name, cwd,
  // and uptime. Distinct from `auditSessions` (distinct session_ids in the
  // recent audit window, which includes already-ended sessions).
  const [liveSessions, setLiveSessions] = useState<SessionSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [selectedRecord, setSelectedRecord] = useState<AuditRecord | null>(null);
  const tierState = useTier();

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
      ]);

      const [h, p, e, audit, sessions] = results;

      if (h.status === "fulfilled") setHealth(h.value);
      if (p.status === "fulfilled") setProxy(p.value);
      if (e.status === "fulfilled") setExfil(e.value);
      if (audit.status === "fulfilled") {
        setAuditStats(computeStats(audit.value.records, audit.value.total));
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
        setAuditStats(null);
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
  }, []);

  // Prefer audit-derived stats (real data from thin client evaluations)
  // over proxy in-memory counters (only counts in-process evaluations).
  const totalEvals = auditStats?.dbTotal ?? proxy?.total_evaluations ?? 0;
  const allowCount = auditStats?.allow ?? proxy?.allow_count ?? 0;
  const queueCount = auditStats?.queue ?? proxy?.queue_count ?? 0;
  const denyCount = auditStats?.deny ?? proxy?.deny_count ?? 0;
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
        <div className="bg-status-deny-red/10 border border-status-deny-red/30 rounded-xl p-3 mb-6 text-sm text-status-deny-red">
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
      />

      {/* Persistent upgrade banner — hidden only for Enterprise. */}
      <UpgradeBanner tierState={tierState} />

      {/* Interactive score scatter — the hero visualization */}
      {auditRecords.length > 0 && (
        <div className="bg-white border border-grith-border rounded-xl p-5 mb-8">
          <h2 className="text-sm font-medium text-grith-text mb-2">
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
          <div className="bg-white border border-grith-border rounded-xl p-5">
            <h2 className="text-sm font-medium text-grith-text mb-2">
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
        <div className="bg-white border border-grith-border rounded-xl p-5 mb-8">
          <div className="flex items-baseline justify-between mb-3">
            <h2 className="text-sm font-medium text-grith-text">
              Threat Signals
            </h2>
            <span className="text-xs text-grith-muted">which filters fired</span>
          </div>
          <ThreatSignals records={auditRecords} />
        </div>
      )}

      {/* Call types + latency, side by side */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
        {auditRecords.length > 0 && (
          <div className="bg-white border border-grith-border rounded-xl p-5">
            <h2 className="text-sm font-medium text-grith-text mb-2">
              Call Types
            </h2>
            <CallTypeBar records={auditRecords} />
          </div>
        )}
        {auditRecords.length > 0 && (
          <div className="bg-white border border-grith-border rounded-xl p-5">
            <h2 className="text-sm font-medium text-grith-text mb-2">
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
            <h2 className="text-sm font-medium text-grith-text">
              Premium Insights
            </h2>
            <span className="text-xs text-grith-muted">available on Pro</span>
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
        <div className="bg-white border border-grith-border rounded-xl p-5 mb-8">
          <div className="flex items-baseline justify-between mb-3">
            <h2 className="text-sm font-medium text-grith-text">
              Session Comparison
            </h2>
            <span className="text-xs text-grith-muted">posture by session</span>
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
        <div className="bg-white border border-grith-border rounded-xl p-5 mb-8">
          <h2 className="text-sm font-medium text-grith-text mb-4">
            Exfiltration Attempts
          </h2>
          <div className="grid grid-cols-3 gap-4 mb-4">
            <div className="text-center">
              <p className="text-xs text-grith-muted uppercase">Blocked</p>
              <p className="text-xl font-semibold text-status-deny-red">
                {exfil.total_blocked}
              </p>
            </div>
            <div className="text-center">
              <p className="text-xs text-grith-muted uppercase">Queued</p>
              <p className="text-xl font-semibold text-status-queue-amber">
                {exfil.total_queued}
              </p>
            </div>
            <div className="text-center">
              <p className="text-xs text-grith-muted uppercase">Redacted (DLP)</p>
              <p className="text-xl font-semibold text-grith-text">
                {exfil.total_redacted}
              </p>
            </div>
          </div>

          {/* Contextual upsell — only fires when there's a real number to act on. */}
          {tierState.tierKey !== "enterprise" && exfil.total_blocked > 0 && (
            <a
              href={tierState.billingUrl}
              className="group mb-4 flex items-center justify-between gap-3 rounded-lg border border-status-deny-red/30 bg-status-deny-red/5 px-4 py-3 transition-colors hover:border-status-deny-red/50"
            >
              <div className="flex items-center gap-3 min-w-0">
                <span className="flex-shrink-0 inline-flex h-8 w-8 items-center justify-center rounded-lg bg-status-deny-red/10 text-status-deny-red">
                  <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" aria-hidden>
                    <path d="M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
                  </svg>
                </span>
                <p className="text-xs text-grith-text min-w-0">
                  grith blocked{" "}
                  <span className="font-semibold">
                    {exfil.total_blocked.toLocaleString()}
                  </span>{" "}
                  exfiltration attempt{exfil.total_blocked !== 1 ? "s" : ""}.{" "}
                  <span className="text-grith-muted">
                    Get a real-time Slack &amp; email alert the moment it happens with Pro.
                  </span>
                </p>
              </div>
              <span className="flex-shrink-0 inline-flex items-center gap-1 rounded-lg bg-green px-3 py-1.5 text-[11px] font-semibold text-white transition-transform group-hover:translate-x-0.5">
                Enable alerts →
              </span>
            </a>
          )}

          {Object.keys(exfil.by_protocol).length > 0 && (
            <div className="mb-4">
              <h3 className="text-xs text-grith-muted uppercase mb-2">By Protocol</h3>
              <div className="flex flex-wrap gap-2">
                {Object.entries(exfil.by_protocol).map(([protocol, count]) => (
                  <span
                    key={protocol}
                    className="inline-flex items-center gap-1.5 px-2 py-1 rounded-lg bg-grith-surface text-xs"
                  >
                    <span className="text-grith-text">{protocol}</span>
                    <span className="text-grith-muted font-mono">{count}</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {exfil.top_blocked_destinations.length > 0 && (
            <div>
              <h3 className="text-xs text-grith-muted uppercase mb-2">
                Top Blocked Destinations
              </h3>
              <div className="space-y-1">
                {exfil.top_blocked_destinations.map((d) => (
                  <div
                    key={d.domain}
                    className="flex items-center justify-between py-1 px-3 rounded-md"
                  >
                    <span className="text-xs text-grith-text font-mono truncate max-w-[300px]">
                      {d.domain}
                    </span>
                    <span className="text-xs text-status-deny-red font-mono">
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
            <h2 className="text-sm font-medium text-grith-text">Sessions</h2>
            <span className="text-xs text-grith-muted">
              {liveSessions.length > 0 ? (
                <>
                  <span className="font-mono font-semibold text-status-allow-green">
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
              className="bg-white border border-grith-border rounded-xl p-5 transition-colors hover:border-grith-border-hover"
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
                          <span className="grith-pulse-ring relative w-2 h-2 rounded-full text-status-allow-green">
                            <span className="block w-2 h-2 rounded-full bg-status-allow-green" />
                          </span>
                        </span>
                      )}
                      <span className="text-sm font-semibold text-grith-text truncate">
                        {s.project_name ?? s.name}
                      </span>
                      <span className="flex-shrink-0 inline-flex items-center px-1.5 py-0.5 rounded-md bg-grith-surface text-[11px] font-medium text-grith-muted">
                        {s.name}
                      </span>
                      <span className="hidden sm:inline text-[11px] text-grith-dim font-mono flex-shrink-0">
                        {s.session_id.slice(0, 8)}
                      </span>
                    </div>
                    <span className="text-xs text-grith-muted flex-shrink-0">
                      {s.is_live && s.uptime_seconds !== undefined
                        ? `${formatUptime(s.uptime_seconds)} up`
                        : new Date(s.last_seen).toLocaleTimeString()}
                    </span>
                  </div>

                  {/* cwd path, when known */}
                  {s.cwd && (
                    <p className="text-[11px] text-grith-dim font-mono truncate mb-3 -mt-1">
                      {s.cwd}
                    </p>
                  )}

                  {/* Session stats */}
                  <div className="flex gap-6 text-xs mb-3">
                    <span>
                      <span className="text-grith-muted">Total </span>
                      <span className="font-semibold text-grith-text font-mono">
                        {s.total.toLocaleString()}
                      </span>
                    </span>
                    <span>
                      <span className="text-grith-muted">Allow </span>
                      <span className="font-semibold text-status-allow-green font-mono">
                        {s.allowed.toLocaleString()}
                      </span>
                    </span>
                    <span>
                      <span className="text-grith-muted">Queue </span>
                      <span className="font-semibold text-status-queue-amber font-mono">
                        {s.queued.toLocaleString()}
                      </span>
                    </span>
                    <span>
                      <span className="text-grith-muted">Deny </span>
                      <span className="font-semibold text-status-deny-red font-mono">
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
        <div className="bg-white border border-grith-border rounded-xl p-5">
          <h2 className="text-sm font-medium text-grith-text mb-4">
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
                        ? "bg-status-allow-green"
                        : sub.status === "degraded"
                          ? "bg-status-queue-amber"
                          : "bg-status-deny-red"
                    }`}
                  />
                  <span className="text-sm text-grith-text capitalize">
                    {name}
                  </span>
                </div>
                {sub.latency_ms !== undefined && (
                  <span className="text-xs text-grith-muted">
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
