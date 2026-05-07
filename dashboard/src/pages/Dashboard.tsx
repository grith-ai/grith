import { useEffect, useState } from "react";
import type {
  AuditRecord,
  ExfilStatsResponse,
  HealthResponse,
  ProxyStatusResponse,
} from "@/types/api";
import {
  getHealth,
  getProxyStatus,
  getExfilStats,
  getAuditRecords,
} from "@/lib/api";
import { ScoreScatter } from "@/components/charts/ScoreScatter";
import { MiniDonut } from "@/components/charts/MiniDonut";
import { CallTypeBar } from "@/components/charts/CallTypeBar";

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

function StatCard({
  label,
  value,
  color,
}: {
  label: string;
  value: string | number;
  color?: string;
}) {
  return (
    <div className="bg-white border border-grith-border rounded-xl p-4">
      <p className="text-xs text-grith-muted uppercase tracking-wider mb-1">
        {label}
      </p>
      <p className={`text-2xl font-semibold ${color ?? "text-grith-text"}`}>
        {value}
      </p>
    </div>
  );
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
      };
      map.set(r.session_id, s);
    }
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
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      // Fetch each endpoint independently so one failure doesn't blank
      // the entire dashboard.
      const results = await Promise.allSettled([
        getHealth(),
        getProxyStatus(),
        getExfilStats(),
        getAuditRecords({ limit: 500, offset: 0 }),
      ]);

      const [h, p, e, audit] = results;

      if (h.status === "fulfilled") setHealth(h.value);
      if (p.status === "fulfilled") setProxy(p.value);
      if (e.status === "fulfilled") setExfil(e.value);
      if (audit.status === "fulfilled") {
        setAuditStats(computeStats(audit.value.records, audit.value.total));
        setAuditSessions(deriveSessionsFromAudit(audit.value.records));
        setAuditRecords(audit.value.records);
      }

      const allFailed = results.every((r) => r.status === "rejected");
      if (allFailed) {
        setHealth(null);
        setProxy(null);
        setExfil(null);
        setAuditStats(null);
        setAuditSessions([]);
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

  return (
    <div className="p-6 max-w-6xl">
      <h1 className="text-xl font-semibold text-grith-text mb-6">
        Dashboard
      </h1>

      {error && (
        <div className="bg-status-deny-red/10 border border-status-deny-red/30 rounded-xl p-3 mb-6 text-sm text-status-deny-red">
          {error}
        </div>
      )}

      {/* Stats grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <StatCard
          label="Status"
          value={health?.status ?? "--"}
          color={
            health?.status === "healthy"
              ? "text-status-allow-green"
              : health?.status === "degraded"
                ? "text-status-queue-amber"
                : "text-grith-muted"
          }
        />
        <StatCard
          label="Total Evaluations"
          value={totalEvals.toLocaleString()}
        />
        <StatCard
          label="Sessions"
          value={auditSessions.length}
          color={
            auditSessions.length > 0
              ? "text-status-allow-green"
              : "text-grith-text"
          }
        />
        <StatCard
          label="Uptime"
          value={
            health
              ? formatUptime(health.uptime_seconds)
              : "--"
          }
        />
      </div>

      {/* Decision distribution (from most recent evaluations) */}
      {(allowCount + queueCount + denyCount) > 0 && (
        <div className="bg-white border border-grith-border rounded-xl p-5 mb-8">
          <h2 className="text-sm font-medium text-grith-text mb-4">
            Recent Decision Distribution
          </h2>
          <ScoreDistributionBar
            allow={allowCount}
            queue={queueCount}
            deny={denyCount}
          />
          <div className="flex gap-6 mt-3 text-xs text-grith-muted">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-status-allow-green" />
              Allow: {allowCount.toLocaleString()}
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-status-queue-amber" />
              Queue: {queueCount.toLocaleString()}
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-status-deny-red" />
              Deny: {denyCount.toLocaleString()}
            </span>
          </div>
        </div>
      )}

      {/* Live score scatter — the hero visualization */}
      {auditRecords.length > 0 && (
        <div className="bg-white border border-grith-border rounded-xl p-5 mb-8">
          <h2 className="text-sm font-medium text-grith-text mb-2">
            Evaluation Scores
          </h2>
          <ScoreScatter records={auditRecords} />
        </div>
      )}

      {/* Call type breakdown + filter summary side by side */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
        {auditRecords.length > 0 && (
          <div className="bg-white border border-grith-border rounded-xl p-5">
            <h2 className="text-sm font-medium text-grith-text mb-2">
              Call Types
            </h2>
            <CallTypeBar records={auditRecords} />
          </div>
        )}
        {proxy && proxy.filters.length > 0 && (
          <div className="bg-white border border-grith-border rounded-xl p-5 flex items-center">
            <span className="text-sm text-grith-muted">
              {proxy.filters.filter((f) => f.is_ready).length} filters active
              <span className="text-grith-dim mx-1">&middot;</span>
              {proxy.filters.filter((f) => f.phase === "static").length} static
              <span className="text-grith-dim mx-1">&middot;</span>
              {proxy.filters.filter((f) => f.phase === "pattern").length} pattern
              <span className="text-grith-dim mx-1">&middot;</span>
              {proxy.filters.filter((f) => f.phase === "context").length} context
            </span>
          </div>
        )}
      </div>

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

      {/* Sessions — derived from audit records */}
      {auditSessions.length > 0 && (
        <div className="mb-8 space-y-4">
          <h2 className="text-sm font-medium text-grith-text">
            Sessions
          </h2>
          {auditSessions.map((s) => (
            <div
              key={s.session_id}
              className="bg-white border border-grith-border rounded-xl p-5"
            >
              <div className="flex gap-5">
                {/* Donut */}
                <div className="flex-shrink-0 flex items-center">
                  <MiniDonut allow={s.allowed} queue={s.queued} deny={s.denied} size={56} />
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  {/* Session header */}
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <span className="text-sm font-semibold text-grith-text">
                        {s.name}
                      </span>
                      <span className="text-xs text-grith-dim font-mono">
                        {s.session_id.slice(0, 8)}
                      </span>
                    </div>
                    <span className="text-xs text-grith-muted">
                      {new Date(s.last_seen).toLocaleTimeString()}
                    </span>
                  </div>

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
    </div>
  );
}
