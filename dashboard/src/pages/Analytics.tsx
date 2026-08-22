/**
 * Analytics — the tiered local analytics surface backed by the precomputed
 * projection (work/82), never by raw-record aggregation in the browser.
 *
 * Free renders exactly the explicit Free contract from
 * `/api/analytics/v2/free`: 7-day decision summary, audit health, the recent
 * queue/deny list, and a Pro affordance. Pro adds the 30/90-day rollup
 * panels from `/api/analytics/v2/pro`. Both endpoints read precomputed
 * rollups server-side; this page only shapes rows for display.
 */

import { useEffect, useMemo, useState } from "react";
import type {
  AnalyticsCategory,
  AnalyticsSecurityEvent,
  AnalyticsVerdict,
  LocalFreeAnalyticsResponse,
  LocalProAnalyticsResponse,
  UtcWindow,
} from "@/types/api";
import { ApiError, getAnalyticsV2Free, getAnalyticsV2Pro } from "@/lib/api";
import { VerdictTrendBars } from "@/components/charts/VerdictTrendBars";
import { ScoreHistogram30 } from "@/components/charts/ScoreHistogram30";
import { LockedProCard } from "@/components/LockedProCard";
import {
  AnomalyPreview,
  RetentionTrendPreview,
  MultiSessionPreview,
} from "@/components/charts/ProPreviews";
import { useTier } from "@/hooks/useTier";

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/** Parts-per-million → "12.3%". */
function pct(ppm: number): string {
  return `${(ppm / 10_000).toFixed(1)}%`;
}

/** Integer USD micros → "$1.23" / "$0.0042". */
function usd(micros: number): string {
  const dollars = micros / 1_000_000;
  if (dollars === 0) return "$0";
  if (dollars >= 1) return `$${dollars.toFixed(2)}`;
  return `$${dollars.toFixed(4)}`;
}

function fmtTime(iso: string): string {
  return new Date(iso).toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

/** Dimension sentinels (`<unknown>`, `<not-applicable>`) → dim placeholder. */
function dim(value: string): { text: string; isSentinel: boolean } {
  if (value === "<unknown>" || value === "<not-applicable>") {
    return { text: "—", isSentinel: true };
  }
  return { text: value, isSentinel: false };
}

const CATEGORY_LABELS: Record<AnalyticsCategory, string> = {
  file_read: "File read",
  file_mutation: "File mutation",
  process: "Process",
  network_egress: "Network egress",
  network_listen: "Network listen",
  cross_process: "Cross-process",
  namespace: "Namespace",
  llm: "LLM",
  system: "System",
  other: "Other",
};

const VERDICT_TEXT: Record<AnalyticsVerdict, string> = {
  allow: "text-accent-text",
  queue: "text-warning-text",
  deny: "text-danger-text",
};

// ---------------------------------------------------------------------------
// Shared building blocks
// ---------------------------------------------------------------------------

function Card({
  title,
  aside,
  children,
  className = "",
}: {
  title: string;
  aside?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`bg-surface border border-border rounded-card p-5 ${className}`}
    >
      <div className="mb-3 flex items-baseline justify-between gap-3">
        <h2 className="font-heading text-[15px] font-semibold text-text">
          {title}
        </h2>
        {aside && (
          <span className="text-xs text-text-secondary">{aside}</span>
        )}
      </div>
      {children}
    </div>
  );
}

function StatTile({
  label,
  value,
  sub,
  valueClass = "text-text",
}: {
  label: string;
  value: string;
  sub?: string;
  valueClass?: string;
}) {
  return (
    <div className="bg-surface border border-border rounded-card px-5 py-4">
      <p className="font-label text-[11px] uppercase tracking-[0.08em] text-text-dim">
        {label}
      </p>
      <p
        className={`font-heading text-2xl font-semibold tabular-nums tracking-[-0.02em] ${valueClass}`}
      >
        {value}
      </p>
      {sub && <p className="mt-0.5 text-[11px] text-text-secondary">{sub}</p>}
    </div>
  );
}

const EVENT_BADGE: Record<
  AnalyticsSecurityEvent["event_type"],
  { label: string; className: string }
> = {
  queue: { label: "queued", className: "bg-warning-light text-warning-text" },
  deny: { label: "denied", className: "bg-danger-light text-danger-text" },
  canary: { label: "canary", className: "bg-danger-light text-danger-text" },
  gap: { label: "gap", className: "bg-surface-2 text-text-secondary" },
};

function SecurityEventList({
  events,
  emptyText,
}: {
  events: AnalyticsSecurityEvent[];
  emptyText: string;
}) {
  if (events.length === 0) {
    return <p className="text-xs text-text-secondary">{emptyText}</p>;
  }
  return (
    <div className="space-y-1">
      {events.map((e) => {
        const badge = EVENT_BADGE[e.event_type];
        const project = dim(e.project);
        const tool = dim(e.supervised_tool);
        return (
          <div
            key={`${e.event_id}:${e.event_revision}`}
            className="flex items-center gap-3 rounded-md px-3 py-1.5 hover:bg-surface-2"
          >
            <span className="w-24 flex-shrink-0 font-code text-[11px] text-text-dim">
              {fmtTime(e.occurred_at)}
            </span>
            <span
              className={`flex-shrink-0 rounded-md px-1.5 py-0.5 text-[11px] font-medium ${badge.className}`}
            >
              {badge.label}
            </span>
            <span className="flex-shrink-0 text-[11px] text-text-secondary">
              {CATEGORY_LABELS[e.category]}
            </span>
            <span className="min-w-0 flex-1 truncate text-xs text-text">
              {!project.isSentinel && (
                <span className="font-medium">{project.text}</span>
              )}
              {!project.isSentinel && !tool.isSentinel && (
                <span className="text-text-dim"> · </span>
              )}
              {!tool.isSentinel && (
                <span className="text-text-secondary">{tool.text}</span>
              )}
              {e.gap_count !== undefined && (
                <span className="text-text-secondary">
                  {(!project.isSentinel || !tool.isSentinel) && (
                    <span className="text-text-dim"> · </span>
                  )}
                  {e.gap_count.toLocaleString()} records affected
                </span>
              )}
            </span>
            {e.top_filter_ids.length > 0 && (
              <span className="hidden max-w-[220px] truncate font-code text-[10px] text-text-dim md:inline">
                {e.top_filter_ids.join(", ")}
              </span>
            )}
            {e.score_micros !== undefined && (
              <span className="w-10 flex-shrink-0 text-right font-code text-[11px] text-text-secondary">
                {(e.score_micros / 1_000_000).toFixed(1)}
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}

const CHAIN_HEALTH_UI: Record<
  LocalFreeAnalyticsResponse["chain_health"],
  { label: string; dot: string }
> = {
  healthy: { label: "Healthy", dot: "bg-green" },
  gap: { label: "Recorded gaps", dot: "bg-warning" },
  broken: { label: "Broken", dot: "bg-danger" },
  quarantined: { label: "Quarantined", dot: "bg-danger" },
  unknown: { label: "Unknown", dot: "bg-warning" },
};

function FreshnessLine({
  freshness,
}: {
  freshness: LocalFreeAnalyticsResponse["freshness"];
}) {
  return (
    <p className="text-[11px] leading-relaxed text-text-secondary">
      Data through{" "}
      <span className="font-code text-text">
        {freshness.materialized_through_at
          ? fmtTime(freshness.materialized_through_at)
          : "no records yet"}
      </span>
      {freshness.dirty_day_count > 0 && (
        <>
          {" "}
          · {freshness.dirty_day_count} day
          {freshness.dirty_day_count !== 1 ? "s" : ""} refreshing
        </>
      )}
      {freshness.rebuilding && <> · rebuilding</>}
      {freshness.gap_count > 0 && (
        <>
          {" "}
          ·{" "}
          <span className="text-warning-text">
            {freshness.gap_count.toLocaleString()} record
            {freshness.gap_count !== 1 ? "s" : ""} not analysable
          </span>
        </>
      )}
    </p>
  );
}

/** Inline proportional bar for table rows — magnitude only, single hue. */
function InlineBar({ fraction }: { fraction: number }) {
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-2">
      <div
        className="h-full rounded-full bg-green"
        style={{ width: `${Math.min(100, Math.max(0, fraction * 100))}%` }}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Pro aggregations — display shaping over precomputed rollups
// ---------------------------------------------------------------------------

interface ProView {
  window: UtcWindow;
  totals: { allow: number; queue: number; deny: number; total: number };
  avgScore: number | null;
  categories: { category: AnalyticsCategory; count: number }[];
  filters: {
    filterId: string;
    evaluated: number;
    triggered: number;
    triggerRate: number | null;
    denyContribution: number | null;
  }[];
  projects: {
    key: string;
    sessions: number;
    decisions: number;
    queue: number;
    deny: number;
    llmCalls: number;
    costMicros: number;
  }[];
  tools: {
    key: string;
    sessions: number;
    decisions: number;
    queue: number;
    deny: number;
  }[];
  llm: {
    key: string;
    provider: string;
    model: string;
    calls: number;
    promptTokens: number;
    completionTokens: number;
    costMicros: number;
    priceSource: string;
  }[];
  totalCostMicros: number;
  costSessions: number;
  destinations: {
    key: string;
    kind: string;
    label: string;
    isHmac: boolean;
    allow: number;
    queue: number;
    deny: number;
    total: number;
  }[];
}

function buildProView(pro: LocalProAnalyticsResponse, win: UtcWindow): ProView {
  const inWindow = (day: string) => day >= win.start_day;

  const totals = { allow: 0, queue: 0, deny: 0, total: 0 };
  let scoreSum = 0;
  let scoreCount = 0;
  const categories = new Map<AnalyticsCategory, number>();
  for (const row of pro.usage_rows) {
    if (!inWindow(row.bucket_start.slice(0, 10))) continue;
    if (row.record_class !== "decision") continue;
    if (row.verdict !== null) {
      totals[row.verdict] += row.event_count;
      totals.total += row.event_count;
    }
    scoreSum += row.score_sum_micros;
    scoreCount += row.event_count;
    categories.set(
      row.category,
      (categories.get(row.category) ?? 0) + row.event_count,
    );
  }

  const filterAgg = new Map<
    string,
    {
      evaluated: number;
      triggered: number;
      deniedEvaluated: number;
      deniedPositive: number;
    }
  >();
  for (const row of pro.filter_rows) {
    if (!inWindow(row.day)) continue;
    const agg = filterAgg.get(row.filter_id) ?? {
      evaluated: 0,
      triggered: 0,
      deniedEvaluated: 0,
      deniedPositive: 0,
    };
    agg.evaluated += row.evaluated_events;
    agg.triggered += row.triggered_events;
    agg.deniedEvaluated += row.denied_evaluated_events;
    agg.deniedPositive += row.denied_positive_contributions;
    filterAgg.set(row.filter_id, agg);
  }

  const projectAgg = new Map<
    string,
    {
      sessions: Set<string>;
      decisions: number;
      queue: number;
      deny: number;
      llmCalls: number;
      costMicros: number;
    }
  >();
  const toolAgg = new Map<
    string,
    { sessions: Set<string>; decisions: number; queue: number; deny: number }
  >();
  const costSessions = new Set<string>();
  for (const row of pro.session_rows) {
    if (!inWindow(row.day)) continue;
    const project = projectAgg.get(row.project) ?? {
      sessions: new Set<string>(),
      decisions: 0,
      queue: 0,
      deny: 0,
      llmCalls: 0,
      costMicros: 0,
    };
    project.sessions.add(row.session_id);
    project.decisions += row.decision_count;
    project.queue += row.queue_count;
    project.deny += row.deny_count;
    project.llmCalls += row.llm_calls;
    project.costMicros += row.cost_micros;
    projectAgg.set(row.project, project);

    const tool = toolAgg.get(row.supervised_tool) ?? {
      sessions: new Set<string>(),
      decisions: 0,
      queue: 0,
      deny: 0,
    };
    tool.sessions.add(row.session_id);
    tool.decisions += row.decision_count;
    tool.queue += row.queue_count;
    tool.deny += row.deny_count;
    toolAgg.set(row.supervised_tool, tool);

    if (row.llm_calls > 0) costSessions.add(row.session_id);
  }

  const llmAgg = new Map<
    string,
    {
      provider: string;
      model: string;
      calls: number;
      promptTokens: number;
      completionTokens: number;
      costMicros: number;
      priceSource: string;
    }
  >();
  let totalCostMicros = 0;
  for (const row of pro.llm_rows) {
    if (!inWindow(row.day)) continue;
    const key = `${row.provider}/${row.model}`;
    const agg = llmAgg.get(key) ?? {
      provider: row.provider,
      model: row.model,
      calls: 0,
      promptTokens: 0,
      completionTokens: 0,
      costMicros: 0,
      priceSource: row.price_source,
    };
    agg.calls += row.calls;
    agg.promptTokens += row.prompt_tokens;
    agg.completionTokens += row.completion_tokens;
    agg.costMicros += row.cost_micros;
    llmAgg.set(key, agg);
    totalCostMicros += row.cost_micros;
  }

  const destAgg = new Map<
    string,
    {
      kind: string;
      label: string;
      isHmac: boolean;
      allow: number;
      queue: number;
      deny: number;
      total: number;
    }
  >();
  for (const row of pro.destination_rows) {
    if (!inWindow(row.day)) continue;
    const label =
      row.approved_display_label ?? `${row.destination_hmac.slice(0, 12)}…`;
    const key = `${row.kind}|${row.destination_hmac}|${row.approved_display_label ?? ""}`;
    const agg = destAgg.get(key) ?? {
      kind: row.kind.replace(/_/g, " "),
      label,
      isHmac: row.approved_display_label === null,
      allow: 0,
      queue: 0,
      deny: 0,
      total: 0,
    };
    agg[row.verdict] += row.event_count;
    agg.total += row.event_count;
    destAgg.set(key, agg);
  }

  return {
    window: win,
    totals,
    avgScore: scoreCount > 0 ? scoreSum / scoreCount / 1_000_000 : null,
    categories: [...categories.entries()]
      .map(([category, count]) => ({ category, count }))
      .sort((a, b) => b.count - a.count),
    filters: [...filterAgg.entries()]
      .map(([filterId, agg]) => ({
        filterId,
        evaluated: agg.evaluated,
        triggered: agg.triggered,
        // "A zero denominator displays no rate" — the frozen panel rule.
        triggerRate: agg.evaluated > 0 ? agg.triggered / agg.evaluated : null,
        denyContribution:
          agg.deniedEvaluated > 0
            ? agg.deniedPositive / agg.deniedEvaluated
            : null,
      }))
      .sort((a, b) => b.triggered - a.triggered || b.evaluated - a.evaluated),
    projects: [...projectAgg.entries()]
      .map(([key, agg]) => ({
        key,
        sessions: agg.sessions.size,
        decisions: agg.decisions,
        queue: agg.queue,
        deny: agg.deny,
        llmCalls: agg.llmCalls,
        costMicros: agg.costMicros,
      }))
      .sort((a, b) => b.decisions - a.decisions),
    tools: [...toolAgg.entries()]
      .map(([key, agg]) => ({
        key,
        sessions: agg.sessions.size,
        decisions: agg.decisions,
        queue: agg.queue,
        deny: agg.deny,
      }))
      .sort((a, b) => b.decisions - a.decisions),
    llm: [...llmAgg.values()]
      .map((agg) => ({ key: `${agg.provider}/${agg.model}`, ...agg }))
      .sort((a, b) => b.costMicros - a.costMicros),
    totalCostMicros,
    costSessions: costSessions.size,
    destinations: [...destAgg.entries()]
      .map(([key, agg]) => ({ key, ...agg }))
      .sort((a, b) => b.total - a.total)
      .slice(0, 20),
  };
}

function downloadBlob(content: string, mime: string, filename: string) {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function usageRowsCsv(pro: LocalProAnalyticsResponse): string {
  const header =
    "bucket_start,project,profile_id,supervised_tool,record_class,category,verdict,score_bucket,event_count,score_sum_micros";
  const lines = pro.usage_rows.map((r) =>
    [
      r.bucket_start,
      JSON.stringify(r.project),
      JSON.stringify(r.profile_id),
      JSON.stringify(r.supervised_tool),
      r.record_class,
      r.category,
      r.verdict ?? "",
      r.score_bucket ?? "",
      r.event_count,
      r.score_sum_micros,
    ].join(","),
  );
  return [header, ...lines].join("\n");
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function AnalyticsPage() {
  const [free, setFree] = useState<LocalFreeAnalyticsResponse | null>(null);
  const [pro, setPro] = useState<LocalProAnalyticsResponse | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [range, setRange] = useState<30 | 90>(30);
  const tierState = useTier();

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const freeResponse = await getAnalyticsV2Free();
        if (cancelled) return;
        setFree(freeResponse);
        setUnavailable(false);
        setError(null);
        if (freeResponse.pro_available) {
          try {
            const proResponse = await getAnalyticsV2Pro();
            if (!cancelled) setPro(proResponse);
          } catch {
            // Feature-gate race or transient failure — the Free surface
            // stands on its own; Pro panels just stay absent this poll.
            if (!cancelled) setPro(null);
          }
        } else {
          setPro(null);
        }
      } catch (e) {
        if (cancelled) return;
        if (e instanceof ApiError && e.isAnalyticsUnavailable) {
          setUnavailable(true);
          setError(null);
        } else {
          setError(
            e instanceof Error ? e.message : "Failed to load analytics.",
          );
        }
      }
    }
    void load();
    // Rollups refresh on the daemon's cadence; 30s matches the product's
    // freshness target without hammering the projection.
    const interval = setInterval(() => void load(), 30_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const proView = useMemo(() => {
    if (!pro) return null;
    const win = pro.windows[range === 30 ? 0 : 1] ?? pro.windows[0];
    return win ? buildProView(pro, win) : null;
  }, [pro, range]);

  if (unavailable) {
    return (
      <div className="max-w-6xl p-6">
        <PageHeader />
        <div className="rounded-card border border-warning-border bg-warning-light p-4 text-sm text-warning-text">
          Analytics is unavailable: the process that owns the audit database is
          an older grith version. Restart it to enable analytics:{" "}
          <span className="font-code">grith daemon restart</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-6xl p-6">
        <PageHeader />
        <div className="rounded-card border border-danger-border bg-danger-light p-3 text-sm text-danger-text">
          {error}
        </div>
      </div>
    );
  }

  if (!free) {
    return (
      <div className="max-w-6xl p-6">
        <PageHeader />
        <p className="text-sm text-text-secondary">Loading analytics…</p>
      </div>
    );
  }

  const health = CHAIN_HEALTH_UI[free.chain_health];

  return (
    <div className="max-w-6xl p-6">
      <PageHeader
        aside={
          pro && (
            <div className="flex items-center gap-1 rounded-btn border border-border bg-surface p-0.5">
              {([30, 90] as const).map((days) => (
                <button
                  key={days}
                  onClick={() => setRange(days)}
                  className={`rounded-btn px-3 py-1 text-xs transition-colors ${
                    range === days
                      ? "bg-green-light font-medium text-accent-text"
                      : "text-text-secondary hover:text-text"
                  }`}
                >
                  {days} days
                </button>
              ))}
            </div>
          )
        }
      />

      {/* Free contract: 7-day decision summary */}
      <div className="mb-4 grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatTile
          label="Decisions · 7 days"
          value={free.decisions.total.toLocaleString()}
          sub={
            free.window.current_day_partial
              ? `${free.window.start_day} → today (partial)`
              : `${free.window.start_day} → ${free.window.end_day}`
          }
        />
        <StatTile
          label="Allowed"
          value={free.decisions.allow.toLocaleString()}
          sub={free.decisions.total > 0 ? pct(free.decisions.allow_rate_ppm) : undefined}
          valueClass="text-accent-text"
        />
        <StatTile
          label="Queued"
          value={free.decisions.queue.toLocaleString()}
          sub={free.decisions.total > 0 ? pct(free.decisions.queue_rate_ppm) : undefined}
          valueClass="text-warning-text"
        />
        <StatTile
          label="Denied"
          value={free.decisions.deny.toLocaleString()}
          sub={free.decisions.total > 0 ? pct(free.decisions.deny_rate_ppm) : undefined}
          valueClass="text-danger-text"
        />
      </div>

      {/* Audit health + freshness */}
      <div className="mb-8 grid grid-cols-1 gap-4 md:grid-cols-2">
        <Card title="Audit Health">
          <div className="mb-2 flex items-center gap-2">
            <span className={`h-2 w-2 rounded-full ${health.dot}`} />
            <span className="text-sm text-text">{health.label}</span>
            {free.latest_audit_record_at && (
              <span className="ml-auto font-code text-[11px] text-text-secondary">
                latest {fmtTime(free.latest_audit_record_at)}
              </span>
            )}
          </div>
          <FreshnessLine freshness={free.freshness} />
        </Card>
        <Card
          title="Recent Queue & Deny"
          aside={`newest ${free.recent_queue_and_deny.length}`}
        >
          <SecurityEventList
            events={free.recent_queue_and_deny.slice(0, 8)}
            emptyText="No queued or denied calls recorded — quiet is good."
          />
        </Card>
      </div>

      {/* Pro panels */}
      {proView && pro ? (
        <ProPanels pro={pro} view={proView} />
      ) : (
        !free.pro_available && (
          <div className="mb-8">
            <div className="mb-3 flex items-baseline justify-between">
              <h2 className="font-heading text-[15px] font-semibold text-text">
                Pro Analytics
              </h2>
              <span className="text-xs text-text-secondary">
                30/90-day trends, cost &amp; filter analytics
              </span>
            </div>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              <LockedProCard
                title="90-Day Trends"
                description="Daily verdict, category and score trends over calendar-exact UTC windows."
                billingUrl={tierState.billingUrl}
              >
                <RetentionTrendPreview />
              </LockedProCard>
              <LockedProCard
                title="Cost Analytics"
                description="LLM spend by provider, model, project and session — priced per call."
                billingUrl={tierState.billingUrl}
              >
                <AnomalyPreview />
              </LockedProCard>
              <LockedProCard
                title="Filter Effectiveness"
                description="Trigger rates and deny contributions per filter, with honest denominators."
                billingUrl={tierState.billingUrl}
              >
                <MultiSessionPreview />
              </LockedProCard>
            </div>
          </div>
        )
      )}
    </div>
  );
}

function PageHeader({ aside }: { aside?: React.ReactNode }) {
  return (
    <div className="mb-6 flex items-center justify-between gap-4">
      <div>
        <h1 className="font-heading text-xl font-semibold text-text">
          Analytics
        </h1>
        <p className="mt-0.5 text-xs text-text-secondary">
          Security decisions and cost, from the local analytics projection.
          All windows are UTC calendar days.
        </p>
      </div>
      {aside}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Pro panel group
// ---------------------------------------------------------------------------

function ProPanels({
  pro,
  view,
}: {
  pro: LocalProAnalyticsResponse;
  view: ProView;
}) {
  return (
    <>
      {/* Freshness / coverage banner */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-card border border-border bg-surface px-4 py-2.5">
        <FreshnessLine freshness={pro.freshness} />
        <div className="flex items-center gap-2">
          {pro.truncated && (
            <span
              className="rounded-md bg-warning-light px-2 py-0.5 text-[11px] text-warning-text"
              title="A rollup family exceeded its row cap; the oldest days were dropped from this view."
            >
              oldest days clipped
            </span>
          )}
          <button
            onClick={() =>
              downloadBlob(
                JSON.stringify(pro, null, 2),
                "application/json",
                `grith-analytics-${view.window.end_day}.json`,
              )
            }
            className="rounded-btn border border-border px-2.5 py-1 text-[11px] text-text-secondary transition-colors hover:bg-surface-2 hover:text-text"
          >
            Export JSON
          </button>
          <button
            onClick={() =>
              downloadBlob(
                usageRowsCsv(pro),
                "text/csv",
                `grith-usage-rollups-${view.window.end_day}.csv`,
              )
            }
            className="rounded-btn border border-border px-2.5 py-1 text-[11px] text-text-secondary transition-colors hover:bg-surface-2 hover:text-text"
          >
            Export CSV
          </button>
        </div>
      </div>

      {/* Verdict trend */}
      <Card
        title="Decisions Over Time"
        aside={`${view.window.start_day} → ${view.window.end_day}`}
        className="mb-4"
      >
        <VerdictTrendBars rows={pro.usage_rows} window={view.window} />
      </Card>

      {/* Score histogram + categories */}
      <div className="mb-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card
          title="Score Distribution"
          aside={
            view.avgScore !== null
              ? `average ${view.avgScore.toFixed(2)}`
              : undefined
          }
        >
          <ScoreHistogram30
            rows={pro.usage_rows.filter((r) =>
              r.bucket_start.slice(0, 10) >= view.window.start_day,
            )}
          />
        </Card>
        <Card title="Decision Categories">
          {view.categories.length === 0 ? (
            <p className="text-xs text-text-secondary">
              No decisions in this window yet.
            </p>
          ) : (
            <div className="space-y-2">
              {view.categories.slice(0, 8).map((c) => {
                const max = view.categories[0]!.count;
                return (
                  <div key={c.category} className="flex items-center gap-3">
                    <span className="w-32 flex-shrink-0 text-xs text-text">
                      {CATEGORY_LABELS[c.category]}
                    </span>
                    <div className="flex-1">
                      <InlineBar fraction={c.count / max} />
                    </div>
                    <span className="w-16 flex-shrink-0 text-right font-code text-xs text-text-secondary">
                      {c.count.toLocaleString()}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>

      {/* Filter effectiveness */}
      <Card
        title="Filter Effectiveness"
        aside="triggered / evaluated, per filter"
        className="mb-4"
      >
        {view.filters.length === 0 ? (
          <p className="text-xs text-text-secondary">
            No filter evaluations in this window yet.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left font-label text-[11px] uppercase tracking-[0.08em] text-text-dim">
                  <th className="pb-2 pr-4 font-medium">Filter</th>
                  <th className="pb-2 pr-4 text-right font-medium">Evaluated</th>
                  <th className="pb-2 pr-4 text-right font-medium">Triggered</th>
                  <th className="w-40 pb-2 pr-4 font-medium">Trigger rate</th>
                  <th className="pb-2 text-right font-medium">
                    Deny contribution
                  </th>
                </tr>
              </thead>
              <tbody>
                {view.filters.slice(0, 12).map((f) => (
                  <tr key={f.filterId} className="border-t border-border">
                    <td className="py-1.5 pr-4 font-code text-text">
                      {f.filterId}
                    </td>
                    <td className="py-1.5 pr-4 text-right font-code text-text-secondary">
                      {f.evaluated.toLocaleString()}
                    </td>
                    <td className="py-1.5 pr-4 text-right font-code text-text-secondary">
                      {f.triggered.toLocaleString()}
                    </td>
                    <td className="py-1.5 pr-4">
                      {f.triggerRate === null ? (
                        <span className="text-text-dim">—</span>
                      ) : (
                        <div className="flex items-center gap-2">
                          <div className="flex-1">
                            <InlineBar fraction={f.triggerRate} />
                          </div>
                          <span className="w-12 text-right font-code text-text-secondary">
                            {(f.triggerRate * 100).toFixed(1)}%
                          </span>
                        </div>
                      )}
                    </td>
                    <td className="py-1.5 text-right font-code text-text-secondary">
                      {f.denyContribution === null
                        ? "—"
                        : `${(f.denyContribution * 100).toFixed(1)}%`}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Projects + tools */}
      <div className="mb-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Projects" aside="exact distinct sessions">
          <BreakdownTable
            rows={view.projects.slice(0, 8).map((p) => ({
              key: p.key,
              label: dim(p.key),
              sessions: p.sessions,
              decisions: p.decisions,
              queue: p.queue,
              deny: p.deny,
              cost: p.costMicros > 0 ? usd(p.costMicros) : undefined,
            }))}
            emptyText="No sessions in this window yet."
          />
        </Card>
        <Card title="Supervised Tools">
          <BreakdownTable
            rows={view.tools.slice(0, 8).map((t) => ({
              key: t.key,
              label: dim(t.key),
              sessions: t.sessions,
              decisions: t.decisions,
              queue: t.queue,
              deny: t.deny,
            }))}
            emptyText="No sessions in this window yet."
          />
        </Card>
      </div>

      {/* LLM cost */}
      <Card
        title="LLM Cost"
        aside={
          view.llm.length > 0
            ? `${usd(view.totalCostMicros)} total · ${view.costSessions} cost session${view.costSessions !== 1 ? "s" : ""}`
            : undefined
        }
        className="mb-4"
      >
        {view.llm.length === 0 ? (
          <p className="text-xs text-text-secondary">
            No LLM usage recorded in this window.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left font-label text-[11px] uppercase tracking-[0.08em] text-text-dim">
                  <th className="pb-2 pr-4 font-medium">Provider / model</th>
                  <th className="pb-2 pr-4 text-right font-medium">Calls</th>
                  <th className="pb-2 pr-4 text-right font-medium">
                    Prompt tokens
                  </th>
                  <th className="pb-2 pr-4 text-right font-medium">
                    Completion tokens
                  </th>
                  <th className="pb-2 text-right font-medium">Cost</th>
                </tr>
              </thead>
              <tbody>
                {view.llm.map((l) => (
                  <tr key={l.key} className="border-t border-border">
                    <td className="py-1.5 pr-4">
                      <span className="text-text">{l.provider}</span>
                      <span className="text-text-dim"> / </span>
                      <span className="font-code text-text-secondary">
                        {l.model}
                      </span>
                      {l.priceSource === "legacy-local" && (
                        <span
                          className="ml-2 rounded-md bg-surface-2 px-1.5 py-0.5 text-[10px] text-text-dim"
                          title="Recorded before per-call pricing metadata existed."
                        >
                          legacy pricing
                        </span>
                      )}
                    </td>
                    <td className="py-1.5 pr-4 text-right font-code text-text-secondary">
                      {l.calls.toLocaleString()}
                    </td>
                    <td className="py-1.5 pr-4 text-right font-code text-text-secondary">
                      {l.promptTokens.toLocaleString()}
                    </td>
                    <td className="py-1.5 pr-4 text-right font-code text-text-secondary">
                      {l.completionTokens.toLocaleString()}
                    </td>
                    <td className="py-1.5 text-right font-code text-text">
                      {usd(l.costMicros)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Destinations + security events */}
      <div className="mb-8 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Destinations" aside="anonymised by default">
          {view.destinations.length === 0 ? (
            <p className="text-xs text-text-secondary">
              No destination activity in this window.
            </p>
          ) : (
            <div className="space-y-1">
              {view.destinations.map((d) => (
                <div
                  key={d.key}
                  className="flex items-center gap-3 rounded-md px-2 py-1"
                >
                  <span className="w-24 flex-shrink-0 text-[11px] text-text-secondary">
                    {d.kind}
                  </span>
                  <span
                    className={`min-w-0 flex-1 truncate text-xs ${
                      d.isHmac
                        ? "font-code text-text-dim"
                        : "font-medium text-text"
                    }`}
                    title={
                      d.isHmac
                        ? "Team-scoped HMAC — the clear destination never leaves this machine."
                        : undefined
                    }
                  >
                    {d.label}
                  </span>
                  <span className="flex flex-shrink-0 gap-3 font-code text-[11px]">
                    {(["allow", "queue", "deny"] as const).map((v) =>
                      d[v] > 0 ? (
                        <span key={v} className={VERDICT_TEXT[v]}>
                          {d[v].toLocaleString()} {v}
                        </span>
                      ) : null,
                    )}
                  </span>
                </div>
              ))}
            </div>
          )}
        </Card>
        <Card
          title="Security Events"
          aside={`${view.window.start_day} → today`}
        >
          <SecurityEventList
            events={pro.security_events.slice(0, 12)}
            emptyText="No queue, deny, canary or gap events in this window."
          />
        </Card>
      </div>
    </>
  );
}

function BreakdownTable({
  rows,
  emptyText,
}: {
  rows: {
    key: string;
    label: { text: string; isSentinel: boolean };
    sessions: number;
    decisions: number;
    queue: number;
    deny: number;
    cost?: string;
  }[];
  emptyText: string;
}) {
  if (rows.length === 0) {
    return <p className="text-xs text-text-secondary">{emptyText}</p>;
  }
  return (
    <div className="space-y-1">
      {rows.map((r) => (
        <div
          key={r.key}
          className="flex items-center gap-3 rounded-md px-2 py-1.5 hover:bg-surface-2"
        >
          <span
            className={`min-w-0 flex-1 truncate text-xs ${
              r.label.isSentinel ? "text-text-dim" : "font-medium text-text"
            }`}
          >
            {r.label.text}
          </span>
          <span className="flex-shrink-0 font-code text-[11px] text-text-secondary">
            {r.sessions} session{r.sessions !== 1 ? "s" : ""}
          </span>
          <span className="flex-shrink-0 font-code text-[11px] text-text-secondary">
            {r.decisions.toLocaleString()} calls
          </span>
          {r.queue > 0 && (
            <span className="flex-shrink-0 font-code text-[11px] text-warning-text">
              {r.queue.toLocaleString()} q
            </span>
          )}
          {r.deny > 0 && (
            <span className="flex-shrink-0 font-code text-[11px] text-danger-text">
              {r.deny.toLocaleString()} d
            </span>
          )}
          {r.cost && (
            <span className="flex-shrink-0 font-code text-[11px] text-text">
              {r.cost}
            </span>
          )}
        </div>
      ))}
    </div>
  );
}
