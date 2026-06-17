/**
 * Live decision ticker — a rolling feed of the most recent proxy evaluations.
 *
 * Hybrid feed: it merges two sources so it is both real-time AND never empty.
 *   • WebSocket (`/ws/live`) — sub-second push. `grith exec` forwards every
 *     proxy evaluation to the daemon's `/api/ipc/events`, which rebroadcasts to
 *     WS clients. This is the live path.
 *   • Audit records — the dashboard already polls these every ~5s. They seed
 *     the feed on load and act as a fallback if the WS handshake can't
 *     authenticate (e.g. the dashboard was opened without its token).
 *
 * Rows from the two sources are de-duplicated by a best-effort composite key
 * (second-resolution timestamp + decision + call type + score) so a decision
 * that arrives over WS and is later confirmed by the audit poll only shows once.
 * A row carries its underlying audit record when one is available, so clicking
 * it opens the full detail (WS-only rows become clickable once the poll catches
 * up — usually within a few seconds).
 */

import { useEffect, useMemo, useRef } from "react";
import { useWebSocket } from "@/hooks/useWebSocket";
import type { AuditRecord, ProxyActionSummary, WsEvent } from "@/types/api";

const COLORS: Record<ProxyActionSummary, string> = {
  allow: "#00a85a",
  queue: "#bf8700",
  deny: "#d1242f",
};

const MAX_ROWS = 12;
/** A row newer than this (ms) means the feed is actively streaming. */
const LIVE_WINDOW_MS = 30_000;

interface Row {
  key: string;
  ts: number;
  action: ProxyActionSummary;
  callType: string;
  score: number;
  sessionId: string | null;
  /** Full audit record, when this row was sourced from / matched the audit poll. */
  record: AuditRecord | null;
}

interface Props {
  /** Audit records, newest first (as returned by the audit API). */
  records: AuditRecord[];
  /** Whether the daemon is reachable. */
  online: boolean;
  /** Session id → human project label, for naming rows by project. */
  projects?: Map<string, string>;
  /** Open a record's full detail (clicking a row with a known record). */
  onSelect?: (record: AuditRecord) => void;
}

const ACTIONS: ProxyActionSummary[] = ["allow", "queue", "deny"];

function normaliseAction(a: string): ProxyActionSummary {
  // The supervisor may emit "allow (logged)" in Log mode — treat as allow.
  const base = a.split(" ")[0] as ProxyActionSummary;
  return ACTIONS.includes(base) ? base : "allow";
}

function dedupKey(ts: number, action: string, callType: string, score: number): string {
  return `${Math.round(ts / 1000)}|${action}|${callType}|${score.toFixed(1)}`;
}

function isEval(e: WsEvent): e is Extract<WsEvent, { type: "proxy_evaluation" }> {
  return e.type === "proxy_evaluation";
}

export function LiveTicker({ records, online, projects, onSelect }: Props) {
  const { messages, connected } = useWebSocket();
  const seen = useRef<Set<string>>(new Set());

  const rows = useMemo<Row[]>(() => {
    const byKey = new Map<string, Row>();

    // Audit records (history + fallback) — these carry the full record.
    for (const r of records) {
      const ts = new Date(r.timestamp).getTime();
      const action = normaliseAction(r.proxy_action);
      const key = dedupKey(ts, action, r.tool_call_type, r.composite_score);
      if (!byKey.has(key)) {
        byKey.set(key, {
          key,
          ts,
          action,
          callType: r.tool_call_type,
          score: r.composite_score,
          sessionId: r.session_id,
          record: r,
        });
      }
    }

    // Live WS events (augment — same key collapses with an audit row, keeping
    // that row's full record so it stays clickable).
    for (const e of messages) {
      if (!isEval(e)) continue;
      const ts = new Date(e.timestamp).getTime();
      const action = normaliseAction(e.action);
      const callType = e.call_type ?? "—";
      const key = dedupKey(ts, action, callType, e.composite_score);
      const existing = byKey.get(key);
      byKey.set(key, {
        key,
        ts,
        action,
        callType,
        score: e.composite_score,
        sessionId: e.session_id ?? existing?.sessionId ?? null,
        record: existing?.record ?? null,
      });
    }

    return [...byKey.values()].sort((a, b) => b.ts - a.ts).slice(0, MAX_ROWS);
  }, [records, messages]);

  // Track which keys we've already shown so freshly-arrived rows can fade in.
  const newKeys = useMemo(() => {
    const fresh = new Set<string>();
    for (const r of rows) if (!seen.current.has(r.key)) fresh.add(r.key);
    return fresh;
  }, [rows]);

  useEffect(() => {
    for (const r of rows) seen.current.add(r.key);
  }, [rows]);

  const newestAgeMs = rows[0] ? Date.now() - rows[0].ts : Infinity;
  const streaming = online && (connected || newestAgeMs < LIVE_WINDOW_MS);

  /** Project label for a row. Preference order:
   *  1. live session registry — freshest, reflects mid-session renames;
   *  2. the record's `project_name` — persisted on every supervisor record,
   *     so it survives after the session ends and ages out of (1);
   *  3. `task_context` — legacy fallback for records written before the
   *     dedicated `project_name` column existed (supervisor rows only);
   *  4. the supervised tool name as a last resort. */
  function label(r: Row): string | null {
    if (r.sessionId && projects?.has(r.sessionId)) {
      return projects.get(r.sessionId) ?? null;
    }
    const rec = r.record;
    if (rec?.project_name) return rec.project_name;
    if (rec && rec.supervised_tool && rec.task_context) {
      return rec.task_context;
    }
    return rec?.supervised_tool ?? null;
  }

  return (
    <div className="bg-white border border-grith-border rounded-xl p-5">
      <div className="flex items-baseline justify-between mb-3">
        <h2 className="text-sm font-medium text-grith-text">Live Decisions</h2>
        <span className="inline-flex items-center gap-1.5 text-xs text-grith-muted">
          <span
            className={`h-2 w-2 rounded-full ${
              streaming
                ? "bg-status-allow-green animate-pulse"
                : online
                  ? "bg-status-queue-amber"
                  : "bg-grith-dim"
            }`}
          />
          {streaming ? (connected ? "streaming" : "polling") : online ? "idle" : "offline"}
        </span>
      </div>

      {rows.length === 0 ? (
        <p className="text-xs text-grith-muted py-6 text-center">
          Waiting for activity — run a supervised tool and decisions appear here.
        </p>
      ) : (
        <div className="space-y-0.5 font-mono text-xs">
          {rows.map((r, i) => {
            const isNew = newKeys.has(r.key);
            const clickable = r.record !== null && onSelect !== undefined;
            const proj = label(r);
            return (
              <div
                key={r.key}
                role={clickable ? "button" : undefined}
                tabIndex={clickable ? 0 : undefined}
                onClick={clickable ? () => onSelect!(r.record!) : undefined}
                onKeyDown={
                  clickable
                    ? (e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          onSelect!(r.record!);
                        }
                      }
                    : undefined
                }
                title={clickable ? "Click to see full details" : undefined}
                className={`flex items-center gap-3 py-1 border-b border-grith-border/40 last:border-0 rounded-sm ${
                  isNew ? "grith-fade-up" : ""
                } ${clickable ? "cursor-pointer hover:bg-grith-surface" : ""}`}
                style={isNew ? { animationDelay: `${Math.min(i, 6) * 40}ms` } : undefined}
              >
                <span className="text-grith-dim tabular-nums">
                  {new Date(r.ts).toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                  })}
                </span>
                <span
                  className="inline-flex w-12 justify-center rounded px-1 py-0.5 text-[10px] font-semibold uppercase"
                  style={{
                    color: COLORS[r.action],
                    backgroundColor: `${COLORS[r.action]}1a`,
                  }}
                >
                  {r.action}
                </span>
                <span className="text-grith-text truncate flex-1">{r.callType}</span>
                {proj && (
                  <span className="hidden sm:inline text-grith-dim truncate max-w-[140px]">
                    {proj}
                  </span>
                )}
                <span className="text-grith-muted tabular-nums">
                  {r.score.toFixed(1)}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
