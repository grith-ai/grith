/**
 * Threat Signals — ranks the security filters that actually contributed score
 * across recent evaluations. Surfaces the per-filter `filter_results` data that
 * grith records on every call but never visualised. Bar length = share of total
 * contributed score; the count chip = how many calls each filter fired on.
 * Clicking a signal drills into the Live Audit feed.
 */

import { useMemo } from "react";
import type { AuditRecord } from "@/types/api";

interface Signal {
  name: string;
  score: number;
  hits: number;
  /** Calls where this filter fired AND the call was queued or denied. */
  heldBack: number;
}

const MAX_ROWS = 7;

export function ThreatSignals({ records }: { records: AuditRecord[] }) {
  const signals = useMemo<Signal[]>(() => {
    const map = new Map<string, Signal>();
    for (const r of records) {
      const held = r.proxy_action !== "allow";
      for (const f of r.filter_results) {
        if (!f.matched || f.score <= 0) continue;
        let s = map.get(f.filter_name);
        if (!s) {
          s = { name: f.filter_name, score: 0, hits: 0, heldBack: 0 };
          map.set(f.filter_name, s);
        }
        s.score += f.score;
        s.hits++;
        if (held) s.heldBack++;
      }
    }
    return [...map.values()].sort((a, b) => b.score - a.score).slice(0, MAX_ROWS);
  }, [records]);

  if (signals.length === 0) {
    return (
      <p className="text-xs text-grith-muted py-4 text-center">
        No filters have contributed score yet — your agents have been clean.
      </p>
    );
  }

  const maxScore = signals[0]!.score;

  return (
    <div className="space-y-2">
      {signals.map((s) => {
        const pct = (s.score / maxScore) * 100;
        const danger = s.heldBack > 0;
        return (
          <a
            key={s.name}
            href="/audit"
            className="group block"
            title={`${s.name} — ${s.score.toFixed(1)} total score across ${s.hits} calls`}
          >
            <div className="flex items-center justify-between mb-1">
              <span className="font-mono text-xs text-grith-text truncate group-hover:text-green-dark transition-colors">
                {s.name}
              </span>
              <span className="flex items-center gap-2 text-[11px] flex-shrink-0">
                {s.heldBack > 0 && (
                  <span className="text-status-deny-red font-mono">{s.heldBack} held</span>
                )}
                <span className="text-grith-dim font-mono">{s.hits} hits</span>
                <span className="font-mono font-semibold text-grith-text">{s.score.toFixed(1)}</span>
              </span>
            </div>
            <div className="h-2 rounded-full bg-grith-surface overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${
                  danger ? "bg-status-deny-red" : "bg-status-queue-amber"
                }`}
                style={{ width: `${Math.max(pct, 3)}%` }}
              />
            </div>
          </a>
        );
      })}
      <p className="text-[11px] text-grith-dim pt-1">
        Ranked by total score contributed. Click a signal to inspect the calls it fired on.
      </p>
    </div>
  );
}
