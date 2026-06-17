/**
 * Real multi-session posture comparison (the unlocked, Pro/Enterprise version
 * of the MultiSessionPreview teaser). Ranks the busiest sessions and shows each
 * one's allow / queue / deny split side by side so an operator can spot which
 * tool or project is generating the most risk.
 */

import { useMemo } from "react";

export interface SessionRow {
  id: string;
  label: string;
  allow: number;
  queue: number;
  deny: number;
  total: number;
}

const MAX_ROWS = 8;

export function SessionComparison({ sessions }: { sessions: SessionRow[] }) {
  const rows = useMemo(
    () =>
      [...sessions]
        .filter((s) => s.total > 0)
        .sort((a, b) => b.total - a.total)
        .slice(0, MAX_ROWS),
    [sessions],
  );

  if (rows.length === 0) {
    return (
      <p className="py-4 text-center text-xs text-grith-muted">
        No session activity to compare yet.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      {rows.map((s) => {
        const allowPct = (s.allow / s.total) * 100;
        const queuePct = (s.queue / s.total) * 100;
        const denyPct = (s.deny / s.total) * 100;
        return (
          <div key={s.id}>
            <div className="mb-1 flex items-baseline justify-between gap-2">
              <span className="truncate text-xs font-medium text-grith-text">
                {s.label}
              </span>
              <span className="flex flex-shrink-0 items-center gap-2 font-mono text-[11px]">
                <span className="text-status-allow-green">{allowPct.toFixed(0)}%</span>
                {s.deny > 0 && (
                  <span className="text-status-deny-red">{s.deny} denied</span>
                )}
                <span className="text-grith-dim">{s.total.toLocaleString()}</span>
              </span>
            </div>
            <div className="flex h-2.5 overflow-hidden rounded-full bg-grith-surface">
              {allowPct > 0 && (
                <div style={{ width: `${allowPct}%`, backgroundColor: "#00a85a" }} />
              )}
              {queuePct > 0 && (
                <div style={{ width: `${queuePct}%`, backgroundColor: "#bf8700" }} />
              )}
              {denyPct > 0 && (
                <div style={{ width: `${denyPct}%`, backgroundColor: "#d1242f" }} />
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
