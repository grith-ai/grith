/**
 * Daily verdict trend — one stacked bar per UTC calendar date over the
 * selected window, built from precomputed hourly usage rollups (decision
 * class only). Calendar-aligned by construction: every date in the window
 * gets a slot, empty days render as gaps in activity rather than being
 * silently skipped, and the partial current day is visually marked.
 */

import { useMemo, useRef, useState } from "react";
import * as d3Scale from "d3-scale";
import type { AnalyticsVerdict, UsageRollupRow, UtcWindow } from "@/types/api";
import { chartColors } from "@/lib/chartPalette";

const COLORS: Record<AnalyticsVerdict, string> = {
  allow: chartColors.accent,
  queue: chartColors.warning,
  deny: chartColors.danger,
};

const VERDICTS: AnalyticsVerdict[] = ["allow", "queue", "deny"];

const TICK_FONT = "'IBM Plex Mono', monospace";
const MARGIN = { top: 12, right: 8, bottom: 26, left: 40 };

interface DayStack {
  day: string;
  allow: number;
  queue: number;
  deny: number;
}

/** Every UTC date from start to end inclusive (ISO "YYYY-MM-DD" strings). */
function enumerateDays(startDay: string, endDay: string): string[] {
  const out: string[] = [];
  const cursor = new Date(`${startDay}T00:00:00Z`);
  const end = new Date(`${endDay}T00:00:00Z`);
  while (cursor.getTime() <= end.getTime() && out.length <= 366) {
    out.push(cursor.toISOString().slice(0, 10));
    cursor.setUTCDate(cursor.getUTCDate() + 1);
  }
  return out;
}

interface Props {
  rows: UsageRollupRow[];
  window: UtcWindow;
  width?: number;
  height?: number;
}

export function VerdictTrendBars({
  rows,
  window: win,
  width = 800,
  height = 220,
}: Props) {
  const innerW = width - MARGIN.left - MARGIN.right;
  const innerH = height - MARGIN.top - MARGIN.bottom;
  const ref = useRef<HTMLDivElement>(null);
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);

  const { days, yScale } = useMemo(() => {
    const dayList = enumerateDays(win.start_day, win.end_day);
    const byDay = new Map<string, DayStack>(
      dayList.map((day) => [day, { day, allow: 0, queue: 0, deny: 0 }]),
    );
    for (const row of rows) {
      if (row.record_class !== "decision" || row.verdict === null) continue;
      const stack = byDay.get(row.bucket_start.slice(0, 10));
      if (!stack) continue;
      stack[row.verdict] += row.event_count;
    }
    const stacked = dayList.map((day) => byDay.get(day)!);
    const max = Math.max(1, ...stacked.map((d) => d.allow + d.queue + d.deny));
    const ys = d3Scale
      .scaleLinear()
      .domain([0, max])
      .range([innerH, 0])
      .nice();
    return { days: stacked, yScale: ys, maxTotal: max };
  }, [rows, win.start_day, win.end_day, innerH]);

  const n = days.length;
  if (n === 0) return null;
  const slot = innerW / n;
  // 2px surface gap between adjacent bars; collapse the gap when the window
  // is dense enough that it would eat the bar itself.
  const gap = slot > 5 ? 2 : slot > 2.5 ? 1 : 0;
  const barW = Math.max(1, slot - gap);

  function onMove(e: React.MouseEvent) {
    const el = ref.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const svgX = ((e.clientX - rect.left) / rect.width) * width - MARGIN.left;
    const idx = Math.floor(svgX / slot);
    setHoverIdx(idx >= 0 && idx < n ? idx : null);
  }

  const hovered = hoverIdx !== null ? days[hoverIdx]! : null;
  const monthTickEvery = n > 40 ? 14 : n > 10 ? 7 : 1;

  return (
    <div ref={ref} className="relative">
      {/* Legend — identity is never color-alone. */}
      <div className="mb-2 flex items-center gap-4 text-[11px] text-text-secondary">
        {VERDICTS.map((v) => (
          <span key={v} className="inline-flex items-center gap-1.5">
            <span
              className="h-2 w-2 rounded-sm"
              style={{ backgroundColor: COLORS[v] }}
            />
            <span className="capitalize">{v}</span>
          </span>
        ))}
        {win.current_day_partial && (
          <span className="ml-auto text-text-dim">today is partial</span>
        )}
      </div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full select-none"
        preserveAspectRatio="xMidYMid meet"
        onMouseMove={onMove}
        onMouseLeave={() => setHoverIdx(null)}
      >
        <g transform={`translate(${MARGIN.left},${MARGIN.top})`}>
          {yScale.ticks(4).map((t) => (
            <g key={t}>
              <line
                x1={0}
                x2={innerW}
                y1={yScale(t)}
                y2={yScale(t)}
                stroke={chartColors.border}
                strokeWidth={0.5}
              />
              <text
                x={-8}
                y={yScale(t) + 3}
                textAnchor="end"
                fontSize={10}
                fontFamily={TICK_FONT}
                fill={chartColors.faint}
              >
                {t.toLocaleString()}
              </text>
            </g>
          ))}

          {days.map((d, i) => {
            const x = i * slot;
            const isPartial = win.current_day_partial && i === n - 1;
            let y0 = 0;
            return (
              <g key={d.day} opacity={isPartial ? 0.55 : 1}>
                {VERDICTS.map((v) => {
                  const value = d[v];
                  if (value === 0) return null;
                  const yTop = yScale(y0 + value);
                  const h = yScale(y0) - yTop;
                  y0 += value;
                  return (
                    <rect
                      key={v}
                      x={x}
                      // 1px surface gap between stacked segments.
                      y={yTop + (y0 - value > 0 ? 0.5 : 0)}
                      width={barW}
                      height={Math.max(0.75, h - (y0 - value > 0 ? 1 : 0))}
                      rx={Math.min(1.5, barW / 3)}
                      fill={COLORS[v]}
                    />
                  );
                })}
              </g>
            );
          })}

          {hoverIdx !== null && (
            <rect
              x={hoverIdx * slot - gap / 2}
              y={0}
              width={slot}
              height={innerH}
              fill={chartColors.text}
              opacity={0.07}
            />
          )}

          <line
            x1={0}
            x2={innerW}
            y1={innerH}
            y2={innerH}
            stroke={chartColors.border}
          />
          {days.map((d, i) =>
            i % monthTickEvery === 0 ? (
              <text
                key={d.day}
                x={i * slot + barW / 2}
                y={innerH + 16}
                textAnchor="middle"
                fontSize={9}
                fontFamily={TICK_FONT}
                fill={chartColors.faint}
              >
                {d.day.slice(5)}
              </text>
            ) : null,
          )}
        </g>
      </svg>

      {hovered && (
        <div className="pointer-events-none absolute right-2 top-8 rounded-lg border border-border bg-surface px-3 py-2 text-[11px]">
          <div className="mb-1 font-code text-text-secondary">
            {hovered.day}
            {win.current_day_partial && hoverIdx === n - 1 ? " (partial)" : ""}
          </div>
          {VERDICTS.map((v) => (
            <div key={v} className="flex items-center gap-2">
              <span
                className="h-2 w-2 rounded-sm"
                style={{ backgroundColor: COLORS[v] }}
              />
              <span className="capitalize text-text-secondary">{v}</span>
              <span className="ml-auto pl-4 font-code text-text">
                {hovered[v].toLocaleString()}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
