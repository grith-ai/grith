/**
 * Composite-score histogram over the frozen v1 bin geometry: 30 half-point
 * bins across [0, 15], summed from decision usage rollups. Magnitude in a
 * single hue — identity lives on the axis; the allow/queue/deny thresholds
 * are drawn as reference lines so the shape reads as a security posture.
 */

import { useMemo, useRef, useState } from "react";
import * as d3Scale from "d3-scale";
import type { UsageRollupRow } from "@/types/api";
import { chartColors, withAlpha } from "@/lib/chartPalette";

const TICK_FONT = "'IBM Plex Mono', monospace";
const MARGIN = { top: 12, right: 8, bottom: 26, left: 40 };
const BINS = 30;
const BIN_WIDTH = 0.5;

interface Props {
  rows: UsageRollupRow[];
  /** Auto-allow / auto-deny score thresholds, drawn as reference lines. */
  thresholds?: { allow: number; deny: number };
  width?: number;
  height?: number;
}

export function ScoreHistogram30({
  rows,
  thresholds = { allow: 3, deny: 8 },
  width = 400,
  height = 180,
}: Props) {
  const innerW = width - MARGIN.left - MARGIN.right;
  const innerH = height - MARGIN.top - MARGIN.bottom;
  const ref = useRef<HTMLDivElement>(null);
  const [hoverBin, setHoverBin] = useState<number | null>(null);

  const { bins, yScale, total } = useMemo(() => {
    const counts = new Array<number>(BINS).fill(0);
    let sum = 0;
    for (const row of rows) {
      if (row.record_class !== "decision" || row.score_bucket === null) {
        continue;
      }
      const bin = Math.min(BINS - 1, Math.max(0, row.score_bucket));
      counts[bin] = (counts[bin] ?? 0) + row.event_count;
      sum += row.event_count;
    }
    const max = Math.max(1, ...counts);
    const ys = d3Scale
      .scaleLinear()
      .domain([0, max])
      .range([innerH, 0])
      .nice();
    return { bins: counts, yScale: ys, total: sum };
  }, [rows, innerH]);

  const slot = innerW / BINS;
  const barW = Math.max(1.5, slot - 2);
  const xForScore = (score: number) => (score / (BINS * BIN_WIDTH)) * innerW;

  function onMove(e: React.MouseEvent) {
    const el = ref.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const svgX = ((e.clientX - rect.left) / rect.width) * width - MARGIN.left;
    const idx = Math.floor(svgX / slot);
    setHoverBin(idx >= 0 && idx < BINS ? idx : null);
  }

  return (
    <div ref={ref} className="relative">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full select-none"
        preserveAspectRatio="xMidYMid meet"
        onMouseMove={onMove}
        onMouseLeave={() => setHoverBin(null)}
      >
        <g transform={`translate(${MARGIN.left},${MARGIN.top})`}>
          {yScale.ticks(3).map((t) => (
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

          {/* Threshold reference lines: allow→queue and queue→deny. */}
          {[thresholds.allow, thresholds.deny].map((score, i) => (
            <g key={score}>
              <line
                x1={xForScore(score)}
                x2={xForScore(score)}
                y1={0}
                y2={innerH}
                stroke={i === 0 ? chartColors.warning : chartColors.danger}
                strokeWidth={1}
                strokeDasharray="3 3"
                opacity={0.6}
              />
              <text
                x={xForScore(score) + 3}
                y={9}
                fontSize={9}
                fontFamily={TICK_FONT}
                fill={chartColors.faint}
              >
                {i === 0 ? "queue" : "deny"}
              </text>
            </g>
          ))}

          {bins.map((count, i) => {
            if (count === 0) return null;
            const y = yScale(count);
            return (
              <rect
                key={i}
                x={i * slot}
                y={y}
                width={barW}
                height={innerH - y}
                rx={1}
                fill={
                  hoverBin === i
                    ? chartColors.accent
                    : withAlpha(chartColors.accent, 0.75)
                }
              />
            );
          })}

          <line
            x1={0}
            x2={innerW}
            y1={innerH}
            y2={innerH}
            stroke={chartColors.border}
          />
          {[0, 5, 10, 15].map((score) => (
            <text
              key={score}
              x={xForScore(score)}
              y={innerH + 16}
              textAnchor={score === 0 ? "start" : score === 15 ? "end" : "middle"}
              fontSize={10}
              fontFamily={TICK_FONT}
              fill={chartColors.faint}
            >
              {score}
            </text>
          ))}
        </g>
      </svg>

      {hoverBin !== null && bins[hoverBin]! > 0 && (
        <div className="pointer-events-none absolute right-2 top-2 rounded-lg border border-border bg-surface px-3 py-2 text-[11px]">
          <div className="font-code text-text-secondary">
            score {(hoverBin * BIN_WIDTH).toFixed(1)}–
            {((hoverBin + 1) * BIN_WIDTH).toFixed(1)}
          </div>
          <div className="font-code text-text">
            {bins[hoverBin]!.toLocaleString()} decision
            {bins[hoverBin] !== 1 ? "s" : ""}
            {total > 0 && (
              <span className="text-text-secondary">
                {" "}
                · {((bins[hoverBin]! / total) * 100).toFixed(1)}%
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
