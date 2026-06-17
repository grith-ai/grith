/**
 * Latency histogram with p50 / p95 / p99 markers — proves the proxy's
 * sub-15ms P95 target visually. Bins evaluation_time_ms and overlays the key
 * percentile lines.
 */

import { useMemo } from "react";
import * as d3Scale from "d3-scale";
import { bin as d3bin } from "d3-array";
import type { AuditRecord } from "@/types/api";

const MARGIN = { top: 14, right: 14, bottom: 26, left: 32 };

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx]!;
}

interface Props {
  records: AuditRecord[];
  width?: number;
  height?: number;
  target?: number;
}

export function LatencyHistogram({ records, width = 380, height = 180, target = 15 }: Props) {
  const innerW = width - MARGIN.left - MARGIN.right;
  const innerH = height - MARGIN.top - MARGIN.bottom;

  const { bins, xScale, yScale, p50, p95, p99 } = useMemo(() => {
    const values = records
      .map((r) => r.evaluation_time_ms)
      .filter((v) => Number.isFinite(v) && v >= 0);
    if (values.length === 0) {
      return { bins: [], xScale: null, yScale: null, p50: 0, p95: 0, p99: 0 };
    }
    const sorted = [...values].sort((a, b) => a - b);
    // Cap the axis at p99 (or target, whichever larger) so a single outlier
    // doesn't flatten the whole chart.
    const hi = Math.max(percentile(sorted, 99), target) * 1.1;
    const xs = d3Scale.scaleLinear().domain([0, hi]).range([0, innerW]);
    const binned = d3bin<number, number>()
      .domain([0, hi])
      .thresholds(24)(values.map((v) => Math.min(v, hi)));
    const maxCount = Math.max(1, ...binned.map((b) => b.length));
    const ys = d3Scale.scaleLinear().domain([0, maxCount]).range([innerH, 0]).nice();
    return {
      bins: binned,
      xScale: xs,
      yScale: ys,
      p50: percentile(sorted, 50),
      p95: percentile(sorted, 95),
      p99: percentile(sorted, 99),
    };
  }, [records, innerW, innerH, target]);

  if (!xScale || !yScale || bins.length === 0) return null;

  const markers: { label: string; value: number; color: string }[] = [
    { label: "p50", value: p50, color: "#57606a" },
    { label: "p95", value: p95, color: "#bf8700" },
    { label: "p99", value: p99, color: "#d1242f" },
  ];

  return (
    <div>
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full" preserveAspectRatio="xMidYMid meet">
        <g transform={`translate(${MARGIN.left},${MARGIN.top})`}>
          {yScale.ticks(3).map((t) => (
            <g key={t}>
              <line x1={0} x2={innerW} y1={yScale(t)} y2={yScale(t)} stroke="#e2e6eb" strokeWidth={0.5} />
              <text x={-6} y={yScale(t) + 3} textAnchor="end" fontSize={9} fontFamily="'JetBrains Mono', monospace" fill="#8b949e">{t}</text>
            </g>
          ))}

          {/* Target band (≤ target ms is the goal). */}
          <rect x={0} y={0} width={xScale(target)} height={innerH} fill="#00a85a" opacity={0.06} />

          {bins.map((b, i) => {
            const x0 = xScale(b.x0 ?? 0);
            const x1 = xScale(b.x1 ?? 0);
            const h = innerH - yScale(b.length);
            return (
              <rect
                key={i}
                x={x0 + 0.5}
                y={yScale(b.length)}
                width={Math.max(0, x1 - x0 - 1)}
                height={h}
                rx={1.5}
                fill="#00a85a"
                opacity={0.65}
              >
                <title>
                  {(b.x0 ?? 0).toFixed(1)}–{(b.x1 ?? 0).toFixed(1)}ms · {b.length} calls
                </title>
              </rect>
            );
          })}

          {/* Percentile markers */}
          {markers.map((m) => (
            <g key={m.label}>
              <line x1={xScale(Math.min(m.value, xScale.domain()[1]!))} x2={xScale(Math.min(m.value, xScale.domain()[1]!))} y1={-6} y2={innerH} stroke={m.color} strokeWidth={1} strokeDasharray="3 2" />
              <text x={xScale(Math.min(m.value, xScale.domain()[1]!))} y={-8} textAnchor="middle" fontSize={8} fontFamily="'JetBrains Mono', monospace" fill={m.color}>{m.label}</text>
            </g>
          ))}

          <line x1={0} x2={innerW} y1={innerH} y2={innerH} stroke="#e2e6eb" />
          {xScale.ticks(5).map((t) => (
            <text key={t} x={xScale(t)} y={innerH + 15} textAnchor="middle" fontSize={9} fontFamily="'JetBrains Mono', monospace" fill="#8b949e">{t}ms</text>
          ))}
        </g>
      </svg>
      <div className="mt-1 flex justify-center gap-4 text-[11px]">
        {markers.map((m) => (
          <span key={m.label} className="flex items-center gap-1">
            <span className="text-grith-muted">{m.label}</span>
            <span className="font-mono" style={{ color: m.color }}>{m.value.toFixed(1)}ms</span>
          </span>
        ))}
      </div>
    </div>
  );
}
