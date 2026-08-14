/**
 * Stacked activity-over-time area chart — tool-call volume bucketed across the
 * observed window and stacked by decision (allow / queue / deny). Reads as
 * "what the agent did over the session" far better than a scatter does, and a
 * hovered bucket reveals the exact split.
 */

import { useMemo, useRef, useState } from "react";
import * as d3Scale from "d3-scale";
import { area, stack, curveMonotoneX } from "d3-shape";
import type { AuditRecord, ProxyActionSummary } from "@/types/api";
import { chartColors } from "@/lib/chartPalette";

const COLORS: Record<ProxyActionSummary, string> = {
  allow: chartColors.accent,
  queue: chartColors.warning,
  deny: chartColors.danger,
};

const TICK_FONT = "'IBM Plex Mono', monospace";

const MARGIN = { top: 12, right: 16, bottom: 26, left: 36 };
const BUCKETS = 32;

interface Bucket {
  t: number;
  allow: number;
  queue: number;
  deny: number;
}

interface Props {
  records: AuditRecord[];
  width?: number;
  height?: number;
}

export function ActivityArea({ records, width = 800, height = 200 }: Props) {
  const innerW = width - MARGIN.left - MARGIN.right;
  const innerH = height - MARGIN.top - MARGIN.bottom;
  const ref = useRef<HTMLDivElement>(null);
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);

  const { buckets, xScale, yScale, paths, xTicks } = useMemo(() => {
    if (records.length === 0) {
      return { buckets: [] as Bucket[], xScale: null, yScale: null, paths: [], xTicks: [] as number[] };
    }
    const times = records.map((r) => new Date(r.timestamp).getTime());
    const min = Math.min(...times);
    const max = Math.max(...times);
    const span = Math.max(max - min, 1);
    const step = span / BUCKETS;

    const buck: Bucket[] = Array.from({ length: BUCKETS }, (_, i) => ({
      t: min + step * (i + 0.5),
      allow: 0,
      queue: 0,
      deny: 0,
    }));
    for (const r of records) {
      const idx = Math.min(
        BUCKETS - 1,
        Math.floor((new Date(r.timestamp).getTime() - min) / step),
      );
      buck[idx]![r.proxy_action]++;
    }

    const maxTotal = Math.max(1, ...buck.map((b) => b.allow + b.queue + b.deny));
    const xs = d3Scale.scaleLinear().domain([min, max]).range([0, innerW]);
    const ys = d3Scale.scaleLinear().domain([0, maxTotal]).range([innerH, 0]).nice();

    const series = stack<Bucket>().keys(["allow", "queue", "deny"])(buck);
    const areaGen = area<(typeof series)[number][number]>()
      .x((d) => xs(d.data.t))
      .y0((d) => ys(d[0]))
      .y1((d) => ys(d[1]))
      .curve(curveMonotoneX);

    const ps = series.map((s) => ({
      key: s.key as ProxyActionSummary,
      d: areaGen(s) ?? "",
    }));

    return { buckets: buck, xScale: xs, yScale: ys, paths: ps, xTicks: xs.ticks(5) };
  }, [records, innerW, innerH]);

  if (!xScale || !yScale || buckets.length === 0) return null;

  function onMove(e: React.MouseEvent) {
    const el = ref.current;
    if (!el || !xScale) return;
    const rect = el.getBoundingClientRect();
    const svgX = ((e.clientX - rect.left) / rect.width) * width - MARGIN.left;
    const t = xScale.invert(Math.min(innerW, Math.max(0, svgX)));
    const min = xScale.domain()[0]!;
    const max = xScale.domain()[1]!;
    const idx = Math.min(
      BUCKETS - 1,
      Math.max(0, Math.floor(((t - min) / Math.max(max - min, 1)) * BUCKETS)),
    );
    setHoverIdx(idx);
  }

  const hb = hoverIdx != null ? buckets[hoverIdx] : null;

  return (
    <div ref={ref} className="relative">
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
              <line x1={0} x2={innerW} y1={yScale(t)} y2={yScale(t)} stroke={chartColors.border} strokeWidth={0.5} />
              <text x={-8} y={yScale(t) + 3} textAnchor="end" fontSize={10} fontFamily={TICK_FONT} fill={chartColors.faint}>{t}</text>
            </g>
          ))}

          {paths.map((p) => (
            <path key={p.key} d={p.d} fill={COLORS[p.key]} opacity={0.55} stroke={COLORS[p.key]} strokeWidth={1.5} />
          ))}

          {hoverIdx != null && (
            <line
              x1={xScale(buckets[hoverIdx]!.t)}
              x2={xScale(buckets[hoverIdx]!.t)}
              y1={0}
              y2={innerH}
              stroke={chartColors.text}
              strokeWidth={1}
              opacity={0.25}
            />
          )}

          <line x1={0} x2={innerW} y1={innerH} y2={innerH} stroke={chartColors.border} />
          {xTicks.map((t) => (
            <text key={t} x={xScale(t)} y={innerH + 16} textAnchor="middle" fontSize={10} fontFamily={TICK_FONT} fill={chartColors.faint}>
              {new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
            </text>
          ))}
        </g>
      </svg>

      {hb && hb.allow + hb.queue + hb.deny > 0 && (
        <div className="pointer-events-none absolute right-2 top-2 rounded-lg border border-border bg-surface px-3 py-2 text-[11px]">
          <div className="mb-1 font-code text-text-secondary">
            {new Date(hb.t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
          </div>
          {(["allow", "queue", "deny"] as ProxyActionSummary[]).map((k) => (
            <div key={k} className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-sm" style={{ backgroundColor: COLORS[k] }} />
              <span className="capitalize text-text-secondary">{k}</span>
              <span className="ml-auto font-code text-text">{hb[k]}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
