/**
 * Interactive score scatter — recent evaluations plotted on a time × score
 * grid, coloured by decision. Adds, over the static version:
 *   • hover tooltip card (type · score · decision · latency · top filter)
 *   • clickable legend to toggle each decision series
 *   • drag across the plot to zoom a time window (with reset)
 *   • click a point to drill into the Live Audit feed for that session
 *
 * All pointer handling lives on ONE overlay rect painted on top of the points,
 * which resolves hover by nearest-point search. (Per-circle handlers don't work
 * here: the same overlay needed for drag-zoom would otherwise sit above the
 * circles and swallow their mouse events — the bug where only some dots
 * appeared hoverable.)
 */

import { useMemo, useRef, useState } from "react";
import * as d3Scale from "d3-scale";
import type { AuditRecord, ProxyActionSummary } from "@/types/api";
import { chartColors } from "@/lib/chartPalette";

const COLORS: Record<ProxyActionSummary, string> = {
  allow: chartColors.accent,
  queue: chartColors.warning,
  deny: chartColors.danger,
};

const TICK_FONT = "'IBM Plex Mono', monospace";

const MARGIN = { top: 12, right: 16, bottom: 28, left: 40 };
/** Max pixel distance (in viewBox units) for a point to register as hovered. */
const HOVER_RADIUS = 16;

interface Point {
  id: string;
  session_id: string;
  t: Date;
  score: number;
  action: ProxyActionSummary;
  type: string;
  latency: number;
  topFilter: string | null;
  record: AuditRecord;
}

interface Props {
  records: AuditRecord[];
  width?: number;
  height?: number;
  allowThreshold?: number;
  denyThreshold?: number;
  /** Called when a point is clicked (no meaningful drag). Opens the record. */
  onSelect?: (record: AuditRecord) => void;
}

function topFilterName(r: AuditRecord): string | null {
  let best: { name: string; score: number } | null = null;
  for (const f of r.filter_results) {
    if (f.matched && (best === null || f.score > best.score)) {
      best = { name: f.filter_name, score: f.score };
    }
  }
  return best?.name ?? null;
}

export function InteractiveScoreScatter({
  records,
  width = 800,
  height = 240,
  allowThreshold = 3,
  denyThreshold = 8,
  onSelect,
}: Props) {
  const innerW = width - MARGIN.left - MARGIN.right;
  const innerH = height - MARGIN.top - MARGIN.bottom;
  const containerRef = useRef<HTMLDivElement>(null);

  const [visible, setVisible] = useState<Record<ProxyActionSummary, boolean>>({
    allow: true,
    queue: true,
    deny: true,
  });
  const [zoom, setZoom] = useState<[Date, Date] | null>(null);
  const [drag, setDrag] = useState<{ start: number; cur: number } | null>(null);
  const [hover, setHover] = useState<{ px: number; py: number; p: Point } | null>(
    null,
  );

  const allPoints = useMemo<Point[]>(
    () =>
      records.map((r) => ({
        id: r.id,
        session_id: r.session_id,
        t: new Date(r.timestamp),
        score: r.composite_score,
        action: r.proxy_action,
        type: r.tool_call_type,
        latency: r.evaluation_time_ms,
        topFilter: topFilterName(r),
        record: r,
      })),
    [records],
  );

  const { xScale, yScale, xTicks, yTicks } = useMemo(() => {
    if (allPoints.length === 0) {
      const xs = d3Scale.scaleTime().domain([new Date(0), new Date(1)]).range([0, innerW]);
      const ys = d3Scale.scaleLinear().domain([0, 10]).range([innerH, 0]);
      return { xScale: xs, yScale: ys, xTicks: [] as Date[], yTicks: ys.ticks(5) };
    }
    const times = allPoints.map((p) => p.t.getTime());
    const base: [number, number] = [Math.min(...times), Math.max(...times)];
    const range = base[1] - base[0];
    const pad = Math.max(range * 0.05, 2000);
    const domain: [Date, Date] = zoom ?? [
      new Date(base[0] - pad),
      new Date(base[1] + pad),
    ];
    const maxScore = Math.max(10, ...allPoints.map((p) => p.score));
    const xs = d3Scale.scaleTime().domain(domain).range([0, innerW]);
    const ys = d3Scale
      .scaleLinear()
      .domain([0, maxScore])
      .range([innerH, 0])
      .nice();
    return { xScale: xs, yScale: ys, xTicks: xs.ticks(5), yTicks: ys.ticks(5) };
  }, [allPoints, innerW, innerH, zoom]);

  const points = useMemo(
    () => allPoints.filter((p) => visible[p.action]),
    [allPoints, visible],
  );

  /** Map a mouse event to inner-plot viewBox coords + container-relative px. */
  function getMouse(e: React.MouseEvent): {
    ix: number;
    iy: number;
    px: number;
    py: number;
  } | null {
    const el = containerRef.current;
    if (!el) return null;
    const rect = el.getBoundingClientRect();
    const scale = width / rect.width;
    const ix = (e.clientX - rect.left) * scale - MARGIN.left;
    const iy = (e.clientY - rect.top) * scale - MARGIN.top;
    return { ix, iy, px: e.clientX - rect.left, py: e.clientY - rect.top };
  }

  function nearest(ix: number, iy: number): Point | null {
    let best: { p: Point; d: number } | null = null;
    for (const p of points) {
      const dx = xScale(p.t) - ix;
      const dy = yScale(p.score) - iy;
      const d = Math.hypot(dx, dy);
      if (d <= HOVER_RADIUS && (best === null || d < best.d)) {
        best = { p, d };
      }
    }
    return best?.p ?? null;
  }

  function onMove(e: React.MouseEvent) {
    const m = getMouse(e);
    if (!m) return;
    if (drag) {
      setDrag({ ...drag, cur: Math.min(innerW, Math.max(0, m.ix)) });
      return;
    }
    const p = nearest(m.ix, m.iy);
    setHover(p ? { px: m.px, py: m.py, p } : null);
  }

  function onDown(e: React.MouseEvent) {
    const m = getMouse(e);
    if (!m) return;
    const x = Math.min(innerW, Math.max(0, m.ix));
    setDrag({ start: x, cur: x });
  }

  function onUp() {
    if (drag) {
      const a = Math.min(drag.start, drag.cur);
      const b = Math.max(drag.start, drag.cur);
      if (b - a > 8) {
        setZoom([xScale.invert(a), xScale.invert(b)]);
        setDrag(null);
        return;
      }
    }
    setDrag(null);
    // A click (no meaningful drag) on a hovered point opens its full record.
    if (hover) {
      if (onSelect) {
        onSelect(hover.p.record);
      } else {
        window.location.assign(
          `/audit?session_id=${encodeURIComponent(hover.p.session_id)}`,
        );
      }
    }
  }

  const counts = useMemo(() => {
    const c: Record<ProxyActionSummary, number> = { allow: 0, queue: 0, deny: 0 };
    for (const p of allPoints) c[p.action]++;
    return c;
  }, [allPoints]);

  return (
    <div ref={containerRef} className="relative">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full select-none"
        preserveAspectRatio="xMidYMid meet"
      >
        <g transform={`translate(${MARGIN.left},${MARGIN.top})`}>
          {/* Grid */}
          {yTicks.map((t) => (
            <line key={t} x1={0} x2={innerW} y1={yScale(t)} y2={yScale(t)} stroke={chartColors.border} strokeWidth={0.5} />
          ))}

          {/* Threshold guides */}
          <line x1={0} x2={innerW} y1={yScale(allowThreshold)} y2={yScale(allowThreshold)} stroke={chartColors.accent} strokeWidth={1} strokeDasharray="4 3" opacity={0.5} />
          <line x1={0} x2={innerW} y1={yScale(denyThreshold)} y2={yScale(denyThreshold)} stroke={chartColors.danger} strokeWidth={1} strokeDasharray="4 3" opacity={0.5} />

          {/* Zone labels */}
          <text x={innerW - 2} y={yScale(allowThreshold / 2)} textAnchor="end" fontSize={9} fontFamily={TICK_FONT} fill={chartColors.accent} opacity={0.6}>ALLOW</text>
          <text x={innerW - 2} y={yScale((allowThreshold + denyThreshold) / 2)} textAnchor="end" fontSize={9} fontFamily={TICK_FONT} fill={chartColors.warning} opacity={0.6}>QUEUE</text>
          {yScale.domain()[1]! > denyThreshold && (
            <text x={innerW - 2} y={yScale((denyThreshold + yScale.domain()[1]!) / 2)} textAnchor="end" fontSize={9} fontFamily={TICK_FONT} fill={chartColors.danger} opacity={0.6}>DENY</text>
          )}

          {/* Drag-zoom selection band */}
          {drag && (
            <rect
              x={Math.min(drag.start, drag.cur)}
              y={0}
              width={Math.abs(drag.cur - drag.start)}
              height={innerH}
              fill={chartColors.accent}
              opacity={0.1}
            />
          )}

          {/* Points (purely visual; hover/click handled by the overlay below) */}
          {points.map((p) => {
            const active = hover?.p.id === p.id;
            return (
              <circle
                key={p.id}
                cx={xScale(p.t)}
                cy={yScale(p.score)}
                r={active ? 5 : 3}
                fill={COLORS[p.action]}
                opacity={active ? 1 : 0.7}
                stroke={active ? chartColors.bg : "none"}
                strokeWidth={active ? 1 : 0}
                style={{ pointerEvents: "none" }}
              />
            );
          })}

          {/* Single pointer overlay on top — handles hover, click-drill, drag-zoom */}
          <rect
            x={0}
            y={0}
            width={innerW}
            height={innerH}
            fill="transparent"
            className={hover ? "cursor-pointer" : "cursor-crosshair"}
            onMouseMove={onMove}
            onMouseDown={onDown}
            onMouseUp={onUp}
            onMouseLeave={() => {
              setHover(null);
              setDrag(null);
            }}
          />

          {/* Axes */}
          <line x1={0} x2={innerW} y1={innerH} y2={innerH} stroke={chartColors.border} style={{ pointerEvents: "none" }} />
          {xTicks.map((t) => (
            <text key={t.getTime()} x={xScale(t)} y={innerH + 16} textAnchor="middle" fontSize={10} fontFamily={TICK_FONT} fill={chartColors.faint} style={{ pointerEvents: "none" }}>
              {t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
            </text>
          ))}
          {yTicks.map((t) => (
            <text key={t} x={-8} y={yScale(t) + 3} textAnchor="end" fontSize={10} fontFamily={TICK_FONT} fill={chartColors.faint} style={{ pointerEvents: "none" }}>{t}</text>
          ))}
          <text x={-8} y={-4} textAnchor="end" fontSize={9} fill={chartColors.faint} fontFamily={TICK_FONT} style={{ pointerEvents: "none" }}>score</text>
        </g>
      </svg>

      {/* Legend + zoom control */}
      <div className="mt-1 flex items-center justify-between gap-3 px-1">
        <div className="flex items-center gap-3 text-[11px]">
          {(["allow", "queue", "deny"] as ProxyActionSummary[]).map((a) => (
            <button
              key={a}
              type="button"
              onClick={() => setVisible((v) => ({ ...v, [a]: !v[a] }))}
              className={`inline-flex items-center gap-1.5 rounded-md px-1.5 py-0.5 transition-opacity ${
                visible[a] ? "opacity-100" : "opacity-35"
              } hover:bg-surface-2`}
              title={`Toggle ${a}`}
            >
              <span className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: COLORS[a] }} />
              <span className="capitalize text-text-secondary">{a}</span>
              <span className="font-code text-text-dim">{counts[a]}</span>
            </button>
          ))}
        </div>
        {zoom ? (
          <button
            type="button"
            onClick={() => setZoom(null)}
            className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-0.5 text-[11px] text-text-secondary hover:text-text hover:border-border-dark"
          >
            Reset zoom
          </button>
        ) : (
          <span className="text-[11px] text-text-dim">drag to zoom · click a point to inspect</span>
        )}
      </div>

      {/* Hover tooltip */}
      {hover && (
        <div
          className="pointer-events-none absolute z-10 rounded-lg border border-border bg-surface px-3 py-2 text-xs"
          style={{
            left: Math.min(hover.px + 12, (containerRef.current?.clientWidth ?? 0) - 180),
            top: Math.max(hover.py - 12, 0),
          }}
        >
          <div className="flex items-center gap-1.5 font-code text-text">
            <span className="h-2 w-2 rounded-sm" style={{ backgroundColor: COLORS[hover.p.action] }} />
            <span className="truncate max-w-[200px]">{hover.p.type}</span>
          </div>
          <div className="mt-1 grid grid-cols-2 gap-x-3 gap-y-0.5 text-[11px] text-text-secondary">
            <span>score</span>
            <span className="text-right font-code text-text">{hover.p.score.toFixed(1)}</span>
            <span>decision</span>
            <span className="text-right font-code capitalize" style={{ color: COLORS[hover.p.action] }}>{hover.p.action}</span>
            <span>latency</span>
            <span className="text-right font-code text-text">{hover.p.latency.toFixed(1)}ms</span>
            {hover.p.topFilter && (
              <>
                <span>filter</span>
                <span className="text-right font-code text-text truncate">{hover.p.topFilter}</span>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
