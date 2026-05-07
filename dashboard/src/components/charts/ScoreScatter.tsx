/**
 * Live score scatter plot — shows recent evaluations as dots on a
 * time x score grid, colored by decision.
 */

import { useMemo } from "react";
import * as d3Scale from "d3-scale";
import type { AuditRecord, ProxyActionSummary } from "@/types/api";

const COLORS: Record<ProxyActionSummary, string> = {
  allow: "#00a85a",
  queue: "#bf8700",
  deny: "#d1242f",
};

const MARGIN = { top: 12, right: 16, bottom: 28, left: 40 };

interface Props {
  records: AuditRecord[];
  width?: number;
  height?: number;
  /** Score threshold lines. */
  allowThreshold?: number;
  denyThreshold?: number;
}

export function ScoreScatter({
  records,
  width = 800,
  height = 220,
  allowThreshold = 3,
  denyThreshold = 8,
}: Props) {
  const innerW = width - MARGIN.left - MARGIN.right;
  const innerH = height - MARGIN.top - MARGIN.bottom;

  const { xScale, yScale, points, xTicks } = useMemo(() => {
    if (records.length === 0) {
      return {
        xScale: d3Scale.scaleTime().domain([new Date(), new Date()]).range([0, innerW]),
        yScale: d3Scale.scaleLinear().domain([0, 10]).range([innerH, 0]),
        points: [],
        xTicks: [] as Date[],
      };
    }

    const parsed = records.map((r) => ({
      t: new Date(r.timestamp),
      score: r.composite_score,
      action: r.proxy_action,
      type: r.tool_call_type,
      latency: r.evaluation_time_ms,
    }));

    const tExtent = [
      parsed[parsed.length - 1]!.t,
      parsed[0]!.t,
    ] as [Date, Date];

    // Pad time range by 5% on each side for breathing room
    const range = tExtent[1].getTime() - tExtent[0].getTime();
    const pad = Math.max(range * 0.05, 2000);
    const domain: [Date, Date] = [
      new Date(tExtent[0].getTime() - pad),
      new Date(tExtent[1].getTime() + pad),
    ];

    const maxScore = Math.max(10, ...parsed.map((p) => p.score));

    const xs = d3Scale.scaleTime().domain(domain).range([0, innerW]);
    const ys = d3Scale.scaleLinear().domain([0, maxScore]).range([innerH, 0]).nice();

    return {
      xScale: xs,
      yScale: ys,
      points: parsed,
      xTicks: xs.ticks(5),
    };
  }, [records, innerW, innerH]);

  const yTicks = yScale.ticks(5);

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      className="w-full"
      preserveAspectRatio="xMidYMid meet"
    >
      <g transform={`translate(${MARGIN.left},${MARGIN.top})`}>
        {/* Grid lines */}
        {yTicks.map((t) => (
          <line
            key={t}
            x1={0}
            x2={innerW}
            y1={yScale(t)}
            y2={yScale(t)}
            stroke="#e2e6eb"
            strokeWidth={0.5}
          />
        ))}

        {/* Threshold zones */}
        {allowThreshold != null && (
          <line
            x1={0}
            x2={innerW}
            y1={yScale(allowThreshold)}
            y2={yScale(allowThreshold)}
            stroke="#00a85a"
            strokeWidth={1}
            strokeDasharray="4 3"
            opacity={0.5}
          />
        )}
        {denyThreshold != null && (
          <line
            x1={0}
            x2={innerW}
            y1={yScale(denyThreshold)}
            y2={yScale(denyThreshold)}
            stroke="#d1242f"
            strokeWidth={1}
            strokeDasharray="4 3"
            opacity={0.5}
          />
        )}

        {/* Zone labels */}
        <text x={innerW - 2} y={yScale(allowThreshold / 2)} textAnchor="end" fontSize={9} fill="#00a85a" opacity={0.6}>
          ALLOW
        </text>
        <text x={innerW - 2} y={yScale((allowThreshold + denyThreshold) / 2)} textAnchor="end" fontSize={9} fill="#bf8700" opacity={0.6}>
          QUEUE
        </text>
        {yScale.domain()[1]! > denyThreshold && (
          <text x={innerW - 2} y={yScale((denyThreshold + yScale.domain()[1]!) / 2)} textAnchor="end" fontSize={9} fill="#d1242f" opacity={0.6}>
            DENY
          </text>
        )}

        {/* Points */}
        {points.map((p, i) => (
          <circle
            key={i}
            cx={xScale(p.t)}
            cy={yScale(p.score)}
            r={3}
            fill={COLORS[p.action]}
            opacity={0.7}
          >
            <title>
              {p.type} — score {p.score.toFixed(1)} ({p.action}) {p.latency.toFixed(1)}ms
            </title>
          </circle>
        ))}

        {/* X axis */}
        <line x1={0} x2={innerW} y1={innerH} y2={innerH} stroke="#e2e6eb" />
        {xTicks.map((t) => (
          <text
            key={t.getTime()}
            x={xScale(t)}
            y={innerH + 16}
            textAnchor="middle"
            fontSize={10}
            fontFamily="'JetBrains Mono', monospace"
            fill="#8b949e"
          >
            {t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
          </text>
        ))}

        {/* Y axis */}
        {yTicks.map((t) => (
          <text
            key={t}
            x={-8}
            y={yScale(t) + 3}
            textAnchor="end"
            fontSize={10}
            fontFamily="'JetBrains Mono', monospace"
            fill="#8b949e"
          >
            {t}
          </text>
        ))}
        <text
          x={-8}
          y={-4}
          textAnchor="end"
          fontSize={9}
          fill="#8b949e"
          fontFamily="'JetBrains Mono', monospace"
        >
          score
        </text>
      </g>
    </svg>
  );
}
