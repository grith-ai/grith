/**
 * Compact donut chart for allow/queue/deny ratios.
 */

import * as d3Shape from "d3-shape";

import { chartColors } from "@/lib/chartPalette";

const COLORS = {
  allow: chartColors.accent,
  queue: chartColors.warning,
  deny: chartColors.danger,
};

interface Props {
  allow: number;
  queue: number;
  deny: number;
  size?: number;
}

export function MiniDonut({ allow, queue, deny, size = 48 }: Props) {
  const total = allow + queue + deny;
  if (total === 0) {
    return (
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={size / 2 - 4}
          fill="none"
          stroke={chartColors.border}
          strokeWidth={4}
        />
      </svg>
    );
  }

  const r = size / 2;
  const innerR = r - 6;

  const data = [
    { value: allow, color: COLORS.allow },
    { value: queue, color: COLORS.queue },
    { value: deny, color: COLORS.deny },
  ].filter((d) => d.value > 0);

  const pie = d3Shape.pie<(typeof data)[number]>()
    .value((d) => d.value)
    .sort(null)
    .padAngle(0.04);

  const arc = d3Shape.arc<d3Shape.PieArcDatum<(typeof data)[number]>>()
    .innerRadius(innerR)
    .outerRadius(r - 1)
    .cornerRadius(1);

  const arcs = pie(data);

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <g transform={`translate(${r},${r})`}>
        {arcs.map((a, i) => (
          <path key={i} d={arc(a) ?? ""} fill={a.data.color} />
        ))}
        {/* Center percentage sits over the themed card fill, so it follows
            the theme via currentColor rather than the fixed chart palette. */}
        <text
          className="text-text"
          textAnchor="middle"
          dominantBaseline="central"
          fontSize={11}
          fontFamily="'IBM Plex Mono', monospace"
          fontWeight={600}
          fill="currentColor"
        >
          {Math.round((allow / total) * 100)}%
        </text>
      </g>
    </svg>
  );
}
