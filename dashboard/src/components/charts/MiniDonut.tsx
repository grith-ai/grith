/**
 * Compact donut chart for allow/queue/deny ratios.
 */

import * as d3Shape from "d3-shape";

const COLORS = {
  allow: "#00a85a",
  queue: "#bf8700",
  deny: "#d1242f",
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
          stroke="#e2e6eb"
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
        {/* Center percentage */}
        <text
          textAnchor="middle"
          dominantBaseline="central"
          fontSize={11}
          fontFamily="'JetBrains Mono', monospace"
          fontWeight={600}
          fill="#0d1117"
        >
          {Math.round((allow / total) * 100)}%
        </text>
      </g>
    </svg>
  );
}
