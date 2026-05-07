/**
 * Horizontal bar chart showing call type frequency breakdown.
 */

import { useMemo } from "react";
import * as d3Scale from "d3-scale";
import * as d3Array from "d3-array";
import type { AuditRecord } from "@/types/api";

const MARGIN = { top: 8, right: 16, bottom: 4, left: 120 };
const BAR_HEIGHT = 22;
const BAR_GAP = 4;
const MAX_BARS = 8;

/** Extract the base call type name (e.g. "FileRead" from "FileRead(/home/...)") */
function baseType(callType: string): string {
  const paren = callType.indexOf("(");
  return paren > 0 ? callType.slice(0, paren) : callType;
}

interface Props {
  records: AuditRecord[];
  width?: number;
}

export function CallTypeBar({ records, width = 400 }: Props) {
  const { bars, xScale, innerW } = useMemo(() => {
    const counts = d3Array.rollup(
      records,
      (v) => v.length,
      (r) => baseType(r.tool_call_type),
    );

    const sorted = [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, MAX_BARS);

    const maxVal = sorted.length > 0 ? sorted[0]![1] : 0;
    const iw = width - MARGIN.left - MARGIN.right;

    return {
      bars: sorted,
      xScale: d3Scale.scaleLinear().domain([0, maxVal]).range([0, iw]),
      innerW: iw,
    };
  }, [records, width]);

  const totalH = MARGIN.top + bars.length * (BAR_HEIGHT + BAR_GAP) + MARGIN.bottom;

  if (bars.length === 0) return null;

  return (
    <svg
      viewBox={`0 0 ${width} ${totalH}`}
      className="w-full"
      preserveAspectRatio="xMidYMid meet"
    >
      <g transform={`translate(${MARGIN.left},${MARGIN.top})`}>
        {bars.map(([name, count], i) => {
          const y = i * (BAR_HEIGHT + BAR_GAP);
          const barW = xScale(count);
          return (
            <g key={name}>
              {/* Label */}
              <text
                x={-8}
                y={y + BAR_HEIGHT / 2 + 1}
                textAnchor="end"
                dominantBaseline="central"
                fontSize={11}
                fontFamily="'JetBrains Mono', monospace"
                fill="#0d1117"
              >
                {name}
              </text>
              {/* Bar */}
              <rect
                x={0}
                y={y}
                width={barW}
                height={BAR_HEIGHT}
                rx={3}
                fill="#00a85a"
                opacity={0.75}
              />
              {/* Count */}
              <text
                x={barW + 6}
                y={y + BAR_HEIGHT / 2 + 1}
                dominantBaseline="central"
                fontSize={10}
                fontFamily="'JetBrains Mono', monospace"
                fill="#8b949e"
              >
                {count.toLocaleString()}
              </text>
              {/* Grid line */}
              <line
                x1={0}
                x2={innerW}
                y1={y + BAR_HEIGHT + BAR_GAP / 2}
                y2={y + BAR_HEIGHT + BAR_GAP / 2}
                stroke="#e2e6eb"
                strokeWidth={0.5}
                opacity={i < bars.length - 1 ? 1 : 0}
              />
            </g>
          );
        })}
      </g>
    </svg>
  );
}
