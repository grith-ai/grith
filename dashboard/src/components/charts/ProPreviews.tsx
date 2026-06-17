/**
 * Static, decorative "preview" visuals for locked Pro/Enterprise cards. These
 * render behind the frosted upgrade overlay in LockedProCard — they exist to
 * convey what the real feature looks like, so they use representative shapes
 * rather than live data.
 */

/** Anomaly detection: a baseline band with a flagged spike. */
export function AnomalyPreview() {
  const pts = [8, 9, 7, 10, 8, 9, 22, 9, 8, 10, 7, 9];
  const w = 320;
  const h = 110;
  const max = 24;
  const step = w / (pts.length - 1);
  const y = (v: number) => h - (v / max) * h;
  const line = pts.map((v, i) => `${i === 0 ? "M" : "L"}${i * step},${y(v)}`).join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-28">
      <rect x={0} y={y(12)} width={w} height={y(6) - y(12)} fill="#00a85a" opacity={0.08} />
      <path d={line} fill="none" stroke="#57606a" strokeWidth={1.5} />
      <circle cx={6 * step} cy={y(22)} r={5} fill="#d1242f" />
      <circle cx={6 * step} cy={y(22)} r={10} fill="none" stroke="#d1242f" strokeWidth={1.5} opacity={0.5} />
      <text x={6 * step + 14} y={y(22) + 4} fontSize={10} fill="#d1242f" fontFamily="'JetBrains Mono', monospace">
        anomaly
      </text>
    </svg>
  );
}

/** 90-day retention trend: a long faded multi-day bar series. */
export function RetentionTrendPreview() {
  const bars = [4, 6, 5, 8, 7, 9, 6, 10, 8, 12, 9, 11, 7, 13, 10, 9, 12, 8, 11, 14];
  const w = 320;
  const h = 110;
  const max = 14;
  const bw = w / bars.length;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-28">
      {bars.map((v, i) => (
        <rect
          key={i}
          x={i * bw + 1}
          y={h - (v / max) * h}
          width={bw - 2}
          height={(v / max) * h}
          rx={1.5}
          fill="#00a85a"
          opacity={0.3 + (i / bars.length) * 0.5}
        />
      ))}
    </svg>
  );
}

/** Multi-session comparison: a few labelled mini posture bars. */
export function MultiSessionPreview() {
  const rows = [
    { name: "claude-code", a: 82, q: 12, d: 6 },
    { name: "codex", a: 74, q: 18, d: 8 },
    { name: "aider", a: 91, q: 7, d: 2 },
    { name: "grith run", a: 96, q: 3, d: 1 },
  ];
  return (
    <div className="space-y-2.5 py-1">
      {rows.map((r) => (
        <div key={r.name}>
          <div className="mb-1 flex justify-between font-mono text-[11px] text-grith-muted">
            <span>{r.name}</span>
            <span>{r.a}% allow</span>
          </div>
          <div className="flex h-2 overflow-hidden rounded-full bg-grith-surface">
            <div style={{ width: `${r.a}%`, backgroundColor: "#00a85a" }} />
            <div style={{ width: `${r.q}%`, backgroundColor: "#bf8700" }} />
            <div style={{ width: `${r.d}%`, backgroundColor: "#d1242f" }} />
          </div>
        </div>
      ))}
    </div>
  );
}
