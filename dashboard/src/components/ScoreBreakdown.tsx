import type { FilterResultSummary } from "@/types/api";

interface ScoreBreakdownProps {
  filterResults: FilterResultSummary[];
  compositeScore: number;
  allowThreshold?: number;
  denyThreshold?: number;
}

function scoreColor(score: number): string {
  if (score < 2) return "bg-status-allow-green";
  if (score <= 5) return "bg-status-queue-amber";
  return "bg-status-deny-red";
}

function scoreTextColor(score: number): string {
  if (score < 2) return "text-status-allow-green";
  if (score <= 5) return "text-status-queue-amber";
  return "text-status-deny-red";
}

function decisionLabel(
  score: number,
  allowThreshold: number,
  denyThreshold: number,
): { text: string; color: string } {
  if (score < allowThreshold) {
    return { text: "ALLOW", color: "text-status-allow-green" };
  }
  if (score > denyThreshold) {
    return { text: "DENY", color: "text-status-deny-red" };
  }
  return { text: "QUEUE (digest review)", color: "text-status-queue-amber" };
}

export function ScoreBreakdown({
  filterResults,
  compositeScore,
  allowThreshold = 3.0,
  denyThreshold = 8.0,
}: ScoreBreakdownProps) {
  const matched = filterResults.filter((f) => f.matched && f.score > 0);

  if (matched.length === 0) {
    return (
      <div className="bg-white border border-grith-border rounded-xl p-5">
        <p className="text-xs text-grith-muted uppercase tracking-wider mb-3">
          Score Breakdown
        </p>
        <div className="flex items-center gap-3">
          <div className="flex-1 h-8 rounded-lg bg-white flex items-center justify-center">
            <span className="text-xs text-grith-muted italic">
              No filters triggered
            </span>
          </div>
        </div>
        <div className="mt-3 flex items-center justify-between">
          <span className="text-xs text-grith-muted">
            Composite score:{" "}
            <span className="font-mono text-status-allow-green font-medium">
              {compositeScore.toFixed(1)}
            </span>
          </span>
          <span className="text-xs font-medium text-status-allow-green">
            ALLOW
          </span>
        </div>
      </div>
    );
  }

  const totalFilterScore = matched.reduce((sum, f) => sum + f.score, 0);
  // Use max of compositeScore and totalFilterScore for the bar width calculations
  // to ensure bars always fit
  const barMax = Math.max(compositeScore, totalFilterScore, denyThreshold + 1);

  const decision = decisionLabel(compositeScore, allowThreshold, denyThreshold);

  return (
    <div className="bg-white border border-grith-border rounded-xl p-5">
      <p className="text-xs text-grith-muted uppercase tracking-wider mb-3">
        Score Breakdown
      </p>

      {/* Stacked bar */}
      <div className="relative">
        <div className="h-8 rounded-lg bg-white overflow-hidden flex">
          {matched.map((f, i) => {
            const widthPct = (f.score / barMax) * 100;
            return (
              <div
                key={i}
                className={`${scoreColor(f.score)} relative group flex items-center justify-center min-w-[2px] transition-all`}
                style={{ width: `${widthPct}%` }}
                title={`${f.filter_name}: +${f.score.toFixed(1)}`}
              >
                {widthPct > 8 && (
                  <span className="text-[10px] font-mono text-white/90 truncate px-1">
                    {f.filter_name}
                  </span>
                )}
              </div>
            );
          })}
        </div>

        {/* Threshold markers */}
        {allowThreshold > 0 && allowThreshold < barMax && (
          <div
            className="absolute top-0 h-full border-l border-dashed border-status-allow-green/50"
            style={{ left: `${(allowThreshold / barMax) * 100}%` }}
          >
            <span className="absolute -top-4 -translate-x-1/2 text-[9px] font-mono text-status-allow-green/70">
              {allowThreshold.toFixed(1)}
            </span>
          </div>
        )}
        {denyThreshold > 0 && denyThreshold < barMax && (
          <div
            className="absolute top-0 h-full border-l border-dashed border-status-deny-red/50"
            style={{ left: `${(denyThreshold / barMax) * 100}%` }}
          >
            <span className="absolute -top-4 -translate-x-1/2 text-[9px] font-mono text-status-deny-red/70">
              {denyThreshold.toFixed(1)}
            </span>
          </div>
        )}
      </div>

      {/* Filter legend */}
      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1">
        {matched.map((f, i) => (
          <span key={i} className="flex items-center gap-1.5 text-xs">
            <span
              className={`w-2 h-2 rounded-sm ${scoreColor(f.score)}`}
            />
            <span className="text-grith-text">{f.filter_name}</span>
            <span className={`font-mono ${scoreTextColor(f.score)}`}>
              +{f.score.toFixed(1)}
            </span>
          </span>
        ))}
      </div>

      {/* Composite score and decision */}
      <div className="mt-3 pt-3 border-t border-grith-border flex items-center justify-between">
        <span className="text-xs text-grith-muted">
          Composite score:{" "}
          <span
            className={`font-mono font-medium ${scoreTextColor(compositeScore)}`}
          >
            {compositeScore.toFixed(1)}
          </span>
        </span>
        <span className={`text-xs font-medium ${decision.color}`}>
          {decision.text}
        </span>
      </div>
    </div>
  );
}
