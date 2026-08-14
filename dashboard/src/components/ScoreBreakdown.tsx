import type { FilterResultSummary } from "@/types/api";

interface ScoreBreakdownProps {
  filterResults: FilterResultSummary[];
  compositeScore: number;
  allowThreshold?: number;
  denyThreshold?: number;
}

function scoreColor(score: number): string {
  if (score < 2) return "bg-green";
  if (score <= 5) return "bg-warning";
  return "bg-danger";
}

function scoreTextColor(score: number): string {
  if (score < 2) return "text-accent-text";
  if (score <= 5) return "text-warning-text";
  return "text-danger-text";
}

function decisionLabel(
  score: number,
  allowThreshold: number,
  denyThreshold: number,
): { text: string; color: string } {
  if (score < allowThreshold) {
    return { text: "ALLOW", color: "text-accent-text" };
  }
  if (score > denyThreshold) {
    return { text: "DENY", color: "text-danger-text" };
  }
  return { text: "QUEUE (digest review)", color: "text-warning-text" };
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
      <div className="bg-surface border border-border rounded-card p-5">
        <p className="font-label text-[11px] font-medium text-text-dim uppercase tracking-[0.1em] mb-3">
          Score Breakdown
        </p>
        <div className="flex items-center gap-3">
          <div className="flex-1 h-8 rounded-lg bg-surface-2 flex items-center justify-center">
            <span className="text-xs text-text-secondary italic">
              No filters triggered
            </span>
          </div>
        </div>
        <div className="mt-3 flex items-center justify-between">
          <span className="text-xs text-text-secondary">
            Composite score:{" "}
            <span className="font-code text-accent-text font-medium">
              {compositeScore.toFixed(1)}
            </span>
          </span>
          <span className="text-xs font-medium text-accent-text">
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
    <div className="bg-surface border border-border rounded-card p-5">
      <p className="font-label text-[11px] font-medium text-text-dim uppercase tracking-[0.1em] mb-3">
        Score Breakdown
      </p>

      {/* Stacked bar */}
      <div className="relative">
        <div className="h-8 rounded-lg bg-surface-2 overflow-hidden flex">
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
                  <span className="text-[10px] font-code text-accent-ink truncate px-1">
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
            className="absolute top-0 h-full border-l border-dashed border-green-border"
            style={{ left: `${(allowThreshold / barMax) * 100}%` }}
          >
            <span className="absolute -top-4 -translate-x-1/2 text-[9px] font-code text-accent-text/70">
              {allowThreshold.toFixed(1)}
            </span>
          </div>
        )}
        {denyThreshold > 0 && denyThreshold < barMax && (
          <div
            className="absolute top-0 h-full border-l border-dashed border-danger-border"
            style={{ left: `${(denyThreshold / barMax) * 100}%` }}
          >
            <span className="absolute -top-4 -translate-x-1/2 text-[9px] font-code text-danger-text/70">
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
            <span className="text-text">{f.filter_name}</span>
            <span className={`font-code ${scoreTextColor(f.score)}`}>
              +{f.score.toFixed(1)}
            </span>
          </span>
        ))}
      </div>

      {/* Composite score and decision */}
      <div className="mt-3 pt-3 border-t border-border flex items-center justify-between">
        <span className="text-xs text-text-secondary">
          Composite score:{" "}
          <span
            className={`font-code font-medium ${scoreTextColor(compositeScore)}`}
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
