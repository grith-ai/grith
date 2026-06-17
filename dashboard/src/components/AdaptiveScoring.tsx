import { useState, useEffect, useCallback } from "react";
import type {
  AdaptiveStatsResponse,
  AdaptiveFeedbackRequest,
} from "@/types/api";
import { csrfHeaders } from "@/lib/csrf";

interface TierInfo {
  features: Record<string, boolean>;
}

export function AdaptiveScoring() {
  const [tierInfo, setTierInfo] = useState<TierInfo | null>(null);
  const [stats, setStats] = useState<AdaptiveStatsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [feedbackMsg, setFeedbackMsg] = useState<string | null>(null);

  // Form state
  const [category, setCategory] = useState("filesystem");
  const [filters, setFilters] = useState("");
  const [score, setScore] = useState("5.0");
  const [outcome, setOutcome] = useState<"approved" | "denied">("approved");

  useEffect(() => {
    fetch("/api/tier")
      .then((res) => res.json())
      .then((data) => setTierInfo(data))
      .catch(() => {});
  }, []);

  const allowed = tierInfo?.features?.adaptive_scoring ?? false;

  const fetchStats = useCallback(() => {
    if (!allowed) return;
    fetch("/api/adaptive/stats")
      .then((res) => {
        if (!res.ok) throw new Error(`${res.status}`);
        return res.json();
      })
      .then((data: AdaptiveStatsResponse) => {
        setStats(data);
        setError(null);
      })
      .catch((e) => setError(e.message));
  }, [allowed]);

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  const handleSubmitFeedback = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setFeedbackMsg(null);
      const body: AdaptiveFeedbackRequest = {
        tool_type_category: category,
        matched_filters: filters
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        original_score: parseFloat(score) || 0,
        outcome,
      };
      try {
        const res = await fetch("/api/adaptive/feedback", {
          method: "POST",
          headers: { "Content-Type": "application/json", ...csrfHeaders() },
          body: JSON.stringify(body),
        });
        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          throw new Error(data.error || `HTTP ${res.status}`);
        }
        setFeedbackMsg("Feedback recorded.");
        fetchStats();
        setTimeout(() => setFeedbackMsg(null), 3000);
      } catch (err) {
        setFeedbackMsg(
          `Error: ${err instanceof Error ? err.message : "unknown"}`,
        );
      }
    },
    [category, filters, score, outcome, fetchStats],
  );

  if (!allowed) {
    return (
      <div className="bg-white border border-grith-border rounded-xl p-5 opacity-75">
        <h2 className="text-sm font-medium text-grith-text mb-1">
          Adaptive Scoring
        </h2>
        <p className="text-xs text-grith-muted mb-4">
          Bayesian learning engine that adjusts proxy scores based on digest
          review feedback over time.
        </p>
        <div className="flex flex-col items-center gap-3 py-6">
          <span className="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-medium rounded-full bg-gradient-to-r from-green/20 to-green-dark/20 border border-green/30 text-green">
            Pro Feature
          </span>
          <p className="text-xs text-grith-muted text-center max-w-xs">
            Upgrade to Pro for adaptive scoring that learns from your review
            decisions.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white border border-grith-border rounded-xl p-5">
      <h2 className="text-sm font-medium text-grith-text mb-1">
        Adaptive Scoring
      </h2>
      <p className="text-xs text-grith-muted mb-4">
        Bayesian learning engine that adjusts proxy scores based on digest
        review feedback.
      </p>

      {error && (
        <div className="mb-4 text-xs text-status-deny-red">{error}</div>
      )}

      {stats && (
        <div className="space-y-4">
          {/* Status cards */}
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-grith-bg rounded-xl px-3 py-2">
              <div className="text-xs text-grith-muted">Status</div>
              <div className="text-sm font-mono text-grith-text">
                {stats.enabled ? "Enabled" : "Disabled"}
              </div>
            </div>
            <div className="bg-grith-bg rounded-xl px-3 py-2">
              <div className="text-xs text-grith-muted">Observations</div>
              <div className="text-sm font-mono text-grith-text">
                {stats.total_observations}
              </div>
            </div>
          </div>

          {/* Category breakdown */}
          {Object.keys(stats.categories).length > 0 && (
            <div>
              <h3 className="text-xs text-grith-muted uppercase tracking-wider mb-2">
                Category Breakdown
              </h3>
              <div className="space-y-2">
                {Object.entries(stats.categories).map(([name, cat]) => (
                  <div
                    key={name}
                    className="bg-grith-bg rounded-xl px-3 py-2 flex items-center justify-between"
                  >
                    <span className="text-xs font-mono text-grith-text">
                      {name}
                    </span>
                    <div className="flex items-center gap-3 text-xs font-mono">
                      <span className="text-status-allow-green">
                        {cat.approved}
                      </span>
                      <span className="text-grith-muted">/</span>
                      <span className="text-status-deny-red">{cat.denied}</span>
                      <span className="text-grith-muted">
                        ({(cat.approval_rate * 100).toFixed(0)}%)
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Feedback form */}
          <div>
            <h3 className="text-xs text-grith-muted uppercase tracking-wider mb-2">
              Submit Manual Feedback
            </h3>
            <form onSubmit={handleSubmitFeedback} className="space-y-2">
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-xs text-grith-muted mb-1">
                    Category
                  </label>
                  <select
                    value={category}
                    onChange={(e) => setCategory(e.target.value)}
                    className="w-full bg-grith-bg border border-grith-border rounded px-2 py-1.5 text-xs text-grith-text focus:outline-none focus:border-green/50"
                  >
                    <option value="filesystem">filesystem</option>
                    <option value="shell">shell</option>
                    <option value="network">network</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-grith-muted mb-1">
                    Outcome
                  </label>
                  <select
                    value={outcome}
                    onChange={(e) =>
                      setOutcome(e.target.value as "approved" | "denied")
                    }
                    className="w-full bg-grith-bg border border-grith-border rounded px-2 py-1.5 text-xs text-grith-text focus:outline-none focus:border-green/50"
                  >
                    <option value="approved">Approved</option>
                    <option value="denied">Denied</option>
                  </select>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-xs text-grith-muted mb-1">
                    Matched Filters
                  </label>
                  <input
                    type="text"
                    value={filters}
                    onChange={(e) => setFilters(e.target.value)}
                    placeholder="path-match, secret-scan"
                    className="w-full bg-grith-bg border border-grith-border rounded px-2 py-1.5 text-xs text-grith-text placeholder:text-grith-muted/50 focus:outline-none focus:border-green/50"
                  />
                </div>
                <div>
                  <label className="block text-xs text-grith-muted mb-1">
                    Original Score
                  </label>
                  <input
                    type="number"
                    step="0.1"
                    value={score}
                    onChange={(e) => setScore(e.target.value)}
                    className="w-full bg-grith-bg border border-grith-border rounded px-2 py-1.5 text-xs text-grith-text focus:outline-none focus:border-green/50"
                  />
                </div>
              </div>
              <button
                type="submit"
                className="px-3 py-1.5 text-xs font-medium rounded bg-green/20 border border-green/30 text-green hover:bg-green/30 transition-colors"
              >
                Submit Feedback
              </button>
              {feedbackMsg && (
                <p
                  className={`text-xs mt-1 ${feedbackMsg.startsWith("Error") ? "text-status-deny-red" : "text-status-allow-green"}`}
                >
                  {feedbackMsg}
                </p>
              )}
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
