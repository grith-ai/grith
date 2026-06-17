import { useCallback, useEffect, useState } from "react";
import type { AuditRecord, AuditListResponse } from "@/types/api";
import { getAuditRecords, exportAudit } from "@/lib/api";
import { ActionBadge, AuditDetailModal } from "@/components/AuditDetailModal";

export function AuditPage() {
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<AuditRecord | null>(null);
  const [showRoutine, setShowRoutine] = useState(false);
  const limit = 50;

  const fetchRecords = useCallback(async () => {
    setLoading(true);
    try {
      const data: AuditListResponse = await getAuditRecords({
        limit,
        offset,
        include: showRoutine ? "all" : "full",
      });
      setRecords(data.records);
      setTotal(data.total);
      setError(null);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load audit records",
      );
    } finally {
      setLoading(false);
    }
  }, [offset, showRoutine]);

  // Reset to first page when the toggle changes so pagination stays sane.
  useEffect(() => {
    setOffset(0);
  }, [showRoutine]);

  useEffect(() => {
    void fetchRecords();
    // Auto-refresh every 3 seconds when on the first page.
    if (offset === 0) {
      const interval = setInterval(() => void fetchRecords(), 3_000);
      return () => clearInterval(interval);
    }
  }, [fetchRecords, offset]);

  const handleExport = async (format: "json" | "csv") => {
    try {
      const blob = await exportAudit(format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `grith-audit-export.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Export failed",
      );
    }
  };

  return (
    <div className="p-6 max-w-6xl">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-semibold text-grith-text">
          Live Audit
        </h1>
        <div className="flex items-center gap-3">
          <label
            className="flex items-center gap-2 text-xs text-grith-muted cursor-pointer select-none"
            title="Include compact rows from session-allowed short-circuits and noise-path filters. Server must be running with audit.completeness >= spawns for these to exist."
          >
            <input
              type="checkbox"
              checked={showRoutine}
              onChange={(e) => setShowRoutine(e.target.checked)}
              className="accent-status-allow-green"
            />
            <span>Show routine activity</span>
          </label>
          <button
            onClick={() => void handleExport("json")}
            className="px-3 py-1.5 text-xs font-medium rounded-lg border border-grith-border text-grith-muted hover:text-grith-text hover:border-grith-border-hover transition-colors"
          >
            Export JSON
          </button>
          <button
            onClick={() => void handleExport("csv")}
            className="px-3 py-1.5 text-xs font-medium rounded-lg border border-grith-border text-grith-muted hover:text-grith-text hover:border-grith-border-hover transition-colors"
          >
            Export CSV
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-status-deny-red/10 border border-status-deny-red/30 rounded-xl p-3 mb-6 text-sm text-status-deny-red">
          {error}
        </div>
      )}

      {/* Table */}
      <div className="bg-white border border-grith-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-grith-border text-left">
                <th className="px-4 py-3 text-xs font-medium text-grith-muted uppercase tracking-wider">
                  Time
                </th>
                <th className="px-4 py-3 text-xs font-medium text-grith-muted uppercase tracking-wider">
                  Type
                </th>
                <th className="px-4 py-3 text-xs font-medium text-grith-muted uppercase tracking-wider">
                  Session
                </th>
                <th className="px-4 py-3 text-xs font-medium text-grith-muted uppercase tracking-wider">
                  Score
                </th>
                <th className="px-4 py-3 text-xs font-medium text-grith-muted uppercase tracking-wider">
                  Action
                </th>
                <th className="px-4 py-3 text-xs font-medium text-grith-muted uppercase tracking-wider">
                  Latency
                </th>
                <th className="px-4 py-3 text-xs font-medium text-grith-muted uppercase tracking-wider">
                  Summary
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-grith-border">
              {records.map((rec) => {
                const isCompact = rec.record_type === "compact";
                return (
                  <tr
                    key={rec.id}
                    onClick={() => setSelected(rec)}
                    className={`hover:bg-grith-surface transition-colors cursor-pointer ${
                      isCompact ? "text-grith-muted/80" : ""
                    }`}
                    title="Click to see full details"
                  >
                    <td className="px-4 py-3 text-xs text-grith-muted font-mono whitespace-nowrap">
                      {new Date(rec.timestamp).toLocaleTimeString()}
                    </td>
                    <td
                      className={`px-4 py-3 text-xs font-mono max-w-md truncate ${
                        isCompact ? "text-grith-muted" : "text-green"
                      }`}
                      title={rec.tool_call_type}
                    >
                      {isCompact && (
                        <span className="inline-block mr-1.5 px-1 py-px text-[9px] font-medium rounded bg-grith-border/40 text-grith-muted uppercase tracking-wider align-middle">
                          routine
                        </span>
                      )}
                      {rec.tool_call_type}
                    </td>
                    <td className="px-4 py-3 text-xs text-grith-text">
                      {rec.supervised_tool ?? rec.source}
                    </td>
                    <td className="px-4 py-3 text-xs font-mono text-grith-text">
                      {isCompact ? "—" : rec.composite_score.toFixed(1)}
                    </td>
                    <td className="px-4 py-3">
                      <ActionBadge action={rec.proxy_action} />
                    </td>
                    <td className="px-4 py-3 text-xs text-grith-muted font-mono">
                      {isCompact ? "—" : `${rec.evaluation_time_ms.toFixed(2)}ms`}
                    </td>
                    <td className="px-4 py-3 text-xs text-grith-muted max-w-xs truncate">
                      {rec.arguments_summary}
                    </td>
                  </tr>
                );
              })}
              {!loading && records.length === 0 && (
                <tr>
                  <td
                    colSpan={7}
                    className="px-4 py-8 text-center text-grith-muted text-sm"
                  >
                    No audit records found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {total > limit && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-grith-border">
            <span className="text-xs text-grith-muted">
              Showing {offset + 1}-{Math.min(offset + limit, total)} of {total}
            </span>
            <div className="flex gap-2">
              <button
                onClick={() => setOffset(Math.max(0, offset - limit))}
                disabled={offset === 0}
                className="px-3 py-1 text-xs rounded-lg border border-grith-border text-grith-muted hover:text-grith-text disabled:opacity-30 transition-colors"
              >
                Previous
              </button>
              <button
                onClick={() => setOffset(offset + limit)}
                disabled={offset + limit >= total}
                className="px-3 py-1 text-xs rounded-lg border border-grith-border text-grith-muted hover:text-grith-text disabled:opacity-30 transition-colors"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {selected && (
        <AuditDetailModal record={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}
