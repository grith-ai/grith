import { useCallback, useEffect, useState } from "react";
import type { AuditRecord, AuditListResponse, ProxyActionSummary } from "@/types/api";
import { getAuditRecords, exportAudit } from "@/lib/api";

function ActionBadge({ action }: { action: ProxyActionSummary }) {
  const styles: Record<ProxyActionSummary, string> = {
    allow: "text-status-allow-green bg-status-allow-green/10",
    queue: "text-status-queue-amber bg-status-queue-amber/10",
    deny: "text-status-deny-red bg-status-deny-red/10",
  };
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-lg text-xs font-mono font-medium uppercase ${styles[action]}`}
    >
      {action}
    </span>
  );
}

export function AuditPage() {
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);
  const limit = 50;

  const fetchRecords = useCallback(async () => {
    setLoading(true);
    try {
      const data: AuditListResponse = await getAuditRecords({
        limit,
        offset,
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
  }, [offset]);

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
        <div className="flex gap-2">
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
              {records.map((rec) => (
                <tr
                  key={rec.id}
                  className="hover:bg-grith-surface transition-colors"
                >
                  <td className="px-4 py-3 text-xs text-grith-muted font-mono whitespace-nowrap">
                    {new Date(rec.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-green">
                    {rec.tool_call_type}
                  </td>
                  <td className="px-4 py-3 text-xs text-grith-text">
                    {rec.supervised_tool ?? rec.source}
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-grith-text">
                    {rec.composite_score.toFixed(1)}
                  </td>
                  <td className="px-4 py-3">
                    <ActionBadge action={rec.proxy_action} />
                  </td>
                  <td className="px-4 py-3 text-xs text-grith-muted font-mono">
                    {rec.evaluation_time_ms.toFixed(2)}ms
                  </td>
                  <td className="px-4 py-3 text-xs text-grith-muted max-w-xs truncate">
                    {rec.arguments_summary}
                  </td>
                </tr>
              ))}
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
    </div>
  );
}
