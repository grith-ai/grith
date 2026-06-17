/**
 * Full audit-record detail modal — metadata, arguments, and the per-filter
 * score contributions. Shared between the Live Audit table and the dashboard's
 * interactive charts (click a scatter point to open the record behind it).
 */

import { useEffect } from "react";
import type { AuditRecord, ProxyActionSummary } from "@/types/api";

export function ActionBadge({ action }: { action: ProxyActionSummary }) {
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

function tryPrettyJson(text: string): string {
  // arguments_summary is a JSON blob in most cases. Pretty-print when it
  // parses; otherwise show as-is so we don't mangle plain-text payloads.
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
}

/** Human explanation for why a record has no per-filter breakdown. Hard-deny
 *  / carve-out syscalls (io_uring, kernel-module ops, …) are decided before the
 *  proxy pipeline runs, and compact rows are routine short-circuits — in both
 *  cases `filter_results` is legitimately empty rather than missing. */
function noFilterExplanation(record: AuditRecord): string {
  if (record.record_type === "compact") {
    return "Routine short-circuit — this call was recorded for completeness but not scored by the filter pipeline, so there are no per-filter contributions.";
  }
  const reason = record.execution_result ?? "";
  if (/before proxy evaluation/i.test(reason)) {
    return `This call was ${
      record.proxy_action === "deny" ? "denied" : "handled"
    } before the proxy pipeline ran — a hard-deny or carve-out rule decided it directly, so no filters were evaluated.`;
  }
  if (record.proxy_action === "deny") {
    return "No per-filter breakdown — this decision came from a pre-evaluation rule rather than the scoring pipeline.";
  }
  return "No filter contributions were recorded for this evaluation.";
}

function DetailRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[10rem_1fr] gap-3 text-xs">
      <dt className="text-grith-muted">{label}</dt>
      <dd className="font-mono text-grith-text break-all">{value}</dd>
    </div>
  );
}

export function AuditDetailModal({
  record,
  onClose,
}: {
  record: AuditRecord;
  onClose: () => void;
}) {
  // Close on Escape.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  const matched = record.filter_results.filter((f) => f.matched);
  const unmatched = record.filter_results.filter((f) => !f.matched);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4"
      onClick={onClose}
    >
      <div
        className="bg-white border border-grith-border rounded-xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-grith-border">
          <div className="flex items-center gap-3">
            <ActionBadge action={record.proxy_action} />
            {record.record_type === "compact" && (
              <span className="px-2 py-0.5 rounded-lg text-xs font-mono font-medium uppercase bg-grith-border/40 text-grith-muted">
                routine
              </span>
            )}
            <span className="text-sm font-mono text-grith-text">
              {record.tool_call_type}
            </span>
            {record.record_type !== "compact" && (
              <span className="text-xs text-grith-muted font-mono">
                score {record.composite_score.toFixed(1)}
              </span>
            )}
          </div>
          <button
            onClick={onClose}
            className="text-grith-muted hover:text-grith-text text-xl leading-none px-2"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        {/* Body */}
        <div className="overflow-y-auto px-5 py-4 space-y-6">
          {/* Metadata */}
          <section>
            <h3 className="text-xs font-semibold text-grith-muted uppercase tracking-wider mb-3">
              Metadata
            </h3>
            <dl className="space-y-1.5">
              <DetailRow label="Timestamp" value={new Date(record.timestamp).toISOString()} />
              <DetailRow label="Record ID" value={record.id} />
              <DetailRow label="Session" value={record.session_id} />
              <DetailRow
                label="Tool / source"
                value={record.supervised_tool ?? record.source}
              />
              {record.supervised_pid != null && (
                <DetailRow label="Supervised PID" value={record.supervised_pid} />
              )}
              <DetailRow label="Plugin" value={record.plugin_id} />
              <DetailRow
                label="Evaluation time"
                value={`${record.evaluation_time_ms.toFixed(2)}ms`}
              />
              {record.correlation_id && (
                <DetailRow label="Correlation ID" value={record.correlation_id} />
              )}
              {record.chain_sequence != null && (
                <DetailRow label="Chain sequence" value={record.chain_sequence} />
              )}
              {record.task_context && (
                <DetailRow label="Task context" value={record.task_context} />
              )}
              {record.execution_result && (
                <DetailRow label="Execution result" value={record.execution_result} />
              )}
            </dl>
          </section>

          {/* Arguments */}
          <section>
            <h3 className="text-xs font-semibold text-grith-muted uppercase tracking-wider mb-2">
              Arguments
            </h3>
            <pre className="bg-grith-surface border border-grith-border rounded-lg p-3 text-xs font-mono text-grith-text whitespace-pre-wrap break-all overflow-x-auto max-h-80">
              {tryPrettyJson(record.arguments_summary)}
            </pre>
          </section>

          {/* Filter results */}
          <section>
            <h3 className="text-xs font-semibold text-grith-muted uppercase tracking-wider mb-2">
              Filter contributions
              {record.filter_results.length > 0 && (
                <span className="ml-2 text-grith-muted/70 font-normal normal-case">
                  {matched.length} matched · {unmatched.length} no-match
                </span>
              )}
            </h3>
            {record.filter_results.length === 0 ? (
              <div className="border border-grith-border rounded-lg bg-grith-surface px-4 py-3 text-xs text-grith-muted leading-relaxed">
                {noFilterExplanation(record)}
              </div>
            ) : (
            <div className="border border-grith-border rounded-lg overflow-hidden">
              <table className="w-full text-xs">
                <thead className="bg-grith-surface">
                  <tr className="text-left">
                    <th className="px-3 py-2 font-medium text-grith-muted">Filter</th>
                    <th className="px-3 py-2 font-medium text-grith-muted">Rule</th>
                    <th className="px-3 py-2 font-medium text-grith-muted text-right">Score</th>
                    <th className="px-3 py-2 font-medium text-grith-muted">Severity</th>
                    <th className="px-3 py-2 font-medium text-grith-muted">Message</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-grith-border">
                  {matched.map((f) => (
                    <tr key={`m-${f.filter_name}-${f.rule_id}`} className="bg-status-queue-amber/5">
                      <td className="px-3 py-2 font-mono text-grith-text">{f.filter_name}</td>
                      <td className="px-3 py-2 font-mono text-grith-muted">{f.rule_id || "—"}</td>
                      <td className="px-3 py-2 font-mono text-right text-grith-text">
                        +{f.score.toFixed(1)}
                      </td>
                      <td className="px-3 py-2 text-grith-muted">{f.severity}</td>
                      <td className="px-3 py-2 text-grith-muted break-words">{f.message || "—"}</td>
                    </tr>
                  ))}
                  {unmatched.map((f) => (
                    <tr key={`n-${f.filter_name}`} className="text-grith-muted/70">
                      <td className="px-3 py-2 font-mono">{f.filter_name}</td>
                      <td className="px-3 py-2">—</td>
                      <td className="px-3 py-2 text-right font-mono">0.0</td>
                      <td className="px-3 py-2">—</td>
                      <td className="px-3 py-2">no match</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            )}
          </section>
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-grith-border bg-grith-surface text-xs text-grith-muted flex items-center justify-between">
          <span>Press Esc or click outside to close</span>
          <button
            onClick={() => void navigator.clipboard.writeText(JSON.stringify(record, null, 2))}
            className="text-grith-muted hover:text-grith-text"
          >
            Copy JSON
          </button>
        </div>
      </div>
    </div>
  );
}
