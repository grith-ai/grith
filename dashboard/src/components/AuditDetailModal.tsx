/**
 * Full audit-record detail modal — metadata, arguments, and the per-filter
 * score contributions. Shared between the Live Audit table and the dashboard's
 * interactive charts (click a scatter point to open the record behind it).
 */

import { useEffect } from "react";
import type { AuditRecord, ProxyActionSummary } from "@/types/api";

/** Verdict badge (spec section 6): tint pill, mono label, glyph + word. */
export function ActionBadge({ action }: { action: ProxyActionSummary }) {
  const styles: Record<ProxyActionSummary, string> = {
    allow: "bg-green-light border-green-border text-accent-text",
    queue: "bg-warning-light border-warning-border text-warning-text",
    deny: "bg-danger-light border-danger-border text-danger-text",
  };
  const glyphs: Record<ProxyActionSummary, string> = {
    allow: "✓",
    queue: "⏸",
    deny: "⛔",
  };
  return (
    <span
      className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-pill border font-label text-[11px] font-medium uppercase tracking-[0.08em] ${styles[action]}`}
    >
      <span aria-hidden>{glyphs[action]}</span>
      <span>{action}</span>
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
    return "Routine short-circuit - this call was recorded for completeness but not scored by the filter pipeline, so there are no per-filter contributions.";
  }
  const reason = record.execution_result ?? "";
  if (/before proxy evaluation/i.test(reason)) {
    return `This call was ${
      record.proxy_action === "deny" ? "denied" : "handled"
    } before the proxy pipeline ran - a hard-deny or carve-out rule decided it directly, so no filters were evaluated.`;
  }
  if (record.proxy_action === "deny") {
    return "No per-filter breakdown - this decision came from a pre-evaluation rule rather than the scoring pipeline.";
  }
  return "No filter contributions were recorded for this evaluation.";
}

function DetailRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[10rem_1fr] gap-3 text-xs">
      <dt className="text-text-secondary">{label}</dt>
      <dd className="font-code text-text break-all">{value}</dd>
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
        className="bg-surface border border-border rounded-card max-w-4xl w-full max-h-[90vh] overflow-hidden flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <div className="flex items-center gap-3">
            <ActionBadge action={record.proxy_action} />
            {record.record_type === "compact" && (
              <span className="px-2 py-0.5 rounded-lg text-xs font-code font-medium uppercase bg-border/40 text-text-secondary">
                routine
              </span>
            )}
            <span className="text-sm font-code text-text">
              {record.tool_call_type}
            </span>
            {record.record_type !== "compact" && (
              <span className="text-xs text-text-secondary font-code">
                score {record.composite_score.toFixed(1)}
              </span>
            )}
          </div>
          <button
            onClick={onClose}
            className="text-text-secondary hover:text-text text-xl leading-none px-2"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        {/* Body */}
        <div className="overflow-y-auto px-5 py-4 space-y-6">
          {/* Metadata */}
          <section>
            <h3 className="font-label text-[11px] font-medium text-text-dim uppercase tracking-[0.1em] mb-3">
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
            <h3 className="font-label text-[11px] font-medium text-text-dim uppercase tracking-[0.1em] mb-2">
              Arguments
            </h3>
            <pre className="bg-terminal-bg border border-border rounded-code p-3 text-xs font-code text-terminal-text whitespace-pre-wrap break-all overflow-x-auto max-h-80">
              {tryPrettyJson(record.arguments_summary)}
            </pre>
          </section>

          {/* Filter results */}
          <section>
            <h3 className="font-label text-[11px] font-medium text-text-dim uppercase tracking-[0.1em] mb-2">
              Filter contributions
              {record.filter_results.length > 0 && (
                <span className="ml-2 text-text-secondary/70 font-normal normal-case">
                  {matched.length} matched · {unmatched.length} no-match
                </span>
              )}
            </h3>
            {record.filter_results.length === 0 ? (
              <div className="border border-border rounded-lg bg-surface-2 px-4 py-3 text-xs text-text-secondary leading-relaxed">
                {noFilterExplanation(record)}
              </div>
            ) : (
            <div className="border border-border rounded-lg overflow-hidden">
              <table className="w-full text-xs">
                <thead className="bg-surface-2">
                  <tr className="text-left border-b border-border font-label text-[11px] font-medium text-text-dim uppercase tracking-[0.08em]">
                    <th className="px-3 py-2">Filter</th>
                    <th className="px-3 py-2">Rule</th>
                    <th className="px-3 py-2 text-right">Score</th>
                    <th className="px-3 py-2">Severity</th>
                    <th className="px-3 py-2">Message</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {matched.map((f) => (
                    <tr key={`m-${f.filter_name}-${f.rule_id}`} className="bg-warning/5">
                      <td className="px-3 py-2 font-code text-text">{f.filter_name}</td>
                      <td className="px-3 py-2 font-code text-text-secondary">{f.rule_id || "—"}</td>
                      <td className="px-3 py-2 font-code text-right text-text">
                        +{f.score.toFixed(1)}
                      </td>
                      <td className="px-3 py-2 text-text-secondary">{f.severity}</td>
                      <td className="px-3 py-2 text-text-secondary break-words">{f.message || "—"}</td>
                    </tr>
                  ))}
                  {unmatched.map((f) => (
                    <tr key={`n-${f.filter_name}`} className="text-text-secondary/70">
                      <td className="px-3 py-2 font-code">{f.filter_name}</td>
                      <td className="px-3 py-2">—</td>
                      <td className="px-3 py-2 text-right font-code">0.0</td>
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
        <div className="px-5 py-3 border-t border-border bg-surface-2 text-xs text-text-secondary flex items-center justify-between">
          <span>Press Esc or click outside to close</span>
          <button
            onClick={() => void navigator.clipboard.writeText(JSON.stringify(record, null, 2))}
            className="text-text-secondary hover:text-text"
          >
            Copy JSON
          </button>
        </div>
      </div>
    </div>
  );
}
