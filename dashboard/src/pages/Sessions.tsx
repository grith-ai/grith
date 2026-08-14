import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import type { SessionSummary } from "@/types/api";
import { getSessions, killSession } from "@/lib/api";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Format a duration in seconds as a compact human label (e.g. "2d 21h", "6m"). */
function formatDuration(secs: number): string {
  const d = Math.floor(secs / 86_400);
  const h = Math.floor((secs % 86_400) / 3_600);
  const m = Math.floor((secs % 3_600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m`;
  return `${secs}s`;
}

// A session is "possibly orphaned" when it's been alive a long time and has
// gone quiet — advisory only, never an auto-action.
const ORPHAN_UPTIME_SECS = 24 * 3_600;
const ORPHAN_IDLE_SECS = 3_600;

function isPossiblyOrphaned(s: SessionSummary): boolean {
  const idle = s.last_activity_seconds ?? 0;
  return s.uptime_seconds >= ORPHAN_UPTIME_SECS && idle >= ORPHAN_IDLE_SECS;
}

function locationLabel(s: SessionSummary): string {
  return s.project_name || s.cwd || "—";
}

// ---------------------------------------------------------------------------
// Sessions page
// ---------------------------------------------------------------------------

/**
 * Live supervisor sessions with the where-to-find-it details (project, tty,
 * pid, uptime, idle) and a Kill action. Closes the gap where the sidebar
 * footer counts sessions but offers no way to see or manage them.
 *
 * Dead sessions are reaped automatically by the daemon, so the page lists
 * live sessions and offers Kill only. Killing terminates the supervised
 * process tree — it is operator-initiated and confirmed.
 */
export function SessionsPage() {
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [killing, setKilling] = useState<string | null>(null);
  const [confirmId, setConfirmId] = useState<string | null>(null);

  const fetchSessions = useCallback(async () => {
    try {
      const response = await getSessions();
      setSessions(response.sessions);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load sessions");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchSessions();
    const interval = setInterval(() => void fetchSessions(), 5_000);
    return () => clearInterval(interval);
  }, [fetchSessions]);

  const handleKill = async (id: string) => {
    setKilling(id);
    try {
      await killSession(id);
      setConfirmId(null);
      await fetchSessions();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to kill session");
    } finally {
      setKilling(null);
    }
  };

  if (loading && sessions.length === 0) {
    return (
      <div className="p-6">
        <p className="text-text-secondary">Loading sessions…</p>
      </div>
    );
  }

  return (
    <div className="p-6">
      <div className="flex items-baseline justify-between mb-4">
        <h1 className="font-heading text-[22px] font-semibold tracking-[-0.02em] text-text">
          Sessions
          <span className="ml-2 text-sm font-normal text-text-secondary">
            {sessions.length} active
          </span>
        </h1>
        <button
          onClick={() => void fetchSessions()}
          className="px-3 py-1.5 text-xs font-medium rounded-lg border border-border text-text-secondary hover:text-text hover:border-border-dark transition-colors"
        >
          Refresh
        </button>
      </div>

      {error && (
        <div className="mb-4 rounded-card border border-danger-border bg-danger-light px-4 py-3 text-sm text-danger-text">
          {error}
        </div>
      )}

      <div className="bg-surface border border-border rounded-card overflow-hidden">
        <table className="w-full text-sm">
          <thead className="border-b border-border font-label text-text-dim text-[11px] uppercase tracking-[0.08em]">
            <tr>
              <th className="text-left px-4 py-2 font-medium">Session</th>
              <th className="text-left px-4 py-2 font-medium">Project</th>
              <th className="text-left px-4 py-2 font-medium">TTY</th>
              <th className="text-right px-4 py-2 font-medium">PID</th>
              <th className="text-right px-4 py-2 font-medium">Uptime</th>
              <th className="text-right px-4 py-2 font-medium">Idle</th>
              <th className="text-right px-4 py-2 font-medium">Activity</th>
              <th className="px-4 py-2" />
            </tr>
          </thead>
          <tbody>
            {sessions.map((s) => {
              const idle = s.last_activity_seconds ?? 0;
              const orphaned = isPossiblyOrphaned(s);
              const contained = s.containment_remaining_seconds != null;
              return (
                <tr
                  key={s.id}
                  className="border-t border-border hover:bg-surface-2"
                >
                  <td className="px-4 py-2">
                    <Link
                      to={`/audit?session_id=${s.id}`}
                      className="font-code text-text hover:text-accent-text"
                      title={s.id}
                    >
                      {s.id.slice(0, 8)}
                    </Link>
                    <span className="ml-2 text-text-secondary">{s.tool_name}</span>
                    {contained && (
                      <span className="ml-2 font-label text-[11px] font-medium tracking-[0.08em] text-danger-text">
                        CONTAINED
                      </span>
                    )}
                    {orphaned && (
                      <span
                        className="ml-2 text-xs font-medium text-warning-text"
                        title="Long-lived and idle - possibly a forgotten session."
                      >
                        possibly orphaned
                      </span>
                    )}
                  </td>
                  <td
                    className="px-4 py-2 text-text truncate max-w-xs"
                    title={s.cwd ?? undefined}
                  >
                    {locationLabel(s)}
                  </td>
                  <td className="px-4 py-2 font-code text-text-secondary">
                    {s.tty ?? "—"}
                  </td>
                  <td className="px-4 py-2 text-right font-code text-text-secondary">
                    {s.root_pid}
                  </td>
                  <td className="px-4 py-2 text-right text-text">
                    {formatDuration(s.uptime_seconds)}
                  </td>
                  <td
                    className={`px-4 py-2 text-right ${
                      orphaned ? "text-warning-text" : "text-text-secondary"
                    }`}
                  >
                    {idle >= 5 ? formatDuration(idle) : "active"}
                  </td>
                  <td className="px-4 py-2 text-right text-text-secondary">
                    {s.stats.total_intercepted.toLocaleString()} ·{" "}
                    {s.stats.total_queued} queued
                  </td>
                  <td className="px-4 py-2 text-right whitespace-nowrap">
                    {confirmId === s.id ? (
                      <span className="inline-flex items-center gap-1">
                        <button
                          onClick={() => void handleKill(s.id)}
                          disabled={killing === s.id}
                          className="px-2 py-1 text-xs font-medium rounded-btn border border-danger-border bg-danger-light text-danger-text hover:bg-danger/15 transition-colors disabled:opacity-50"
                        >
                          {killing === s.id ? "Killing…" : "Confirm kill"}
                        </button>
                        <button
                          onClick={() => setConfirmId(null)}
                          className="px-2 py-1 text-xs rounded-lg border border-border text-text-secondary hover:text-text"
                        >
                          Cancel
                        </button>
                      </span>
                    ) : (
                      <button
                        onClick={() => setConfirmId(s.id)}
                        className="px-2 py-1 text-xs font-medium rounded-btn border border-border text-text-secondary hover:text-danger-text hover:border-danger-border hover:bg-danger-light transition-colors"
                      >
                        Kill
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
            {sessions.length === 0 && (
              <tr>
                <td
                  colSpan={8}
                  className="px-4 py-8 text-center text-text-secondary"
                >
                  No active sessions. Start one with{" "}
                  <code className="font-code text-text bg-surface-2 px-1 rounded">
                    grith exec &lt;tool&gt;
                  </code>
                  .
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {confirmId && (
        <p className="mt-3 text-xs text-text-secondary">
          Killing a session terminates the supervised process and its children.
        </p>
      )}
    </div>
  );
}
