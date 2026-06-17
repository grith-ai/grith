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
        <p className="text-grith-muted">Loading sessions…</p>
      </div>
    );
  }

  return (
    <div className="p-6">
      <div className="flex items-baseline justify-between mb-4">
        <h1 className="text-xl font-semibold text-grith-text">
          Sessions
          <span className="ml-2 text-sm font-normal text-grith-muted">
            {sessions.length} active
          </span>
        </h1>
        <button
          onClick={() => void fetchSessions()}
          className="px-3 py-1.5 text-xs font-medium rounded-lg border border-grith-border text-grith-muted hover:text-grith-text hover:border-grith-border-hover transition-colors"
        >
          Refresh
        </button>
      </div>

      {error && (
        <div className="mb-4 rounded-xl border border-status-deny-red bg-status-deny-light px-4 py-3 text-sm text-status-deny-red">
          {error}
        </div>
      )}

      <div className="bg-white border border-grith-border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-grith-surface text-grith-muted text-xs uppercase tracking-wide">
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
                  className="border-t border-grith-border hover:bg-grith-surface/60"
                >
                  <td className="px-4 py-2">
                    <Link
                      to={`/audit?session_id=${s.id}`}
                      className="font-mono text-grith-text hover:text-accent"
                      title={s.id}
                    >
                      {s.id.slice(0, 8)}
                    </Link>
                    <span className="ml-2 text-grith-muted">{s.tool_name}</span>
                    {contained && (
                      <span className="ml-2 text-xs font-medium text-status-deny-red">
                        CONTAINED
                      </span>
                    )}
                    {orphaned && (
                      <span
                        className="ml-2 text-xs font-medium text-status-queue-amber"
                        title="Long-lived and idle — possibly a forgotten session."
                      >
                        possibly orphaned
                      </span>
                    )}
                  </td>
                  <td
                    className="px-4 py-2 text-grith-text truncate max-w-xs"
                    title={s.cwd ?? undefined}
                  >
                    {locationLabel(s)}
                  </td>
                  <td className="px-4 py-2 font-mono text-grith-muted">
                    {s.tty ?? "—"}
                  </td>
                  <td className="px-4 py-2 text-right font-mono text-grith-muted">
                    {s.root_pid}
                  </td>
                  <td className="px-4 py-2 text-right text-grith-text">
                    {formatDuration(s.uptime_seconds)}
                  </td>
                  <td
                    className={`px-4 py-2 text-right ${
                      orphaned ? "text-status-queue-amber" : "text-grith-muted"
                    }`}
                  >
                    {idle >= 5 ? formatDuration(idle) : "active"}
                  </td>
                  <td className="px-4 py-2 text-right text-grith-muted">
                    {s.stats.total_intercepted.toLocaleString()} ·{" "}
                    {s.stats.total_queued} queued
                  </td>
                  <td className="px-4 py-2 text-right whitespace-nowrap">
                    {confirmId === s.id ? (
                      <span className="inline-flex items-center gap-1">
                        <button
                          onClick={() => void handleKill(s.id)}
                          disabled={killing === s.id}
                          className="px-2 py-1 text-xs font-medium rounded-lg bg-status-deny-red text-white hover:opacity-90 transition-opacity disabled:opacity-50"
                        >
                          {killing === s.id ? "Killing…" : "Confirm kill"}
                        </button>
                        <button
                          onClick={() => setConfirmId(null)}
                          className="px-2 py-1 text-xs rounded-lg border border-grith-border text-grith-muted hover:text-grith-text"
                        >
                          Cancel
                        </button>
                      </span>
                    ) : (
                      <button
                        onClick={() => setConfirmId(s.id)}
                        className="px-2 py-1 text-xs font-medium rounded-lg border border-grith-border text-grith-muted hover:text-status-deny-red hover:border-status-deny-red transition-colors"
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
                  className="px-4 py-8 text-center text-grith-muted"
                >
                  No active sessions. Start one with{" "}
                  <code className="font-mono text-grith-text bg-grith-surface px-1 rounded">
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
        <p className="mt-3 text-xs text-grith-muted">
          Killing a session terminates the supervised process and its children.
        </p>
      )}
    </div>
  );
}
