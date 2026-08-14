import { useEffect, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import type { SessionSummary } from "@/types/api";
import { getSessions } from "@/lib/api";

interface SessionPickerProps {
  title: string;
  basePath: string;
  emptyHint: string;
}

export function SessionPicker({ title, basePath, emptyHint }: SessionPickerProps) {
  const navigate = useNavigate();
  const [sessions, setSessions] = useState<SessionSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void getSessions()
      .then((resp) => {
        if (cancelled) return;
        const ordered = [...resp.sessions].sort(
          (a, b) => a.uptime_seconds - b.uptime_seconds,
        );
        setSessions(ordered);
      })
      .catch((e) => {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : "Failed to load sessions");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) {
    return (
      <div className="p-6">
        <h1 className="font-heading text-[22px] font-semibold tracking-[-0.02em] text-text mb-4">{title}</h1>
        <div className="bg-danger-light border border-danger-border rounded-card p-4">
          <p className="text-danger-text text-sm">{error}</p>
        </div>
      </div>
    );
  }

  if (sessions === null) {
    return (
      <div className="p-6">
        <p className="text-text-secondary text-sm">Loading sessions…</p>
      </div>
    );
  }

  if (sessions.length === 1) {
    const only = sessions[0]!;
    return <Navigate to={`${basePath}?session_id=${only.id}`} replace />;
  }

  if (sessions.length === 0) {
    return (
      <div className="p-6">
        <h1 className="font-heading text-[22px] font-semibold tracking-[-0.02em] text-text mb-4">{title}</h1>
        <div className="bg-surface-2 border border-border rounded-card p-8 text-center">
          <p className="font-heading text-[15px] font-semibold text-text mb-1">No active sessions.</p>
          <p className="text-text-secondary text-sm max-w-md mx-auto">
            {emptyHint}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      <h1 className="font-heading text-[22px] font-semibold tracking-[-0.02em] text-text mb-1">{title}</h1>
      <p className="text-text-secondary text-sm mb-4">
        Multiple sessions are active - pick one.
      </p>
      <ul className="bg-surface border border-border rounded-card overflow-hidden">
        {sessions.map((s, i) => (
          <li
            key={s.id}
            className={i === 0 ? "" : "border-t border-border"}
          >
            <button
              onClick={() => navigate(`${basePath}?session_id=${s.id}`)}
              className="w-full text-left px-4 py-3 hover:bg-surface-2 transition-colors"
            >
              <div className="flex items-baseline justify-between gap-4">
                <div className="text-sm">
                  <span className="font-code text-text font-medium">
                    {s.tool_name}
                  </span>
                  {s.project_name && (
                    <span className="text-text-secondary">
                      {" "}
                      · {s.project_name}
                    </span>
                  )}
                </div>
                <div className="text-xs text-text-secondary shrink-0">
                  pid {s.root_pid} · {formatUptime(s.uptime_seconds)}
                </div>
              </div>
              <div className="text-xs text-text-dim font-code mt-1 truncate">
                {s.id}
              </div>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${Math.floor(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}
