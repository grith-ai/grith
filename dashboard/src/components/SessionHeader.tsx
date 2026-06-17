import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import type { SessionSummary } from "@/types/api";
import { getSessions } from "@/lib/api";

interface SessionHeaderProps {
  sessionId: string;
  basePath: string;
}

export function SessionHeader({ sessionId, basePath }: SessionHeaderProps) {
  const [summary, setSummary] = useState<SessionSummary | null>(null);

  useEffect(() => {
    const cancelled = false;
    void getSessions()
      .then((resp) => {
        if (cancelled) return;
        setSummary(resp.sessions.find((s) => s.id === sessionId) ?? null);
      })
      .catch(() => {
        if (cancelled) return;
        setSummary(null);
      });
  }, [sessionId]);

  return (
    <div className="mb-4 flex flex-wrap items-baseline gap-x-3 gap-y-1 text-sm">
      {summary ? (
        <>
          <span className="font-mono text-grith-text font-medium">
            {summary.tool_name}
          </span>
          {summary.project_name && (
            <span className="text-grith-muted">· {summary.project_name}</span>
          )}
          <span className="text-grith-muted text-xs">pid {summary.root_pid}</span>
          <span
            className="text-grith-dim text-xs font-mono truncate"
            title={sessionId}
          >
            {sessionId.slice(0, 8)}…
          </span>
        </>
      ) : (
        <span
          className="font-mono text-xs text-grith-dim truncate"
          title={sessionId}
        >
          Session {sessionId.slice(0, 8)}… (not in active registry)
        </span>
      )}
      <Link
        to={basePath}
        className="ml-auto text-xs text-grith-muted hover:text-grith-text"
      >
        Switch session ↗
      </Link>
    </div>
  );
}
