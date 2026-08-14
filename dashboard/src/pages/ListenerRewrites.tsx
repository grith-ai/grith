import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import type { ListenerRewritesResponse } from "@/types/api";
import { getListenerRewrites } from "@/lib/api";
import { SessionPicker } from "@/components/SessionPicker";
import { SessionHeader } from "@/components/SessionHeader";

/**
 * PR 5 Phase E — "Listener rewrites".
 *
 * Renders every wildcard → loopback clamp the supervisor performed
 * for the session in `?session_id=<uuid>`. Silent rewrites without
 * a UI surface would themselves be a surprise — this view is the
 * audit trail.
 */
export function ListenerRewritesPage() {
  const [searchParams] = useSearchParams();
  const sessionId = searchParams.get("session_id") ?? "";

  const [data, setData] = useState<ListenerRewritesResponse | null>(null);
  const [filter, setFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchRewrites = useCallback(async () => {
    if (!sessionId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const response = await getListenerRewrites(sessionId);
      setData(response);
      setError(null);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load listener rewrites",
      );
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => {
    void fetchRewrites();
  }, [fetchRewrites]);

  const rewrites = useMemo(() => {
    if (!data) return [];
    if (!filter) return data.rewrites;
    const needle = filter.toLowerCase();
    return data.rewrites.filter(
      (r) =>
        r.original_addr.toLowerCase().includes(needle) ||
        r.rewritten_addr.toLowerCase().includes(needle) ||
        r.clamp_profile_entry.toLowerCase().includes(needle) ||
        (r.tool ?? "").toLowerCase().includes(needle),
    );
  }, [data, filter]);

  if (!sessionId) {
    return (
      <SessionPicker
        title="Listener rewrites"
        basePath="/listener-rewrites"
        emptyHint="The supervisor only clamps wildcard binds during an active session. Start a supervised tool to see any rewrites it performs."
      />
    );
  }

  if (loading && !data) {
    return (
      <div className="p-6">
        <p className="text-text-secondary">Loading listener rewrites…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <h1 className="font-heading text-[22px] font-semibold tracking-[-0.02em] text-text mb-4">Listener rewrites</h1>
        <p className="text-danger-text">{error}</p>
      </div>
    );
  }

  if (!data) {
    return null;
  }

  const isEmpty = data.rewrites.length === 0;

  return (
    <div className="p-6">
      <div className="flex items-baseline justify-between mb-2">
        <h1 className="font-heading text-[22px] font-semibold tracking-[-0.02em] text-text">
          Listener rewrites
        </h1>
        <button
          onClick={() => void fetchRewrites()}
          className="px-3 py-1.5 text-xs font-medium rounded-lg border border-border text-text-secondary hover:text-text hover:border-border-dark transition-colors"
        >
          Refresh
        </button>
      </div>

      <SessionHeader sessionId={data.session_id} basePath="/listener-rewrites" />

      {isEmpty ? (
        <div className="bg-surface-2 border border-border rounded-card px-6 py-10 text-center">
          <p className="font-heading text-[15px] font-semibold text-text mb-2">
            No listener rewrites for this session.
          </p>
          <p className="text-text-secondary text-sm max-w-lg mx-auto">
            The supervisor only logs here when it rewrites a wildcard{" "}
            <code className="font-code text-text bg-surface px-1 rounded">
              bind()
            </code>{" "}
            to loopback per the profile's{" "}
            <code className="font-code text-text bg-surface px-1 rounded">
              local_listener_policy
            </code>
            . Tools that only make outbound connections never trigger it.
          </p>
        </div>
      ) : (
        <>
          <p className="text-text-secondary text-sm mb-4">
            {data.rewrites.length} rewrite
            {data.rewrites.length === 1 ? "" : "s"} this session - each one is a
            wildcard{" "}
            <code className="font-code text-text bg-surface-2 px-1 rounded">
              bind()
            </code>{" "}
            the supervisor clamped to loopback.
          </p>

          <div className="relative max-w-md mb-4">
            <svg
              className="absolute left-3 top-2.5 w-4 h-4 text-text-dim pointer-events-none"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z"
              />
            </svg>
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter by address, profile entry, or tool"
              className="w-full pl-9 pr-3 py-2 rounded-btn border border-border bg-surface text-sm font-code text-text placeholder:text-text-dim focus:outline-none focus:border-green focus:shadow-glow"
            />
          </div>

          <div className="bg-surface border border-border rounded-card overflow-hidden">
            <table className="w-full text-sm">
              <thead className="border-b border-border font-label text-text-dim text-[11px] uppercase tracking-[0.08em]">
                <tr>
                  <th className="text-left px-4 py-2 font-medium">When</th>
                  <th className="text-left px-4 py-2 font-medium">Tool / PID</th>
                  <th className="text-left px-4 py-2 font-medium">Original</th>
                  <th className="text-left px-4 py-2 font-medium">Rewritten</th>
                  <th className="text-left px-4 py-2 font-medium">Policy entry</th>
                </tr>
              </thead>
              <tbody>
                {rewrites.map((r) => (
                  <tr
                    key={r.id}
                    className="border-t border-border hover:bg-surface-2"
                  >
                    <td className="px-4 py-2 font-code text-xs text-text-secondary whitespace-nowrap">
                      {new Date(r.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-2 font-code text-xs text-text whitespace-nowrap">
                      {r.tool ?? "?"}
                      {r.pid !== undefined ? ` (pid ${r.pid})` : ""}
                    </td>
                    <td className="px-4 py-2 font-code text-warning-text whitespace-nowrap">
                      {r.original_addr}
                    </td>
                    <td className="px-4 py-2 font-code text-accent-text whitespace-nowrap">
                      {r.rewritten_addr}
                    </td>
                    <td className="px-4 py-2 text-text">
                      {r.clamp_profile_entry || (
                        <span className="text-text-dim italic">
                          (no description)
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
                {rewrites.length === 0 && (
                  <tr>
                    <td
                      colSpan={5}
                      className="px-4 py-8 text-center text-text-secondary"
                    >
                      No rewrites match the filter.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
