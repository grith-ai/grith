import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import type { InventoryResponse } from "@/types/api";
import { getInventory } from "@/lib/api";
import { SessionPicker } from "@/components/SessionPicker";
import { SessionHeader } from "@/components/SessionHeader";

/**
 * PR 4 Phase G — "Binaries trusted this session".
 *
 * Renders the session-pinned binary inventory installed at session
 * start. The session ID is read from the `session_id` query parameter
 * (e.g. `/inventory?session_id=<uuid>`). Cross-session diff is deferred
 * until last-N inventories persist to the audit DB.
 */
export function InventoryPage() {
  // useSearchParams (not window.location.search) so in-page navigations
  // that swap the session_id re-render correctly.
  const [searchParams] = useSearchParams();
  const sessionId = searchParams.get("session_id") ?? "";

  const [data, setData] = useState<InventoryResponse | null>(null);
  const [filter, setFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchInventory = useCallback(async () => {
    if (!sessionId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const response = await getInventory(sessionId);
      setData(response);
      setError(null);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load inventory",
      );
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => {
    void fetchInventory();
  }, [fetchInventory]);

  const entries = useMemo(() => {
    if (!data) return [];
    if (!filter) return data.entries;
    const needle = filter.toLowerCase();
    return data.entries.filter(
      (e) =>
        e.path.toLowerCase().includes(needle) ||
        e.sha256.toLowerCase().startsWith(needle),
    );
  }, [data, filter]);

  if (!sessionId) {
    return (
      <SessionPicker
        title="Binaries trusted this session"
        basePath="/inventory"
        emptyHint="Trusted binaries are pinned at the start of each grith exec session. Start a supervised tool to populate the inventory."
      />
    );
  }

  if (loading && !data) {
    return (
      <div className="p-6">
        <p className="text-zinc-400">Loading inventory…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <h1 className="text-2xl font-semibold mb-4">Binaries trusted this session</h1>
        <p className="text-status-deny-red">{error}</p>
      </div>
    );
  }

  if (!data) {
    return null;
  }

  return (
    <div className="p-6">
      <div className="flex items-baseline justify-between mb-2">
        <h1 className="text-xl font-semibold text-grith-text">
          Binaries trusted this session
        </h1>
        <button
          onClick={() => void fetchInventory()}
          className="px-3 py-1.5 text-xs font-medium rounded-lg border border-grith-border text-grith-muted hover:text-grith-text hover:border-grith-border-hover transition-colors"
        >
          Refresh
        </button>
      </div>

      <SessionHeader sessionId={data.session_id} basePath="/inventory" />

      <div className="grid grid-cols-3 gap-4 mb-4 text-sm">
        <div className="bg-white border border-grith-border rounded-xl px-4 py-3">
          <div className="text-grith-muted text-xs uppercase tracking-wide">
            Binaries pinned
          </div>
          <div className="text-2xl font-semibold text-grith-text mt-1">
            {data.binaries_pinned}
          </div>
        </div>
        <div className="bg-white border border-grith-border rounded-xl px-4 py-3">
          <div className="text-grith-muted text-xs uppercase tracking-wide">
            Files scanned
          </div>
          <div className="text-2xl font-semibold text-grith-text mt-1">
            {data.total_scanned}
          </div>
        </div>
        <div
          className={`border rounded-xl px-4 py-3 ${
            data.truncated
              ? "border-status-queue-amber bg-status-queue-light"
              : "border-grith-border bg-white"
          }`}
        >
          <div className="text-grith-muted text-xs uppercase tracking-wide">
            Walk
          </div>
          <div
            className={`text-2xl font-semibold mt-1 ${
              data.truncated ? "text-status-queue-amber" : "text-grith-text"
            }`}
          >
            {data.truncated ? "Truncated" : "Complete"}
          </div>
        </div>
      </div>

      {data.truncated && (
        <div className="mb-4 rounded-xl border border-status-queue-amber bg-status-queue-light px-4 py-3 text-sm text-grith-text">
          <span className="font-medium text-status-queue-amber">
            Walk hit the file cap.
          </span>{" "}
          Tighten the profile's{" "}
          <code className="font-mono text-grith-text bg-white px-1 rounded">
            routine_exec_roots
          </code>{" "}
          glob patterns so the session-start scan completes.
        </div>
      )}

      <div className="relative max-w-md mb-4">
        <svg
          className="absolute left-3 top-2.5 w-4 h-4 text-grith-dim pointer-events-none"
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
          placeholder="Filter by path or SHA-256 prefix"
          className="w-full pl-9 pr-3 py-2 rounded-input border border-grith-border bg-white text-sm font-mono text-grith-text placeholder:text-grith-dim focus:outline-none focus:border-accent"
        />
      </div>

      <div className="bg-white border border-grith-border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-grith-surface text-grith-muted text-xs uppercase tracking-wide">
            <tr>
              <th className="text-left px-4 py-2 font-medium">Path</th>
              <th className="text-left px-4 py-2 font-medium w-72">SHA-256</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <tr
                key={entry.path}
                className="border-t border-grith-border hover:bg-grith-surface/60"
              >
                <td className="px-4 py-2 font-mono text-grith-text break-all">
                  {entry.path}
                </td>
                <td
                  className="px-4 py-2 font-mono text-xs text-grith-muted truncate"
                  title={entry.sha256}
                >
                  {entry.sha256.slice(0, 16)}…
                </td>
              </tr>
            ))}
            {entries.length === 0 && (
              <tr>
                <td colSpan={2} className="px-4 py-8 text-center text-grith-muted">
                  {data.entries.length === 0
                    ? "No binaries pinned yet — the session-start scan may still be running, or this profile declares no routine_exec_roots."
                    : "No entries match the filter."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
