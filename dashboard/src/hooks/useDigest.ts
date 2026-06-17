import { useCallback, useEffect, useRef, useState } from "react";
import type { DigestItem } from "@/types/api";
import {
  getDigestItems,
  approveDigest,
  denyDigest,
  learnDigest,
  escalateDigest,
} from "@/lib/api";

/** Auto-refresh interval in milliseconds. */
const REFRESH_INTERVAL = 30_000;

/** Max concurrent in-flight requests for a bulk action, so clearing a large
 *  backlog doesn't fire hundreds of requests at the daemon at once. */
const BULK_CONCURRENCY = 6;

/** Run `fn` over every item with a bounded number of concurrent workers. */
async function runWithConcurrency<T>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  const queue = [...items];
  const worker = async () => {
    for (;;) {
      const next = queue.shift();
      if (next === undefined) return;
      await fn(next);
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(limit, queue.length) }, worker),
  );
}

export interface UseDigestReturn {
  /** List of pending/escalated digest items. */
  items: DigestItem[];
  /** Number of pending items. */
  pendingCount: number;
  /** Number of escalated items. */
  escalatedCount: number;
  /** Whether the initial load or a refresh is in progress. */
  loading: boolean;
  /** Most recent error, or null. */
  error: string | null;
  /** Approve a digest item by ID. Optimistically removes it from the list. */
  approve: (id: string, notes?: string) => Promise<void>;
  /** Deny a digest item by ID. Optimistically removes it from the list. */
  deny: (id: string, notes?: string) => Promise<void>;
  /** Approve and train the adaptive classifier. Optimistically removes it. */
  learn: (id: string, notes?: string) => Promise<void>;
  /** Escalate a digest item for senior review. Stays in the list with updated status. */
  escalate: (id: string, notes?: string) => Promise<void>;
  /** Approve many items at once (bounded concurrency). */
  approveMany: (ids: string[]) => Promise<void>;
  /** Deny many items at once (bounded concurrency). */
  denyMany: (ids: string[]) => Promise<void>;
  /** Whether a bulk action is currently in flight. */
  bulkBusy: boolean;
  /** Manually trigger a refresh. */
  refresh: () => Promise<void>;
}

/**
 * Hook for managing the digest review queue.
 *
 * Fetches pending items on mount and auto-refreshes every 30 seconds.
 * Actions (approve/deny/learn) perform optimistic updates, removing the
 * item from the local list immediately while the request is in flight.
 */
export function useDigest(): UseDigestReturn {
  const [items, setItems] = useState<DigestItem[]>([]);
  const [pendingCount, setPendingCount] = useState(0);
  const [escalatedCount, setEscalatedCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [bulkBusy, setBulkBusy] = useState(false);
  const mountedRef = useRef(true);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchItems = useCallback(async () => {
    try {
      const data = await getDigestItems();
      if (!mountedRef.current) return;
      setItems(data.items);
      setPendingCount(data.pending_count);
      setEscalatedCount(data.escalated_count);
      setError(null);
    } catch (err) {
      if (!mountedRef.current) return;
      setError(err instanceof Error ? err.message : "Failed to fetch digest");
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, []);

  // Optimistic removal helper.
  const removeItem = useCallback((id: string) => {
    setItems((prev) => prev.filter((item) => item.id !== id));
    setPendingCount((prev) => Math.max(0, prev - 1));
  }, []);

  // Rollback helper: re-insert an item if the API call failed.
  const rollbackItem = useCallback((item: DigestItem) => {
    setItems((prev) => {
      if (prev.some((i) => i.id === item.id)) return prev;
      return [...prev, item].sort(
        (a, b) =>
          new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
      );
    });
    setPendingCount((prev) => prev + 1);
  }, []);

  const approve = useCallback(
    async (id: string, notes?: string) => {
      const item = items.find((i) => i.id === id);
      if (!item) return;
      removeItem(id);
      try {
        await approveDigest(id, notes);
      } catch (err) {
        rollbackItem(item);
        setError(
          err instanceof Error ? err.message : "Failed to approve item",
        );
      }
    },
    [items, removeItem, rollbackItem],
  );

  const deny = useCallback(
    async (id: string, notes?: string) => {
      const item = items.find((i) => i.id === id);
      if (!item) return;
      removeItem(id);
      try {
        await denyDigest(id, notes);
      } catch (err) {
        rollbackItem(item);
        setError(err instanceof Error ? err.message : "Failed to deny item");
      }
    },
    [items, removeItem, rollbackItem],
  );

  const learn = useCallback(
    async (id: string, notes?: string) => {
      const item = items.find((i) => i.id === id);
      if (!item) return;
      removeItem(id);
      try {
        await learnDigest(id, notes);
      } catch (err) {
        rollbackItem(item);
        setError(
          err instanceof Error ? err.message : "Failed to learn from item",
        );
      }
    },
    [items, removeItem, rollbackItem],
  );

  const escalate = useCallback(
    async (id: string, notes?: string) => {
      const item = items.find((i) => i.id === id);
      if (!item) return;
      // Optimistic: update status in place (not removed from list)
      setItems((prev) =>
        prev.map((i) =>
          i.id === id ? { ...i, status: "escalated" as const } : i,
        ),
      );
      setEscalatedCount((prev) => prev + 1);
      setPendingCount((prev) => Math.max(0, prev - 1));
      try {
        await escalateDigest(id, notes);
      } catch (err) {
        // Rollback to pending
        setItems((prev) =>
          prev.map((i) =>
            i.id === id ? { ...i, status: "pending" as const } : i,
          ),
        );
        setEscalatedCount((prev) => Math.max(0, prev - 1));
        setPendingCount((prev) => prev + 1);
        setError(
          err instanceof Error ? err.message : "Failed to escalate item",
        );
      }
    },
    [items],
  );

  const approveMany = useCallback(
    async (ids: string[]) => {
      if (ids.length === 0) return;
      setBulkBusy(true);
      try {
        await runWithConcurrency(ids, BULK_CONCURRENCY, (id) => approve(id));
      } finally {
        if (mountedRef.current) setBulkBusy(false);
      }
    },
    [approve],
  );

  const denyMany = useCallback(
    async (ids: string[]) => {
      if (ids.length === 0) return;
      setBulkBusy(true);
      try {
        await runWithConcurrency(ids, BULK_CONCURRENCY, (id) => deny(id));
      } finally {
        if (mountedRef.current) setBulkBusy(false);
      }
    },
    [deny],
  );

  useEffect(() => {
    mountedRef.current = true;
    void fetchItems();

    intervalRef.current = setInterval(() => {
      void fetchItems();
    }, REFRESH_INTERVAL);

    return () => {
      mountedRef.current = false;
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [fetchItems]);

  return {
    items,
    pendingCount,
    escalatedCount,
    loading,
    error,
    approve,
    deny,
    learn,
    escalate,
    approveMany,
    denyMany,
    bulkBusy,
    refresh: fetchItems,
  };
}
