import { useCallback, useEffect, useRef, useState } from "react";
import { useDigest } from "@/hooks/useDigest";
import { useWebSocket } from "@/hooks/useWebSocket";
import { getTier } from "@/lib/api";
import type { DigestItem, FilterBreakdown, WsDigestQueued } from "@/types/api";

function ScoreBadge({ score }: { score: number }) {
  const color =
    score < 3
      ? "text-accent-text bg-green-light border-green-border"
      : score < 8
        ? "text-warning-text bg-warning-light border-warning-border"
        : "text-danger-text bg-danger-light border-danger-border";

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-pill border text-xs font-code font-medium ${color}`}
    >
      {score.toFixed(1)}
    </span>
  );
}

function FilterBreakdownList({
  filters,
}: {
  filters: FilterBreakdown[];
}) {
  const triggered = filters.filter((f) => f.score > 0);
  if (triggered.length === 0) {
    return (
      <p className="text-xs text-text-secondary italic">No filters triggered</p>
    );
  }
  return (
    <div className="space-y-1">
      {triggered.map((f, i) => (
        <div key={i} className="flex items-center gap-2 text-xs">
          <span className="font-code text-text-secondary w-8 text-right">
            +{f.score.toFixed(1)}
          </span>
          <span
            className={`capitalize ${
              f.score >= 8
                ? "text-danger-text"
                : f.score >= 5
                  ? "text-danger-text/80"
                  : f.score >= 3
                    ? "text-warning-text"
                    : "text-text-secondary"
            }`}
          >
            {f.score >= 8 ? "critical" : f.score >= 5 ? "high" : f.score >= 3 ? "medium" : "low"}
          </span>
          <span className="text-text">{f.message}</span>
          <span className="text-text-secondary font-code">
            ({f.filter_name})
          </span>
        </div>
      ))}
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  if (status !== "escalated") return null;
  return (
    <span className="inline-flex items-center px-2.5 py-0.5 rounded-pill border border-purple-border bg-purple-light font-label text-[11px] font-medium uppercase tracking-[0.08em] text-purple">
      Escalated
    </span>
  );
}

function DigestCard({
  item,
  onApprove,
  onDeny,
  onLearn,
  onEscalate,
  canEscalate,
}: {
  item: DigestItem;
  onApprove: (id: string) => void;
  onDeny: (id: string) => void;
  onLearn: (id: string) => void;
  onEscalate: (id: string) => void;
  canEscalate: boolean;
}) {
  const isPending = item.status === "pending";
  const isEscalated = item.status === "escalated";

  return (
    <div className="bg-surface border border-border rounded-card p-4">
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <ScoreBadge score={item.composite_score} />
          <span className="text-sm font-code text-accent-text">
            {item.tool_call_type}
          </span>
          <StatusBadge status={item.status} />
        </div>
        <time className="text-xs text-text-secondary">
          {new Date(item.created_at).toLocaleString()}
        </time>
      </div>

      {/* Arguments */}
      <p className="text-sm text-text font-code bg-surface-2 rounded-lg px-3 py-2 mb-3 break-all">
        {item.arguments_summary}
      </p>

      {/* Context */}
      {item.task_context && (
        <p className="text-xs text-text-secondary mb-3">
          <span className="text-text">Context:</span> {item.task_context}
        </p>
      )}

      {/* Filter breakdown */}
      <div className="mb-4">
        <p className="font-label text-[11px] font-medium text-text-dim mb-1.5 uppercase tracking-[0.1em]">
          Filter breakdown
        </p>
        <FilterBreakdownList filters={item.filter_breakdown} />
      </div>

      {/* Actions */}
      <div className="flex gap-2">
        <button
          onClick={() => onApprove(item.id)}
          className="px-3 py-1.5 text-xs font-medium rounded-btn border border-green-border bg-green-light text-accent-text hover:bg-green/15 transition-colors"
        >
          Approve
        </button>
        <button
          onClick={() => onDeny(item.id)}
          className="px-3 py-1.5 text-xs font-medium rounded-btn border border-danger-border bg-danger-light text-danger-text hover:bg-danger/15 transition-colors"
        >
          Deny
        </button>
        <button
          onClick={() => onLearn(item.id)}
          className="px-3 py-1.5 text-xs font-medium rounded-btn border border-green-border bg-green-light text-accent-text hover:bg-green/15 transition-colors"
        >
          Approve &amp; Learn
        </button>
        {isPending && !isEscalated && (
          <button
            onClick={() => onEscalate(item.id)}
            disabled={!canEscalate}
            title={canEscalate ? "Escalate for senior review" : "Upgrade to Pro for escalation"}
            className="px-3 py-1.5 text-xs font-medium rounded-btn border border-purple-border bg-purple-light text-purple hover:bg-purple/15 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Escalate
          </button>
        )}
      </div>
    </div>
  );
}

/** Confirmation modal for a destructive/bulk action. */
function ConfirmDialog({
  kind,
  count,
  busy,
  onConfirm,
  onCancel,
}: {
  kind: "approve" | "deny" | "clear";
  count: number;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  // Close on Escape.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) onCancel();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onCancel, busy]);

  const verb =
    kind === "approve" ? "Approve" : kind === "deny" ? "Deny" : "Clear";
  const confirmClass =
    kind === "approve"
      ? "bg-green text-accent-ink font-heading font-semibold hover:bg-green-dark"
      : kind === "deny"
        ? "border border-danger-border text-danger-text hover:bg-danger-light"
        : "border border-border text-text hover:border-border-dark hover:bg-surface-2";

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4"
      onClick={busy ? undefined : onCancel}
    >
      <div
        className="bg-surface border border-border rounded-card max-w-md w-full p-5"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="font-heading text-[15px] font-semibold text-text mb-1.5">
          {verb} {count} {kind === "clear" ? "" : "pending "}item
          {count !== 1 ? "s" : ""}?
        </h2>
        <p className="text-sm text-text-secondary mb-5">
          {kind === "approve" &&
            "Every pending item in the queue will be approved and its tool call allowed. This cannot be undone. "}
          {kind === "deny" &&
            "Every pending item in the queue will be denied and its tool call stopped. This cannot be undone. "}
          {kind === "clear" &&
            "Every actionable item (pending and escalated) will be dismissed from the queue - not approved or denied, just cleared. This cannot be undone."}
          {kind !== "clear" && "Escalated items are not affected."}
        </p>
        <div className="flex justify-end gap-2">
          <button
            onClick={onCancel}
            disabled={busy}
            className="px-3 py-1.5 text-xs font-medium rounded-lg border border-border text-text-secondary hover:text-text hover:border-border-dark transition-colors disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={busy}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors disabled:opacity-60 ${confirmClass}`}
          >
            {busy ? `${verb}ing…` : `${verb} all ${count}`}
          </button>
        </div>
      </div>
    </div>
  );
}

function severityLabel(score: number): string {
  if (score >= 8) return "critical";
  if (score >= 5) return "high";
  if (score >= 3) return "medium";
  return "low";
}

export function DigestPage() {
  const {
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
    clearAll,
    bulkBusy,
    refresh,
  } = useDigest();
  const [canEscalate, setCanEscalate] = useState(false);
  // Captured at the moment the bulk action is requested, so the confirmation
  // count stays stable while items clear out of the list.
  const [confirmBulk, setConfirmBulk] = useState<null | {
    kind: "approve" | "deny" | "clear";
    ids: string[];
  }>(null);
  const { lastEvent, liveFeedUnavailable } = useWebSocket();
  const permissionRequested = useRef(false);

  // Request browser notification permission once on mount.
  useEffect(() => {
    if (
      permissionRequested.current ||
      typeof Notification === "undefined" ||
      Notification.permission === "granted" ||
      Notification.permission === "denied"
    ) {
      return;
    }
    permissionRequested.current = true;
    void Notification.requestPermission();
  }, []);

  // Show a browser push notification when a digest_queued event arrives.
  useEffect(() => {
    if (!lastEvent || lastEvent.type !== "digest_queued") return;
    if (typeof Notification === "undefined" || Notification.permission !== "granted") return;

    const event = lastEvent as WsDigestQueued;
    const severity = severityLabel(event.composite_score);

    const notification = new Notification("grith - Digest Item Queued", {
      body: `${event.tool_call_type} (score ${event.composite_score.toFixed(1)}, ${severity})`,
      tag: event.item_id,
      icon: "/favicon.ico",
    });

    notification.addEventListener("click", () => {
      window.focus();
      notification.close();
    });
  }, [lastEvent]);

  const fetchTier = useCallback(async () => {
    try {
      const tier = await getTier();
      setCanEscalate(tier.features.escalation ?? false);
    } catch {
      // Non-critical: default to disabled
    }
  }, []);

  useEffect(() => {
    void fetchTier();
  }, [fetchTier]);

  // Bulk actions operate on pending items only — escalated items are awaiting
  // a separate senior-review workflow and are intentionally left untouched.
  const pendingItems = items.filter((i) => i.status === "pending");

  const runBulk = async () => {
    if (!confirmBulk) return;
    const { kind, ids } = confirmBulk;
    if (kind === "approve") await approveMany(ids);
    else if (kind === "deny") await denyMany(ids);
    else await clearAll();
    setConfirmBulk(null);
  };

  return (
    <div className="p-6 max-w-4xl">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <h1 className="font-heading text-[22px] font-semibold tracking-[-0.02em] text-text">
            Digest
          </h1>
          {pendingCount > 0 && (
            <span className="inline-flex items-center justify-center min-w-[20px] h-5 px-1.5 text-xs font-medium rounded-pill border border-warning-border bg-warning-light text-warning-text">
              {pendingCount}
            </span>
          )}
          {escalatedCount > 0 && (
            <span className="inline-flex items-center justify-center min-w-[20px] h-5 px-1.5 text-xs font-medium rounded-pill border border-purple-border bg-purple-light text-purple">
              {escalatedCount} escalated
            </span>
          )}
          {liveFeedUnavailable && (
            <span
              title="Re-open the dashboard using the URL grith printed on startup (it carries a one-time #token=…) to restore live updates."
              className="inline-flex items-center gap-1 h-5 px-1.5 text-xs font-medium rounded-pill border border-warning-border bg-warning-light text-warning-text"
            >
              live feed offline
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {pendingItems.length > 1 && (
            <>
              <button
                onClick={() =>
                  setConfirmBulk({
                    kind: "approve",
                    ids: pendingItems.map((i) => i.id),
                  })
                }
                disabled={bulkBusy}
                className="px-3 py-1.5 text-xs font-medium rounded-btn border border-green-border bg-green-light text-accent-text hover:bg-green/15 transition-colors disabled:opacity-50"
              >
                Approve all
              </button>
              <button
                onClick={() =>
                  setConfirmBulk({
                    kind: "deny",
                    ids: pendingItems.map((i) => i.id),
                  })
                }
                disabled={bulkBusy}
                className="px-3 py-1.5 text-xs font-medium rounded-btn border border-danger-border bg-danger-light text-danger-text hover:bg-danger/15 transition-colors disabled:opacity-50"
              >
                Deny all
              </button>
            </>
          )}
          {items.length > 0 && (
            <button
              onClick={() =>
                setConfirmBulk({
                  kind: "clear",
                  ids: items.map((i) => i.id),
                })
              }
              disabled={bulkBusy}
              title="Dismiss all items (pending + escalated) without approving or denying them"
              className="px-3 py-1.5 text-xs font-medium rounded-lg border border-border text-text-secondary hover:text-text hover:border-border-dark transition-colors disabled:opacity-50"
            >
              Clear all
            </button>
          )}
          {items.length > 0 && (
            <span className="w-px h-5 bg-border mx-1" />
          )}
          <button
            onClick={() => void refresh()}
            disabled={loading}
            className="px-3 py-1.5 text-xs font-medium rounded-lg border border-border text-text-secondary hover:text-text hover:border-border-dark transition-colors disabled:opacity-50"
          >
            {loading ? "Loading..." : "Refresh"}
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-danger-light border border-danger-border rounded-card p-3 mb-6 text-sm text-danger-text">
          {error}
        </div>
      )}

      {!loading && items.length === 0 && (
        <div className="bg-surface-2 border border-border rounded-card p-8 text-center">
          <p className="text-text-secondary text-sm">
            No pending digest items. The proxy is handling everything
            automatically.
          </p>
        </div>
      )}

      <div className="space-y-4">
        {items.map((item) => (
          <DigestCard
            key={item.id}
            item={item}
            onApprove={(id) => void approve(id)}
            onDeny={(id) => void deny(id)}
            onLearn={(id) => void learn(id)}
            onEscalate={(id) => void escalate(id)}
            canEscalate={canEscalate}
          />
        ))}
      </div>

      {confirmBulk && (
        <ConfirmDialog
          kind={confirmBulk.kind}
          count={confirmBulk.ids.length}
          busy={bulkBusy}
          onConfirm={() => void runBulk()}
          onCancel={() => setConfirmBulk(null)}
        />
      )}
    </div>
  );
}
