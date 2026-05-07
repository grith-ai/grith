import { useCallback, useEffect, useRef, useState } from "react";
import { useDigest } from "@/hooks/useDigest";
import { useWebSocket } from "@/hooks/useWebSocket";
import { getTier } from "@/lib/api";
import type { DigestItem, FilterBreakdown, WsDigestQueued } from "@/types/api";

function ScoreBadge({ score }: { score: number }) {
  const color =
    score < 3
      ? "text-status-allow-green bg-status-allow-green/10"
      : score < 8
        ? "text-status-queue-amber bg-status-queue-amber/10"
        : "text-status-deny-red bg-status-deny-red/10";

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-lg text-xs font-mono font-medium ${color}`}
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
      <p className="text-xs text-grith-muted italic">No filters triggered</p>
    );
  }
  return (
    <div className="space-y-1">
      {triggered.map((f, i) => (
        <div key={i} className="flex items-center gap-2 text-xs">
          <span className="font-mono text-grith-muted w-8 text-right">
            +{f.score.toFixed(1)}
          </span>
          <span
            className={`capitalize ${
              f.score >= 8
                ? "text-status-deny-red"
                : f.score >= 5
                  ? "text-status-deny-red/80"
                  : f.score >= 3
                    ? "text-status-queue-amber"
                    : "text-grith-muted"
            }`}
          >
            {f.score >= 8 ? "critical" : f.score >= 5 ? "high" : f.score >= 3 ? "medium" : "low"}
          </span>
          <span className="text-grith-text">{f.message}</span>
          <span className="text-grith-muted font-mono">
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
    <span className="inline-flex items-center px-2 py-0.5 rounded-lg text-xs font-medium bg-purple-500/15 text-purple-400">
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
    <div className="bg-white border border-grith-border rounded-xl p-4">
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <ScoreBadge score={item.composite_score} />
          <span className="text-sm font-mono text-green">
            {item.tool_call_type}
          </span>
          <StatusBadge status={item.status} />
        </div>
        <time className="text-xs text-grith-muted">
          {new Date(item.created_at).toLocaleString()}
        </time>
      </div>

      {/* Arguments */}
      <p className="text-sm text-grith-text font-mono bg-white rounded-lg px-3 py-2 mb-3 break-all">
        {item.arguments_summary}
      </p>

      {/* Context */}
      {item.task_context && (
        <p className="text-xs text-grith-muted mb-3">
          <span className="text-grith-text">Context:</span> {item.task_context}
        </p>
      )}

      {/* Filter breakdown */}
      <div className="mb-4">
        <p className="text-xs text-grith-muted mb-1.5 uppercase tracking-wider">
          Filter breakdown
        </p>
        <FilterBreakdownList filters={item.filter_breakdown} />
      </div>

      {/* Actions */}
      <div className="flex gap-2">
        <button
          onClick={() => onApprove(item.id)}
          className="px-3 py-1.5 text-xs font-medium rounded-lg bg-status-allow-green/15 text-status-allow-green hover:bg-status-allow-green/25 transition-colors"
        >
          Approve
        </button>
        <button
          onClick={() => onDeny(item.id)}
          className="px-3 py-1.5 text-xs font-medium rounded-lg bg-status-deny-red/15 text-status-deny-red hover:bg-status-deny-red/25 transition-colors"
        >
          Deny
        </button>
        <button
          onClick={() => onLearn(item.id)}
          className="px-3 py-1.5 text-xs font-medium rounded-lg bg-green/15 text-green hover:bg-green/25 transition-colors"
        >
          Approve &amp; Learn
        </button>
        {isPending && !isEscalated && (
          <button
            onClick={() => onEscalate(item.id)}
            disabled={!canEscalate}
            title={canEscalate ? "Escalate for senior review" : "Upgrade to Pro for escalation"}
            className="px-3 py-1.5 text-xs font-medium rounded-lg bg-purple-500/15 text-purple-400 hover:bg-purple-500/25 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Escalate
          </button>
        )}
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
  const { items, pendingCount, escalatedCount, loading, error, approve, deny, learn, escalate, refresh } =
    useDigest();
  const [canEscalate, setCanEscalate] = useState(false);
  const { lastEvent } = useWebSocket();
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

  return (
    <div className="p-6 max-w-4xl">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-semibold text-grith-text">
            Digest
          </h1>
          {pendingCount > 0 && (
            <span className="inline-flex items-center justify-center min-w-[20px] h-5 px-1.5 text-xs font-medium rounded-full bg-status-queue-amber/20 text-status-queue-amber">
              {pendingCount}
            </span>
          )}
          {escalatedCount > 0 && (
            <span className="inline-flex items-center justify-center min-w-[20px] h-5 px-1.5 text-xs font-medium rounded-full bg-purple-500/20 text-purple-400">
              {escalatedCount} escalated
            </span>
          )}
        </div>
        <button
          onClick={() => void refresh()}
          disabled={loading}
          className="px-3 py-1.5 text-xs font-medium rounded-lg border border-grith-border text-grith-muted hover:text-grith-text hover:border-grith-border-hover transition-colors disabled:opacity-50"
        >
          {loading ? "Loading..." : "Refresh"}
        </button>
      </div>

      {error && (
        <div className="bg-status-deny-red/10 border border-status-deny-red/30 rounded-xl p-3 mb-6 text-sm text-status-deny-red">
          {error}
        </div>
      )}

      {!loading && items.length === 0 && (
        <div className="bg-white border border-grith-border rounded-xl p-8 text-center">
          <p className="text-grith-muted text-sm">
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
    </div>
  );
}
