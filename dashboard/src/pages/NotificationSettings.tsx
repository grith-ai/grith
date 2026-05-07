import { useState } from "react";
import { useNotifications } from "@/hooks/useNotifications";
import type { ChannelInfo, NotificationEvent } from "@/types/api";

// ---------------------------------------------------------------------------
// Tier badge
// ---------------------------------------------------------------------------

function TierBadge({ tier }: { tier: ChannelInfo["required_tier"] }) {
  const styles: Record<string, string> = {
    community: "bg-status-allow-green/10 text-status-allow-green",
    pro: "bg-green/10 text-green",
    enterprise: "bg-purple-500/15 text-purple-400",
  };

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-lg text-xs font-medium capitalize ${styles[tier]}`}
    >
      {tier}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Health indicator
// ---------------------------------------------------------------------------

function HealthDot({ health }: { health: ChannelInfo["health"] }) {
  if (!health) {
    return (
      <span className="flex items-center gap-1.5 text-xs text-grith-muted">
        <span className="w-2 h-2 rounded-full bg-grith-muted/40" />
        No data
      </span>
    );
  }

  if (health.connected) {
    return (
      <span className="flex items-center gap-1.5 text-xs text-status-allow-green">
        <span className="w-2 h-2 rounded-full bg-status-allow-green" />
        Connected
        {health.latency_ms !== undefined && (
          <span className="text-grith-muted font-mono">
            {health.latency_ms}ms
          </span>
        )}
      </span>
    );
  }

  return (
    <span className="flex items-center gap-1.5 text-xs text-status-deny-red">
      <span className="w-2 h-2 rounded-full bg-status-deny-red" />
      Disconnected
      {health.error && (
        <span className="text-grith-muted truncate max-w-[160px]" title={health.error}>
          {health.error}
        </span>
      )}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Channel card
// ---------------------------------------------------------------------------

function ChannelCard({
  channel,
  onTest,
}: {
  channel: ChannelInfo;
  onTest: (id: string) => void;
}) {
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      onTest(channel.id);
      setTestResult("sent");
    } catch {
      setTestResult("failed");
    } finally {
      setTesting(false);
      // Clear the result badge after 3 seconds
      setTimeout(() => setTestResult(null), 3000);
    }
  };

  return (
    <div className="bg-white border border-grith-border rounded-xl p-4">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm font-medium text-grith-text">
            {channel.display_name}
          </span>
          <TierBadge tier={channel.required_tier} />
          {channel.supports_interactive && (
            <span className="inline-flex items-center px-2 py-0.5 rounded-lg text-xs font-medium bg-blue-500/10 text-blue-400">
              Interactive
            </span>
          )}
        </div>
        <span
          className={`inline-flex items-center px-2 py-0.5 rounded-lg text-xs font-medium ${
            channel.enabled
              ? "bg-status-allow-green/10 text-status-allow-green"
              : "bg-white text-grith-muted"
          }`}
        >
          {channel.enabled ? "Enabled" : "Disabled"}
        </span>
      </div>

      <div className="flex items-center justify-between">
        <HealthDot health={channel.health} />

        <div className="flex items-center gap-2">
          {testResult && (
            <span
              className={`text-xs font-medium ${
                testResult === "sent"
                  ? "text-status-allow-green"
                  : "text-status-deny-red"
              }`}
            >
              {testResult === "sent" ? "Sent" : "Failed"}
            </span>
          )}
          <button
            onClick={() => void handleTest()}
            disabled={testing || !channel.enabled}
            className="px-3 py-1.5 text-xs font-medium rounded-lg border border-grith-border text-grith-muted hover:text-grith-text hover:border-grith-border-hover transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {testing ? "Sending..." : "Test"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Event row
// ---------------------------------------------------------------------------

function EventRow({ event }: { event: NotificationEvent }) {
  const time = new Date(event.timestamp).toLocaleString();

  switch (event.type) {
    case "sent":
      return (
        <div className="flex items-center gap-3 py-2 border-b border-grith-border last:border-b-0">
          <span className="w-2 h-2 rounded-full bg-status-allow-green flex-shrink-0" />
          <span className="text-xs text-grith-muted font-mono w-40 flex-shrink-0">
            {time}
          </span>
          <span className="text-xs text-grith-text">
            Sent to{" "}
            <span className="font-mono text-green">
              {event.channel_id}
            </span>
          </span>
          <span className="text-xs text-grith-muted font-mono ml-auto">
            {event.item_id.slice(0, 8)}
          </span>
        </div>
      );
    case "failed":
      return (
        <div className="flex items-center gap-3 py-2 border-b border-grith-border last:border-b-0">
          <span className="w-2 h-2 rounded-full bg-status-deny-red flex-shrink-0" />
          <span className="text-xs text-grith-muted font-mono w-40 flex-shrink-0">
            {time}
          </span>
          <span className="text-xs text-grith-text">
            Failed on{" "}
            <span className="font-mono text-green">
              {event.channel_id}
            </span>
            <span className="text-status-deny-red ml-2">{event.error}</span>
          </span>
          <span className="text-xs text-grith-muted font-mono ml-auto">
            {event.item_id.slice(0, 8)}
          </span>
        </div>
      );
    case "interactive_response":
      return (
        <div className="flex items-center gap-3 py-2 border-b border-grith-border last:border-b-0">
          <span className="w-2 h-2 rounded-full bg-blue-400 flex-shrink-0" />
          <span className="text-xs text-grith-muted font-mono w-40 flex-shrink-0">
            {time}
          </span>
          <span className="text-xs text-grith-text">
            <span className="text-blue-400">{event.reviewer}</span>{" "}
            responded{" "}
            <span className="font-mono text-green">{event.action}</span>{" "}
            on{" "}
            <span className="font-mono text-green">
              {event.channel_id}
            </span>
          </span>
          <span className="text-xs text-grith-muted font-mono ml-auto">
            {event.item_id.slice(0, 8)}
          </span>
        </div>
      );
  }
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function NotificationSettingsPage() {
  const {
    channels,
    recentEvents,
    loading,
    error,
    featureGated,
    requiredTier,
    testChannel,
    refresh,
  } = useNotifications();

  const enabledCount = channels.filter((c) => c.enabled).length;
  const displayedEvents = recentEvents.slice(0, 20);

  // Feature-gated — show upgrade prompt instead of error banner
  if (featureGated) {
    return (
      <div className="p-6 max-w-4xl">
        <h1 className="text-xl font-semibold text-grith-text mb-6">
          Notifications
        </h1>
        <div className="bg-white border border-grith-border rounded-xl p-8 text-center">
          <div className="mb-4">
            <span className="inline-flex items-center px-2.5 py-1 rounded-lg text-xs font-semibold bg-green/10 text-green uppercase tracking-wider">
              {requiredTier} Feature
            </span>
          </div>
          <p className="text-grith-text mb-2">
            Multi-channel notifications require a{" "}
            <span className="font-semibold text-grith-text">
              {requiredTier}
            </span>{" "}
            subscription.
          </p>
          <p className="text-sm text-grith-muted mb-6">
            Get Slack, email, Telegram, Discord, PagerDuty, and webhook
            notifications for digest events and security alerts.
          </p>
          <div className="flex items-center justify-center gap-3">
            <a
              href="https://grith.ai/pricing"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-green text-white text-sm font-medium hover:bg-green-dark transition-colors"
            >
              Upgrade to {requiredTier}
              <svg
                className="w-3.5 h-3.5"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M13.5 6H5.25A2.25 2.25 0 0 0 3 8.25v10.5A2.25 2.25 0 0 0 5.25 21h10.5A2.25 2.25 0 0 0 18 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25"
                />
              </svg>
            </a>
          </div>
          <p className="text-xs text-grith-muted mt-4">
            Or run{" "}
            <code className="font-mono text-green">
              grith pro upgrade
            </code>{" "}
            from the CLI.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-4xl">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-semibold text-grith-text">
            Notifications
          </h1>
          <span className="inline-flex items-center justify-center min-w-[20px] h-5 px-1.5 text-xs font-medium rounded-full bg-green/20 text-green">
            {enabledCount} enabled
          </span>
        </div>
        <button
          onClick={() => void refresh()}
          disabled={loading}
          className="px-3 py-1.5 text-xs font-medium rounded-lg border border-grith-border text-grith-muted hover:text-grith-text hover:border-grith-border-hover transition-colors disabled:opacity-50"
        >
          {loading ? "Loading..." : "Refresh"}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-status-deny-red/10 border border-status-deny-red/30 rounded-xl p-3 mb-6 text-sm text-status-deny-red">
          {error}
        </div>
      )}

      {/* Channel grid */}
      {!loading && channels.length === 0 && (
        <div className="bg-white border border-grith-border rounded-xl p-8 text-center mb-8">
          <p className="text-grith-muted text-sm">
            No notification channels configured.
          </p>
        </div>
      )}

      {channels.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-8">
          {channels.map((channel) => (
            <ChannelCard
              key={channel.id}
              channel={channel}
              onTest={(id) => void testChannel(id)}
            />
          ))}
        </div>
      )}

      {/* Recent events */}
      <div>
        <h2 className="text-sm font-semibold text-grith-text mb-3 uppercase tracking-wider">
          Recent Events
        </h2>
        {displayedEvents.length === 0 ? (
          <div className="bg-white border border-grith-border rounded-xl p-6 text-center">
            <p className="text-grith-muted text-sm">
              No recent notification events.
            </p>
          </div>
        ) : (
          <div className="bg-white border border-grith-border rounded-xl px-4 py-2">
            {displayedEvents.map((event, i) => (
              <EventRow key={`${event.item_id}-${event.timestamp}-${i}`} event={event} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
