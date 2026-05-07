import { useCallback, useEffect, useRef, useState } from "react";
import type { ChannelInfo, NotificationEvent } from "@/types/api";
import {
  ApiError,
  getNotificationChannels,
  getNotificationStatus,
  testNotification,
} from "@/lib/api";

/** Auto-refresh interval in milliseconds. */
const REFRESH_INTERVAL = 30_000;

export interface UseNotificationsReturn {
  /** List of notification channels. */
  channels: ChannelInfo[];
  /** Recent notification events. */
  recentEvents: NotificationEvent[];
  /** Whether the initial load or a refresh is in progress. */
  loading: boolean;
  /** Most recent error, or null. */
  error: string | null;
  /** True when the notification feature is gated behind a paid tier. */
  featureGated: boolean;
  /** The tier required to access notifications (e.g. "Pro"), if gated. */
  requiredTier: string | null;
  /** Send a test notification on the given channel. Returns the result status. */
  testChannel: (id: string) => Promise<{ status: string; channel: string }>;
  /** Manually trigger a refresh. */
  refresh: () => Promise<void>;
}

/**
 * Hook for managing notification channel settings.
 *
 * Fetches channels and recent events on mount and auto-refreshes every
 * 30 seconds.
 */
export function useNotifications(): UseNotificationsReturn {
  const [channels, setChannels] = useState<ChannelInfo[]>([]);
  const [recentEvents, setRecentEvents] = useState<NotificationEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [featureGated, setFeatureGated] = useState(false);
  const [requiredTier, setRequiredTier] = useState<string | null>(null);
  const mountedRef = useRef(true);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const [channelsRes, statusRes] = await Promise.all([
        getNotificationChannels(),
        getNotificationStatus(),
      ]);
      if (!mountedRef.current) return;
      setChannels(channelsRes.channels);
      setRecentEvents(statusRes.recent_events);
      setError(null);
      setFeatureGated(false);
      setRequiredTier(null);
    } catch (err) {
      if (!mountedRef.current) return;
      if (err instanceof ApiError && err.isFeatureGated) {
        setFeatureGated(true);
        setRequiredTier(err.requiredTier ?? "Pro");
        setError(null);
      } else {
        setError(
          err instanceof Error ? err.message : "Failed to fetch notifications",
        );
      }
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, []);

  const testChannel = useCallback(
    async (id: string): Promise<{ status: string; channel: string }> => {
      return testNotification(id);
    },
    [],
  );

  useEffect(() => {
    mountedRef.current = true;
    void fetchData();

    intervalRef.current = setInterval(() => {
      void fetchData();
    }, REFRESH_INTERVAL);

    return () => {
      mountedRef.current = false;
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [fetchData]);

  return {
    channels,
    recentEvents,
    loading,
    error,
    featureGated,
    requiredTier,
    testChannel,
    refresh: fetchData,
  };
}
