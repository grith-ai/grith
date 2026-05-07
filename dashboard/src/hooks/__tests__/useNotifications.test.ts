import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { useNotifications } from "../useNotifications";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    getNotificationChannels: vi.fn(),
    getNotificationStatus: vi.fn(),
    testNotification: vi.fn(),
  };
});

import {
  ApiError,
  getNotificationChannels,
  getNotificationStatus,
  testNotification,
} from "@/lib/api";

const mockChannels = {
  channels: [
    {
      id: "slack-1",
      display_name: "Slack",
      required_tier: "community" as const,
      supports_interactive: true,
      enabled: true,
      health: { connected: true, latency_ms: 42 },
    },
  ],
  total: 1,
};

const mockStatus = {
  recent_events: [
    {
      type: "sent" as const,
      item_id: "item-1",
      channel_id: "slack-1",
      timestamp: "2024-01-01T12:00:00Z",
    },
  ],
};

describe("useNotifications", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("fetches channels and events on mount", async () => {
    vi.mocked(getNotificationChannels).mockResolvedValue(mockChannels);
    vi.mocked(getNotificationStatus).mockResolvedValue(mockStatus);

    const { result } = renderHook(() => useNotifications());

    await waitFor(() => {
      expect(result.current.channels).toHaveLength(1);
    });

    expect(result.current.channels[0]?.display_name).toBe("Slack");
    expect(result.current.recentEvents).toHaveLength(1);
  });

  it("sets loading false after fetch", async () => {
    vi.mocked(getNotificationChannels).mockResolvedValue(mockChannels);
    vi.mocked(getNotificationStatus).mockResolvedValue(mockStatus);

    const { result } = renderHook(() => useNotifications());

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });
  });

  it("testChannel calls API", async () => {
    vi.mocked(getNotificationChannels).mockResolvedValue(mockChannels);
    vi.mocked(getNotificationStatus).mockResolvedValue(mockStatus);
    vi.mocked(testNotification).mockResolvedValue({
      status: "ok",
      channel: "slack-1",
    });

    const { result } = renderHook(() => useNotifications());

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    await act(async () => {
      await result.current.testChannel("slack-1");
    });

    expect(vi.mocked(testNotification)).toHaveBeenCalledWith("slack-1");
  });

  it("sets error on failure", async () => {
    vi.mocked(getNotificationChannels).mockRejectedValue(
      new Error("Network error"),
    );
    vi.mocked(getNotificationStatus).mockRejectedValue(
      new Error("Network error"),
    );

    const { result } = renderHook(() => useNotifications());

    await waitFor(() => {
      expect(result.current.error).toBe("Network error");
    });
  });

  it("sets featureGated on 403 FEATURE_GATED error", async () => {
    const gatedError = new ApiError(
      403,
      "Forbidden",
      JSON.stringify({
        error: "notification_channels requires a Pro subscription",
        code: "FEATURE_GATED",
        required_tier: "Pro",
      }),
    );
    vi.mocked(getNotificationChannels).mockRejectedValue(gatedError);
    vi.mocked(getNotificationStatus).mockRejectedValue(gatedError);

    const { result } = renderHook(() => useNotifications());

    await waitFor(() => {
      expect(result.current.featureGated).toBe(true);
    });

    expect(result.current.requiredTier).toBe("Pro");
    expect(result.current.error).toBeNull();
  });

  it("refresh re-fetches", async () => {
    vi.mocked(getNotificationChannels).mockResolvedValue(mockChannels);
    vi.mocked(getNotificationStatus).mockResolvedValue(mockStatus);

    const { result } = renderHook(() => useNotifications());

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    await act(async () => {
      await result.current.refresh();
    });

    // At least 2 calls: initial mount + manual refresh (interval may add more)
    expect(vi.mocked(getNotificationChannels).mock.calls.length).toBeGreaterThanOrEqual(2);
    expect(vi.mocked(getNotificationStatus).mock.calls.length).toBeGreaterThanOrEqual(2);
  });
});
