import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { NotificationSettingsPage } from "../NotificationSettings";
import type { UseNotificationsReturn } from "@/hooks/useNotifications";

const mockNotifications: UseNotificationsReturn = {
  channels: [],
  recentEvents: [],
  loading: false,
  error: null,
  featureGated: false,
  requiredTier: null,
  testChannel: vi.fn().mockResolvedValue({ status: "ok", channel: "test" }),
  refresh: vi.fn().mockResolvedValue(undefined),
};

vi.mock("@/hooks/useNotifications", () => ({
  useNotifications: () => mockNotifications,
}));

const mockChannel = {
  id: "slack-1",
  display_name: "Slack",
  required_tier: "community" as const,
  supports_interactive: true,
  enabled: true,
  health: {
    connected: true,
    latency_ms: 42,
  },
};

const mockDisabledChannel = {
  id: "teams-1",
  display_name: "Teams",
  required_tier: "enterprise" as const,
  supports_interactive: false,
  enabled: false,
  health: null,
};

describe("NotificationSettingsPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mockNotifications.channels = [];
    mockNotifications.recentEvents = [];
    mockNotifications.loading = false;
    mockNotifications.error = null;
    mockNotifications.featureGated = false;
    mockNotifications.requiredTier = null;
    mockNotifications.testChannel = vi.fn().mockResolvedValue({ status: "ok", channel: "test" });
    mockNotifications.refresh = vi.fn().mockResolvedValue(undefined);
  });

  it("renders channel cards with names and tiers", () => {
    mockNotifications.channels = [mockChannel, mockDisabledChannel];

    render(<NotificationSettingsPage />);

    expect(screen.getByText("Slack")).toBeTruthy();
    expect(screen.getByText("Teams")).toBeTruthy();
    expect(screen.getByText("community")).toBeTruthy();
    expect(screen.getByText("enterprise")).toBeTruthy();
  });

  it("shows enabled count badge", () => {
    mockNotifications.channels = [mockChannel, mockDisabledChannel];

    render(<NotificationSettingsPage />);

    expect(screen.getByText("1 enabled")).toBeTruthy();
  });

  it("shows empty state", () => {
    mockNotifications.channels = [];

    render(<NotificationSettingsPage />);

    expect(
      screen.getByText("No notification channels configured."),
    ).toBeTruthy();
  });

  it("test button calls handler", () => {
    mockNotifications.channels = [mockChannel];

    render(<NotificationSettingsPage />);

    const testBtn = screen.getByText("Test");
    fireEvent.click(testBtn);

    expect(mockNotifications.testChannel).toHaveBeenCalledWith("slack-1");
  });

  it("test button disabled for disabled channels", () => {
    mockNotifications.channels = [mockDisabledChannel];

    render(<NotificationSettingsPage />);

    const testBtn = screen.getByText("Test");
    expect(testBtn).toHaveAttribute("disabled");
  });

  it("renders recent events", () => {
    mockNotifications.channels = [mockChannel];
    mockNotifications.recentEvents = [
      {
        type: "sent",
        item_id: "12345678-abcd",
        channel_id: "slack-1",
        timestamp: "2024-01-01T12:00:00Z",
      },
      {
        type: "failed",
        item_id: "87654321-dcba",
        channel_id: "teams-1",
        error: "Connection refused",
        timestamp: "2024-01-01T12:01:00Z",
      },
    ];

    render(<NotificationSettingsPage />);

    expect(screen.getByText("slack-1")).toBeTruthy();
    expect(screen.getByText("teams-1")).toBeTruthy();
    expect(screen.getByText("12345678")).toBeTruthy();
  });

  it("shows connected health indicator", () => {
    mockNotifications.channels = [mockChannel];

    render(<NotificationSettingsPage />);

    expect(screen.getByText("Connected")).toBeTruthy();
    expect(screen.getByText("42ms")).toBeTruthy();
  });

  it("refresh button calls refresh", () => {
    render(<NotificationSettingsPage />);

    const refreshBtn = screen.getByText("Refresh");
    fireEvent.click(refreshBtn);

    expect(mockNotifications.refresh).toHaveBeenCalled();
  });

  it("shows upgrade prompt when feature-gated", () => {
    mockNotifications.featureGated = true;
    mockNotifications.requiredTier = "Pro";

    render(<NotificationSettingsPage />);

    expect(screen.getByText("Pro Feature")).toBeTruthy();
    expect(screen.getByText("Upgrade to Pro")).toBeTruthy();
    expect(screen.getByText("grith pro upgrade")).toBeTruthy();
    // Should NOT show the error banner or channel grid
    expect(screen.queryByText("Refresh")).toBeNull();
  });
});
