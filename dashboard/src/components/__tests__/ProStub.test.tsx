import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { PolicyEditor, UsageAnalytics } from "../ProStub";

describe("ProStub", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("PolicyEditor shows badge when community tier", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          tier: "community",
          seats: 1,
          max_sessions: 1,
          features: { policy_editor: false, usage_analytics: false },
        }),
    });

    render(<PolicyEditor />);

    await waitFor(() => {
      expect(screen.getByText("Upgrade Required")).toBeTruthy();
    });
  });

  it("PolicyEditor hides badge when enterprise", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          tier: "enterprise",
          seats: 10,
          max_sessions: 50,
          features: { policy_editor: true, usage_analytics: true },
        }),
    });

    render(<PolicyEditor />);

    await waitFor(() => {
      // The Policy Editor heading should always be present
      expect(screen.getByText("Policy Editor")).toBeTruthy();
    });

    // The upgrade badge should NOT be present when feature is allowed
    expect(screen.queryByText("Upgrade Required")).toBeNull();
  });

  it("UsageAnalytics shows badge when community", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          tier: "community",
          seats: 1,
          max_sessions: 1,
          features: { policy_editor: false, usage_analytics: false },
        }),
    });

    render(<UsageAnalytics />);

    await waitFor(() => {
      expect(screen.getByText("Upgrade Required")).toBeTruthy();
    });
  });

  it("UsageAnalytics hides badge when pro", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          tier: "pro",
          seats: 5,
          max_sessions: 10,
          features: { policy_editor: false, usage_analytics: true },
        }),
    });

    render(<UsageAnalytics />);

    await waitFor(() => {
      expect(screen.getByText("Usage Analytics")).toBeTruthy();
    });

    // Since usage_analytics: true, the upgrade badge should not appear at all
    expect(screen.queryByText("Upgrade Required")).toBeNull();
    expect(screen.queryByText("Coming Soon")).toBeNull();
  });
});
