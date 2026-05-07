import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { SettingsPage } from "../Settings";

beforeEach(() => {
  vi.restoreAllMocks();
  // Mock fetch for both FilterConfig proxy/test and ProStub /api/tier
  global.fetch = vi.fn().mockImplementation((url: string) => {
    if (url.includes("/api/tier")) {
      return Promise.resolve({
        ok: true,
        json: () =>
          Promise.resolve({
            tier: "community",
            seats: 1,
            max_sessions: 1,
            features: {
              policy_editor: false,
              usage_analytics: false,
            },
          }),
      });
    }
    return Promise.resolve({
      ok: true,
      status: 200,
      json: () => Promise.resolve({}),
    });
  });
});

describe("SettingsPage", () => {
  it("renders FilterConfig component", async () => {
    render(<SettingsPage />);

    // FilterConfig includes a "Run Test" button
    await waitFor(() => {
      expect(screen.getByText("Run Test")).toBeTruthy();
    });
  });

  it("renders Pro Features section", async () => {
    render(<SettingsPage />);

    await waitFor(() => {
      expect(screen.getByText("Policy Editor")).toBeTruthy();
    });

    expect(screen.getByText("Usage Analytics")).toBeTruthy();
  });

  it("renders CLI config hint", async () => {
    render(<SettingsPage />);

    expect(screen.getByText("~/.config/grith/config.toml")).toBeTruthy();

    // Ensure async tier fetch/setState completes before test exits.
    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalled();
    });
  });
});
