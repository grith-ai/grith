import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { PolicyEditor, UsageAnalytics } from "../ProStub";

/**
 * Route the mocked fetch by URL path. A single mockResolvedValue previously
 * answered EVERY request with the license object, so when a feature gate
 * passed (pro/enterprise) the gated content's own fetch (analytics summary,
 * policy list) resolved to the wrong shape and crashed the render - usually
 * after the test had already finished, surfacing as a flaky unhandled error
 * in CI. Unmatched paths reject, which the components handle via their
 * error states.
 */
function mockFetchRoutes(routes: Record<string, unknown>) {
  global.fetch = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    const match = Object.entries(routes).find(([path]) => url.includes(path));
    if (!match) {
      return Promise.reject(new Error(`unmocked fetch: ${url}`));
    }
    return Promise.resolve({
      ok: true,
      json: () => Promise.resolve(match[1]),
    } as Response);
  }) as unknown as typeof fetch;
}

function tierResponse(
  tier: string,
  features: { policy_editor: boolean; usage_analytics: boolean },
) {
  return {
    tier,
    seats: tier === "community" ? 1 : 10,
    max_sessions: tier === "community" ? 1 : 50,
    features,
  };
}

// The explicit Free contract served by /api/analytics/v2/free — the gated
// content reads the precomputed projection, never a raw-table summary.
const EMPTY_FREE_ANALYTICS = {
  protocol_version: 2,
  schema_version: 1,
  access: "free",
  window: { start_day: "2026-08-15", end_day: "2026-08-21", current_day_partial: true },
  decisions: {
    total: 0,
    allow: 0,
    queue: 0,
    deny: 0,
    allow_rate_ppm: 0,
    queue_rate_ppm: 0,
    deny_rate_ppm: 0,
  },
  chain_health: "healthy",
  recent_queue_and_deny: [],
  freshness: {
    materialized_through_sequence: 0,
    dirty_day_count: 0,
    rebuilding: false,
    gap_count: 0,
  },
  pro_available: true,
};

describe("ProStub", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("PolicyEditor shows badge when community tier", async () => {
    mockFetchRoutes({
      "/api/tier": tierResponse("community", {
        policy_editor: false,
        usage_analytics: false,
      }),
    });

    render(<PolicyEditor />);

    await waitFor(() => {
      expect(screen.getByText("Upgrade Required")).toBeTruthy();
    });
  });

  it("PolicyEditor hides badge when enterprise", async () => {
    mockFetchRoutes({
      "/api/tier": tierResponse("enterprise", {
        policy_editor: true,
        usage_analytics: true,
      }),
      "/api/policies": { policies: [], total: 0 },
    });

    render(<PolicyEditor />);

    await waitFor(() => {
      // The Policy Editor heading should always be present
      expect(screen.getByText("Policy Editor")).toBeTruthy();
    });

    // The upgrade badge should NOT be present when feature is allowed
    expect(screen.queryByText("Upgrade Required")).toBeNull();

    // The gated content's own fetch resolves with a real policy list - wait
    // for it to render so no in-flight promise outlives the test.
    await waitFor(() => {
      expect(screen.getByText("+ New Policy")).toBeTruthy();
    });
  });

  it("UsageAnalytics shows badge when community", async () => {
    mockFetchRoutes({
      "/api/tier": tierResponse("community", {
        policy_editor: false,
        usage_analytics: false,
      }),
    });

    render(
      <MemoryRouter>
        <UsageAnalytics />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByText("Upgrade Required")).toBeTruthy();
    });
  });

  it("UsageAnalytics hides badge when pro", async () => {
    mockFetchRoutes({
      "/api/tier": tierResponse("pro", {
        policy_editor: false,
        usage_analytics: true,
      }),
      "/api/analytics/v2/free": EMPTY_FREE_ANALYTICS,
    });

    render(
      <MemoryRouter>
        <UsageAnalytics />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByText("Usage Analytics")).toBeTruthy();
    });

    // Since usage_analytics: true, the upgrade badge should not appear at all
    expect(screen.queryByText("Upgrade Required")).toBeNull();
    expect(screen.queryByText("Coming Soon")).toBeNull();

    // The gated content's own fetch resolves with the Free contract shape -
    // wait for it to render so no in-flight promise outlives the test.
    await waitFor(() => {
      expect(screen.getByText("Decisions \u00b7 7 days")).toBeTruthy();
    });
  });
});
