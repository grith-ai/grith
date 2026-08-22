import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { AnalyticsPage } from "../Analytics";

const freshness = {
  materialized_through_at: "2026-08-21T10:15:00.000000Z",
  materialized_through_sequence: 42,
  dirty_day_count: 0,
  rebuilding: false,
  gap_count: 0,
};

const mockFree = {
  protocol_version: 2,
  schema_version: 1,
  access: "free",
  window: {
    start_day: "2026-08-15",
    end_day: "2026-08-21",
    current_day_partial: true,
  },
  decisions: {
    total: 10,
    allow: 7,
    queue: 2,
    deny: 1,
    allow_rate_ppm: 700000,
    queue_rate_ppm: 200000,
    deny_rate_ppm: 100000,
  },
  chain_health: "healthy",
  latest_audit_record_at: "2026-08-21T10:15:00.000000Z",
  recent_queue_and_deny: [
    {
      event_id: "00000000-0000-4000-8000-000000000001",
      event_revision: 1,
      occurred_at: "2026-08-21T10:14:00.000000Z",
      event_type: "deny",
      initial_verdict: "deny",
      project: "grith",
      profile_id: "claude-code",
      supervised_tool: "claude",
      category: "network_egress",
      score_micros: 9_500_000,
      top_filter_ids: ["secret-scan", "egress-policy"],
    },
  ],
  freshness,
  pro_available: false,
};

const mockPro = {
  protocol_version: 2,
  schema_version: 1,
  access: "pro",
  generated_at: "2026-08-21T11:15:30.000000Z",
  windows: [
    { start_day: "2026-07-23", end_day: "2026-08-21", current_day_partial: true },
    { start_day: "2026-05-24", end_day: "2026-08-21", current_day_partial: true },
  ],
  usage_rows: [
    {
      bucket_start: "2026-08-21T10:00:00.000000Z",
      project: "grith",
      profile_id: "claude-code",
      config_hash: "a".repeat(64),
      supervised_tool: "claude",
      record_class: "decision",
      category: "file_read",
      verdict: "allow",
      score_bin_version: 1,
      score_bucket: 2,
      event_count: 40,
      score_sum_micros: 48_000_000,
      first_event_at: "2026-08-21T10:00:01.000000Z",
      last_event_at: "2026-08-21T10:59:59.000000Z",
    },
  ],
  filter_rows: [
    {
      day: "2026-08-21",
      project: "grith",
      profile_id: "claude-code",
      config_hash: "a".repeat(64),
      filter_set_version: 1,
      filter_id: "secret-scan",
      evaluated_events: 40,
      triggered_events: 4,
      denied_evaluated_events: 1,
      denied_positive_contributions: 1,
    },
  ],
  session_rows: [
    {
      day: "2026-08-21",
      session_id: "00000000-0000-4000-8000-000000000002",
      project: "grith",
      profile_id: "claude-code",
      config_hash: "a".repeat(64),
      supervised_tool: "claude",
      first_event_at: "2026-08-21T10:00:01.000000Z",
      last_event_at: "2026-08-21T10:59:59.000000Z",
      decision_count: 40,
      queue_count: 2,
      deny_count: 1,
      llm_calls: 3,
      prompt_tokens: 1200,
      completion_tokens: 400,
      cost_micros: 12_345,
    },
  ],
  llm_rows: [
    {
      day: "2026-08-21",
      project: "grith",
      provider: "anthropic",
      model: "claude-fable-5",
      currency: "USD",
      price_source: "catalog",
      pricing_version: "2026-08",
      calls: 3,
      prompt_tokens: 1200,
      completion_tokens: 400,
      cost_micros: 12_345,
    },
  ],
  destination_rows: [],
  security_events: [],
  freshness,
  export_formats: ["json", "csv"],
  export_max_days: 90,
  truncated: false,
};

function jsonResponse(body: unknown) {
  return Promise.resolve({
    ok: true,
    status: 200,
    json: () => Promise.resolve(body),
  });
}

function mockTier(paid: boolean) {
  return {
    tier: paid ? "Pro" : "Community",
    features: paid ? { usage_analytics: true } : {},
  };
}

function installFetch({ paid }: { paid: boolean }) {
  global.fetch = vi.fn().mockImplementation((url: string) => {
    if (url.includes("/api/analytics/v2/free")) {
      return jsonResponse({ ...mockFree, pro_available: paid });
    }
    if (url.includes("/api/analytics/v2/pro")) {
      return jsonResponse(mockPro);
    }
    if (url.includes("/api/tier")) {
      return jsonResponse(mockTier(paid));
    }
    return Promise.resolve({
      ok: false,
      status: 404,
      statusText: "Not Found",
      text: () => Promise.resolve(""),
    });
  });
}

describe("AnalyticsPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the explicit Free contract with a Pro affordance", async () => {
    installFetch({ paid: false });
    render(<AnalyticsPage />);

    await waitFor(() => {
      expect(screen.getByText("Decisions · 7 days")).toBeInTheDocument();
    });
    // Verdict split + rates come straight from the server contract.
    expect(screen.getByText("10")).toBeInTheDocument();
    expect(screen.getByText("70.0%")).toBeInTheDocument();
    // Recent deny event with its filters.
    expect(screen.getByText("denied")).toBeInTheDocument();
    expect(screen.getByText(/secret-scan/)).toBeInTheDocument();
    // The Free view never fetches or renders Pro rows — it upsells instead.
    expect(screen.getByText("Pro Analytics")).toBeInTheDocument();
    // "Filter Effectiveness" exists as a locked-card title too; the Pro-only
    // trend panel is the discriminator.
    expect(screen.queryByText("Decisions Over Time")).not.toBeInTheDocument();
    const fetchMock = global.fetch as ReturnType<typeof vi.fn>;
    const proCalls = fetchMock.mock.calls.filter((c) =>
      String(c[0]).includes("/analytics/v2/pro"),
    );
    expect(proCalls).toHaveLength(0);
  });

  it("renders Pro panels from precomputed rollups when entitled", async () => {
    installFetch({ paid: true });
    render(<AnalyticsPage />);

    await waitFor(() => {
      expect(screen.getByText("Filter Effectiveness")).toBeInTheDocument();
    });
    // Filter table with honest denominators: trigger 4/40, deny 1/1.
    expect(screen.getByText("secret-scan")).toBeInTheDocument();
    expect(screen.getByText("100.0%")).toBeInTheDocument();
    // USD from integer micros, in both the LLM table and the project cost.
    expect(screen.getByText("anthropic")).toBeInTheDocument();
    expect(screen.getAllByText("$0.0123")).toHaveLength(2);
    // Exact distinct session counting feeds both breakdown tables.
    expect(screen.getAllByText("1 session")).toHaveLength(2);
    // 30/90-day range toggle present.
    expect(screen.getByText("30 days")).toBeInTheDocument();
    expect(screen.getByText("90 days")).toBeInTheDocument();
  });

  it("shows the remediation message when the audit writer predates analytics", async () => {
    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes("/api/analytics/v2/free")) {
        return Promise.resolve({
          ok: false,
          status: 503,
          statusText: "Service Unavailable",
          text: () =>
            Promise.resolve(
              JSON.stringify({ code: "ANALYTICS_UNAVAILABLE", error: "n/a" }),
            ),
        });
      }
      if (url.includes("/api/tier")) {
        return jsonResponse(mockTier(false));
      }
      return Promise.resolve({
        ok: false,
        status: 404,
        statusText: "Not Found",
        text: () => Promise.resolve(""),
      });
    });
    render(<AnalyticsPage />);

    await waitFor(() => {
      expect(
        screen.getByText(/older grith version/),
      ).toBeInTheDocument();
    });
    expect(screen.getByText("grith daemon restart")).toBeInTheDocument();
  });
});
