import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { DashboardPage } from "../Dashboard";

const mockHealth = {
  status: "healthy",
  version: "0.1.0-test",
  uptime_seconds: 3661,
  subsystems: {
    proxy: { status: "ok", latency_ms: 1.2 },
    audit: { status: "ok", latency_ms: 0.5 },
    digest: { status: "ok" },
  },
};

const mockProxy = {
  auto_allow_threshold: 3.0,
  auto_deny_threshold: 8.0,
  total_evaluations: 1500,
  allow_count: 1200,
  queue_count: 250,
  deny_count: 50,
  cold_start_remaining: 0,
  filters: [
    {
      name: "path_match",
      phase: "static",
      enabled: true,
      is_ready: true,
      evaluation_count: 1500,
      avg_latency_ms: 0.05,
    },
    {
      name: "secret_scan",
      phase: "pattern",
      enabled: true,
      is_ready: true,
      evaluation_count: 1500,
      avg_latency_ms: 1.2,
    },
  ],
};

const mockExfil = {
  total_blocked: 0,
  total_queued: 0,
  total_redacted: 0,
  by_protocol: {},
  top_blocked_destinations: [],
};

function mockFetchSuccess() {
  global.fetch = vi.fn().mockImplementation((url: string) => {
    if (url.includes("/api/health")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockHealth),
      });
    }
    if (url.includes("/api/proxy/status")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockProxy),
      });
    }
    if (url.includes("/api/audit/exfil-stats")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockExfil),
      });
    }
    if (url.includes("/api/audit")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve({
            records: [
              ...Array.from({ length: 3 }, (_, i) => ({
                id: `allow-${i}`,
                timestamp: "2024-01-01T12:00:00Z",
                session_id: "sess-1",
                plugin_id: "p",
                tool_call_type: "FileRead",
                arguments_summary: "",
                arguments_hash: "",
                composite_score: 1,
                proxy_action: "allow",
                filter_results: [],
                execution_result: null,
                evaluation_time_ms: 0.1,
                task_context: null,
                source: "supervisor",
                supervised_tool: "grith",
              })),
              {
                id: "queue-0",
                timestamp: "2024-01-01T12:00:00Z",
                session_id: "sess-1",
                plugin_id: "p",
                tool_call_type: "ShellExec",
                arguments_summary: "",
                arguments_hash: "",
                composite_score: 5,
                proxy_action: "queue",
                filter_results: [],
                execution_result: null,
                evaluation_time_ms: 1,
                task_context: null,
                source: "supervisor",
                supervised_tool: "grith",
              },
              {
                id: "deny-0",
                timestamp: "2024-01-01T12:00:00Z",
                session_id: "sess-1",
                plugin_id: "p",
                tool_call_type: "ShellExec",
                arguments_summary: "",
                arguments_hash: "",
                composite_score: 9,
                proxy_action: "deny",
                filter_results: [],
                execution_result: null,
                evaluation_time_ms: 1,
                task_context: null,
                source: "supervisor",
                supervised_tool: "grith",
              },
            ],
            total: 5,
          }),
      });
    }
    return Promise.resolve({
      ok: true,
      status: 200,
      json: () => Promise.resolve(null),
    });
  });
}

describe("DashboardPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders health status and stats", async () => {
    mockFetchSuccess();
    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText("healthy")).toBeTruthy();
    });

    expect(screen.getAllByText("5").length).toBeGreaterThan(0);
    expect(screen.getByText("1h 1m")).toBeTruthy();
  });

  it("shows error on API failure", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("Network error"));
    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText(/daemon has stopped/)).toBeTruthy();
    });
  });

  it("renders decision distribution counts from audit records", async () => {
    mockFetchSuccess();
    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText(/Allow: 3/)).toBeTruthy();
    });

    expect(screen.getByText(/Queue: 1/)).toBeTruthy();
    expect(screen.getByText(/Deny: 1/)).toBeTruthy();
  });

  it("renders filter summary line", async () => {
    mockFetchSuccess();
    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText(/2 filters active/)).toBeTruthy();
    });
  });

  it("renders subsystem health indicators", async () => {
    mockFetchSuccess();
    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText("proxy")).toBeTruthy();
    });

    expect(screen.getByText("audit")).toBeTruthy();
    expect(screen.getByText("digest")).toBeTruthy();
  });

  it("renders sessions derived from audit records", async () => {
    mockFetchSuccess();
    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText("grith")).toBeTruthy(); // session name from supervised_tool
    });

    // Per-session stats (3 allow + 1 queue + 1 deny = 5 total)
    expect(screen.getAllByText("3").length).toBeGreaterThan(0);  // allowed
    expect(screen.getAllByText("1").length).toBeGreaterThan(0);  // queued / denied
  });
});
