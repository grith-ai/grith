import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { DashboardPage } from "../Dashboard";

// jsdom has no real <canvas>, so stub the card generator and assert wiring.
const shareSpy = vi.fn().mockResolvedValue("downloaded");
vi.mock("@/lib/shareCard", () => ({
  shareOrDownloadStats: (s: unknown) => shareSpy(s),
  // The hero's share menu pre-warms a link on open; give it a resolvable stub
  // so it doesn't hit the network in tests.
  createShareLink: vi.fn().mockResolvedValue("https://grith.ai/s/test123"),
  shareIntents: () => ({ x: "#", threads: "#", hn: "#" }),
}));

// The Live Decisions ticker opens a real WebSocket on mount, which jsdom
// cannot service — stub the hook so the dashboard renders without spawning
// background reconnect timers. The ticker falls back to audit records, which
// the fetch mock supplies.
vi.mock("@/hooks/useWebSocket", () => ({
  useWebSocket: () => ({
    connected: false,
    messages: [],
    lastEvent: null,
    liveFeedUnavailable: false,
  }),
}));

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
  filters: [
    {
      name: "path-match",
      phase: "static",
      enabled: true,
      is_ready: true,
      evaluation_count: 1500,
      avg_latency_ms: 0.05,
    },
    {
      name: "secret-scan",
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
    if (url.includes("/api/supervisor/sessions")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve({
            sessions: [
              {
                id: "sess-1",
                tool_name: "grith",
                root_pid: 1234,
                uptime_seconds: 10,
                last_activity_seconds: 0,
                stats: {
                  total_intercepted: 5,
                  total_allowed: 3,
                  total_queued: 1,
                  total_denied: 1,
                  total_filtered_noise: 0,
                },
              },
            ],
            total: 1,
          }),
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
    window.history.replaceState({}, "", "/");
  });

  it("renders the hero with live status and uptime", async () => {
    mockFetchSuccess();
    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText("Supervising live")).toBeTruthy();
    });

    // Brand + tagline in the hero.
    expect(screen.getAllByText("grith").length).toBeGreaterThan(0);
    expect(screen.getByText("Zero Trust for AI Agents")).toBeTruthy();
    // Uptime surfaced in the hero legend ("uptime 1h 1m").
    expect(screen.getByText(/1h 1m/)).toBeTruthy();
  });

  it("shows error on API failure", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("Network error"));
    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText(/daemon has stopped/)).toBeTruthy();
    });
  });

  it("renders the decision posture legend in the hero", async () => {
    mockFetchSuccess();
    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getAllByText("Allowed").length).toBeGreaterThan(0);
    });

    expect(screen.getAllByText("Queued").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Denied").length).toBeGreaterThan(0);
  });

  it("share menu downloads a stats card with aggregate numbers only", async () => {
    shareSpy.mockClear();
    mockFetchSuccess();
    render(<DashboardPage />);

    // Open the share menu, then choose the PNG download item.
    const btn = await screen.findByText("Share stats");
    fireEvent.click(btn);
    const dl = await screen.findByText("Download image (PNG)");
    fireEvent.click(dl);

    await waitFor(() => expect(shareSpy).toHaveBeenCalledTimes(1));
    const arg = shareSpy.mock.calls[0]?.[0] as Record<string, unknown>;
    // Only aggregate counts — no path, project, cwd, or session detail.
    expect(arg).toHaveProperty("totalEvals");
    expect(arg).toHaveProperty("allow");
    expect(arg).toHaveProperty("deny");
    expect(arg).not.toHaveProperty("cwd");
    expect(arg).not.toHaveProperty("project_name");
    // Confirms the success label swap.
    await waitFor(() => expect(screen.getByText("Saved PNG")).toBeTruthy());
  });

  it("opens the existing share menu from the CLI deep link", async () => {
    window.history.replaceState({}, "", "/?share=1");
    mockFetchSuccess();
    render(<DashboardPage />);

    expect(await screen.findByText("Post to X")).toBeTruthy();
    expect(screen.getByText("Post to Threads")).toBeTruthy();
    expect(screen.getByText("Submit to Hacker News")).toBeTruthy();
  });

  it("renders the filter pipeline with active count", async () => {
    mockFetchSuccess();
    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText("Filter Pipeline")).toBeTruthy();
    });

    // Phase labels from the pipeline viz.
    expect(screen.getByText("Static")).toBeTruthy();
    expect(screen.getByText("Pattern")).toBeTruthy();
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
