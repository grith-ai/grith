import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ListenerRewritesPage } from "../ListenerRewrites";

vi.mock("@/lib/api", () => ({
  getListenerRewrites: vi.fn(),
  // ListenerRewritesPage renders <SessionHeader>, which calls getSessions().
  // Provide a plain resolver (not a vi.fn() — beforeEach's restoreAllMocks
  // would reset it to return undefined and SessionHeader would throw).
  getSessions: () => Promise.resolve({ sessions: [] }),
}));

import { getListenerRewrites } from "@/lib/api";

const SESSION_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <ListenerRewritesPage />
    </MemoryRouter>,
  );
}

describe("ListenerRewritesPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the session picker when no session_id is in the URL", async () => {
    renderAt("/listener-rewrites");
    // With no session_id the page renders <SessionPicker>; getSessions is
    // mocked to resolve with no sessions, so its empty-state hint appears.
    expect(
      await screen.findByText(/only clamps wildcard binds/i),
    ).toBeInTheDocument();
  });

  it("renders the rewrites table with rows", async () => {
    vi.mocked(getListenerRewrites).mockResolvedValue({
      session_id: SESSION_ID,
      total: 2,
      rewrites: [
        {
          id: "r1",
          timestamp: "2026-01-01T12:00:00Z",
          pid: 1234,
          tool: "codex",
          original_addr: "0.0.0.0:41234",
          rewritten_addr: "127.0.0.1:41234",
          clamp_profile_entry: "MCP local server",
        },
        {
          id: "r2",
          timestamp: "2026-01-01T12:01:00Z",
          pid: 1234,
          tool: "codex",
          original_addr: "[::]:9090",
          rewritten_addr: "[::1]:9090",
          clamp_profile_entry: "secondary server",
        },
      ],
    });

    renderAt(`/listener-rewrites?session_id=${SESSION_ID}`);

    await waitFor(() => {
      expect(screen.getByText("0.0.0.0:41234")).toBeInTheDocument();
      expect(screen.getByText("127.0.0.1:41234")).toBeInTheDocument();
      expect(screen.getByText("MCP local server")).toBeInTheDocument();
    });
  });

  it("filters by substring across original/rewritten/profile/tool", async () => {
    vi.mocked(getListenerRewrites).mockResolvedValue({
      session_id: SESSION_ID,
      total: 2,
      rewrites: [
        {
          id: "r1",
          timestamp: "2026-01-01T12:00:00Z",
          pid: 1234,
          tool: "codex",
          original_addr: "0.0.0.0:41234",
          rewritten_addr: "127.0.0.1:41234",
          clamp_profile_entry: "MCP local server",
        },
        {
          id: "r2",
          timestamp: "2026-01-01T12:01:00Z",
          pid: 5678,
          tool: "claude-code",
          original_addr: "[::]:9090",
          rewritten_addr: "[::1]:9090",
          clamp_profile_entry: "secondary",
        },
      ],
    });

    renderAt(`/listener-rewrites?session_id=${SESSION_ID}`);

    await waitFor(() => {
      expect(screen.getByText("MCP local server")).toBeInTheDocument();
    });

    const input = screen.getByPlaceholderText(/Filter by address/i);
    fireEvent.change(input, { target: { value: "claude" } });

    await waitFor(() => {
      expect(screen.queryByText("MCP local server")).not.toBeInTheDocument();
      expect(screen.getByText("secondary")).toBeInTheDocument();
    });
  });

  it("shows an empty-state when no rewrites exist", async () => {
    vi.mocked(getListenerRewrites).mockResolvedValue({
      session_id: SESSION_ID,
      total: 0,
      rewrites: [],
    });

    renderAt(`/listener-rewrites?session_id=${SESSION_ID}`);

    await waitFor(() => {
      expect(
        screen.getByText(/No listener rewrites for this session/i),
      ).toBeInTheDocument();
    });
  });

  it("shows an error message when the fetch fails", async () => {
    vi.mocked(getListenerRewrites).mockRejectedValue(new Error("api boom"));

    renderAt(`/listener-rewrites?session_id=${SESSION_ID}`);

    await waitFor(() => {
      expect(screen.getByText("api boom")).toBeInTheDocument();
    });
  });
});
