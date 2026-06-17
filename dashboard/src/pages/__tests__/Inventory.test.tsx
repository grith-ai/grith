import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { InventoryPage } from "../Inventory";

vi.mock("@/lib/api", () => ({
  getInventory: vi.fn(),
  // InventoryPage renders <SessionHeader>, which calls getSessions(). Provide
  // a plain resolver (not a vi.fn() — beforeEach's restoreAllMocks would reset
  // it to return undefined and SessionHeader would throw).
  getSessions: () => Promise.resolve({ sessions: [] }),
}));

import { getInventory } from "@/lib/api";

const SESSION_ID = "11111111-2222-3333-4444-555555555555";

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <InventoryPage />
    </MemoryRouter>,
  );
}

describe("InventoryPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the session picker when no session_id is in the URL", async () => {
    renderAt("/inventory");
    // With no session_id the page renders <SessionPicker>; getSessions is
    // mocked to resolve with no sessions, so its empty-state hint appears.
    expect(
      await screen.findByText(/Trusted binaries are pinned/i),
    ).toBeInTheDocument();
  });

  it("renders the inventory table with entries", async () => {
    vi.mocked(getInventory).mockResolvedValue({
      session_id: SESSION_ID,
      binaries_pinned: 2,
      total_scanned: 5,
      truncated: false,
      entries: [
        { path: "/usr/bin/aaa", sha256: "aa".repeat(32) },
        { path: "/usr/bin/zsh", sha256: "bb".repeat(32) },
      ],
    });

    renderAt(`/inventory?session_id=${SESSION_ID}`);

    await waitFor(() => {
      expect(screen.getByText("/usr/bin/aaa")).toBeInTheDocument();
      expect(screen.getByText("/usr/bin/zsh")).toBeInTheDocument();
    });

    // Summary cards.
    expect(screen.getByText("2")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
    expect(screen.getByText("Complete")).toBeInTheDocument();
  });

  it("flags truncation prominently when the walk hit the cap", async () => {
    vi.mocked(getInventory).mockResolvedValue({
      session_id: SESSION_ID,
      binaries_pinned: 5000,
      total_scanned: 5000,
      truncated: true,
      entries: [],
    });

    renderAt(`/inventory?session_id=${SESSION_ID}`);

    await waitFor(() => {
      expect(screen.getByText("Truncated")).toBeInTheDocument();
      expect(screen.getByText(/Walk hit the file cap/i)).toBeInTheDocument();
    });
  });

  it("filters entries by path substring", async () => {
    vi.mocked(getInventory).mockResolvedValue({
      session_id: SESSION_ID,
      binaries_pinned: 2,
      total_scanned: 2,
      truncated: false,
      entries: [
        { path: "/usr/bin/curl", sha256: "11".repeat(32) },
        { path: "/usr/bin/git", sha256: "22".repeat(32) },
      ],
    });

    renderAt(`/inventory?session_id=${SESSION_ID}`);

    await waitFor(() => {
      expect(screen.getByText("/usr/bin/curl")).toBeInTheDocument();
    });

    const input = screen.getByPlaceholderText(/Filter by path or SHA-256/i);
    fireEvent.change(input, { target: { value: "curl" } });

    await waitFor(() => {
      expect(screen.queryByText("/usr/bin/git")).not.toBeInTheDocument();
      expect(screen.getByText("/usr/bin/curl")).toBeInTheDocument();
    });
  });

  it("shows an empty-state message when no binaries are pinned", async () => {
    vi.mocked(getInventory).mockResolvedValue({
      session_id: SESSION_ID,
      binaries_pinned: 0,
      total_scanned: 0,
      truncated: false,
      entries: [],
    });

    renderAt(`/inventory?session_id=${SESSION_ID}`);

    await waitFor(() => {
      expect(screen.getByText(/No binaries pinned yet/i)).toBeInTheDocument();
    });
  });

  it("shows an error message when the fetch fails", async () => {
    vi.mocked(getInventory).mockRejectedValue(new Error("boom"));

    renderAt(`/inventory?session_id=${SESSION_ID}`);

    await waitFor(() => {
      expect(screen.getByText("boom")).toBeInTheDocument();
    });
  });
});
