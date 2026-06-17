import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { useDigest } from "../useDigest";
import type { DigestItem } from "@/types/api";

vi.mock("@/lib/api", () => ({
  getDigestItems: vi.fn(),
  approveDigest: vi.fn(),
  denyDigest: vi.fn(),
  learnDigest: vi.fn(),
  escalateDigest: vi.fn(),
}));

import {
  getDigestItems,
  approveDigest,
  denyDigest,
  escalateDigest,
} from "@/lib/api";

const mockItem: DigestItem = {
  id: "item-1",
  created_at: "2024-01-01T00:00:00Z",
  tool_call_type: "ShellExec",
  arguments_summary: "ls -la",
  composite_score: 5.0,
  severity: "high",
  filter_breakdown: [],
  task_context: null,
  plugin_id: "shell",
  status: "pending",
  reviewed_at: null,
  review_action: null,
  reviewer_notes: null,
  informational_only: false,
  escalated_at: null,
  escalated_by: null,
};

const mockListResponse = {
  items: [mockItem],
  total: 1,
  pending_count: 1,
  escalated_count: 0,
  limit: 50,
  offset: 0,
};

describe("useDigest", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("fetches items on mount", async () => {
    vi.mocked(getDigestItems).mockResolvedValue(mockListResponse);

    const { result } = renderHook(() => useDigest());

    await waitFor(() => {
      expect(result.current.items).toHaveLength(1);
    });

    expect(result.current.items[0]?.id).toBe("item-1");
    expect(result.current.pendingCount).toBe(1);
  });

  it("sets loading false after fetch", async () => {
    vi.mocked(getDigestItems).mockResolvedValue(mockListResponse);

    const { result } = renderHook(() => useDigest());

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });
  });

  it("approve removes item optimistically", async () => {
    vi.mocked(getDigestItems).mockResolvedValue(mockListResponse);
    // Make approveDigest hang so we can observe optimistic state
    vi.mocked(approveDigest).mockReturnValue(new Promise(() => {}));

    const { result } = renderHook(() => useDigest());

    await waitFor(() => {
      expect(result.current.items).toHaveLength(1);
    });

    act(() => {
      void result.current.approve("item-1");
    });

    // Item should be removed optimistically before API resolves
    expect(result.current.items).toHaveLength(0);
  });

  it("approve rolls back on API failure", async () => {
    vi.mocked(getDigestItems).mockResolvedValue(mockListResponse);
    vi.mocked(approveDigest).mockRejectedValue(new Error("API error"));

    const { result } = renderHook(() => useDigest());

    await waitFor(() => {
      expect(result.current.items).toHaveLength(1);
    });

    await act(async () => {
      await result.current.approve("item-1");
    });

    // Item should be rolled back
    expect(result.current.items).toHaveLength(1);
    expect(result.current.error).toBe("API error");
  });

  it("deny removes item optimistically", async () => {
    vi.mocked(getDigestItems).mockResolvedValue(mockListResponse);
    vi.mocked(denyDigest).mockReturnValue(new Promise(() => {}));

    const { result } = renderHook(() => useDigest());

    await waitFor(() => {
      expect(result.current.items).toHaveLength(1);
    });

    act(() => {
      void result.current.deny("item-1");
    });

    expect(result.current.items).toHaveLength(0);
  });

  it("escalate updates status in place", async () => {
    vi.mocked(getDigestItems).mockResolvedValue(mockListResponse);
    vi.mocked(escalateDigest).mockResolvedValue({ status: "ok", id: "item-1" });

    const { result } = renderHook(() => useDigest());

    await waitFor(() => {
      expect(result.current.items).toHaveLength(1);
    });

    await act(async () => {
      await result.current.escalate("item-1");
    });

    // Item stays in list but status changes
    expect(result.current.items).toHaveLength(1);
    expect(result.current.items[0]?.status).toBe("escalated");
  });

  it("escalate rolls back on failure", async () => {
    vi.mocked(getDigestItems).mockResolvedValue(mockListResponse);
    vi.mocked(escalateDigest).mockRejectedValue(new Error("API error"));

    const { result } = renderHook(() => useDigest());

    await waitFor(() => {
      expect(result.current.items).toHaveLength(1);
    });

    await act(async () => {
      await result.current.escalate("item-1");
    });

    // Status should revert to pending
    expect(result.current.items[0]?.status).toBe("pending");
  });

  it("approveMany approves every given item and clears the list", async () => {
    const items = ["a", "b", "c"].map((id) => ({ ...mockItem, id }));
    vi.mocked(getDigestItems).mockResolvedValue({
      ...mockListResponse,
      items,
      pending_count: 3,
    });
    vi.mocked(approveDigest).mockResolvedValue(mockItem);

    const { result } = renderHook(() => useDigest());
    await waitFor(() => expect(result.current.items).toHaveLength(3));
    // Ignore any calls from earlier tests (factory mocks aren't auto-cleared).
    vi.mocked(approveDigest).mockClear();

    await act(async () => {
      await result.current.approveMany(["a", "b", "c"]);
    });

    expect(approveDigest).toHaveBeenCalledTimes(3);
    expect(result.current.items).toHaveLength(0);
    expect(result.current.bulkBusy).toBe(false);
  });

  it("denyMany denies every given item", async () => {
    const items = ["a", "b"].map((id) => ({ ...mockItem, id }));
    vi.mocked(getDigestItems).mockResolvedValue({
      ...mockListResponse,
      items,
      pending_count: 2,
    });
    vi.mocked(denyDigest).mockResolvedValue(mockItem);

    const { result } = renderHook(() => useDigest());
    await waitFor(() => expect(result.current.items).toHaveLength(2));
    vi.mocked(denyDigest).mockClear();

    await act(async () => {
      await result.current.denyMany(["a", "b"]);
    });

    expect(denyDigest).toHaveBeenCalledTimes(2);
    expect(result.current.items).toHaveLength(0);
  });

  it("approveMany with no ids is a no-op", async () => {
    vi.mocked(getDigestItems).mockResolvedValue(mockListResponse);
    const { result } = renderHook(() => useDigest());
    await waitFor(() => expect(result.current.items).toHaveLength(1));
    vi.mocked(approveDigest).mockClear();

    await act(async () => {
      await result.current.approveMany([]);
    });

    expect(approveDigest).not.toHaveBeenCalled();
    expect(result.current.items).toHaveLength(1);
  });

  it("sets error on fetch failure", async () => {
    vi.mocked(getDigestItems).mockRejectedValue(new Error("Network error"));

    const { result } = renderHook(() => useDigest());

    await waitFor(() => {
      expect(result.current.error).toBe("Network error");
    });
  });

  it("refresh re-fetches", async () => {
    vi.mocked(getDigestItems).mockResolvedValue(mockListResponse);

    const { result } = renderHook(() => useDigest());

    await waitFor(() => {
      expect(result.current.items).toHaveLength(1);
    });

    vi.mocked(getDigestItems).mockResolvedValue({
      ...mockListResponse,
      items: [],
      pending_count: 0,
      limit: 50,
      offset: 0,
    });

    await act(async () => {
      await result.current.refresh();
    });

    expect(result.current.items).toHaveLength(0);
    // At least 2 calls: initial mount + manual refresh (interval may add more)
    expect(vi.mocked(getDigestItems).mock.calls.length).toBeGreaterThanOrEqual(2);
  });
});
