import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { DigestPage } from "../Digest";
import type { UseDigestReturn } from "@/hooks/useDigest";

// Mock the hooks and API calls
const mockDigestReturn: UseDigestReturn = {
  items: [],
  pendingCount: 0,
  escalatedCount: 0,
  loading: false,
  error: null,
  approve: vi.fn().mockResolvedValue(undefined),
  deny: vi.fn().mockResolvedValue(undefined),
  learn: vi.fn().mockResolvedValue(undefined),
  escalate: vi.fn().mockResolvedValue(undefined),
  refresh: vi.fn().mockResolvedValue(undefined),
};

vi.mock("@/hooks/useDigest", () => ({
  useDigest: () => mockDigestReturn,
}));

vi.mock("@/hooks/useWebSocket", () => ({
  useWebSocket: () => ({
    connected: true,
    messages: [],
    lastEvent: null,
  }),
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual("@/lib/api");
  return {
    ...actual,
    getTier: vi.fn().mockResolvedValue({ tier: "community", features: { escalation: false } }),
  };
});

const mockItem = {
  id: "item-1",
  created_at: "2024-01-01T00:00:00Z",
  tool_call_type: "ShellExec",
  arguments_summary: "ls -la /home/user",
  composite_score: 5.5,
  severity: "high" as const,
  filter_breakdown: [
    {
      filter_name: "command",
      score: 3.0,
      rule_id: "test-rule",
      message: "Suspicious command",
    },
    {
      filter_name: "path_match",
      score: 2.5,
      rule_id: "env-file",
      message: "Access to env file",
    },
  ],
  task_context: "test context",
  plugin_id: "shell",
  status: "pending" as const,
  reviewed_at: null,
  review_action: null,
  reviewer_notes: null,
  informational_only: false,
  escalated_at: null,
  escalated_by: null,
};

describe("DigestPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    // Reset mock state
    mockDigestReturn.items = [];
    mockDigestReturn.pendingCount = 0;
    mockDigestReturn.escalatedCount = 0;
    mockDigestReturn.loading = false;
    mockDigestReturn.error = null;
    mockDigestReturn.approve = vi.fn().mockResolvedValue(undefined);
    mockDigestReturn.deny = vi.fn().mockResolvedValue(undefined);
    mockDigestReturn.learn = vi.fn().mockResolvedValue(undefined);
    mockDigestReturn.escalate = vi.fn().mockResolvedValue(undefined);
    mockDigestReturn.refresh = vi.fn().mockResolvedValue(undefined);
  });

  it("renders items with score badges and tool type", () => {
    mockDigestReturn.items = [mockItem];
    mockDigestReturn.pendingCount = 1;

    render(<DigestPage />);

    expect(screen.getByText("5.5")).toBeTruthy();
    expect(screen.getByText("ShellExec")).toBeTruthy();
  });

  it("renders empty state when no items", () => {
    mockDigestReturn.items = [];

    render(<DigestPage />);

    expect(screen.getByText(/No pending digest items/)).toBeTruthy();
  });

  it("shows loading state", () => {
    mockDigestReturn.loading = true;

    render(<DigestPage />);

    expect(screen.getByText("Loading...")).toBeTruthy();
  });

  it("shows pending and escalated count badges", () => {
    mockDigestReturn.items = [mockItem];
    mockDigestReturn.pendingCount = 3;
    mockDigestReturn.escalatedCount = 2;

    render(<DigestPage />);

    expect(screen.getByText("3")).toBeTruthy();
    expect(screen.getByText("2 escalated")).toBeTruthy();
  });

  it("approve button calls handler", () => {
    mockDigestReturn.items = [mockItem];

    render(<DigestPage />);

    const approveBtn = screen.getByText("Approve");
    fireEvent.click(approveBtn);

    expect(mockDigestReturn.approve).toHaveBeenCalledWith("item-1");
  });

  it("deny button calls handler", () => {
    mockDigestReturn.items = [mockItem];

    render(<DigestPage />);

    const denyBtn = screen.getByText("Deny");
    fireEvent.click(denyBtn);

    expect(mockDigestReturn.deny).toHaveBeenCalledWith("item-1");
  });

  it("learn button calls handler", () => {
    mockDigestReturn.items = [mockItem];

    render(<DigestPage />);

    // The button text in the component uses &amp; which renders as &
    const learnBtn = screen.getByText("Approve & Learn");
    fireEvent.click(learnBtn);

    expect(mockDigestReturn.learn).toHaveBeenCalledWith("item-1");
  });

  it("escalate button disabled when tier lacks feature", () => {
    mockDigestReturn.items = [mockItem];

    render(<DigestPage />);

    const escalateBtn = screen.getByText("Escalate");
    expect(escalateBtn).toHaveAttribute("disabled");
  });

  it("renders filter breakdown for matched filters", () => {
    mockDigestReturn.items = [mockItem];

    render(<DigestPage />);

    expect(screen.getByText("Suspicious command")).toBeTruthy();
    expect(screen.getByText("(command)")).toBeTruthy();
    expect(screen.getByText("+3.0")).toBeTruthy();
    expect(screen.getByText("Access to env file")).toBeTruthy();
    expect(screen.getByText("(path_match)")).toBeTruthy();
  });

  it("shows error message", () => {
    mockDigestReturn.error = "Failed to fetch digest items";

    render(<DigestPage />);

    expect(screen.getByText("Failed to fetch digest items")).toBeTruthy();
  });
});
