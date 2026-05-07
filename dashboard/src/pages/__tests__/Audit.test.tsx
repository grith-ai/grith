import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { AuditPage } from "../Audit";

vi.mock("@/lib/api", () => ({
  getAuditRecords: vi.fn(),
  exportAudit: vi.fn(),
}));

import { getAuditRecords, exportAudit } from "@/lib/api";

const mockRecords = [
  {
    id: "rec-1",
    timestamp: "2024-01-01T12:00:00Z",
    session_id: "sess-1",
    plugin_id: "file-ops",
    tool_call_type: "FileRead",
    arguments_summary: "/tmp/test.txt",
    arguments_hash: "abc123",
    composite_score: 1.5,
    proxy_action: "allow" as const,
    filter_results: [],
    execution_result: null,
    evaluation_time_ms: 0.85,
    task_context: null,
    source: "builtin",
  },
  {
    id: "rec-2",
    timestamp: "2024-01-01T12:01:00Z",
    session_id: "sess-1",
    plugin_id: "shell",
    tool_call_type: "ShellExec",
    arguments_summary: "ls -la",
    arguments_hash: "def456",
    composite_score: 5.0,
    proxy_action: "queue" as const,
    filter_results: [],
    execution_result: null,
    evaluation_time_ms: 2.1,
    task_context: null,
    source: "builtin",
  },
];

describe("AuditPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders audit table with records", async () => {
    vi.mocked(getAuditRecords).mockResolvedValue({
      records: mockRecords,
      total: 2,
    });

    render(<AuditPage />);

    await waitFor(() => {
      expect(screen.getByText("FileRead")).toBeTruthy();
    });

    // Table headers
    expect(screen.getByText("Time")).toBeTruthy();
    expect(screen.getByText("Type")).toBeTruthy();
    expect(screen.getByText("Session")).toBeTruthy();
    expect(screen.getByText("Score")).toBeTruthy();
    expect(screen.getByText("Action")).toBeTruthy();
    expect(screen.getByText("Latency")).toBeTruthy();
    expect(screen.getByText("Summary")).toBeTruthy();

    // Record data
    expect(screen.getAllByText("builtin").length).toBeGreaterThan(0);
    expect(screen.getByText("ShellExec")).toBeTruthy();
    expect(screen.getByText("/tmp/test.txt")).toBeTruthy();
  });

  it("renders empty state", async () => {
    vi.mocked(getAuditRecords).mockResolvedValue({
      records: [],
      total: 0,
    });

    render(<AuditPage />);

    await waitFor(() => {
      expect(screen.getByText("No audit records found.")).toBeTruthy();
    });
  });

  it("renders pagination controls", async () => {
    const baseRecord = mockRecords[0]!;
    const manyRecords = Array.from({ length: 50 }, (_, i) => ({
      ...baseRecord,
      id: `rec-${i}`,
    }));

    vi.mocked(getAuditRecords).mockResolvedValue({
      records: manyRecords,
      total: 100,
    });

    render(<AuditPage />);

    await waitFor(() => {
      expect(screen.getByText("Showing 1-50 of 100")).toBeTruthy();
    });

    const prevBtn = screen.getByText("Previous");
    const nextBtn = screen.getByText("Next");

    expect(prevBtn).toHaveAttribute("disabled");
    expect(nextBtn).not.toHaveAttribute("disabled");
  });

  it("next page updates offset", async () => {
    const baseRecord = mockRecords[0]!;
    const manyRecords = Array.from({ length: 50 }, (_, i) => ({
      ...baseRecord,
      id: `rec-${i}`,
    }));

    vi.mocked(getAuditRecords).mockResolvedValue({
      records: manyRecords,
      total: 100,
    });

    render(<AuditPage />);

    await waitFor(() => {
      expect(screen.getByText("Showing 1-50 of 100")).toBeTruthy();
    });

    fireEvent.click(screen.getByText("Next"));

    await waitFor(() => {
      expect(vi.mocked(getAuditRecords)).toHaveBeenCalledWith(
        expect.objectContaining({ offset: 50 }),
      );
    });
  });

  it("export JSON button triggers download", async () => {
    vi.mocked(getAuditRecords).mockResolvedValue({
      records: mockRecords,
      total: 2,
    });
    vi.mocked(exportAudit).mockResolvedValue(new Blob(["{}"]));

    render(<AuditPage />);

    await waitFor(() => {
      expect(screen.getByText("FileRead")).toBeTruthy();
    });

    fireEvent.click(screen.getByText("Export JSON"));

    await waitFor(() => {
      expect(vi.mocked(exportAudit)).toHaveBeenCalledWith("json");
    });
  });

  it("export CSV button triggers download", async () => {
    vi.mocked(getAuditRecords).mockResolvedValue({
      records: mockRecords,
      total: 2,
    });
    vi.mocked(exportAudit).mockResolvedValue(new Blob([""]));

    render(<AuditPage />);

    await waitFor(() => {
      expect(screen.getByText("FileRead")).toBeTruthy();
    });

    fireEvent.click(screen.getByText("Export CSV"));

    await waitFor(() => {
      expect(vi.mocked(exportAudit)).toHaveBeenCalledWith("csv");
    });
  });

  it("shows error on API failure", async () => {
    vi.mocked(getAuditRecords).mockRejectedValue(
      new Error("Failed to load audit records"),
    );

    render(<AuditPage />);

    await waitFor(() => {
      expect(screen.getByText("Failed to load audit records")).toBeTruthy();
    });
  });
});
