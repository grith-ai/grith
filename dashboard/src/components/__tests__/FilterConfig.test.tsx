import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { FilterConfig } from "../FilterConfig";

describe("FilterConfig", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("uses canonical tagged tool-call sample JSON", () => {
    render(<FilterConfig />);
    const textarea = screen.getByPlaceholderText(
      '{"type": "FileRead", "path": "/tmp/test"}',
    ) as HTMLTextAreaElement;
    expect(textarea.value).toContain('"type": "FileRead"');
    expect(textarea.value).toContain('"path": "/etc/passwd"');
  });

  it("posts tool_call JSON to /api/proxy/test", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          composite_score: 0.0,
          action: "allow",
          filters_evaluated: 11,
        }),
    } as Response);

    render(<FilterConfig />);
    fireEvent.click(screen.getByRole("button", { name: "Run Test" }));

    await waitFor(() => expect(global.fetch).toHaveBeenCalledTimes(1));
    const call = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(call[1].body as string);
    expect(body.tool_call.type).toBe("FileRead");
    expect(body.tool_call.path).toBe("/etc/passwd");
  });
});
