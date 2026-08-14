import { useState } from "react";
import { csrfHeaders } from "@/lib/csrf";

interface FilterDef {
  id: string;
  name: string;
  phase: "Static" | "Pattern" | "Context";
}

const KNOWN_FILTERS: FilterDef[] = [
  { id: "path-match", name: "Path Match", phase: "Static" },
  { id: "allowlist", name: "Allowlist", phase: "Static" },
  { id: "capability", name: "Capability", phase: "Static" },
  { id: "argument", name: "Argument Structure", phase: "Static" },
  { id: "secret-scan", name: "Secret Scan", phase: "Pattern" },
  { id: "command", name: "Command Analysis", phase: "Pattern" },
  { id: "reputation", name: "Reputation", phase: "Context" },
  { id: "behavioural", name: "Behavioural", phase: "Context" },
  { id: "taint", name: "Taint Tracking", phase: "Context" },
  { id: "rate-limit", name: "Rate Limit", phase: "Context" },
];

const PHASE_COLORS: Record<string, string> = {
  Static: "text-accent-text bg-green-light border-green-border",
  Pattern: "text-warning-text bg-warning-light border-warning-border",
  Context: "text-accent-text bg-green-light border-green-border",
};

interface FilterConfigProps {
  onSave?: (config: Record<string, unknown>) => void;
}

export function FilterConfig({ onSave }: FilterConfigProps) {
  const [enabledFilters, setEnabledFilters] = useState<Record<string, boolean>>(
    () =>
      Object.fromEntries(KNOWN_FILTERS.map((f) => [f.id, true])),
  );
  const [testInput, setTestInput] = useState<string>(
    JSON.stringify(
      {
        type: "FileRead",
        path: "/etc/passwd",
      },
      null,
      2,
    ),
  );
  const [testResult, setTestResult] = useState<string | null>(null);
  const [testError, setTestError] = useState<string | null>(null);

  function handleToggle(filterId: string) {
    setEnabledFilters((prev) => ({
      ...prev,
      [filterId]: !prev[filterId],
    }));
  }

  function handleSave() {
    if (onSave) {
      onSave({
        filters: Object.entries(enabledFilters).map(([id, enabled]) => ({
          id,
          enabled,
        })),
      });
    }
  }

  async function handleRunTest() {
    setTestError(null);
    setTestResult(null);

    let parsed: unknown;
    try {
      parsed = JSON.parse(testInput);
    } catch {
      setTestError("Invalid JSON. Please check your input.");
      return;
    }

    try {
      const response = await fetch(
        `${window.location.origin}/api/proxy/test`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json", ...csrfHeaders() },
          body: JSON.stringify({
            tool_call: parsed,
            enabled_filters: Object.entries(enabledFilters)
              .filter(([, enabled]) => enabled)
              .map(([id]) => id),
          }),
        },
      );

      if (response.ok) {
        const result = await response.json();
        setTestResult(
          `Score: ${result.composite_score ?? "N/A"} | Action: ${result.action ?? "N/A"} | Filters evaluated: ${result.filters_evaluated ?? "N/A"}`,
        );
      } else if (response.status === 404) {
        // POST /proxy/test is registered (see crates/grith-server/src/
        // routes/mod.rs:258). A 404 means the running daemon predates
        // that route — i.e. an old binary against a newer dashboard.
        setTestError(
          "Your running grith daemon doesn't expose the live proxy-test endpoint. Upgrade grith and try again.",
        );
      } else {
        const body = await response.text().catch(() => "");
        setTestError(`Proxy returned ${response.status}: ${body || response.statusText}`);
      }
    } catch {
      setTestError(
        "Could not reach the grith daemon. Is the dashboard server running (`grith dashboard status`)?",
      );
    }
  }

  return (
    <div className="space-y-6">
      {/* Filter list */}
      <div className="bg-surface border border-border rounded-card p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-heading text-[15px] font-semibold text-text">
            Security Filters
          </h2>
          <button
            onClick={handleSave}
            className="px-3 py-1.5 text-xs rounded-btn bg-green text-accent-ink font-heading font-semibold hover:bg-green-dark transition-colors"
          >
            Save Configuration
          </button>
        </div>

        <div className="space-y-1">
          {KNOWN_FILTERS.map((filter) => (
            <label
              key={filter.id}
              className="flex items-center justify-between py-2.5 px-3 rounded-btn cursor-pointer hover:bg-surface-2 transition-colors"
            >
              <div className="flex items-center gap-3">
                <input
                  type="checkbox"
                  checked={enabledFilters[filter.id] ?? false}
                  onChange={() => handleToggle(filter.id)}
                  className="w-4 h-4 rounded-sm border-border accent-green"
                />
                <span className="text-sm text-text">{filter.name}</span>
                <span className="text-xs font-code text-text-secondary">
                  {filter.id}
                </span>
              </div>
              <span
                className={`font-label text-[10px] font-medium uppercase tracking-[0.08em] px-2.5 py-0.5 rounded-pill border ${PHASE_COLORS[filter.phase]}`}
              >
                {filter.phase}
              </span>
            </label>
          ))}
        </div>
      </div>

      {/* Test section */}
      <div className="bg-surface border border-border rounded-card p-5">
        <h2 className="font-heading text-[15px] font-semibold text-text mb-4">
          Test Tool Call
        </h2>

        <textarea
          value={testInput}
          onChange={(e) => setTestInput(e.target.value)}
          rows={6}
          spellCheck={false}
          className="w-full bg-bg border border-border rounded-btn px-3 py-2 text-xs font-code text-text placeholder:text-text-dim focus:outline-none focus:border-green focus:shadow-glow resize-y"
          placeholder='{"type": "FileRead", "path": "/tmp/test"}'
        />

        <div className="flex items-center gap-3 mt-3">
          <button
            onClick={handleRunTest}
            className="px-4 py-1.5 text-xs rounded-btn bg-green text-accent-ink font-heading font-semibold hover:bg-green-dark transition-colors"
          >
            Run Test
          </button>
          <span className="text-[10px] text-text-secondary">
            Evaluates the JSON tool call against enabled filters
          </span>
        </div>

        {testError && (
          <div className="mt-3 bg-danger-light border border-danger-border rounded-lg px-3 py-2 text-xs text-danger-text">
            {testError}
          </div>
        )}

        {testResult && (
          <div className="mt-3 bg-green-light border border-green-border rounded-lg px-3 py-2 text-xs text-accent-text">
            {testResult}
          </div>
        )}
      </div>
    </div>
  );
}
