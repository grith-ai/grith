import { useState, useCallback } from "react";
import { FilterConfig } from "@/components/FilterConfig";
import { PolicyEditor, UsageAnalytics } from "@/components/ProStub";
import { csrfHeaders } from "@/lib/csrf";

export function SettingsPage() {
  const [saveMessage, setSaveMessage] = useState<string | null>(null);

  const handleSaveConfig = useCallback(
    async (config: Record<string, unknown>) => {
      setSaveMessage(null);
      try {
        const response = await fetch(
          `${window.location.origin}/api/config`,
          {
            method: "PUT",
            headers: { "Content-Type": "application/json", ...csrfHeaders() },
            body: JSON.stringify(config),
          },
        );
        if (response.ok) {
          setSaveMessage("Configuration saved.");
        } else if (response.status === 404) {
          // The current daemon ships PUT /api/config (registered in
          // crates/grith-server/src/routes/mod.rs). A 404 here means
          // the daemon predates that route — i.e. an old binary is
          // running against a newer dashboard bundle.
          setSaveMessage(
            "Your running grith daemon doesn't support live config saves. Upgrade grith, or edit ~/.config/grith/config.toml directly.",
          );
        } else {
          let detail = `${response.status} ${response.statusText}`;
          try {
            const body = await response.json();
            if (body && typeof body.message === "string") {
              detail = body.message;
            }
          } catch {
            // body wasn't JSON — keep the status-line fallback
          }
          setSaveMessage(`Failed to save configuration: ${detail}`);
        }
      } catch {
        setSaveMessage(
          "Could not reach the grith daemon. Is the dashboard server running (`grith dashboard status`)?",
        );
      }
      // Auto-dismiss after 5 seconds
      setTimeout(() => setSaveMessage(null), 5000);
    },
    [],
  );

  return (
    <div className="p-6 max-w-4xl">
      <h1 className="font-heading text-[22px] font-semibold tracking-[-0.02em] text-text mb-6">
        Settings
      </h1>

      {saveMessage && (
        <div className="mb-4 bg-green-light border border-green-border rounded-card px-4 py-3 text-xs text-accent-text">
          {saveMessage}
        </div>
      )}

      {/* Filter configuration */}
      <FilterConfig onSave={handleSaveConfig} />

      {/* Pro features */}
      <div className="mt-8">
        <h2 className="font-label text-[11px] font-medium text-text-dim uppercase tracking-[0.1em] mb-4">
          Pro Features
        </h2>
        <div className="space-y-4">
          <PolicyEditor />
          <UsageAnalytics />
        </div>
      </div>

      {/* CLI hint */}
      <div className="mt-8 bg-surface border border-border rounded-card p-5 text-center">
        <p className="text-text-secondary text-xs">
          Additional configuration available via{" "}
          <code className="font-code text-accent-text">
            ~/.config/grith/config.toml
          </code>{" "}
          or{" "}
          <code className="font-code text-accent-text">
            grith config set
          </code>{" "}
          in the CLI.
        </p>
      </div>
    </div>
  );
}
