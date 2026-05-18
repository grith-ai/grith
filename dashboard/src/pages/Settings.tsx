import { useState, useCallback } from "react";
import { FilterConfig } from "@/components/FilterConfig";
import { AdaptiveScoring } from "@/components/AdaptiveScoring";
import { PolicyEditor, UsageAnalytics } from "@/components/ProStub";

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
            headers: { "Content-Type": "application/json" },
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
      <h1 className="text-xl font-semibold text-grith-text mb-6">
        Settings
      </h1>

      {saveMessage && (
        <div className="mb-4 bg-white border border-green/30 rounded-xl px-4 py-3 text-xs text-green">
          {saveMessage}
        </div>
      )}

      {/* Filter configuration */}
      <FilterConfig onSave={handleSaveConfig} />

      {/* Pro features */}
      <div className="mt-8">
        <h2 className="text-xs text-grith-muted uppercase tracking-wider mb-4">
          Pro Features
        </h2>
        <div className="space-y-4">
          <AdaptiveScoring />
          <PolicyEditor />
          <UsageAnalytics />
        </div>
      </div>

      {/* CLI hint */}
      <div className="mt-8 bg-white border border-grith-border rounded-xl p-5 text-center">
        <p className="text-grith-muted text-xs">
          Additional configuration available via{" "}
          <code className="font-mono text-green">
            ~/.config/grith/config.toml
          </code>{" "}
          or{" "}
          <code className="font-mono text-green">
            grith config set
          </code>{" "}
          in the CLI.
        </p>
      </div>
    </div>
  );
}
