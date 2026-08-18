import { useEffect, useState } from "react";
import { markIntroSeen, setAutoOpenDashboard } from "@/lib/api";

interface IntroOverlayProps {
  /** Called once the intro is acknowledged (and closed). */
  onClose: () => void;
}

/**
 * First-run explainer, shown once when grith auto-opens the dashboard in a
 * browser. It reassures a user who was working in the terminal that this window
 * is a local view (not something that replaced their session) and that the CLI
 * is still running. Offers a checkbox to turn off the browser auto-open.
 *
 * "Seen" is persisted server-side (the `intro_seen` marker via
 * POST /api/onboarding/intro-seen), so it appears only once — not per browser.
 * The checkbox persists `server.auto_open_dashboard` to the daemon config, which
 * the CLI reads at its next launch.
 */
export function IntroOverlay({ onClose }: IntroOverlayProps) {
  const [dontAutoOpen, setDontAutoOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  // Persist "seen" (and the auto-open preference if the box was ticked), then
  // close. Best-effort: the overlay always closes even if a write fails, so it
  // never traps the user — the server marker just may not be set.
  const acknowledge = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await markIntroSeen();
      if (dontAutoOpen) await setAutoOpenDashboard(false);
    } catch {
      // Non-fatal — close regardless.
    }
    onClose();
  };

  // Escape acknowledges too (matches the app's modal convention). Re-bind on
  // checkbox/busy change so the handler closes over the current state.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") void acknowledge();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [dontAutoOpen, busy]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4"
      onClick={() => void acknowledge()}
    >
      <div
        className="bg-surface border border-border rounded-card max-w-lg w-full overflow-hidden flex flex-col"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="intro-overlay-title"
      >
        <div className="px-6 py-5 border-b border-border">
          <h2
            id="intro-overlay-title"
            className="font-heading text-lg font-semibold text-text"
          >
            This is your local dashboard
          </h2>
        </div>

        <div className="px-6 py-5 space-y-4 text-sm leading-relaxed text-text-secondary">
          <p>
            grith just opened this in your browser. It&apos;s a live view of what
            grith is doing on your machine — the tool calls it&apos;s watching,
            what it allowed, held for review, or blocked, and your full audit
            trail.
          </p>
          <p>
            It runs entirely on{" "}
            <span className="font-code text-text">localhost</span> — nothing here
            leaves your computer. And your terminal session is still running
            right where you left it; this opened alongside it, not instead of it.
          </p>

          <label className="flex items-start gap-3 pt-1 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={dontAutoOpen}
              onChange={(e) => setDontAutoOpen(e.target.checked)}
              style={{ accentColor: "#00e5a0" }}
              className="mt-0.5 h-4 w-4 cursor-pointer"
            />
            <span className="text-text">
              Don&apos;t open the dashboard automatically when grith starts
              <span className="block text-xs text-text-dim mt-0.5">
                grith still prints the address each time, so you can open it
                whenever you want.
              </span>
            </span>
          </label>
        </div>

        <div className="px-6 py-4 border-t border-border bg-surface-2 flex justify-end">
          <button
            type="button"
            onClick={() => void acknowledge()}
            disabled={busy}
            className="rounded-btn border border-green-border bg-green-light px-4 py-2 text-sm font-semibold accent-text hover:opacity-90 disabled:opacity-60"
          >
            Got it
          </button>
        </div>
      </div>
    </div>
  );
}
