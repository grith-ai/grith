import { useSyncExternalStore } from "react";

import { THEME_STORAGE_KEY, type Theme } from "@/lib/theme";

/**
 * Theme toggle pill (F4): mono-label `THEME: DARK` / `THEME: LIGHT`, ported
 * from the grith-website pattern. Flips `data-theme` on <html> and persists
 * the choice to localStorage ('grith-theme'), matching the inline FOUC
 * guard in index.html.
 *
 * The current theme is read from the `data-theme` attribute itself via
 * useSyncExternalStore, so multiple toggle instances stay in sync.
 *
 * Token-class styling only, so it re-skins with the theme it controls.
 */

function subscribeToThemeAttribute(onChange: () => void): () => void {
  const observer = new MutationObserver(onChange);
  observer.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ["data-theme"],
  });
  return () => observer.disconnect();
}

function readTheme(): Theme {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

export function ThemeToggle({ className = "" }: { className?: string }) {
  const current = useSyncExternalStore(subscribeToThemeAttribute, readTheme);
  const next: Theme = current === "light" ? "dark" : "light";

  const toggle = () => {
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem(THEME_STORAGE_KEY, next);
    } catch {
      // Storage unavailable (private mode, blocked cookies): the toggle
      // still applies for this page view, it just will not persist.
    }
  };

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={`Switch to ${next} theme`}
      className={`inline-flex items-center rounded-pill border border-border bg-transparent px-3 py-1.5 font-label text-xs uppercase tracking-[0.1em] text-text-secondary transition-colors duration-150 hover:border-border-dark hover:text-text ${className}`}
    >
      Theme: {current}
    </button>
  );
}
