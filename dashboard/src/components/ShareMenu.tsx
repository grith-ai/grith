/**
 * Share menu for the dashboard hero. Mints a public share link on grith.ai
 * (aggregate stats only) and opens a pre-filled post on X / Threads / Hacker
 * News, copies the link, or falls back to the local PNG download.
 *
 * The link is created once (memoised) and pre-warmed when the menu opens, so a
 * platform click can open the intent synchronously without tripping popup
 * blockers.
 */

import { useEffect, useRef, useState } from "react";
import { chartColors } from "@/lib/chartPalette";
import {
  createShareLink,
  shareIntents,
  shareOrDownloadStats,
  type ShareStats,
} from "@/lib/shareCard";

type Network = "x" | "threads" | "hn";

export function ShareMenu({
  stats,
  autoOpen = false,
}: {
  stats: ShareStats;
  /** Open from the CLI's explicit end-of-session dashboard deep link. */
  autoOpen?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [url, setUrl] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [pngLabel, setPngLabel] = useState("Download image (PNG)");
  const promiseRef = useRef<Promise<string> | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const autoOpenConsumedRef = useRef(false);

  useEffect(() => {
    if (autoOpen && !autoOpenConsumedRef.current) {
      autoOpenConsumedRef.current = true;
      // Do not mint a public link yet. Opening the local menu is safe; the
      // user still chooses a network/copy action before aggregate stats leave
      // the machine.
      setOpen(true);
    }
  }, [autoOpen]);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (
        containerRef.current &&
        !containerRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  function ensureUrl(): Promise<string> {
    if (url) return Promise.resolve(url);
    if (!promiseRef.current) {
      setCreating(true);
      setError(null);
      promiseRef.current = createShareLink(stats)
        .then((u) => {
          setUrl(u);
          return u;
        })
        .catch((e) => {
          promiseRef.current = null; // allow retry
          setError("Couldn't create a share link - check your connection.");
          throw e;
        })
        .finally(() => setCreating(false));
    }
    return promiseRef.current;
  }

  function toggle() {
    const next = !open;
    setOpen(next);
    if (next && !url) void ensureUrl().catch(() => {});
  }

  function openIntent(kind: Network) {
    if (url) {
      window.open(shareIntents(url, stats)[kind], "_blank", "noopener,noreferrer");
      setOpen(false);
      return;
    }
    // Not ready yet: open a blank tab synchronously, then redirect on resolve.
    const w = window.open("", "_blank");
    void ensureUrl()
      .then((u) => {
        const intent = shareIntents(u, stats)[kind];
        if (w) w.location.href = intent;
        setOpen(false);
      })
      .catch(() => {
        if (w) w.close();
      });
  }

  async function copyLink() {
    try {
      const u = await ensureUrl();
      await navigator.clipboard.writeText(u);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      /* error surfaced via state */
    }
  }

  async function downloadPng() {
    setPngLabel("Generating…");
    try {
      const outcome = await shareOrDownloadStats(stats);
      setPngLabel(
        outcome === "downloaded"
          ? "Saved PNG"
          : outcome === "shared"
            ? "Shared!"
            : "Download image (PNG)",
      );
    } catch {
      setPngLabel("Couldn't generate");
    }
    // Leave the menu open so the "Saved PNG" feedback is visible.
    setTimeout(() => setPngLabel("Download image (PNG)"), 2400);
  }

  return (
    <div ref={containerRef} className="relative">
      <button
        type="button"
        onClick={toggle}
        title="Share your security posture"
        className="group inline-flex items-center gap-1.5 rounded-lg border border-white/15 bg-white/[0.06] px-3 py-1.5 text-[12px] font-medium text-white/80 transition-colors hover:bg-[#00e5a0]/15 hover:border-[#00e5a0]/40 hover:text-white"
      >
        <svg className="w-3.5 h-3.5" style={{ color: chartColors.accent }} viewBox="0 0 24 24" fill="none" aria-hidden>
          <circle cx="18" cy="5" r="2.5" stroke="currentColor" strokeWidth="1.6" />
          <circle cx="6" cy="12" r="2.5" stroke="currentColor" strokeWidth="1.6" />
          <circle cx="18" cy="19" r="2.5" stroke="currentColor" strokeWidth="1.6" />
          <path d="M8.2 10.8l7.6-4.4M8.2 13.2l7.6 4.4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
        </svg>
        Share stats
        <svg className={`w-3 h-3 transition-transform ${open ? "rotate-180" : ""}`} viewBox="0 0 24 24" fill="none" aria-hidden>
          <path d="M6 9l6 6 6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>

      {open && (
        <div
          className="absolute right-0 z-20 mt-2 w-60 overflow-hidden rounded-code border border-white/10"
          style={{ backgroundColor: chartColors.surface }}
        >
          <MenuItem onClick={() => openIntent("x")} label="Post to X" disabled={!!error} icon={<XIcon />} />
          <MenuItem onClick={() => openIntent("threads")} label="Post to Threads" disabled={!!error} icon={<ThreadsIcon />} />
          <MenuItem onClick={() => openIntent("hn")} label="Submit to Hacker News" disabled={!!error} icon={<HnIcon />} />
          <div className="h-px bg-white/8" />
          <MenuItem onClick={() => void copyLink()} label={copied ? "Link copied" : "Copy link"} disabled={!!error} icon={<LinkIcon />} />
          <MenuItem onClick={() => void downloadPng()} label={pngLabel} icon={<DownloadIcon />} />

          <div className="border-t border-white/8 px-3 py-2">
            {error ? (
              <p className="text-[11px]" style={{ color: chartColors.danger }}>{error}</p>
            ) : creating ? (
              <p className="text-[11px] text-white/40">Preparing share link…</p>
            ) : (
              <p className="text-[11px] text-white/35">
                Shares aggregate counts only - no paths or project names.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function MenuItem({
  onClick,
  label,
  icon,
  disabled,
}: {
  onClick: () => void;
  label: string;
  icon: React.ReactNode;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="flex w-full items-center gap-2.5 px-3 py-2.5 text-left text-[13px] text-white/80 transition-colors hover:bg-white/[0.06] disabled:opacity-40 disabled:hover:bg-transparent"
    >
      <span className="flex w-4 justify-center text-white/55">{icon}</span>
      {label}
    </button>
  );
}

function XIcon() {
  return (
    <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor" aria-hidden>
      <path d="M18.9 2H22l-7.3 8.3L23 22h-6.8l-5.3-6.9L4.8 22H2l7.8-8.9L1.4 2h6.9l4.8 6.4L18.9 2zm-1.2 18h1.9L7.1 4H5.1l12.6 16z" />
    </svg>
  );
}
function ThreadsIcon() {
  return (
    <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path d="M12 21c-4.5 0-7.5-3.2-7.5-9S7.5 3 12 3c3.4 0 5.7 1.7 6.6 4.3M12 17c-1.9 0-3.2-1-3.2-2.4 0-1.6 1.6-2.6 3.8-2.6 2.6 0 4.1 1.3 4.1 3.4 0 2.2-1.6 3.4-3.6 3.4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}
function HnIcon() {
  return (
    <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor" aria-hidden>
      <path d="M3 3h18v18H3V3zm9 11.2l3.2-6.2h-1.7L12 11.3 10.5 8H8.8L12 14.2V18h0v-3.8z" />
    </svg>
  );
}
function LinkIcon() {
  return (
    <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path d="M9 15l6-6M10 6l1-1a4 4 0 016 6l-1 1M8 13l-1 1a4 4 0 01-6-6l1-1" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}
function DownloadIcon() {
  return (
    <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
