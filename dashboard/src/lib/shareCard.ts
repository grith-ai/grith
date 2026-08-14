/**
 * Generates a branded, social-ready PNG of the grith security posture and
 * shares (Web Share API) or downloads it.
 *
 * Drawn directly to a <canvas> (no html2canvas / extra deps) so the output is
 * crisp and font-stable, at the 1200×630 link-card ratio used by Twitter/X,
 * LinkedIn, Slack, etc. Deliberately contains ONLY aggregate counts — never a
 * path, project name, destination, or any session detail — so it's safe to post.
 */

export interface ShareStats {
  totalEvals: number;
  allow: number;
  queue: number;
  deny: number;
  liveSessions: number;
  uptime: string;
  filtersActive: number;
  version?: string;
}

import { chartColors, withAlpha } from "@/lib/chartPalette";

const W = 1200;
const H = 630;
const SCALE = 2; // render @2x for retina-crisp output

/* The card is a fixed-dark branded surface in both themes, so it draws from
   the theme-fixed chart palette (spec section 7, task LD3). */
const BG = chartColors.codeBg;
const GREEN = chartColors.accent;
const AMBER = chartColors.warning;
const RED = chartColors.danger;
const INK = chartColors.text;

const FONT_HEADING = '"Space Grotesk", sans-serif';
const FONT_BODY = '"IBM Plex Sans", sans-serif';
const FONT_MONO = '"IBM Plex Mono", monospace';

function roundRect(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  w: number,
  h: number,
  r: number,
) {
  const rr = Math.min(r, w / 2, h / 2);
  ctx.beginPath();
  ctx.moveTo(x + rr, y);
  ctx.arcTo(x + w, y, x + w, y + h, rr);
  ctx.arcTo(x + w, y + h, x, y + h, rr);
  ctx.arcTo(x, y + h, x, y, rr);
  ctx.arcTo(x, y, x + w, y, rr);
  ctx.closePath();
}

/** The grith hexagon mark, scaled to `size`px tall, top-left at (x, y). */
function drawMark(ctx: CanvasRenderingContext2D, x: number, y: number, size: number) {
  ctx.save();
  ctx.translate(x, y);
  ctx.scale(size / 26, size / 26);
  ctx.beginPath();
  ctx.moveTo(12, 1.5);
  ctx.lineTo(22, 7);
  ctx.lineTo(22, 18);
  ctx.lineTo(12, 23.5);
  ctx.lineTo(2, 18);
  ctx.lineTo(2, 7);
  ctx.closePath();
  ctx.lineWidth = 1.6;
  ctx.strokeStyle = GREEN;
  ctx.stroke();
  ctx.beginPath();
  ctx.arc(12, 12.5, 2.6, 0, Math.PI * 2);
  ctx.fillStyle = GREEN;
  ctx.fill();
  ctx.restore();
}

function drawCard(ctx: CanvasRenderingContext2D, s: ShareStats) {
  const decided = s.allow + s.queue + s.deny;
  const pad = 64;

  // Background + green aurora + fine grid.
  ctx.fillStyle = BG;
  ctx.fillRect(0, 0, W, H);

  const glow = ctx.createRadialGradient(W * 0.84, -40, 40, W * 0.84, -40, 720);
  glow.addColorStop(0, withAlpha(GREEN, 0.26));
  glow.addColorStop(0.5, withAlpha(GREEN, 0.08));
  glow.addColorStop(1, "rgba(0,0,0,0)");
  ctx.fillStyle = glow;
  ctx.fillRect(0, 0, W, H);

  ctx.strokeStyle = "rgba(255,255,255,0.035)";
  ctx.lineWidth = 1;
  for (let gx = 0; gx <= W; gx += 40) {
    ctx.beginPath();
    ctx.moveTo(gx, 0);
    ctx.lineTo(gx, H);
    ctx.stroke();
  }
  for (let gy = 0; gy <= H; gy += 40) {
    ctx.beginPath();
    ctx.moveTo(0, gy);
    ctx.lineTo(W, gy);
    ctx.stroke();
  }

  // Inner hairline border.
  ctx.strokeStyle = "rgba(255,255,255,0.10)";
  ctx.lineWidth = 1.5;
  roundRect(ctx, 8, 8, W - 16, H - 16, 18);
  ctx.stroke();

  // ── Header ──────────────────────────────────────────────────────────
  drawMark(ctx, pad, 54, 34);
  ctx.textBaseline = "alphabetic";
  ctx.fillStyle = INK;
  ctx.font = `700 30px ${FONT_HEADING}`;
  ctx.fillText("grith", pad + 46, 82);
  const gw = ctx.measureText("grith").width;
  if (s.version) {
    ctx.fillStyle = "rgba(255,255,255,0.40)";
    ctx.font = `500 16px ${FONT_MONO}`;
    ctx.fillText(`v${s.version}`, pad + 46 + gw + 12, 82);
  }
  ctx.fillStyle = "rgba(255,255,255,0.45)";
  ctx.font = `500 17px ${FONT_BODY}`;
  ctx.textAlign = "right";
  ctx.fillText("Zero Trust for AI Agents", W - pad, 82);
  ctx.textAlign = "left";

  // ── Headline metric ─────────────────────────────────────────────────
  ctx.fillStyle = INK;
  ctx.font = `700 118px ${FONT_MONO}`;
  ctx.fillText(s.totalEvals.toLocaleString(), pad - 2, 268);

  ctx.fillStyle = "rgba(255,255,255,0.55)";
  ctx.font = `400 25px ${FONT_BODY}`;
  const held = (s.queue + s.deny).toLocaleString();
  ctx.fillText(
    `tool calls inspected under Zero Trust - ${held} queued or denied`,
    pad,
    312,
  );

  // ── Stat rail ───────────────────────────────────────────────────────
  const stats: Array<{ v: string; l: string; c: string }> = [
    { v: String(s.liveSessions), l: "AGENTS LIVE", c: GREEN },
    { v: s.queue.toLocaleString(), l: "QUEUED", c: AMBER },
    { v: s.deny.toLocaleString(), l: "DENIED", c: RED },
    { v: String(s.filtersActive), l: "FILTERS", c: INK },
  ];
  const railY = 384;
  const colW = (W - pad * 2) / 4;
  stats.forEach((st, i) => {
    const cx = pad + i * colW;
    ctx.fillStyle = st.c;
    ctx.font = `600 40px ${FONT_MONO}`;
    ctx.fillText(st.v, cx, railY + 34);
    ctx.fillStyle = "rgba(255,255,255,0.42)";
    ctx.font = `600 13px ${FONT_MONO}`;
    ctx.fillText(spaced(st.l), cx, railY + 58);
  });

  // ── Posture bar ─────────────────────────────────────────────────────
  const barY = 484;
  const barW = W - pad * 2;
  const barH = 14;
  ctx.fillStyle = "rgba(255,255,255,0.06)";
  roundRect(ctx, pad, barY, barW, barH, barH / 2);
  ctx.fill();
  if (decided > 0) {
    let x = pad;
    const seg = (n: number, color: string) => {
      const w = (n / decided) * barW;
      if (w <= 0) return;
      ctx.fillStyle = color;
      roundRect(ctx, x, barY, Math.max(w, w > 0 ? 3 : 0), barH, barH / 2);
      ctx.fill();
      x += w;
    };
    seg(s.allow, GREEN);
    seg(s.queue, AMBER);
    seg(s.deny, RED);
  }

  // Legend + footer.
  const legY = barY + 46;
  const pct = (n: number) => (decided > 0 ? Math.round((n / decided) * 100) : 0);
  let lx = pad;
  const legend = (color: string, label: string, n: number) => {
    ctx.fillStyle = color;
    roundRect(ctx, lx, legY - 11, 11, 11, 2);
    ctx.fill();
    ctx.fillStyle = "rgba(255,255,255,0.85)";
    ctx.font = `600 16px ${FONT_BODY}`;
    ctx.fillText(label, lx + 18, legY);
    const labelW = ctx.measureText(label).width;
    ctx.fillStyle = "rgba(255,255,255,0.45)";
    ctx.font = `400 15px ${FONT_MONO}`;
    const tail = `${n.toLocaleString()} · ${pct(n)}%`;
    ctx.fillText(tail, lx + 18 + labelW + 8, legY);
    lx += 18 + labelW + 8 + ctx.measureText(tail).width + 34;
  };
  legend(GREEN, "Allowed", s.allow);
  legend(AMBER, "Queued", s.queue);
  legend(RED, "Denied", s.deny);

  // Footer brand stamp.
  ctx.fillStyle = "rgba(255,255,255,0.35)";
  ctx.font = `500 16px ${FONT_MONO}`;
  ctx.textAlign = "right";
  ctx.fillText(`grith.ai · uptime ${s.uptime}`, W - pad, legY);
  ctx.textAlign = "left";
}

/** Letter-spaced label (canvas has no letter-spacing pre-2023 everywhere). */
function spaced(s: string): string {
  return s.split("").join(" ");
}

/** Render the share card to a PNG blob. */
export async function generateShareCardBlob(s: ShareStats): Promise<Blob> {
  const canvas = document.createElement("canvas");
  canvas.width = W * SCALE;
  canvas.height = H * SCALE;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("canvas 2d context unavailable");
  ctx.scale(SCALE, SCALE);

  // Ensure the web fonts are loaded before measuring/drawing text.
  if (document.fonts?.ready) {
    try {
      await document.fonts.load('700 118px "IBM Plex Mono"');
      await document.fonts.load('700 30px "Space Grotesk"');
      await document.fonts.load('400 25px "IBM Plex Sans"');
      await document.fonts.ready;
    } catch {
      /* fall through - system fallback fonts still render */
    }
  }

  drawCard(ctx, s);

  return await new Promise<Blob>((resolve, reject) => {
    canvas.toBlob(
      (b) => (b ? resolve(b) : reject(new Error("toBlob produced no blob"))),
      "image/png",
    );
  });
}

/** Base URL of the grith.ai service that mints share links + OG cards. */
const SHARE_SERVICE_BASE = "https://grith.ai";

/**
 * POST the aggregate stats to grith.ai and get back a public, shareable URL
 * (`https://grith.ai/s/<slug>`) whose Open Graph / Twitter card renders this
 * posture. Only aggregate counts leave the machine — the same data the PNG
 * already contains. Throws on network / server error.
 */
export async function createShareLink(s: ShareStats): Promise<string> {
  const res = await fetch(`${SHARE_SERVICE_BASE}/api/share`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ stats: s }),
  });
  if (!res.ok) {
    throw new Error(`share service returned ${res.status}`);
  }
  const data = (await res.json()) as { url?: string };
  if (!data.url) throw new Error("share service response missing url");
  return data.url;
}

/** Suggested post text + title for a share, derived from the stats. */
export function shareCopy(s: ShareStats): { text: string; title: string } {
  const held = (s.queue + s.deny).toLocaleString();
  return {
    text: `My AI agents ran ${s.totalEvals.toLocaleString()} tool calls under Zero Trust supervision with grith - ${held} queued for review or denied.`,
    title: `grith - ${s.totalEvals.toLocaleString()} AI tool calls under Zero Trust`,
  };
}

/** Platform intent URLs that pre-fill a post linking to the share `url`. */
export function shareIntents(url: string, s: ShareStats) {
  const { text, title } = shareCopy(s);
  const u = encodeURIComponent(url);
  return {
    x: `https://x.com/intent/tweet?text=${encodeURIComponent(text)}&url=${u}`,
    threads: `https://www.threads.net/intent/post?text=${encodeURIComponent(
      `${text} ${url}`,
    )}`,
    hn: `https://news.ycombinator.com/submitlink?u=${u}&t=${encodeURIComponent(
      title,
    )}`,
  };
}

export type ShareOutcome = "shared" | "downloaded" | "cancelled";

/** Generate the card and share it natively, falling back to a download. */
export async function shareOrDownloadStats(s: ShareStats): Promise<ShareOutcome> {
  const blob = await generateShareCardBlob(s);
  const file = new File([blob], "grith-stats.png", { type: "image/png" });

  const nav = navigator as Navigator & {
    canShare?: (data?: ShareData) => boolean;
  };
  if (nav.canShare?.({ files: [file] })) {
    try {
      await nav.share({
        files: [file],
        title: "grith - Zero Trust for AI Agents",
        text: "My AI agents, under Zero Trust supervision with grith.",
      });
      return "shared";
    } catch (err) {
      // User dismissed the share sheet — don't also trigger a download.
      if (err instanceof Error && err.name === "AbortError") return "cancelled";
      // Any other failure: fall through to download.
    }
  }

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "grith-stats.png";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  return "downloaded";
}
