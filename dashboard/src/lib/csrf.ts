/**
 * Dashboard CSRF / auth header.
 *
 * Every browser-facing mutating request to the grith daemon must carry the
 * {@link DASHBOARD_CSRF_HEADER}. Requiring a custom header forces a CORS
 * preflight for cross-origin requests, which the daemon's locked-origin CORS
 * layer rejects — closing the browser drive-by CSRF gap. See
 * `crates/grith-server/src/csrf.rs`.
 *
 * The header value is the per-server dashboard token when one has been
 * provisioned (item 2 — captured from the `#token=` launch fragment into
 * `localStorage`), otherwise the public sentinel. The sentinel carries no
 * authority; its only job is to be a non-simple header that triggers preflight.
 */

export const DASHBOARD_CSRF_HEADER = "x-grith-csrf";

/** Non-secret fallback value; mirrors `csrf::DASHBOARD_CSRF_SENTINEL` in Rust. */
export const DASHBOARD_CSRF_SENTINEL = "grith-dashboard";

/** `localStorage` key holding the per-server dashboard token (item 2). */
export const DASHBOARD_TOKEN_STORAGE_KEY = "grith.dashboardToken";

/**
 * Returns the value to send in {@link DASHBOARD_CSRF_HEADER}: the provisioned
 * dashboard token if present, otherwise the public sentinel.
 */
export function getDashboardCsrfValue(): string {
  if (typeof window !== "undefined") {
    try {
      const token = window.localStorage.getItem(DASHBOARD_TOKEN_STORAGE_KEY);
      if (token) return token;
    } catch {
      // localStorage unavailable (private mode / disabled) — fall back.
    }
  }
  return DASHBOARD_CSRF_SENTINEL;
}

/** Header object to spread into any `fetch` that mutates server state. */
export function csrfHeaders(): Record<string, string> {
  return { [DASHBOARD_CSRF_HEADER]: getDashboardCsrfValue() };
}

/**
 * On first load, capture a `#token=...` fragment from the launch URL the CLI
 * prints (`http://127.0.0.1:3141/#token=<tok>`) into `localStorage`, then
 * strip it from the address bar so the secret does not linger in browser
 * history. The fragment is never transmitted to the server. Idempotent — safe
 * to call on every load.
 *
 * The app uses path-based routing (`BrowserRouter`), so the hash is only ever
 * our token carrier; only the `token` parameter is removed, preserving any
 * other hash content defensively.
 */
export function captureDashboardTokenFromUrl(): void {
  if (typeof window === "undefined") return;
  const hash = window.location.hash;
  const match = /[#&]token=([^&]+)/.exec(hash);
  const rawToken = match?.[1];
  if (!rawToken) return;

  let token: string;
  try {
    token = decodeURIComponent(rawToken);
  } catch {
    // Malformed percent-encoding — leave the URL untouched and bail.
    return;
  }
  try {
    window.localStorage.setItem(DASHBOARD_TOKEN_STORAGE_KEY, token);
  } catch {
    // localStorage unavailable — the token simply won't persist, but still
    // strip it from the URL below so the secret doesn't linger.
  }

  // Remove only the token parameter, preserving any other hash content, then
  // normalise a now-orphaned leading or trailing separator so we never emit a
  // malformed hash like "#&foo=bar".
  let stripped = hash
    .replace(/([#&])token=[^&]*/, "$1")
    .replace(/^#&/, "#")
    .replace(/[#&]$/, "");
  if (stripped === "#") stripped = "";
  window.history.replaceState(
    null,
    document.title,
    window.location.pathname + window.location.search + stripped,
  );
}

/** Remove a `#<param>=...` carrier from the current URL hash, in place. */
function stripHashParam(param: string): void {
  const hash = window.location.hash;
  let stripped = hash
    .replace(new RegExp(`([#&])${param}=[^&]*`), "$1")
    .replace(/^#&/, "#")
    .replace(/[#&]$/, "");
  if (stripped === "#") stripped = "";
  window.history.replaceState(
    null,
    document.title,
    window.location.pathname + window.location.search + stripped,
  );
}

/**
 * Capture a single-use `#pair=<code>` fragment from the launch/pair URL the CLI
 * prints or auto-opens (`http://127.0.0.1:3141/#pair=<code>`), exchange it at
 * `/api/dashboard/pair` for the real dashboard token, and store the token in
 * `localStorage`. Unlike `#token=`, the long-lived secret never appears in the
 * URL — only the disposable code does, and it is consumed server-side on first
 * exchange.
 *
 * The code is stripped from the address bar immediately (before the network
 * round-trip) so it never lingers in history even if the exchange fails.
 * Returns `true` when a token was obtained and stored, `false` otherwise
 * (no code present, or exchange rejected). Idempotent and safe on every load.
 */
export async function redeemDashboardPairCode(): Promise<boolean> {
  if (typeof window === "undefined") return false;
  const match = /[#&]pair=([^&]+)/.exec(window.location.hash);
  const raw = match?.[1];
  if (!raw) return false;

  // Strip first: the code must not linger in the URL/history regardless of
  // exchange outcome.
  stripHashParam("pair");

  let code: string;
  try {
    code = decodeURIComponent(raw);
  } catch {
    return false;
  }

  try {
    const res = await fetch(`${window.location.origin}/api/dashboard/pair`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    });
    if (!res.ok) return false;
    const body = (await res.json()) as { token?: unknown };
    if (typeof body.token !== "string" || body.token.length === 0) return false;
    window.localStorage.setItem(DASHBOARD_TOKEN_STORAGE_KEY, body.token);
    return true;
  } catch {
    // Network/daemon error — the operator can re-run `grith dashboard pair`.
    return false;
  }
}
