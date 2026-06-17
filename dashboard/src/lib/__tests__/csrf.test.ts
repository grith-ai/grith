import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DASHBOARD_CSRF_HEADER,
  DASHBOARD_CSRF_SENTINEL,
  DASHBOARD_TOKEN_STORAGE_KEY,
  captureDashboardTokenFromUrl,
  csrfHeaders,
  getDashboardCsrfValue,
  redeemDashboardPairCode,
} from "../csrf";

describe("dashboard csrf header", () => {
  afterEach(() => {
    window.localStorage.removeItem(DASHBOARD_TOKEN_STORAGE_KEY);
    window.history.replaceState(null, "", "/");
  });

  it("falls back to the public sentinel when no token is stored", () => {
    expect(getDashboardCsrfValue()).toBe(DASHBOARD_CSRF_SENTINEL);
  });

  it("uses the stored dashboard token when present", () => {
    window.localStorage.setItem(DASHBOARD_TOKEN_STORAGE_KEY, "secret-token");
    expect(getDashboardCsrfValue()).toBe("secret-token");
  });

  it("emits the header under the agreed name", () => {
    const headers = csrfHeaders();
    expect(headers[DASHBOARD_CSRF_HEADER]).toBe(DASHBOARD_CSRF_SENTINEL);
  });

  it("captures a #token= launch fragment into localStorage and strips it", () => {
    window.history.replaceState(null, "", "/dashboard#token=launch-secret");
    captureDashboardTokenFromUrl();

    expect(window.localStorage.getItem(DASHBOARD_TOKEN_STORAGE_KEY)).toBe(
      "launch-secret",
    );
    // Token must no longer be visible in the URL.
    expect(window.location.hash).toBe("");
    expect(window.location.pathname).toBe("/dashboard");
    // Subsequent header now carries the real token.
    expect(csrfHeaders()[DASHBOARD_CSRF_HEADER]).toBe("launch-secret");
  });

  it("is a no-op when no token fragment is present", () => {
    window.history.replaceState(null, "", "/audit");
    captureDashboardTokenFromUrl();
    expect(window.localStorage.getItem(DASHBOARD_TOKEN_STORAGE_KEY)).toBeNull();
    expect(getDashboardCsrfValue()).toBe(DASHBOARD_CSRF_SENTINEL);
  });

  it("preserves other hash content when stripping the token param", () => {
    window.history.replaceState(null, "", "/p#token=abc123&view=grid");
    captureDashboardTokenFromUrl();
    expect(window.localStorage.getItem(DASHBOARD_TOKEN_STORAGE_KEY)).toBe(
      "abc123",
    );
    expect(window.location.hash).toBe("#view=grid");
  });
});

describe("dashboard pairing code", () => {
  afterEach(() => {
    window.localStorage.removeItem(DASHBOARD_TOKEN_STORAGE_KEY);
    window.history.replaceState(null, "", "/");
    vi.restoreAllMocks();
  });

  it("does nothing and makes no request when no #pair= is present", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    window.history.replaceState(null, "", "/audit");
    const ok = await redeemDashboardPairCode();
    expect(ok).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("exchanges the code for a token, stores it, and strips the URL", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ token: "real-token" }), { status: 200 }),
    );
    window.history.replaceState(null, "", "/#pair=one-time-code");

    const ok = await redeemDashboardPairCode();

    expect(ok).toBe(true);
    // Code is stripped from the URL immediately (before/around the exchange).
    expect(window.location.hash).toBe("");
    // Token stored and now carried in the header.
    expect(window.localStorage.getItem(DASHBOARD_TOKEN_STORAGE_KEY)).toBe(
      "real-token",
    );
    expect(csrfHeaders()[DASHBOARD_CSRF_HEADER]).toBe("real-token");
    // Posted the code to the pairing endpoint.
    const call = fetchSpy.mock.calls[0];
    expect(call).toBeDefined();
    const [url, init] = call!;
    expect(String(url)).toContain("/api/dashboard/pair");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({ code: "one-time-code" });
  });

  it("returns false and stores no token when the exchange is rejected", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ code: "PAIR_CODE_INVALID" }), {
        status: 401,
      }),
    );
    window.history.replaceState(null, "", "/#pair=stale-code");

    const ok = await redeemDashboardPairCode();

    expect(ok).toBe(false);
    // Even on failure, the code must not linger in the URL.
    expect(window.location.hash).toBe("");
    expect(window.localStorage.getItem(DASHBOARD_TOKEN_STORAGE_KEY)).toBeNull();
  });
});
