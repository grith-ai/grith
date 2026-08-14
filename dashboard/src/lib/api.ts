/**
 * Type-safe REST API client for the grith daemon.
 *
 * Base URL is derived from the current window origin so the dashboard works
 * both when served by the embedded grith-server and during Vite dev mode
 * (where requests are proxied to localhost:3141).
 */

import type {
  AnalyticsSummaryResponse,
  AuditExportFormat,
  AuditListResponse,
  AuditQuery,
  AuditRecord,
  CanaryCreateRequest,
  CanaryListResponse,
  CanaryToken,
  ChannelInfo,
  DigestActionRequest,
  DigestItem,
  DigestListResponse,
  ExfilStatsResponse,
  HealthResponse,
  InventoryResponse,
  ListenerRewritesResponse,
  NotificationEvent,
  Policy,
  PolicyListResponse,
  PolicyRules,
  ProxyStatusResponse,
  SessionDetailResponse,
  SessionListResponse,
  LicenseStatusResponse,
  TierResponse,
  OnboardingStatus,
} from "@/types/api";
import { csrfHeaders } from "./csrf";

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

interface ParsedApiError {
  code?: string;
  requiredTier?: string;
}

function parseApiErrorBody(body: string): ParsedApiError {
  try {
    const parsed = JSON.parse(body) as Record<string, unknown>;
    return {
      code: typeof parsed.code === "string" ? parsed.code : undefined,
      requiredTier:
        typeof parsed.required_tier === "string"
          ? parsed.required_tier
          : undefined,
    };
  } catch {
    return {};
  }
}

export class ApiError extends Error {
  /** Structured error code from JSON body (e.g. "FEATURE_GATED"), if present. */
  public readonly code: string | undefined;
  /** Required tier from FEATURE_GATED responses (e.g. "Pro"). */
  public readonly requiredTier: string | undefined;

  constructor(
    public readonly status: number,
    public readonly statusText: string,
    public readonly body: string,
  ) {
    super(ApiError.buildMessage(status, statusText, body));
    this.name = "ApiError";

    const { code, requiredTier } = parseApiErrorBody(body);
    this.code = code;
    this.requiredTier = requiredTier;
  }

  private static buildMessage(
    status: number,
    statusText: string,
    body: string,
  ): string {
    const code = parseApiErrorBody(body).code;
    if (code === "CSRF_REQUIRED" || code === "DASHBOARD_AUTH_REQUIRED") {
      // This browser hasn't paired with the daemon (opened the bare URL
      // directly, or its stored token was cleared). Point the operator at the
      // pairing command, which opens/prints a one-time link.
      return "This browser isn't authorised for the dashboard yet. Run `grith dashboard pair` (it opens or prints a one-time link), then reload.";
    }
    return `API error ${status} (${statusText}): ${body}`;
  }

  get isFeatureGated(): boolean {
    return this.code === "FEATURE_GATED";
  }

  /** True when the request was rejected by the dashboard CSRF / token guard. */
  get isCsrfRejected(): boolean {
    return (
      this.code === "CSRF_REQUIRED" || this.code === "DASHBOARD_AUTH_REQUIRED"
    );
  }
}

// ---------------------------------------------------------------------------
// Fetch wrapper
// ---------------------------------------------------------------------------

const BASE_URL = typeof window !== "undefined" ? window.location.origin : "";

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const url = `${BASE_URL}${path}`;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    // Dashboard CSRF / auth header — harmless on reads, required by the
    // daemon on browser-facing mutations. See lib/csrf.ts.
    ...csrfHeaders(),
    ...(options.headers as Record<string, string> | undefined),
  };

  let response: Response;
  try {
    response = await fetch(url, {
      ...options,
      headers,
    });
  } catch {
    throw new ApiError(0, "NetworkError", "grith daemon has stopped. Restart with grith exec or grith run.");
  }

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new ApiError(response.status, response.statusText, body);
  }

  // Handle 204 No Content
  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/api/health");
}

// ---------------------------------------------------------------------------
// Digest
// ---------------------------------------------------------------------------

export function getDigestItems(
  status?: string,
): Promise<DigestListResponse> {
  const params = status ? `?status=${encodeURIComponent(status)}` : "";
  return request<DigestListResponse>(`/api/digest${params}`);
}

export function approveDigest(
  id: string,
  notes?: string,
): Promise<DigestItem> {
  const body: DigestActionRequest = { action: "approve", notes };
  return request<DigestItem>(`/api/digest/${id}/approve`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function denyDigest(
  id: string,
  notes?: string,
): Promise<DigestItem> {
  const body: DigestActionRequest = { action: "deny", notes };
  return request<DigestItem>(`/api/digest/${id}/deny`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function learnDigest(
  id: string,
  notes?: string,
): Promise<DigestItem> {
  const body: DigestActionRequest = { action: "learn", notes };
  return request<DigestItem>(`/api/digest/${id}/learn`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/**
 * Clear all actionable digest items (pending + escalated) in one atomic call.
 * Dismisses them without approving (executing) or denying — for wiping a
 * backlog of stale items. Returns how many were cleared.
 */
export function clearAllDigest(): Promise<{
  status: string;
  cleared: number;
}> {
  return request<{ status: string; cleared: number }>(
    `/api/digest/clear-all`,
    { method: "POST" },
  );
}

export function escalateDigest(
  id: string,
  notes?: string,
): Promise<{ status: string; id: string }> {
  return request<{ status: string; id: string }>(`/api/digest/${id}/escalate`, {
    method: "POST",
    body: JSON.stringify({ notes }),
  });
}

export function unlockEgressDigest(
  id: string,
): Promise<{ status: string; action: string; id: string }> {
  return request(`/api/digest/${id}/unlock-egress`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function denyTerminateDigest(
  id: string,
): Promise<{ status: string; action: string; id: string }> {
  return request(`/api/digest/${id}/deny-terminate`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function allowAlwaysDigest(
  id: string,
): Promise<{ status: string; action: string; id: string }> {
  return request(`/api/digest/${id}/allow-always`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

// ---------------------------------------------------------------------------
// Tier
// ---------------------------------------------------------------------------

export function getTier(): Promise<TierResponse> {
  return request<TierResponse>("/api/tier");
}

export function getLicenseStatus(): Promise<LicenseStatusResponse> {
  return request<LicenseStatusResponse>("/api/license/status");
}

export function getOnboardingStatus(): Promise<OnboardingStatus> {
  return request<OnboardingStatus>("/api/onboarding/status");
}

export function dismissOnboarding(): Promise<{ dismissed: boolean }> {
  return request<{ dismissed: boolean }>("/api/onboarding/dismiss", {
    method: "POST",
  });
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

export function getAuditRecords(
  query?: AuditQuery,
): Promise<AuditListResponse> {
  const params = new URLSearchParams();

  if (query) {
    if (query.session_id) params.set("session_id", query.session_id);
    if (query.time_from) params.set("time_from", query.time_from);
    if (query.time_to) params.set("time_to", query.time_to);
    if (query.min_score !== undefined)
      params.set("min_score", String(query.min_score));
    if (query.action_filter)
      params.set("action_filter", query.action_filter.join(","));
    if (query.call_type_filter)
      params.set("call_type_filter", query.call_type_filter.join(","));
    if (query.limit !== undefined) params.set("limit", String(query.limit));
    if (query.offset !== undefined)
      params.set("offset", String(query.offset));
    if (query.include) params.set("include", query.include);
  }

  const qs = params.toString();
  return request<AuditListResponse>(`/api/audit${qs ? `?${qs}` : ""}`);
}

export function getAuditRecord(id: string): Promise<AuditRecord> {
  return request<AuditRecord>(`/api/audit/${id}`);
}

// ---------------------------------------------------------------------------
// PR 4 Phase G — Session-pinned binary inventory
// ---------------------------------------------------------------------------

/**
 * Fetch the session-pinned binary inventory ("binaries trusted this session").
 *
 * Returns an empty `entries` array with `binaries_pinned: 0` when the
 * session exists but the inventory hasn't been installed yet (Phase C
 * runs the FS walk in a background task — there's a small race window
 * after session start). Returns a 404 when the session is unknown.
 */
export function getInventory(sessionId: string): Promise<InventoryResponse> {
  return request<InventoryResponse>(`/api/inventory/${sessionId}`);
}

// ---------------------------------------------------------------------------
// PR 5 Phase E — Listener rewrites
// ---------------------------------------------------------------------------

/**
 * Fetch the per-session listener rewrites — every wildcard → loopback
 * clamp the supervisor performed for this session. Returns an empty
 * list (200, total=0) when the session has no clamp events (the
 * common case).
 */
export function getListenerRewrites(
  sessionId: string,
): Promise<ListenerRewritesResponse> {
  return request<ListenerRewritesResponse>(
    `/api/sessions/${sessionId}/listener-rewrites`,
  );
}

export function getExfilStats(): Promise<ExfilStatsResponse> {
  return request<ExfilStatsResponse>("/api/audit/exfil-stats");
}

export function exportAudit(
  format: AuditExportFormat = "json",
  query?: AuditQuery,
): Promise<Blob> {
  const params = new URLSearchParams();
  params.set("format", format);

  if (query) {
    if (query.session_id) params.set("session_id", query.session_id);
    if (query.time_from) params.set("time_from", query.time_from);
    if (query.time_to) params.set("time_to", query.time_to);
    if (query.min_score !== undefined)
      params.set("min_score", String(query.min_score));
    if (query.action_filter)
      params.set("action_filter", query.action_filter.join(","));
  }

  const url = `${BASE_URL}/api/audit/export?${params.toString()}`;
  // `/api/audit/export` is a token-gated sensitive read (item 4), so this raw
  // fetch must carry the dashboard CSRF / token header just like the wrapper.
  return fetch(url, { headers: { ...csrfHeaders() } }).then((res) => {
    if (!res.ok) throw new ApiError(res.status, res.statusText, "");
    return res.blob();
  });
}

// ---------------------------------------------------------------------------
// Supervisor Sessions
// ---------------------------------------------------------------------------

export function getSessions(): Promise<SessionListResponse> {
  return request<SessionListResponse>("/api/supervisor/sessions");
}

export function getSession(id: string): Promise<SessionDetailResponse> {
  return request<SessionDetailResponse>(`/api/supervisor/sessions/${id}`);
}

/**
 * Terminate a supervised session and its process tree. Returns the final
 * session stats. Operator-initiated — this kills a live process.
 *
 * Uses the supervisor route (not the IPC-auth-gated one) so the same-origin
 * dashboard can call it without a bearer token. Dead sessions are reaped
 * automatically by the daemon's always-on reaper, so the UI offers kill only.
 */
export function killSession(id: string): Promise<unknown> {
  return request(`/api/supervisor/sessions/${id}/kill`, { method: "POST" });
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

export function getProxyStatus(): Promise<ProxyStatusResponse> {
  return request<ProxyStatusResponse>("/api/proxy/status");
}

// ---------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------

export interface ShutdownResponse {
  status: string;
  message: string;
}

export function shutdownServer(): Promise<ShutdownResponse> {
  return request<ShutdownResponse>("/api/server/shutdown", {
    method: "POST",
  });
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

export function getNotificationChannels(): Promise<{
  channels: ChannelInfo[];
  total: number;
}> {
  return request("/api/notifications/channels");
}

export function getNotificationStatus(): Promise<{
  recent_events: NotificationEvent[];
}> {
  return request("/api/notifications/status");
}

export function testNotification(
  channel: string,
): Promise<{ status: string; channel: string }> {
  return request(`/api/notifications/test/${encodeURIComponent(channel)}`, {
    method: "POST",
  });
}

// ---------------------------------------------------------------------------
// Canary Tokens
// ---------------------------------------------------------------------------

export function listCanaries(): Promise<CanaryListResponse> {
  return request<CanaryListResponse>("/api/canaries");
}

export function addCanary(
  req: CanaryCreateRequest,
): Promise<CanaryToken> {
  return request<CanaryToken>("/api/canaries", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export function removeCanary(
  id: string,
): Promise<void> {
  return request<void>(`/api/canaries/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

export function rotateCanary(
  id: string,
): Promise<CanaryToken> {
  return request<CanaryToken>(
    `/api/canaries/${encodeURIComponent(id)}/rotate`,
    { method: "POST" },
  );
}

// ---------------------------------------------------------------------------
// Analytics (Pro)
// ---------------------------------------------------------------------------

export function getAnalyticsSummary(): Promise<AnalyticsSummaryResponse> {
  return request<AnalyticsSummaryResponse>("/api/analytics/summary");
}

// ---------------------------------------------------------------------------
// Policies (Enterprise)
// ---------------------------------------------------------------------------

export function listPolicies(): Promise<PolicyListResponse> {
  return request<PolicyListResponse>("/api/policies");
}

export function getPolicy(name: string): Promise<Policy> {
  return request<Policy>(`/api/policies/${encodeURIComponent(name)}`);
}

export function createPolicy(
  name: string,
  description: string,
  rules: PolicyRules,
): Promise<Policy> {
  return request<Policy>("/api/policies", {
    method: "POST",
    body: JSON.stringify({ name, description, rules }),
  });
}

export function updatePolicy(
  name: string,
  update: { description?: string; rules?: PolicyRules },
): Promise<Policy> {
  return request<Policy>(`/api/policies/${encodeURIComponent(name)}`, {
    method: "PUT",
    body: JSON.stringify(update),
  });
}

export function deletePolicy(name: string): Promise<void> {
  return request<void>(`/api/policies/${encodeURIComponent(name)}`, {
    method: "DELETE",
  });
}
