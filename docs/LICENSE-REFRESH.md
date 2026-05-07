# Licence Refresh & Offline Behaviour

**Audience:** customers (activation/troubleshooting), security reviewers (bypass
resistance), enterprise buyers (air-gapped operation).

**Authoritative spec:** [`work/60-licence-refresh-and-gating-hardening-plan.md`](../work/60-licence-refresh-and-gating-hardening-plan.md).
This document is the operator-facing companion: the implemented behaviour, the
threat model, and the configuration paths for unusual deployments.

---

## TL;DR

- A logged-in Pro/Enterprise daemon contacts `grith.ai/api/license/validate`
  approximately every 24 hours.
- Successful refreshes atomically replace `~/.config/grith/license.key` with a
  fresh signed payload and bump `Credentials::last_validated`.
- A short network outage is invisible: the cached signed licence keeps working
  through its natural expiry (default 7 days) plus a 1-day grace + 3-day
  extended-grace window.
- Air-gapped enterprise customers receive a long-lived (365-day) licence
  flagged `air_gapped:true`, which disables scheduled refresh entirely and
  preserves the legacy 7/30-day grace windows.
- Hard failures (subscription revoked, API key invalid) do **not** immediately
  downgrade the daemon. The cached signed licence remains valid until natural
  expiry; meanwhile dashboards and `grith pro status` surface the failure.

---

## What gets called when

| Event                     | Endpoint                          | Frequency / trigger                            |
|---------------------------|-----------------------------------|------------------------------------------------|
| Scheduled refresh         | `POST /api/license/validate`      | When `last_validated` is ≥ 24h old             |
| On-demand refresh         | `POST /api/license/validate`      | `grith pro refresh`                            |
| Initial activation        | `GET  /api/license`               | `grith pro login` / `grith pro activate`       |
| No traffic at all         | —                                 | Air-gapped licence (`air_gapped:true`)         |

The scheduler wakes inside the daemon's existing background task. There is no
separate process or system-level cron — refresh stops when the daemon stops.

### Refresh outcomes

The scheduler treats every response as one of four normalized outcomes:

| Outcome      | Triggered by                                                        | Effect on cached licence                  |
|--------------|---------------------------------------------------------------------|-------------------------------------------|
| Replaced     | `2xx { valid: true, license: <signed payload> }`                    | File rewritten atomically; gate refreshed |
| Acknowledged | `2xx { valid: true, license: null }`                                | `last_validated` bumped; no file change   |
| Hard         | `2xx { valid: false }` / `401` / `403` / other 4xx                  | Cached licence retained until natural expiry; failure surfaced to UI |
| Transient    | DNS, TLS, connection, timeout, `5xx`                                | Backoff retry (15min → 1h → 6h, capped at 48h total) |

Hard failures **never** roll the licence back early. The signed file on disk is
the source of truth for entitlement; refresh is an enforcement bound, not the
gate itself.

---

## Grace windows after natural expiry

Default (refresh-eligible) licences:

| Window       | Duration past `valid_until` | Behaviour                              |
|--------------|-----------------------------|----------------------------------------|
| Valid        | < 0 (still valid)           | Full Pro/Enterprise features           |
| GracePeriod  | 0–1 day                     | Pro features + soft warning            |
| ExtendedGrace| 1–3 days                    | Pro features + strong warning + dashboard banner |
| Expired      | > 3 days                    | Daemon downgrades to Community         |

Air-gapped (`air_gapped:true`) licences keep the legacy generous windows since
they cannot refresh:

| Window        | Duration past `valid_until` |
|---------------|-----------------------------|
| GracePeriod   | 0–7 days                    |
| ExtendedGrace | 7–30 days                   |
| Expired       | > 30 days                   |

These windows are computed in `evaluate_license()` in
`crates/grith-core/src/license.rs`.

---

## Operator commands

```bash
grith pro status     # plan, last_validated, hours-since-refresh, next attempt,
                     # last failure (kind + reason), air-gapped state
grith pro refresh    # force an on-demand refresh now (transient/hard outcomes
                     # are handled the same way the scheduler handles them)
grith pro activate   # one-shot fetch via GET /api/license (used after login)
grith pro logout     # remove credentials and the cached licence file
```

`grith pro status` reads the daemon's live refresh state from
`http://127.0.0.1:<port>/api/license/status` when the daemon is running.
If the daemon isn't running, it falls back to the on-disk
`Credentials::last_validated` and prints a hint to start the daemon.

---

## Dashboard surfacing

The Billing page renders a banner when refresh has failed:

- Hard failure (`unauthorized` / `revoked`) → red banner with remediation
  ("Run `grith pro login`" / "Renew in dashboard").
- Transient failure → yellow banner ("Network failure — daemon will retry").
- Air-gapped licence → muted banner explaining scheduled refresh is disabled.

Programmatic consumers can poll `GET /api/license/status` for:

```jsonc
{
  "tier": "pro",
  "seats": 2,
  "renewal_date": "2026-05-04",
  "billing_portal_url": "https://grith.ai/...",
  "air_gapped": false,
  "hours_since_refresh": 4,
  "refresh": {
    "last_success": "2026-04-27T10:00:00Z",
    "last_failure": null,
    "last_failure_kind": null,
    "last_failure_reason": null,
    "next_attempt": "2026-04-28T10:00:00Z",
    "air_gapped": false,
    "successes_total": 17,
    "failures_total": 0
  }
}
```

`/api/tier` returns the same `refresh` snapshot as a sub-object alongside the
existing tier and feature-list fields.

---

## Security: bypass resistance and what refresh does *not* do

The grith core is MPL-2.0 and ships with the Ed25519 verifier and the
`FeatureGate::allows()` switch in readable Rust. A determined attacker
rebuilding the OSS code with `verify_license` returning `Ok` unconditionally
(or with `allows()` returning `true` for everything) can unlock local-only Pro
features in their custom build.

The licence-refresh model **does not** prevent that, and is not advertised as
doing so. What it does:

1. **Bounds staleness for unmodified clients.** An unmodified daemon that has
   not contacted grith.ai in `7 days + 3 days = 10 days` will downgrade itself
   to Community. A revoked subscription can no longer keep an unmodified
   client running indefinitely on its last issued licence.
2. **Distinguishes server-dependent and local-only Pro features.** Hot-path
   filters (adaptive scoring, custom filters), notification dispatch, and
   anything else that runs entirely on the client are still gated by the local
   `FeatureGate`; they remain modifiable by recompiled OSS builds. Anything
   that calls authenticated `grith.ai/api/*` endpoints (cloud sync, team
   policies, learned-rules sync, provider-key sync, device auth) is enforced
   server-side and is unaffected by client-side patches.
3. **Keeps signed-payload trust intact.** The signature, canonicalization, and
   `air_gapped` flag are all part of the canonical signed payload. Old
   long-lived licences without `air_gapped` continue to verify because the
   verifier reads the field's presence in the JSON and chooses the matching
   canonicalization.

If the local-only bypass becomes commercially material, the follow-up path is
to move local-only Pro modules into a closed-source companion crate
(option 2 in `work/60` §"Signature-verification hardening"), at which point
those features are literally absent from the OSS build rather than gated
inside it.

### What the daemon writes / does not write

- Refreshes write only `~/.config/grith/license.key` (atomic, 0600) and
  `~/.config/grith/credentials.json` (atomic, 0600). No other files are
  touched as part of a refresh.
- API responses with the API key in headers are **not** logged. The
  `last_failure_reason` surfaced to dashboards is sanitized (length-capped,
  whitespace-collapsed) before being stored in `RefreshState`.
- Air-gapped licence detection logs a single auditable notice on startup;
  the scheduler then sleeps and never makes a network call.

---

## Air-gapped / contract deployments

For customers in regulated, air-gapped, or otherwise high-trust-boundary
environments:

1. The customer signs a contract with grith.ai for an air-gapped licence.
2. grith.ai issues a 365-day signed licence with `air_gapped:true` in the
   canonical payload.
3. The customer drops the licence file at
   `~/.config/grith/license.key` (or the agreed shared path) on each host.
4. On startup, the daemon detects `air_gapped:true`, logs:
   `air-gapped licence active — scheduled refresh disabled`,
   and never contacts grith.ai for the lifetime of that licence.
5. Renewal is delivered out-of-band (signed email, shared filesystem, secure
   file transfer); the customer replaces `license.key` and restarts the
   daemon (or `grith pro refresh` is a no-op for air-gapped, so a clean
   restart is the canonical path).

Cloud-dependent Pro features (cloud sync, team policy distribution, learned-
rules sync, provider-key sync, device auth) remain unavailable in air-gapped
mode by definition — the customer either accepts that, or operates a private
mirror of the grith.ai API surface under the contract.

---

## FAQ

**Q. My laptop was offline for a week. Will it still work?**
A. Yes — for default licences, the cached licence is signed for 7 days and
keeps working through the 1-day grace + 3-day extended grace window. You
have ~10 days from the last successful refresh before the daemon
downgrades. `grith pro status` will show the warning.

**Q. I rotated my API key. What happens?**
A. The next scheduled refresh will return `401`/`403`. The daemon logs an
error, the dashboard banner turns red with "Run `grith pro login`" guidance,
but the cached signed licence keeps working until its natural `valid_until`.
Once you log in again, the next scheduled refresh resumes.

**Q. grith.ai is down. Will my workflow break?**
A. No. Transient failures retry with backoff (15min → 1h → 6h, up to 48h).
A multi-day outage is invisible to users running with valid licences.

**Q. Can I disable refresh on a development machine?**
A. The intended path is to stay logged out (`grith pro logout`); the daemon
runs in Community tier and never schedules refresh. There is no per-host
flag to disable refresh while holding a Pro licence — air-gapped operation
requires a contract-issued `air_gapped` licence.

**Q. How do I tell if I have an air-gapped licence?**
A. `grith pro status` prints "Refresh: disabled (air-gapped contract licence)"
when the active licence has `air_gapped:true`. The startup log line
"air-gapped licence active" is the corresponding daemon-side indicator.

---

## Implementation pointers

- Scheduler: `crates/grith-core/src/daemon/background.rs`
  (`spawn_license_revalidation`, `run_license_refresh`, `RefreshOutcome`).
- Atomic licence write: `save_license_to` in `crates/grith-core/src/license.rs`.
- Grace window logic: `evaluate_license` in the same file (constants
  `GRACE_PERIOD_DAYS_*` and `EXTENDED_GRACE_DAYS_*`).
- Refresh state types: `grith_digest::notification::{RefreshState, RefreshFailureKind}`.
- API surface: `crates/grith-server/src/routes/health.rs::get_license_status`
  (and the `refresh` field on `get_tier`).
- CLI: `crates/grith-core/src/commands/pro.rs::{cmd_pro_status, cmd_pro_refresh}`.
- Dashboard: `dashboard/src/pages/Billing.tsx::RefreshBanner`.
