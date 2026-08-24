# Analytics v2 canonical contract

This directory is the source of truth for the Grith analytics protocol. It is
versioned independently of deployment code:

- protocol version: `2`;
- schema version: `1`;
- materializer version: `1`;
- JSON Schema dialect: draft 2020-12.

The schemas describe the only analytics payloads accepted by the service and
the explicit Free and Pro local read contracts. Rust code lives in
`crates/grith-analytics`; TypeScript and server implementations consume these
schemas and the fixtures here rather than maintaining handwritten variants.

## Artifact index

| Frozen artifact | Path |
|---|---|
| JSON request/response/error contracts | `schema/` |
| Shared positive and negative cases | `fixtures/{valid,invalid}/` |
| Protocol/product limits | `protocol-constants.json` |
| Category/filter/completeness/pricing registries | `registries.json` |
| Canonical ordering, fixed point and checksums | `canonical-ordering-and-checksums.md` |
| Row-level archive projection | `parquet-schema.json` |
| PostgreSQL migration acceptance rules | `postgresql-ddl-requirements.md` |
| Panel/query/access definitions | `panel-query-access-matrix.md` |
| Registration/sync/reset/archive/lapse state machines | `state-machines.md` |
| Retention, deletion, lapse and RBAC | `retention-lapse-deletion.md` |
| Uploaded/excluded privacy fields and consent inputs | `privacy-field-dictionary.md` |
| Atomic cutover and forward fix | `cutover-forward-fix-checklist.md` |

Each fixture names a `$defs` entry from `schema/common.schema.json`. Consumers
must validate the nested `value`, apply the named optional semantic validator,
and assert the `valid` result. `cargo test -p grith-analytics` validates every
schema and fixture, registry parity, canonical snapshot checksums and the
Parquet identity/pricing/privacy invariants. TypeScript uses the same files.

## Route map

| Method and route | Authentication | Schema |
|---|---|---|
| `POST /analytics/v2/devices/register` | human API key | `registration-{request,response}` |
| `POST /analytics/v2/devices/credentials/rotate` | human API key + current device secret | `credential-rotation-{request,response}` |
| `POST /analytics/v2/devices/revoke` | human API key + device secret | `device-revocation-{request,response}` |
| `POST /analytics/v2/heartbeat` | human API key + device secret | `heartbeat-{request,response}` |
| `POST /analytics/v2/snapshots` | human API key + device secret | `snapshot-{request,response}` |
| `GET /analytics/v2/state?device_id=<uuid>` | human API key + device secret | `state-{query,response}` |
| `POST /analytics/v2/source/reset` | human API key + device secret | `source-reset-{request,response}` |
| `POST /analytics/v2/archive/presign` | human API key + device secret | `archive-presign-{request,response}` |
| `POST /analytics/v2/archive/finalize` | human API key + device secret | `archive-finalize-{request,response}` |
| `GET /api/analytics/v2/free` | local dashboard token | `local-free-response` |
| `GET /api/analytics/v2/pro` | local dashboard token + active Pro analytics entitlement | `local-pro-response` |

Every error uses `structured-error.schema.json`. An `8 MiB` request limit is
checked before JSON parsing. Supplying `device_id` never establishes identity:
the server binds it to the human API key and device secret.

## Frozen semantics

- Device registration is prospective. No event before `coverage_start` or the
  recorded consent acceptance may be uploaded.
- An epoch covers a half-open interval `[coverage_start, coverage_end)`. Only
  the active epoch has a null end, and epochs for one device never overlap.
- One request contains at most one complete UTC-day replacement. A request may
  contain only security events.
- `day_revision` orders replacements. `request_seq` plus request digest detects
  transport replay and same-sequence/different-content conflicts; it never
  orders day state.
- Security-event identity is `(team_id, device_id, event_id)`. A higher
  `event_revision` may add or change resolution fields, but never changes the
  immutable initial verdict used in headline analytics.
- An archive manifest binds the exact accepted `day_revision`; a newer day
  revision requires a newer archive revision.
- Destination HMAC key rotation starts a separate trend segment. Clear labels
  apply prospectively after the team setting's effective time.
- All calendar buckets are UTC. Scores and costs use integer millionths.

See `state-machines.md`, `canonical-ordering-and-checksums.md`, and
`retention-lapse-deletion.md` for normative failure and lifecycle behavior.
