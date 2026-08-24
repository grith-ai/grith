# Privacy field dictionary and consent inputs

This is the schema-v1 source for product, privacy notice, DPA and onboarding
copy. Pro/trial cloud analytics is opt-in during authorisation and starts at the
recorded prospective `coverage_start`; no earlier local record is uploaded.

| Field family | Examples | Purpose | Treatment |
|---|---|---|---|
| Account ownership | team UUID, opaque actor user ID, registered device UUID/display name | team and device access control; actor/device comparisons | actor ID is a string because the auth provider ID is not a UUID; display name is not placed in Parquet |
| Source and freshness | source epoch, runtime instance, versions, completeness, timestamps, cursor/chain bounds, gaps and drop counts | retry correctness, coverage and freshness UI | bounded operational metadata; runtime identity is lease-scoped |
| Work grouping | session UUID, clear project label, profile/config hash and versions, supervised tool | project/session/profile/tool panels and config drift | project labels are clear text in v1 and may be commercially sensitive |
| Decision analytics | record class, category, immutable initial verdict, score micros/bin, evaluated filters and positive contributions | stable counts, rates, score and filter effectiveness | canonical bounded registries; no operands or free-form explanation |
| LLM accounting | provider, model, prompt/completion token counts, USD cost micros, price source/version | cost and model panels; explain historical estimates | no prompt or response content |
| Destinations | destination kind, team-scoped HMAC/key version, optional approved display label | destination trends | HMAC is default; clear labels are prospective owner/admin opt-in; keys are team scoped |
| Security events | queue/deny/canary/gap type, revision, resolution state/time/code, top filter IDs, structured enforcement code | Security events timeline and resolution workflow | no command, raw path/URL or free-form reason |
| Archive manifest | object key/version, schema/materializer version, checksum, size/count/time/chain bounds, state timestamps | validate, retain, rebuild and delete the daily projection | object-specific encrypted storage metadata |

The row-level Parquet projection uses exactly `parquet-schema.json`. Its
`excluded_fields` list is normative: command/arguments, raw paths and URLs,
prompts/responses, file/source/payload contents, environment values, task
context and free-form decision reasons are not uploaded in this release.

Consent copy must state that Pro/trial sends structured event metadata,
cumulative snapshots, security events and a daily row-level analytics
projection to Grith; normally connected data appears within 60 seconds at p95;
project names are clear; destinations are team-HMACed unless clear labels are
enabled; default cloud retention is 90 days; lapse hides cloud data for a
30-day reactivation period before deletion; disabling `audit_sync` stops every
cloud data plane; and client-computed analytics are never used for billing.
