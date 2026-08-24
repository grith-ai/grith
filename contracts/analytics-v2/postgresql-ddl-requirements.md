# PostgreSQL DDL acceptance contract

The executable schema is owned by the cloud repository at
`grith-website/packages/db/migrations/0018_analytics_v2.sql`. This file is the
cross-repository acceptance contract for that migration; it is deliberately
not a second copy of the SQL.

The migration must create these final tables and no legacy compatibility view:

- `analytics_devices`, `analytics_source_epochs`, `analytics_device_state`;
- `analytics_request_receipts`, `analytics_config_versions`,
  `analytics_day_snapshots`;
- `usage_rollup_hourly`, `filter_rollup_daily`, `session_day`,
  `llm_rollup_daily`, `destination_rollup_daily`;
- `security_events`, `analytics_archive_manifests`, and
  `analytics_rebuild_jobs`.

The following checks block acceptance:

1. `team_id` is `uuid`, `actor_user_id` is bounded `text`, and device IDs,
   source epochs, event IDs and manifest IDs are UUIDs.
2. Every device-owned table has a composite foreign-key path through
   `(team_id, device_id)`; supplying a device UUID cannot cross a team.
3. Source-epoch coverage is half-open and non-overlapping. There is one active
   epoch per device and one active runtime lease.
4. `(device_id, request_seq)` is unique and stores the request digest.
5. Day state is unique by `(team_id, device_id, source_epoch, day)`. Each of
   the five rollup families includes those ownership/day columns in its key so
   a locked day can be replaced atomically.
6. All enum-like values use `CHECK` constraints equal to `registries.json`.
   Scores are signed, individual bounds are +/-100,000,000, aggregate sums are
   signed JSON-safe integers, and counters/costs are non-negative JSON-safe
   integers. Application validation additionally enforces
   `abs(score_sum_micros) <= event_count * 100000000` with overflow-safe math.
7. Project, profile, tool, provider, model, filter, pricing and destination
   fields have the UTF-8 byte bounds in `protocol-constants.json`. SQL character
   limits do not replace the request byte validator.
8. LLM keys include non-null currency, `price_source`, and `pricing_version`.
   Destination keys include kind, HMAC key version and verdict.
9. Security-event identity is globally idempotent for one owning device and a
   higher revision cannot rewrite immutable source fields.
10. Exactly one archive manifest revision is active per
    `(team_id, device_id, source_epoch, day)`. Object keys are unique and
    manifest state supports verified, active, superseded and deletion times.
11. Dashboard range indexes lead with `(team_id, time_bucket)`; device-state,
    actor, project, archive cleanup and per-team retention predicates have
    bounded indexes. `security_events` remains unpartitioned in schema v1.
12. Team deletion cascades through all PostgreSQL analytics tables. The schema
    does not claim that this deletes S3 objects; the object deletion job remains
    part of the team-deletion state machine.
13. The cutover migration drops `audit_records` only after every application
    consumer and the old raw sync route are removed. It contains no copy,
    backfill, dual-write trigger or compatibility view.

Validation must run the migration from an empty database and against a clone
of the latest pre-cutover schema on the deployed PostgreSQL major version.
Both runs execute catalog assertions for all keys, constraints and indexes,
then exercise one atomic higher-revision replacement, one same-sequence digest
conflict, cross-team foreign-key rejection, bounded retention deletes and full
team cascade. The cloud change records the tested PostgreSQL version and the
SHA-256 of the accepted migration in its review evidence.
