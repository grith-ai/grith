# Cutover and forward-fix checklist

## Before enabling uploads

- [ ] Rust and TypeScript validate the same schema-v1 fixtures.
- [ ] Audit producers stamp explicit class/category/config/filter/pricing and
      safe destination/security fields using audit hash version 3.
- [ ] Audit hash v1/v2 fixtures remain unchanged; no existing record is rewritten.
- [ ] Size-based audit DB rotation is retired or generation-safe before the
      sequence tailer is enabled.
- [ ] One audit owner exclusively runs materialization/upload/archive work.
- [ ] Durable consent version and prospective chain/database baseline exist.
- [ ] Free API serialization is proven not to contain Pro fields.
- [ ] Trial, expiry, paid-through cancellation, logout, reauthorization and
      actor-change tests pass.
- [ ] Empty v2 PostgreSQL tables and archive prefix are deployed.
- [ ] The old raw `/sync` endpoint and every raw-table consumer are removed in
      the same cutover. No dual write or backfill is enabled.
- [ ] Privacy/DPA/onboarding copy names every uploaded field family and retention.

## Cutover

1. Deploy schemas/read models/routes with ingest disabled.
2. Deploy v2 clients with local materializer enabled and cloud sends held.
3. Verify local Free/Pro parity, load, rebuild and archive checksums.
4. Enable v2 registration and ingest for internal teams.
5. Run 50-device, 25-seat freshness/load and destructive-rebuild exercises.
6. Enable v2 publicly, repoint all dashboards, remove raw sync, then drop the
   development/test cloud raw table without copying rows.

## Forward fix

- Published schema-v1 meanings are immutable. Additive optional fields require
  schema review and a new schema version; semantic changes require a new
  registry/materializer version or protocol version.
- On an ingest defect, disable v2 ingest and keep local days dirty. Do not
  restore legacy raw sync. After the server fix, clients reconcile state and
  resend complete days at higher revisions where necessary.
- On a bad local materializer release, build a new local read-model generation
  from the prospective baseline, compare golden/archive checksums, and activate
  it atomically. Never edit accepted rows in place.
- On a bad cloud read model, rebuild into staging from active manifests and
  atomically switch generation after parity checks. Preserve the old generation
  until rollback TTL expires.
- A source reset is reserved for lost source history/generation discontinuity;
  it is not a shortcut for correcting aggregate code.

