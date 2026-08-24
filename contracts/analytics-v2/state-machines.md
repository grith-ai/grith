# Analytics v2 state machines

## Device registration and consent

```text
unregistered
  -- active Pro/trial + consent vN + human API key --> registered/active
registered/active -- credential rotate --> registered/active (version + 1)
registered/active -- revoke/logout --> revoked
revoked -- reauthorise --> new device_id + new source_epoch
```

Registration creates one immutable `(team, actor, device)` binding and returns
a device secret once. Both the human API key and device secret are required for
device routes. The local source baseline is prospective: `coverage_start` is no
earlier than consent acceptance and successful registration. Pre-registration
and pre-consent rows stay local and can never become dirty cloud days.

A team may register two active analytics devices per paid seat, capped at 50
for 25 seats. A runtime instance heartbeats every 30 seconds and owns a 90-second
lease. Concurrent use by another runtime instance during that lease fails with
`runtime_instance_conflict`; it does not silently share or transfer identity.

## Source epochs and audit DB generations

An epoch owns a half-open `[coverage_start, coverage_end)` interval. Exactly one
epoch per device is active and has no end. A reset locks the device, closes the
old interval, verifies `old.coverage_end <= new.coverage_start`, creates the new
epoch and baseline, and commits a gap declaration when history was lost.

The audit DB generation is separate from source epoch. Size rotation must be
retired before the v2 tailer ships; an unexpected generation change stops the
tailer until an authorised reset. A cursor is the tuple `(audit DB generation,
chain sequence, chain hash)`, never sequence alone.

## Local materializer and rebuild generation

Only the process holding the audit-writer ownership lock may run the
materializer, allocate day revisions/request sequences, export archives, or
upload. It reads a bounded audit batch, updates every affected rollup/dirty day,
and advances its cursor in one analytics-SQLite transaction.

Projection rebuild writes a new local `read_model_generation`; readers stay on
the old generation until the new generation validates and activates atomically.
Rebuild starts at the stored prospective v2 baseline, reads active and cold
segments, deduplicates by event ID, and never imports pre-cutover rows. Losing
underlying history requires a source reset rather than publishing lower totals
over the old coverage interval.

## Snapshot acceptance

```text
validate body/auth/bounds
  -> record/check (device_id, request_seq, body digest)
  -> for zero or one day: lock device/epoch/day
  -> compare day_revision (ordering authority)
  -> replace all five row families + day state in one transaction
  -> apply security-event revisions
  -> commit and acknowledge
```

An identical request sequence/digest is an idempotent retry. A different digest
at the same sequence is a conflict. A lower day revision is stale. Equal day
revision/equal checksum succeeds idempotently; equal revision/different
checksum conflicts. A higher revision completely replaces that device/epoch/day
and increments the server `read_model_generation` for that day. Event-only
requests skip day replacement.

Security events are keyed `(team_id, device_id, event_id)`. Equal revision and
content is idempotent; equal revision with different content conflicts; a higher
revision may change only resolution fields. Initial verdict, event time/type and
source identity are immutable. Queue approval/denial never rewrites headline
policy verdict counts.

## Normal sync, retry, stale arrival, and offline catch-up

```text
audit batch committed -> materializer transaction -> affected UTC days dirty
  -> current dirty day snapshot every 30s -> allocate request_seq -> persist exact body
  -> send -> accepted acknowledgement -> clear only acknowledged revision
```

A transport failure retries the exact persisted bytes with the same sequence.
Changing any byte allocates a new sequence. On an ambiguous restart, the client
queries state before discarding an outbox item. A stale lower day revision is
acknowledged as stale and the client reconciles to the server revision; it is
not repeatedly retried. Equal revision/checksum clears local work. Equal
revision/different checksum stops that source and requires investigation.

While offline, materialization and dirty-day revision allocation continue but
no cloud action blocks the audit writer. Reconnection first sends heartbeat,
then the current partial day/security events, followed by historical dirty days
oldest first within rate limits. A late event increments its original UTC day's
revision and replaces that complete day. The client does not mark source data
safe for local pruning until both the latest rollup revision and matching
archive revision are acknowledged.

## Heartbeat, freshness, and entitlement

Heartbeat renews the runtime lease and reports cursor/backlog/gaps. After 60
seconds without a heartbeat, the device is stale. On `audit_sync=false`, the
client sends one best-effort `sync_enabled=false` heartbeat and stops snapshots,
security events and archives. Missing data is shown as disabled/stale, not zero.

Trials have full Pro behavior. Cancellation remains active through the paid
period. At entitlement expiry—independent of general license grace—enhanced
local/cloud views and all uploads stop. Cloud data remains unavailable but
retained for 30 days; reactivation restores it. After 30 days it is deleted.
The local 90-day projection may continue materialising behind the Free API gate
so an upgrade has honest local history.

## Archive

Presign succeeds only when the declared `day_revision` and row checksum exactly
match the accepted day. Finalize re-verifies object key, size, checksum,
encryption metadata and Parquet schema, then activates one immutable archive
revision. A corrected day needs a higher archive revision. Superseded revisions
remain recoverable for seven days, then delete. Rollup acknowledgement never
counts as archive acknowledgement for retention safety.
