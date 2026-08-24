# Canonical ordering and checksums

These rules are normative for protocol v2/schema v1.

## Normalisation

- Optional empty dimensions become the literal sentinel `<unknown>` before
  aggregation. “Not applicable” is `<not-applicable>` and is never conflated
  with unknown.
- Display labels preserve Unicode and case. Leading/trailing whitespace is
  removed and runs of ASCII whitespace collapse to one ASCII space. Limits are
  UTF-8 byte limits, not code-point limits. Overlong labels are rejected; they
  are never silently truncated into collisions.
- Filter IDs are trimmed, ASCII-lowercased, `_` becomes `-`, and the result must
  match `^[a-z0-9]+(?:-[a-z0-9]+)*$`. Evaluated IDs are sorted by raw UTF-8
  bytes and deduplicated, maximum 64.
- Positive filter contributions are sorted by normalized filter ID, unique,
  strictly positive, and must reference an evaluated ID.

## Fixed point

- One score unit is `1,000,000` score micros. One USD is `1,000,000` cost
  micros. Float adapters round to nearest integer, half away from zero.
- An individual score is in `[-100,000,000,+100,000,000]` micros.
- `score_sum_micros` is signed and JSON-safe:
  `[-9,007,199,254,740,991,+9,007,199,254,740,991]`. Validation additionally
  checks `abs(score_sum_micros) <= event_count * 100,000,000` with
  overflow-safe integer arithmetic.
- Histogram v1 has 30 half-point bins over `[0,15]`. Only bucket selection
  clamps values outside that interval; stored scores and sums are not clamped.
- Counters and costs are non-negative JSON-safe integers.

## Snapshot row order

Rows compare field-by-field in the order below. Strings compare by UTF-8 bytes;
enums compare in registry order; null sorts before a value.

1. usage: `bucket_start, project, profile_id, config_hash, supervised_tool,
   record_class, category, verdict, score_bucket`;
2. filter: `day, project, profile_id, config_hash, filter_set_version, filter_id`;
3. session: `day, session_id, project, profile_id, config_hash, supervised_tool`;
4. LLM: `day, project, provider, model, currency, price_source, pricing_version`;
5. destination: `day, kind, destination_hmac, hmac_key_version,
   approved_display_label, verdict`;
6. security events: `event_id, event_revision`;
7. config versions: `config_hash`.

## Row checksum

`row_checksum_sha256` is lowercase SHA-256 over compact UTF-8 JSON containing,
in this exact object-field order:

```text
day, source_event_count, first_event_at, last_event_at,
first_chain_sequence, last_chain_sequence, last_chain_hash,
usage_rows, filter_rows, session_rows, llm_rows, destination_rows
```

Arrays must first use the canonical order above. Timestamps use UTC RFC 3339
with `Z` and **exactly six fractional digits** (microsecond precision;
producers truncate toward zero at the adapter boundary, e.g.
`2026-08-20T10:15:00.000000Z`). This is normative for every timestamp in an
analytics payload, not just checksummed fields: a consumer that re-formats a
timestamp through a language date type with different sub-second precision
computes a different checksum for identical data. Consumers that only verify
checksums may treat timestamp values as opaque strings. Integers have no
decimal point; no insignificant whitespace is present. The checksum
deliberately excludes `day_revision`, snapshot state, `read_model_generation`,
and itself, so an identical row set has an identical checksum across
retry/rebuild metadata changes.

The request digest is lowercase SHA-256 of the exact decompressed HTTP body
bytes. `(device_id, request_seq)` stores this digest. The same sequence and
digest is an idempotent retry; the same sequence with a different digest is
`request_seq_digest_conflict`. `request_seq` never orders day revisions.

## Parquet archive

Rows follow `parquet-schema.json` and its sort order. `content_sha256` is over
the final encrypted-upload input object bytes, before transport encoding. A
manifest is valid only for the exact accepted `(device, epoch, day,
day_revision, row_checksum_sha256)` declared at presign time.

