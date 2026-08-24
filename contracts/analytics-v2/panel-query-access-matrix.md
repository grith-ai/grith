# Panel, query, and access matrix

All ranges are calendar-aligned UTC dates. “7 days” is today plus six prior
dates; 30/90 follow the same rule. The current date is labelled partial.
A UTC week is ISO 8601: Monday `00:00:00.000000Z` through the following
Sunday's final microsecond. “Current week” is the partial week containing
today; “prior week” is the last complete week before it.
Primary decision panels always filter `record_class = decision`.
The cloud source names below are the final PostgreSQL table names. The local
SQLite projection stores the same row families under its own names:
`analytics_usage_hourly`, `analytics_filter_daily`, `analytics_session_day`,
`analytics_llm_daily`, `analytics_destination_daily`, and
`analytics_security_events` map to the cloud sources in row-family order
below. A range includes a
row only when its UTC `bucket_start`/`day` is between the inclusive selected
dates; hourly rows on the partial current day are included through the latest
materialized hour. Identity groupings always retain `source_epoch` internally,
even when that key is not displayed.

| Surface / panel | Access | Window | Source | Formula / grouping |
|---|---|---:|---|---|
| Free: decision summary | Free local | 7d | `analytics_usage_hourly` | filter decisions; sum counts by immutable initial verdict; rates use total decision count |
| Free: audit health | Free local | current | local chain + projection state | chain health, latest record, materialized cursor/gaps |
| Free: recent queue/deny | Free local | latest 20 | `analytics_security_events` | initial verdict queue/deny, order `(occurred_at,event_id)` descending; resolution shown separately |
| Free: Pro preview | Free local | - | static contract | no Pro payload fields are returned |
| Overview: verdict trend | Pro local/cloud | 30/90d | `usage_rollup_hourly` | filter decisions; sum `event_count` by UTC hour/day and immutable verdict |
| Overview: week comparison | Pro local/cloud | current/prior UTC week | `usage_rollup_hourly` | filter decisions; exact sum of each aligned week; label partial current week |
| Risk: category trend | Pro local/cloud | 30/90d | `usage_rollup_hourly` | filter decisions; sum count and signed score sum/count by category |
| Risk: score histogram | Pro local/cloud | 30/90d | `usage_rollup_hourly` | filter decisions with non-null bucket; sum count across 30 version-1 buckets; average is sum(score_sum)/sum(count) over decision rows |
| Filters: effectiveness | Pro local/cloud | 30/90d | `filter_rollup_daily` | sum by filter/version; triggered/evaluated and denied-positive/denied-evaluated; zero denominator displays no rate |
| Projects | Pro local/cloud | 30/90d | `usage_rollup_hourly` + `session_day` | clear project label; decision sum and exact distinct `(device_id,session_id)` |
| Sessions | Pro local/cloud | 30/90d | `session_day` | exact distinct `(device_id,session_id)`; never sum daily distincts |
| Profiles/config drift | Pro local/cloud | 30/90d | `usage_rollup_hourly` + `analytics_config_versions` | filter decisions; group profile/config and join effective threshold/policy versions |
| Supervised tools | Pro local/cloud | 30/90d | `usage_rollup_hourly` + `session_day` | decision sum and exact distinct sessions grouped by tool |
| LLM cost | Pro local/cloud | 30/90d | `llm_rollup_daily` + `session_day` | sum calls/tokens/cost micros by provider/model/price source/version; cost sessions require `llm_calls > 0` |
| Destinations | Pro local/cloud | 30/90d | `destination_rollup_daily` | sum count by kind/HMAC/key version/optional label/verdict; rotations are separate trends |
| Security events | Pro local/cloud | 90d | `security_events` | types queue, deny, canary, gap only; order newest first; headline uses immutable initial verdict |
| Freshness/coverage | Pro local/cloud | current + selected range | device/day state | last contact/event/snapshot, completeness and gap/partial states |
| Actor/device comparison | Pro cloud | 30/90d | `usage_rollup_hourly` | same decision denominator grouped by bound actor/device; completeness is displayed and never used to inflate decision totals |
| Exports | Pro local/cloud | max 90d | projection + security events | JSON or CSV; policy edits are joined from separate policy audit |

## Team row-level access

| Principal | Own detail | Other-member detail | Team totals | Destination labels | Settings / export |
|---|---:|---:|---:|---:|---:|
| Team owner/admin | yes | yes | yes | according to team policy | yes |
| Ordinary member | yes | no | anonymised aggregates only | own labels according to policy | no team-wide export/settings |

Actor erasure pseudonymises the actor reference and removes personal display
attributes while retaining non-identifying team aggregates. It never assigns
historical rows to another actor.
