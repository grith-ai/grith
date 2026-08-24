# Frozen retention, lapse, deletion, and RBAC contract

| Data class | Active retention | Expiry/cancellation | Team/user deletion |
|---|---:|---|---|
| PostgreSQL rollups | 90 days | inaccessible at entitlement expiry; retained 30 days for reactivation, then deleted | team cascade; member erasure pseudonymises actor and retains non-identifying totals |
| PostgreSQL security events | 90 days | same 30-day reactivation period | same, except fields that identify the erased actor are removed/pseudonymised |
| Active S3 analytics projection | 90 days | same 30-day reactivation period | explicit object-deletion job; SQL cascade alone is incomplete |
| Superseded S3 revisions | 7 days | never longer than the active object policy | explicit object-deletion job |
| Pro local analytics projection | 90 days | enhanced view stops at expiry; local rows age out normally | device owner controls local deletion |
| Local active forensic SQLite | 30 days | unaffected by plan | device owner controls local deletion |
| Local cold forensic archives | no automatic expiry; user-managed | unaffected by plan | device owner controls local deletion |

Trials are full Pro. Cancellation remains active until the paid-through
timestamp. “Expiry” above means the entitlement end, not the end of the
application's general offline-license grace.

Owner/admin users can see full team detail, manage clear-label policy, export
team data, revoke devices and initiate deletion. Ordinary members see their own
detail plus anonymised team totals. Clear destination labels and destination
HMAC key versions apply prospectively. A key rotation produces a separate trend
segment; historical clear destinations are not requested or reconstructed.

Deletion jobs are idempotent, observable and audited. Failed S3 cleanup leaves
the deletion request incomplete and alerts operations. Legal hold, if later
offered, must be an explicitly contracted tier and cannot be implied by this
standard Pro policy.

