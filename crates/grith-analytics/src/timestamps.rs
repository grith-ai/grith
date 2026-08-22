// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Canonical timestamp serialization for analytics-v2/schema-v1.
//!
//! Every timestamp in an analytics payload serializes as UTC RFC 3339 with
//! exactly six fractional digits (microsecond precision, truncated toward
//! zero). This is a wire contract, not a convenience: row checksums and event
//! digests hash the serialized form, and a consumer that re-formats through a
//! language date type with different sub-second precision (chrono AutoSi's
//! 0/3/6/9 digits, JavaScript's fixed milliseconds) would compute a different
//! SHA-256 for identical data and trip the frozen stop-the-source and
//! rebuild-parity rules.

use chrono::{DateTime, SecondsFormat, Timelike, Utc};

/// Drop sub-microsecond precision so in-memory values compare and order the
/// same way their canonical serialization does. Producers apply this at the
/// adapter boundary; everything downstream is already microsecond-clean.
#[must_use]
pub fn truncate_to_micros(value: DateTime<Utc>) -> DateTime<Utc> {
    value
        .with_nanosecond((value.nanosecond() / 1_000) * 1_000)
        .unwrap_or(value)
}

/// The canonical form: `2026-08-20T10:15:00.123456Z`.
#[must_use]
pub fn format_canonical(value: &DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Micros, true)
}

pub mod ts_micros {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        value: &DateTime<Utc>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::format_canonical(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<DateTime<Utc>, D::Error> {
        let raw = String::deserialize(deserializer)?;
        DateTime::parse_from_rfc3339(&raw)
            .map(|parsed| super::truncate_to_micros(parsed.with_timezone(&Utc)))
            .map_err(serde::de::Error::custom)
    }
}

pub mod ts_micros_opt {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        value: &Option<DateTime<Utc>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(inner) => serializer.serialize_str(&super::format_canonical(inner)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<DateTime<Utc>>, D::Error> {
        let raw = Option::<String>::deserialize(deserializer)?;
        raw.map(|raw| {
            DateTime::parse_from_rfc3339(&raw)
                .map(|parsed| super::truncate_to_micros(parsed.with_timezone(&Utc)))
                .map_err(serde::de::Error::custom)
        })
        .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn canonical_form_is_always_six_fractional_digits() {
        let whole = Utc.with_ymd_and_hms(2026, 8, 20, 10, 15, 0).unwrap();
        assert_eq!(format_canonical(&whole), "2026-08-20T10:15:00.000000Z");

        let nanos = whole + chrono::Duration::nanoseconds(123_456_789);
        assert_eq!(
            format_canonical(&truncate_to_micros(nanos)),
            "2026-08-20T10:15:00.123456Z"
        );
    }

    #[test]
    fn truncation_drops_only_sub_microsecond_precision() {
        let base = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let value = base + chrono::Duration::nanoseconds(999);
        assert_eq!(truncate_to_micros(value), base);
        let value = base + chrono::Duration::nanoseconds(1_001);
        assert_eq!(
            truncate_to_micros(value),
            base + chrono::Duration::microseconds(1)
        );
    }
}
