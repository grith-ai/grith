// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Canonical dimension and fixed-point conversion helpers.

use crate::contract::Category;
use crate::limits::{
    MAX_ABS_SCORE_MICROS, MAX_EVALUATED_FILTERS, MAX_FILTER_ID_BYTES, MAX_SAFE_INTEGER,
    SCORE_BIN_COUNT, SCORE_BIN_WIDTH_MICROS, SCORE_HISTOGRAM_MAX_MICROS,
    SCORE_HISTOGRAM_MIN_MICROS, SCORE_SCALE, UNKNOWN_DIMENSION,
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NormalizationError {
    #[error("{field} is longer than {max_bytes} UTF-8 bytes")]
    TooLong {
        field: &'static str,
        max_bytes: usize,
    },
    #[error("{field} contains an ASCII control character")]
    ControlCharacter { field: &'static str },
    #[error("filter id must contain only lowercase ASCII letters, digits, and hyphens")]
    InvalidFilterId,
    #[error("evaluated filters exceed the maximum of {MAX_EVALUATED_FILTERS}")]
    TooManyFilters,
    #[error("numeric value must be finite")]
    NonFinite,
    #[error("score is outside the supported fixed-point range")]
    ScoreOutOfRange,
    #[error("cost must be non-negative and fit the JSON safe-integer range")]
    CostOutOfRange,
}

/// Trim and collapse ASCII whitespace without changing case or Unicode bytes.
/// Empty optional dimensions use the explicit `<unknown>` sentinel.
pub fn normalize_dimension(
    value: Option<&str>,
    field: &'static str,
    max_bytes: usize,
) -> Result<String, NormalizationError> {
    let raw = value.unwrap_or_default().trim();
    let mut normalized = String::with_capacity(raw.len());
    let mut in_whitespace = false;
    for ch in raw.chars() {
        if ch.is_ascii_control() && !ch.is_ascii_whitespace() {
            return Err(NormalizationError::ControlCharacter { field });
        }
        if ch.is_ascii_whitespace() {
            in_whitespace = !normalized.is_empty();
        } else {
            if in_whitespace {
                normalized.push(' ');
                in_whitespace = false;
            }
            normalized.push(ch);
        }
    }
    if normalized.is_empty() {
        normalized.push_str(UNKNOWN_DIMENSION);
    }
    if normalized.len() > max_bytes {
        return Err(NormalizationError::TooLong { field, max_bytes });
    }
    Ok(normalized)
}

/// Canonical filter identifiers are lower-kebab-case. Historical underscore
/// spellings are converted before validation.
pub fn normalize_filter_id(value: &str) -> Result<String, NormalizationError> {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    if normalized.is_empty()
        || normalized.len() > MAX_FILTER_ID_BYTES
        || normalized.starts_with('-')
        || normalized.ends_with('-')
        || normalized.contains("--")
        || !normalized
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(NormalizationError::InvalidFilterId);
    }
    Ok(normalized)
}

/// Normalize, sort, and deduplicate the evaluated-filter set.
pub fn canonical_filter_ids<I, S>(values: I) -> Result<Vec<String>, NormalizationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut normalized = values
        .into_iter()
        .map(|value| normalize_filter_id(value.as_ref()))
        .collect::<Result<Vec<_>, _>>()?;
    normalized.sort();
    normalized.dedup();
    if normalized.len() > MAX_EVALUATED_FILTERS {
        return Err(NormalizationError::TooManyFilters);
    }
    Ok(normalized)
}

/// Convert a score to signed fixed-point millionths using round-half-away
/// from zero (Rust's `f64::round`).
pub fn score_to_micros(score: f64) -> Result<i64, NormalizationError> {
    if !score.is_finite() {
        return Err(NormalizationError::NonFinite);
    }
    let scaled = (score * SCORE_SCALE as f64).round();
    if scaled < -MAX_ABS_SCORE_MICROS as f64 || scaled > MAX_ABS_SCORE_MICROS as f64 {
        return Err(NormalizationError::ScoreOutOfRange);
    }
    Ok(scaled as i64)
}

/// Convert USD to integer micros using round-half-away from zero. Costs are
/// non-negative and bounded to JavaScript's exact-integer range.
pub fn cost_usd_to_micros(cost_usd: f64) -> Result<u64, NormalizationError> {
    if !cost_usd.is_finite() {
        return Err(NormalizationError::NonFinite);
    }
    let scaled = (cost_usd * 1_000_000.0).round();
    if scaled < 0.0 || scaled > MAX_SAFE_INTEGER as f64 {
        return Err(NormalizationError::CostOutOfRange);
    }
    Ok(scaled as u64)
}

/// Return the frozen 30-bin `[0, 15]` score bucket. Values outside the range
/// are clamped; exactly 15 belongs to the final bucket.
pub fn score_micros_to_bin(score_micros: i64) -> u8 {
    let clamped = score_micros.clamp(SCORE_HISTOGRAM_MIN_MICROS, SCORE_HISTOGRAM_MAX_MICROS);
    let raw = (clamped / SCORE_BIN_WIDTH_MICROS) as u8;
    raw.min(SCORE_BIN_COUNT - 1)
}

/// Stable v1 category mapping. Unknown future tool kinds remain visible in
/// `other`; changing this mapping requires a new category-registry version.
pub fn category_for_tool_kind(tool_kind: &str) -> Category {
    let base = tool_kind
        .trim()
        .split_once('(')
        .map_or(tool_kind.trim(), |(name, _)| name)
        .to_ascii_lowercase()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>();
    match base.as_str() {
        "fileread" | "dirlist" => Category::FileRead,
        "filewrite" | "fileappend" | "filedelete" | "filerename" | "filelink" | "filechmod"
        | "dircreate" | "ownershipchange" | "filesystemmutation" => Category::FileMutation,
        "shellexec" | "processspawn" => Category::Process,
        "httprequest" | "netconnect" | "dnsquery" => Category::NetworkEgress,
        "netlisten" => Category::NetworkListen,
        // A D-Bus method call invokes an action in another process over the
        // session bus — the same authority shape as direct cross-process
        // access, and the reason its decisions must not vanish into `other`.
        "crossprocessaccess" | "dbusmethodcall" => Category::CrossProcess,
        "namespaceop" => Category::Namespace,
        "llmcompletion" => Category::Llm,
        "auditgap" | "lifecycle" | "audithealth" => Category::System,
        _ => Category::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dimensions_are_stable_and_bounded_by_bytes() {
        assert_eq!(
            normalize_dimension(Some("  Project\t Alpha  "), "project", 32).unwrap(),
            "Project Alpha"
        );
        assert_eq!(
            normalize_dimension(None, "project", 32).unwrap(),
            UNKNOWN_DIMENSION
        );
        assert!(matches!(
            normalize_dimension(Some("éé"), "project", 3),
            Err(NormalizationError::TooLong { .. })
        ));
    }

    #[test]
    fn filter_sets_are_normalized_sorted_and_unique() {
        assert_eq!(
            canonical_filter_ids(["secret_scan", "allowlist", "secret-scan"]).unwrap(),
            vec!["allowlist", "secret-scan"]
        );
        assert!(normalize_filter_id("bad filter").is_err());
    }

    #[test]
    fn fixed_point_rounding_and_histogram_geometry_are_frozen() {
        assert_eq!(score_to_micros(3.800_000_4).unwrap(), 3_800_000);
        assert_eq!(score_to_micros(-0.000_000_5).unwrap(), -1);
        assert_eq!(cost_usd_to_micros(0.012_345_6).unwrap(), 12_346);
        assert_eq!(score_micros_to_bin(-1), 0);
        assert_eq!(score_micros_to_bin(0), 0);
        assert_eq!(score_micros_to_bin(499_999), 0);
        assert_eq!(score_micros_to_bin(500_000), 1);
        assert_eq!(score_micros_to_bin(15_000_000), 29);
        assert_eq!(score_micros_to_bin(99_000_000), 29);
    }

    #[test]
    fn categories_cover_canonical_and_persisted_tool_spellings() {
        assert_eq!(category_for_tool_kind("file_read"), Category::FileRead);
        assert_eq!(
            category_for_tool_kind("FileRead(/etc/passwd)"),
            Category::FileRead
        );
        assert_eq!(
            category_for_tool_kind("FilesystemMutation(mount)"),
            Category::FileMutation
        );
        assert_eq!(
            category_for_tool_kind("CrossProcessAccess(ptrace)"),
            Category::CrossProcess
        );
        assert_eq!(category_for_tool_kind("future-tool"), Category::Other);
    }
}
