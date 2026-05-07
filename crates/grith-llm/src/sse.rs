// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Shared SSE (Server-Sent Events) line-parsing utilities.
//!
//! Extracts `data:` payloads from raw SSE text chunks, filtering out
//! empty lines and comment lines (`:` prefix). Protocol-specific sentinels
//! (e.g. `[DONE]`) are left to callers.

/// Iterate over SSE `data:` payloads in a raw text chunk.
///
/// Strips the `data: ` prefix, skips empty lines, and skips SSE comment
/// lines (starting with `:`). Does **not** handle protocol-specific
/// sentinels like `data: [DONE]` — callers must filter those themselves.
pub fn parse_sse_data_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with(':'))
        .filter_map(|line| line.strip_prefix("data: "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_sse_parsing() {
        let input = "data: {\"text\":\"hello\"}\n\ndata: {\"text\":\"world\"}\n\n";
        let payloads: Vec<&str> = parse_sse_data_lines(input).collect();
        assert_eq!(
            payloads,
            vec!["{\"text\":\"hello\"}", "{\"text\":\"world\"}"]
        );
    }

    #[test]
    fn test_filters_comments_and_empty_lines() {
        let input = ": this is a comment\n\ndata: payload\n\n: another comment\n";
        let payloads: Vec<&str> = parse_sse_data_lines(input).collect();
        assert_eq!(payloads, vec!["payload"]);
    }

    #[test]
    fn test_preserves_done_sentinel() {
        let input = "data: {\"ok\":true}\ndata: [DONE]\n";
        let payloads: Vec<&str> = parse_sse_data_lines(input).collect();
        assert_eq!(payloads, vec!["{\"ok\":true}", "[DONE]"]);
    }

    #[test]
    fn test_empty_input() {
        let payloads: Vec<&str> = parse_sse_data_lines("").collect();
        assert!(payloads.is_empty());
    }

    #[test]
    fn test_whitespace_trimming() {
        // Lines are trimmed before prefix stripping, so leading/trailing
        // whitespace on the line itself is removed. Content after "data: "
        // is returned as-is (trim only applies to the whole line).
        let input = "  data: trimmed  \n  \n  data: also trimmed  \n";
        let payloads: Vec<&str> = parse_sse_data_lines(input).collect();
        assert_eq!(payloads, vec!["trimmed", "also trimmed"]);
    }
}
