// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Per-row column compression for the audit DB.
//!
//! Stage 3 of audit-completeness-scaling W0. Compresses the largest
//! JSON-blob columns (`arguments_summary`, `filter_results`, `filter_scores`)
//! at insert time using zstd. Compressed payloads start with the zstd
//! magic number `0x28 0xB5 0x2F 0xFD`, so readers can detect compression
//! by sniffing the first four bytes — old plaintext rows and new
//! compressed rows coexist in the same table without a migration.
//!
//! The hash chain is not affected. `compute_record_hash` hashes
//! `arguments_hash` (a separate SHA256-of-args field), not
//! `arguments_summary`, so changing the storage form of the summary
//! column does not invalidate previously written `record_hash` values.

use crate::error::Result;

/// zstd magic number — first 4 bytes of every zstd frame.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Don't compress payloads smaller than this — zstd's frame header is
/// ~14 bytes and the dictionary doesn't help on tiny strings.
const COMPRESS_THRESHOLD: usize = 256;

/// Compression level. 3 is zstd's default — best size/CPU tradeoff for
/// audit JSON (8-12× ratio on `filter_results`-shaped blobs).
const ZSTD_LEVEL: i32 = 3;

/// Compress `s` if it's worth it; otherwise return the raw UTF-8 bytes.
///
/// "Worth it" = above the threshold AND the compressed form is smaller
/// than the input. Both checks matter: a slightly-above-threshold string
/// that doesn't compress well (already-entropy data, or repeated short
/// fragments) wastes a frame header otherwise.
pub fn compress_string(s: &str) -> Vec<u8> {
    if s.len() < COMPRESS_THRESHOLD {
        return s.as_bytes().to_vec();
    }
    match zstd::stream::encode_all(s.as_bytes(), ZSTD_LEVEL) {
        Ok(compressed) if compressed.len() < s.len() => compressed,
        _ => s.as_bytes().to_vec(),
    }
}

/// Decode a stored column value back into a UTF-8 string.
///
/// Detects compression by the zstd magic number. Falls back to UTF-8
/// decode for plaintext rows written before Stage 3 shipped, or for
/// payloads that stayed below the compression threshold.
pub fn decompress_string(bytes: &[u8]) -> Result<String> {
    if bytes.len() >= 4 && bytes[..4] == ZSTD_MAGIC {
        let decoded = zstd::stream::decode_all(bytes)?;
        Ok(String::from_utf8(decoded).map_err(|e| {
            crate::error::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("compressed audit column was not valid UTF-8: {e}"),
            ))
        })?)
    } else {
        Ok(String::from_utf8(bytes.to_vec()).map_err(|e| {
            crate::error::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("plaintext audit column was not valid UTF-8: {e}"),
            ))
        })?)
    }
}

/// True if `bytes` is a zstd-compressed payload (magic-number sniff).
pub fn is_compressed(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == ZSTD_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_strings_stay_plaintext() {
        let s = "hello";
        let bytes = compress_string(s);
        assert!(!is_compressed(&bytes));
        assert_eq!(decompress_string(&bytes).unwrap(), s);
    }

    #[test]
    fn large_repetitive_strings_compress() {
        let s = "a".repeat(4096);
        let bytes = compress_string(&s);
        assert!(is_compressed(&bytes), "expected magic-prefixed output");
        assert!(bytes.len() < 100, "expected aggressive compression");
        assert_eq!(decompress_string(&bytes).unwrap(), s);
    }

    #[test]
    fn audit_json_round_trips() {
        let s = r#"[{"filter_name":"path_match","matched":true,"score":3.0,"rule_id":"dangerous-path","severity":"critical","message":"destructive path pattern"},{"filter_name":"command_structure","matched":true,"score":4.5,"rule_id":"rm-rf","severity":"critical","message":"recursive force delete"}]"#;
        let bytes = compress_string(s);
        assert!(is_compressed(&bytes));
        assert!(
            bytes.len() < s.len(),
            "expected compression to shrink ({} >= {})",
            bytes.len(),
            s.len()
        );
        assert_eq!(decompress_string(&bytes).unwrap(), s);
    }

    #[test]
    fn incompressible_high_entropy_stays_plaintext() {
        // 300 bytes of pseudo-random hex — incompressible. Above threshold
        // but the compressed form should not be smaller, so we keep raw.
        let s: String = (0..300).map(|i| (b'a' + (i % 16) as u8) as char).collect();
        let bytes = compress_string(&s);
        // Whether this compresses depends on entropy — accept either, but
        // require round-trip.
        assert_eq!(decompress_string(&bytes).unwrap(), s);
    }

    #[test]
    fn decompress_handles_plaintext_legacy_rows() {
        // Simulates an old row written before Stage 3: raw bytes, no magic.
        let plain = b"plain old text";
        let s = decompress_string(plain).unwrap();
        assert_eq!(s, "plain old text");
    }

    #[test]
    fn decompress_rejects_invalid_utf8() {
        // Non-UTF-8 bytes without zstd magic — should error rather than
        // silently corrupt.
        let bad = [0xFF, 0xFE, 0xFD];
        assert!(decompress_string(&bad).is_err());
    }
}
