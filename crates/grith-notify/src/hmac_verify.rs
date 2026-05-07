// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! HMAC-SHA256 signing and verification for webhook callback payloads.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Sign a payload with HMAC-SHA256 and return the hex-encoded signature.
pub fn sign(secret: &[u8], payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

/// Verify that a hex-encoded HMAC-SHA256 signature matches the payload.
pub fn verify(secret: &[u8], payload: &[u8], signature: &str) -> bool {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(payload);

    let Ok(sig_bytes) = hex::decode(signature) else {
        return false;
    };

    mac.verify_slice(&sig_bytes).is_ok()
}

/// Build the `X-Grith-Signature-256` header value in the format `sha256=<hex>`.
pub fn signature_header(secret: &[u8], payload: &[u8]) -> String {
    format!("sha256={}", sign(secret, payload))
}

/// Verify a header value in the format `sha256=<hex>`.
pub fn verify_header(secret: &[u8], payload: &[u8], header: &str) -> bool {
    let Some(hex_sig) = header.strip_prefix("sha256=") else {
        return false;
    };
    verify(secret, payload, hex_sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let secret = b"test-secret-key";
        let payload = b"hello world";
        let sig = sign(secret, payload);
        assert!(verify(secret, payload, &sig));
    }

    #[test]
    fn test_wrong_secret() {
        let payload = b"hello world";
        let sig = sign(b"secret-a", payload);
        assert!(!verify(b"secret-b", payload, &sig));
    }

    #[test]
    fn test_wrong_payload() {
        let secret = b"my-secret";
        let sig = sign(secret, b"payload-a");
        assert!(!verify(secret, b"payload-b", &sig));
    }

    #[test]
    fn test_header_format() {
        let secret = b"key";
        let payload = b"body";
        let header = signature_header(secret, payload);
        assert!(header.starts_with("sha256="));
        assert!(verify_header(secret, payload, &header));
    }

    #[test]
    fn test_invalid_hex() {
        assert!(!verify(b"key", b"body", "not-hex!@#$"));
    }

    #[test]
    fn test_verify_header_no_prefix() {
        assert!(!verify_header(b"key", b"body", "abc123"));
    }
}
