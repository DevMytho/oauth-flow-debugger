//! PKCE code verifier / challenge generation (RFC 7636) and random string
//! helpers for `state` and `nonce`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Generate a cryptographically random, base64url (no padding) string.
/// `bytes` is the amount of entropy; the output is ~1.33x longer.
pub fn random_string(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// A code verifier: 43–128 chars per RFC 7636. 32 random bytes → 43 chars.
pub fn generate_verifier() -> String {
    random_string(32)
}

/// `code_challenge` = BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) without padding.
pub fn challenge_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Random `state` value for CSRF protection.
pub fn generate_state() -> String {
    random_string(24)
}

/// Random `nonce` value for OIDC replay protection.
pub fn generate_nonce() -> String {
    random_string(24)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_appendix_b_vector() {
        // Official test vector from RFC 7636 Appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            challenge_s256(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn verifier_is_43_chars_urlsafe() {
        let v = generate_verifier();
        assert_eq!(v.len(), 43);
        assert!(v
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn random_strings_are_unique() {
        assert_ne!(generate_state(), generate_state());
        assert_ne!(generate_nonce(), generate_nonce());
    }
}
