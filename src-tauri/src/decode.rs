//! JWT decoding: splits a token into header/payload/signature, base64url-decodes
//! the first two segments, and surfaces warnings about suspicious algorithms.
//!
//! Signature verification (JWKS fetch) is intentionally *not* done here — it is
//! on the roadmap. This module is decode-only.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
pub struct DecodedJwt {
    pub header: Value,
    pub payload: Value,
    pub alg: String,
    /// `exp` claim, epoch seconds
    pub exp: Option<i64>,
    /// `iat` claim, epoch seconds
    pub iat: Option<i64>,
    pub warnings: Vec<String>,
}

fn b64url_decode(part: &str) -> Result<Vec<u8>, String> {
    // JWT uses unpadded base64url; strip any padding some producers add.
    let cleaned: String = part.chars().filter(|c| *c != '=').collect();
    URL_SAFE_NO_PAD
        .decode(cleaned)
        .map_err(|e| format!("base64 decode failed: {e}"))
}

fn as_object(value: Value) -> Result<serde_json::Map<String, Value>, String> {
    match value {
        Value::Object(map) => Ok(map),
        _ => Err("JWT segment is not a JSON object".to_string()),
    }
}

/// Decode a JWT (no signature verification). Works for any JWS in compact
/// serialization; returns a descriptive error otherwise.
pub fn decode_jwt(token: &str) -> Result<DecodedJwt, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(format!(
            "not a JWT — expected 3 dot-separated segments, got {}",
            parts.len()
        ));
    }

    let header_bytes = b64url_decode(parts[0]).map_err(|e| format!("header: {e}"))?;
    let payload_bytes = b64url_decode(parts[1]).map_err(|e| format!("payload: {e}"))?;

    let header: Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("header is not valid JSON: {e}"))?;
    let payload: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("payload is not valid JSON: {e}"))?;

    let header_map = as_object(header)?;
    let payload_map = as_object(payload)?;

    let alg = header_map
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or("none")
        .to_string();

    let exp = payload_map.get("exp").and_then(Value::as_i64);
    let iat = payload_map.get("iat").and_then(Value::as_i64);

    let warnings = analyze(&alg, exp, iat, &payload_map);

    Ok(DecodedJwt {
        header: Value::Object(header_map),
        payload: Value::Object(payload_map),
        alg,
        exp,
        iat,
        warnings,
    })
}

fn analyze(
    alg: &str,
    exp: Option<i64>,
    iat: Option<i64>,
    payload: &serde_json::Map<String, Value>,
) -> Vec<String> {
    let mut warnings = Vec::new();

    match alg {
        "none" | "" => warnings.push(
            "alg is \"none\" — the token is unsigned and anyone can forge it".into(),
        ),
        a if a.starts_with("HS") => warnings.push(format!(
            "{a} — HMAC signed. If the provider signs with your client secret, a leaked \
             secret lets attackers mint tokens; RS/ES is preferred"
        )),
        a if a.starts_with("RS") || a.starts_with("PS") || a.starts_with("ES") => {}
        other => warnings.push(format!("uncommon alg \"{other}\" — inspect it carefully")),
    }

    match exp {
        None => warnings.push("no exp claim — token never expires".into()),
        Some(e) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            if e <= now {
                warnings.push("token is already expired".into());
            }
        }
    }

    if let Some(i) = iat {
        if let Some(e) = exp {
            if e < i {
                warnings.push("exp is earlier than iat".into());
            }
        }
    }

    if !payload.contains_key("iss") {
        warnings.push("no iss claim — issuer cannot be checked".into());
    }
    if !payload.contains_key("aud") {
        warnings.push("no aud claim — audience cannot be checked".into());
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// {"alg":"RS256","typ":"JWT"} / {"sub":"1234567890","iss":"https://accounts.example","aud":"client-123","exp":1999999999,"iat":1900000000,"nonce":"abc123"}
    const KNOWN_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5leGFtcGxlIiwiYXVkIjoiY2xpZW50LTEyMyIsImV4cCI6MTk5OTk5OTk5OSwiaWF0IjoxOTAwMDAwMDAwLCJub25jZSI6ImFiYzEyMyJ9.signature";

    #[test]
    fn decodes_known_token() {
        let jwt = decode_jwt(KNOWN_TOKEN).expect("should decode");
        assert_eq!(jwt.alg, "RS256");
        assert_eq!(jwt.exp, Some(1999999999));
        assert_eq!(jwt.iat, Some(1900000000));
        assert_eq!(jwt.payload["sub"], "1234567890");
        assert_eq!(jwt.payload["nonce"], "abc123");
        // RS256 + exp in the future (2033) + iss/aud present → no warnings
        assert!(jwt.warnings.is_empty(), "{:?}", jwt.warnings);
    }

    #[test]
    fn rejects_non_jwt() {
        assert!(decode_jwt("not-a-jwt").is_err());
        assert!(decode_jwt("only.two").is_err());
    }

    #[test]
    fn flags_alg_none() {
        let token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.";
        let jwt = decode_jwt(token).expect("should decode");
        assert_eq!(jwt.alg, "none");
        assert!(jwt.warnings.iter().any(|w| w.contains("unsigned")));
    }

    #[test]
    fn flags_expired_and_missing_claims() {
        // exp: 1000000000 (2001), no iss/aud
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4IiwiZXhwIjoxMDAwMDAwMDAwfQ.sig";
        let jwt = decode_jwt(token).expect("should decode");
        assert!(jwt.warnings.iter().any(|w| w.contains("already expired")));
        assert!(jwt.warnings.iter().any(|w| w.contains("HMAC")));
        assert!(jwt.warnings.iter().any(|w| w.contains("no iss")));
    }
}
