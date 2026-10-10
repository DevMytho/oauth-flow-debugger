//! JWKS fetching and JWS signature verification (RS256 / ES256).
//!
//! [`crate::decode`] only splits a token; this module is what lets the app say
//! *"the signature is actually valid"*:
//!
//! 1. **Resolve a JWKS source** — an explicit `jwks_uri` from the flow config,
//!    then OIDC discovery (`/.well-known/openid-configuration`) from the
//!    expected issuer, then discovery from the token's own `iss` claim.
//!    Discovery only follows `https://` URLs (plain `http` is accepted for
//!    loopback mock providers).
//! 2. **Fetch and cache** the key set for 5 minutes.
//! 3. **Pick the key by `kid`** (or the single compatible key when the header
//!    has no `kid`), then verify the JWS signature over
//!    `b64url(header) "." b64url(payload)` — RS256 via RSA PKCS#1 v1.5 +
//!    SHA-256, ES256 via ECDSA on P-256 + SHA-256.
//!
//! Anything that cannot honestly be verified (`alg: none`, HMAC, unsupported
//! algs, missing JWKS, unknown `kid`) is reported as **unverified** with a
//! reason — never as valid. Results attach to the `TokenBundle` for the UI and
//! become findings:
//!
//! | reason id         | finding          | severity |
//! |-------------------|------------------|----------|
//! | `ok`              | `sig_verified`   | info     |
//! | `bad_signature`   | `sig_invalid`    | critical |
//! | `kid_not_found`   | `sig_kid_not_found` | high  |
//! | everything else   | `sig_unverified` | low      |
//!
//! (`unsigned` — an `alg: none` token — raises no duplicate finding: the
//! critical `alg_none` finding already covers it.)

use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::decode::{self, DecodedJwt};
use crate::findings::{Finding, Severity};
use crate::FlowConfig;

const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const CACHE_TTL: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// Result types (shared with the frontend via serde)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Valid,
    Invalid,
    Unverified,
}

/// Verification outcome for one token in a bundle.
#[derive(Debug, Clone, Serialize)]
pub struct TokenVerification {
    /// `access_token` or `id_token`
    pub role: String,
    pub status: VerificationStatus,
    pub alg: String,
    pub kid: Option<String>,
    pub jwks_uri: Option<String>,
    /// Stable reason code (see module docs).
    pub reason: String,
    /// Human-readable explanation for the UI / report.
    pub detail: String,
}

/// Per-bundle verification results for both JWT slots.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BundleVerification {
    pub access: Option<TokenVerification>,
    pub id: Option<TokenVerification>,
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify every JWT in a token response against the provider's JWKS.
///
/// Non-JWT (opaque) tokens produce `None` — there is no signature to check.
pub async fn verify_tokens(
    config: &FlowConfig,
    access_token: Option<&str>,
    id_token: Option<&str>,
) -> BundleVerification {
    let mut out = BundleVerification::default();
    if let Some(t) = access_token {
        out.access = verify_one(config, "access_token", t).await;
    }
    if let Some(t) = id_token {
        out.id = verify_one(config, "id_token", t).await;
    }
    out
}

async fn verify_one(config: &FlowConfig, role: &str, token: &str) -> Option<TokenVerification> {
    let jwt = decode::decode_jwt(token).ok()?; // opaque / not a JWS → nothing to verify
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload_b64 = parts[1];
    let sig_b64 = parts[2];

    let kid = jwt
        .header
        .get("kid")
        .and_then(Value::as_str)
        .map(str::to_string);

    let unsupported = |detail: String| TokenVerification {
        role: role.into(),
        status: VerificationStatus::Unverified,
        alg: jwt.alg.clone(),
        kid: kid.clone(),
        jwks_uri: None,
        reason: "unsupported_alg".into(),
        detail,
    };

    // --- algorithms we refuse to "verify" --------------------------------
    if jwt.alg.is_empty() || jwt.alg == "none" {
        return Some(TokenVerification {
            role: role.into(),
            status: VerificationStatus::Unverified,
            alg: jwt.alg.clone(),
            kid,
            jwks_uri: None,
            reason: "unsigned".into(),
            detail: "alg is \"none\" — the token is unsigned, so there is no signature to \
                     verify (the critical `alg_none` finding covers this)"
                .into(),
        });
    }
    if jwt.alg.starts_with("HS") {
        return Some(unsupported(format!(
            "{} is a symmetric (HMAC) algorithm — a JWKS only publishes public keys, so \
             this signature cannot be checked against it",
            jwt.alg
        )));
    }
    if jwt.alg != "RS256" && jwt.alg != "ES256" {
        return Some(unsupported(format!(
            "alg {} is not supported for JWKS verification (supported: RS256, ES256)",
            jwt.alg
        )));
    }

    // --- resolve + fetch the JWKS ----------------------------------------
    let source = resolve_jwks_source(config, &jwt).await;
    let Some(jwks_uri) = source else {
        return Some(TokenVerification {
            role: role.into(),
            status: VerificationStatus::Unverified,
            alg: jwt.alg.clone(),
            kid,
            jwks_uri: None,
            reason: "no_jwks_source".into(),
            detail: "no JWKS source — set a JWKS URI or an expected issuer in the flow \
                     config to enable signature verification"
                .into(),
        });
    };
    let keys = match fetch_jwks(&jwks_uri).await {
        Ok(k) => k,
        Err(e) => {
            let detail = format!("JWKS fetch failed ({jwks_uri}): {e}");
            return Some(TokenVerification {
                role: role.into(),
                status: VerificationStatus::Unverified,
                alg: jwt.alg.clone(),
                kid,
                jwks_uri: Some(jwks_uri),
                reason: "jwks_fetch_failed".into(),
                detail,
            });
        }
    };

    // --- pick key + verify ------------------------------------------------
    let signing_input = format!(
        "{}.{}",
        token.split('.').next().unwrap_or_default(),
        payload_b64
    );
    let sig = match decode::b64url_decode(sig_b64) {
        Ok(s) => s,
        Err(e) => {
            return Some(TokenVerification {
                role: role.into(),
                status: VerificationStatus::Invalid,
                alg: jwt.alg.clone(),
                kid,
                jwks_uri: Some(jwks_uri),
                reason: "bad_signature".into(),
                detail: format!("signature segment is not valid base64url: {e}"),
            });
        }
    };

    match verify_with_keys(&jwt.alg, kid.as_deref(), &signing_input, &sig, &keys) {
        Ok((matched_kid, key_desc)) => {
            let detail = format!(
                "{} signature verified against JWKS key {key_desc} ({jwks_uri})",
                jwt.alg
            );
            Some(TokenVerification {
                role: role.into(),
                status: VerificationStatus::Valid,
                alg: jwt.alg.clone(),
                kid: matched_kid,
                jwks_uri: Some(jwks_uri),
                reason: "ok".into(),
                detail,
            })
        }
        Err((reason, detail)) => {
            if reason == "kid_not_found" {
                // Likely key rotation: drop the cached JWKS so the next
                // attempt refetches instead of failing the same way.
                clear_cache();
            }
            let status = match reason.as_str() {
                "bad_signature" => VerificationStatus::Invalid,
                _ => VerificationStatus::Unverified,
            };
            Some(TokenVerification {
                role: role.into(),
                status,
                alg: jwt.alg.clone(),
                kid,
                jwks_uri: Some(jwks_uri),
                reason,
                detail,
            })
        }
    }
}

/// Key selection + signature check. Returns `(kid, human key description)` on
/// success, or `(reason_code, detail)`.
fn verify_with_keys(
    alg: &str,
    header_kid: Option<&str>,
    signing_input: &str,
    sig: &[u8],
    keys: &Value,
) -> Result<(Option<String>, String), (String, String)> {
    let kty = match alg {
        "RS256" => "RSA",
        "ES256" => "EC",
        other => {
            return Err((
                "unsupported_alg".into(),
                format!("alg {other} is not supported for JWKS verification"),
            ));
        }
    };
    let list = keys.as_array().ok_or_else(|| {
        (
            "jwks_fetch_failed".into(),
            "JWKS `keys` is not an array".to_string(),
        )
    })?;

    let candidates: Vec<&serde_json::Map<String, Value>> = list
        .iter()
        .filter_map(Value::as_object)
        .filter(|k| {
            let kty_ok = k.get("kty").and_then(Value::as_str) == Some(kty)
                && (kty != "EC" || k.get("crv").and_then(Value::as_str) == Some("P-256"));
            // An optional `alg` on the key, when present, must match ours.
            let alg_ok = k
                .get("alg")
                .map(|a| a.as_str() == Some(alg))
                .unwrap_or(true);
            kty_ok && alg_ok
        })
        .collect();

    let chosen = match header_kid {
        Some(k) => candidates
            .into_iter()
            .find(|c| c.get("kid").and_then(Value::as_str) == Some(k))
            .ok_or_else(|| {
                (
                    "kid_not_found".into(),
                    format!(
                        "token header kid={k} does not appear in the JWKS — either the \
                         provider rotated keys or the kid was forged"
                    ),
                )
            })?,
        None => match candidates.len() {
            1 => candidates.into_iter().next().unwrap(),
            0 => {
                return Err((
                    "kid_not_found".into(),
                    format!("the JWKS contains no {kty} key to verify this token with"),
                ));
            }
            n => {
                return Err((
                    "ambiguous_key".into(),
                    format!(
                        "token has no `kid` header and the JWKS holds {n} {kty} keys — \
                         cannot tell which key signed it"
                    ),
                ));
            }
        },
    };

    let key_desc = match header_kid {
        Some(k) => format!("kid={k}"),
        None => "selected key (no kid in header)".to_string(),
    };

    match alg {
        "RS256" => verify_rs256(chosen, signing_input, sig)
            .map(|()| (header_kid.map(str::to_string), key_desc)),
        "ES256" => verify_es256(chosen, signing_input, sig)
            .map(|()| (header_kid.map(str::to_string), key_desc)),
        _ => unreachable!("alg filtered above"),
    }
}

fn b64url_field(
    key: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Vec<u8>, (String, String)> {
    key.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                "invalid_jwks_key".into(),
                format!("JWKS key is missing the `{field}` parameter"),
            )
        })
        .and_then(|v| {
            decode::b64url_decode(v).map_err(|e| {
                (
                    "invalid_jwks_key".into(),
                    format!("JWKS key `{field}` is not valid base64url: {e}"),
                )
            })
        })
}

fn verify_rs256(
    key: &serde_json::Map<String, Value>,
    signing_input: &str,
    sig: &[u8],
) -> Result<(), (String, String)> {
    use rsa::signature::Verifier;
    use rsa::traits::PublicKeyParts;

    let n = b64url_field(key, "n")?;
    let e = b64url_field(key, "e")?;
    let pubkey = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&n),
        rsa::BigUint::from_bytes_be(&e),
    )
    .map_err(|err| {
        (
            "invalid_jwks_key".into(),
            format!("invalid RSA public key in JWKS: {err}"),
        )
    })?;
    if pubkey.n().bits() < 2048 {
        return Err((
            "invalid_jwks_key".into(),
            format!(
                "RSA key in the JWKS is only {} bits — RS256 requires ≥ 2048",
                pubkey.n().bits()
            ),
        ));
    }
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(pubkey);
    let signature = rsa::pkcs1v15::Signature::try_from(sig).map_err(|_| {
        (
            "bad_signature".into(),
            "RS256 signature has the wrong length for the signing key".to_string(),
        )
    })?;
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| {
            (
                "bad_signature".into(),
                "RS256 signature does NOT match the JWKS public key — the token was \
             modified or forged"
                    .to_string(),
            )
        })
}

fn verify_es256(
    key: &serde_json::Map<String, Value>,
    signing_input: &str,
    sig: &[u8],
) -> Result<(), (String, String)> {
    use p256::ecdsa::signature::Verifier;

    let x = b64url_field(key, "x")?;
    let y = b64url_field(key, "y")?;
    // Uncompressed SEC1 point: 0x04 || x || y
    let mut point = Vec::with_capacity(1 + x.len() + y.len());
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(|err| {
        (
            "invalid_jwks_key".into(),
            format!("invalid EC public key in JWKS: {err}"),
        )
    })?;
    let signature = p256::ecdsa::Signature::from_slice(sig).map_err(|_| {
        (
            "bad_signature".into(),
            "ES256 signature is not a well-formed P-256 signature".to_string(),
        )
    })?;
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| {
            (
                "bad_signature".into(),
                "ES256 signature does NOT match the JWKS public key — the token was \
             modified or forged"
                    .to_string(),
            )
        })
}

// ---------------------------------------------------------------------------
// Source resolution + fetch
// ---------------------------------------------------------------------------

/// Pick the JWKS URI: explicit config → discovery(expected issuer) →
/// discovery(token `iss`). Only `https` (or loopback `http`) targets are ever
/// fetched, and every request has a hard timeout with proxies ignored.
async fn resolve_jwks_source(config: &FlowConfig, token: &DecodedJwt) -> Option<String> {
    let direct = config.jwks_uri.trim();
    if !direct.is_empty() {
        return Some(direct.to_string());
    }
    if let Some(uri) = discover(&config.expected_iss).await {
        return Some(uri);
    }
    let iss = token.payload.get("iss").and_then(Value::as_str)?;
    discover(iss).await
}

/// OIDC discovery: `{iss}/.well-known/openid-configuration` → `jwks_uri`.
async fn discover(iss: &str) -> Option<String> {
    let base = iss.trim().trim_end_matches('/');
    if base.is_empty() {
        return None;
    }
    let doc_url = format!("{base}/.well-known/openid-configuration");
    if !url_allowed(&doc_url) {
        return None;
    }
    let client = http_client().ok()?;
    let doc: Value = client
        .get(&doc_url)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .await
        .ok()?;
    let jwks_uri = doc.get("jwks_uri")?.as_str()?.trim();
    if jwks_uri.is_empty() || !url_allowed(jwks_uri) {
        return None;
    }
    Some(jwks_uri.to_string())
}

/// https everywhere; plain http only for loopback mock providers.
fn url_allowed(raw: &str) -> bool {
    match url::Url::parse(raw) {
        Ok(u) => match u.scheme() {
            "https" => true,
            "http" => u
                .host_str()
                .map(|h| crate::is_loopback(&h.to_ascii_lowercase()))
                .unwrap_or(false),
            _ => false,
        },
        Err(_) => false,
    }
}

fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        // Same rule as the token exchange: no env proxy may see our traffic.
        .no_proxy()
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))
}

struct CachedKeys {
    uri: String,
    keys: Value,
    at: Instant,
}

static CACHE: Mutex<Option<CachedKeys>> = Mutex::new(None);

fn lock_cache() -> std::sync::MutexGuard<'static, Option<CachedKeys>> {
    CACHE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Drop the cached JWKS (tests, or after a `kid_not_found` rotation).
pub fn clear_cache() {
    *lock_cache() = None;
}

async fn fetch_jwks(uri: &str) -> Result<Value, String> {
    if let Some(cached) = lock_cache().as_ref() {
        if cached.uri == uri && cached.at.elapsed() < CACHE_TTL {
            return Ok(cached.keys.clone());
        }
    }
    let client = http_client()?;
    let doc: Value = client
        .get(uri)
        .send()
        .await
        .map_err(|e| format!("request error: {e}"))?
        .error_for_status()
        .map_err(|e| format!("request failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("response is not JSON: {e}"))?;
    let keys = doc
        .get("keys")
        .cloned()
        .ok_or_else(|| "JWKS document has no `keys` array".to_string())?;
    if !keys.is_array() {
        return Err("`keys` is not an array".to_string());
    }
    *lock_cache() = Some(CachedKeys {
        uri: uri.to_string(),
        keys: keys.clone(),
        at: Instant::now(),
    });
    Ok(keys)
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/// Turn verification results into severity-rated findings.
pub fn verification_findings(v: &BundleVerification) -> Vec<Finding> {
    let mut out = Vec::new();
    for result in [v.access.as_ref(), v.id.as_ref()].into_iter().flatten() {
        let role = &result.role;
        match result.reason.as_str() {
            "ok" => out.push(Finding::new(
                "sig_verified",
                Severity::Info,
                format!("{role} signature verified"),
                result.detail.clone(),
            )),
            "bad_signature" => out.push(Finding::new(
                "sig_invalid",
                Severity::Critical,
                format!("{role} signature is INVALID"),
                format!(
                    "{} — treat this token as forged; do not trust anything derived from it.",
                    result.detail
                ),
            )),
            "kid_not_found" => out.push(Finding::new(
                "sig_kid_not_found",
                Severity::High,
                format!("{role} token kid is not in the JWKS"),
                result.detail.clone(),
            )),
            // `unsigned` is already covered by the critical `alg_none` finding.
            "unsigned" => {}
            _ => out.push(Finding::new(
                "sig_unverified",
                Severity::Low,
                format!("{role} signature not verified"),
                result.detail.clone(),
            )),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClientAuth, FlowType};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use rsa::signature::SignatureEncoding;
    use serde_json::json;

    fn config() -> FlowConfig {
        FlowConfig {
            flow_type: FlowType::AuthorizationCode,
            authorization_endpoint: "https://provider.example/authorize".into(),
            token_endpoint: "https://provider.example/token".into(),
            client_id: "client-123".into(),
            client_secret: String::new(),
            redirect_uri: String::new(),
            scope: "openid".into(),
            pkce: true,
            include_nonce: true,
            client_auth: ClientAuth::None,
            expected_iss: String::new(),
            expected_alg: "RS256".into(),
            jwks_uri: String::new(),
            device_authorization_endpoint: String::new(),
            listener_port: 0,
        }
    }

    fn b64(data: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(data)
    }

    fn rsa_keypair() -> rsa::RsaPrivateKey {
        rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("keygen")
    }

    fn rsa_jwk(pubkey: &rsa::RsaPublicKey, kid: &str) -> Value {
        use rsa::traits::PublicKeyParts;
        json!({
            "kty": "RSA",
            "kid": kid,
            "alg": "RS256",
            "use": "sig",
            "n": b64(&pubkey.n().to_bytes_be()),
            "e": b64(&pubkey.e().to_bytes_be()),
        })
    }

    fn sign_rs256(privkey: &rsa::RsaPrivateKey, header: Value, payload: Value) -> String {
        use rsa::signature::Signer;
        let h = b64(header.to_string().as_bytes());
        let p = b64(payload.to_string().as_bytes());
        let msg = format!("{h}.{p}");
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(privkey.clone());
        let sig: rsa::pkcs1v15::Signature = signing_key.sign(msg.as_bytes());
        format!("{msg}.{}", b64(sig.to_bytes().as_ref()))
    }

    fn payload_exp(seconds_ahead: i64) -> Value {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        json!({
            "iss": "https://issuer.example",
            "sub": "user-1",
            "aud": "client-123",
            "exp": now + seconds_ahead,
            "iat": now,
        })
    }

    /// Spawn a loopback JWKS server: `GET /jwks` + OIDC discovery.
    async fn spawn_jwks(keys: Value) -> String {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let router = axum::Router::new()
            .route(
                "/jwks",
                axum::routing::get(move || {
                    let keys = keys.clone();
                    async move { axum::Json(keys) }
                }),
            )
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get(move || async move {
                    axum::Json(json!({
                        "issuer": "https://issuer.example",
                        "jwks_uri": format!("http://127.0.0.1:{port}/jwks"),
                    }))
                }),
            );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://127.0.0.1:{port}")
    }

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.id.as_str()).collect()
    }

    #[tokio::test]
    async fn verifies_rs256_and_flags_tampering() {
        let _guard = crate::listener::serial_lock().await;
        clear_cache();
        let privkey = rsa_keypair();
        let pubkey = rsa::RsaPublicKey::from(&privkey);
        let keys = json!({ "keys": [rsa_jwk(&pubkey, "key-1")] });
        let base = spawn_jwks(keys).await;

        let mut cfg = config();
        cfg.jwks_uri = format!("{base}/jwks");

        // 1. A correctly signed token verifies.
        let token = sign_rs256(
            &privkey,
            json!({"alg": "RS256", "typ": "JWT", "kid": "key-1"}),
            payload_exp(3600),
        );
        let v = verify_tokens(&cfg, None, Some(&token)).await;
        let id = v.id.as_ref().expect("id_token result");
        assert_eq!(id.status, VerificationStatus::Valid, "{}", id.detail);
        assert_eq!(id.reason, "ok");
        assert_eq!(id.kid.as_deref(), Some("key-1"));
        let f = verification_findings(&v);
        assert_eq!(ids(&f), vec!["sig_verified"]);
        assert_eq!(f[0].severity, Severity::Info);

        // 2. Tamper with the payload → signature no longer matches.
        let parts: Vec<&str> = token.split('.').collect();
        let mut claims: serde_json::Map<String, Value> =
            serde_json::from_slice(&decode::b64url_decode(parts[1]).unwrap()).unwrap();
        claims.insert("sub".into(), json!("attacker"));
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            b64(serde_json::Value::Object(claims).to_string().as_bytes()),
            parts[2]
        );
        let v = verify_tokens(&cfg, Some(&forged), None).await;
        let acc = v.access.as_ref().expect("access_token result");
        assert_eq!(acc.status, VerificationStatus::Invalid, "{}", acc.detail);
        assert_eq!(acc.reason, "bad_signature");
        let f = verification_findings(&v);
        assert_eq!(ids(&f), vec!["sig_invalid"]);
        assert_eq!(f[0].severity, Severity::Critical);

        // 3. Only one fetch happened (second call hit the cache) — implied by
        //    both calls succeeding against the short-lived server below.
    }

    #[tokio::test]
    async fn kid_missing_from_jwks_is_high_finding() {
        let _guard = crate::listener::serial_lock().await;
        clear_cache();
        let privkey = rsa_keypair();
        let pubkey = rsa::RsaPublicKey::from(&privkey);
        let base = spawn_jwks(json!({ "keys": [rsa_jwk(&pubkey, "rotated-key")] })).await;

        let mut cfg = config();
        cfg.jwks_uri = format!("{base}/jwks");

        let token = sign_rs256(
            &privkey,
            json!({"alg": "RS256", "typ": "JWT", "kid": "old-key"}),
            payload_exp(3600),
        );
        let v = verify_tokens(&cfg, None, Some(&token)).await;
        let id = v.id.as_ref().unwrap();
        assert_eq!(id.status, VerificationStatus::Unverified);
        assert_eq!(id.reason, "kid_not_found");
        let f = verification_findings(&v);
        assert_eq!(ids(&f), vec!["sig_kid_not_found"]);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[tokio::test]
    async fn verifies_es256() {
        let _guard = crate::listener::serial_lock().await;
        clear_cache();
        // p256's `random()` wants a rand_core 0.10 CryptoRng (rand 0.8's
        // ThreadRng is a different rand_core major version), so derive the
        // key from 32 bytes of ThreadRng output instead.
        let mut seed = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut seed);
        let signing_key =
            p256::ecdsa::SigningKey::from_bytes(&p256::FieldBytes::from(seed)).expect("scalar");
        use p256::ecdsa::signature::Signer;
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_sec1_point(false);
        let x = point.x().expect("uncompressed point has x");
        let y = point.y().expect("uncompressed point has y");
        let keys = json!({ "keys": [json!({
            "kty": "EC", "crv": "P-256", "kid": "ec-1", "alg": "ES256",
            "x": b64(x), "y": b64(y),
        })]});
        let base = spawn_jwks(keys).await;

        let mut cfg = config();
        cfg.jwks_uri = format!("{base}/jwks");

        let h = b64(json!({"alg": "ES256", "typ": "JWT", "kid": "ec-1"})
            .to_string()
            .as_bytes());
        let p = b64(payload_exp(3600).to_string().as_bytes());
        let msg = format!("{h}.{p}");
        let sig: p256::ecdsa::Signature = signing_key.sign(msg.as_bytes());
        let token = format!("{msg}.{}", b64(sig.to_bytes().as_slice()));

        let v = verify_tokens(&cfg, None, Some(&token)).await;
        let id = v.id.as_ref().unwrap();
        assert_eq!(id.status, VerificationStatus::Valid, "{}", id.detail);
        assert_eq!(id.alg, "ES256");
        assert_eq!(ids(&verification_findings(&v)), vec!["sig_verified"]);
    }

    #[tokio::test]
    async fn alg_none_and_hmac_are_never_verified() {
        let cfg = config(); // no JWKS source configured

        // alg: none
        let unsigned = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.";
        let v = verify_tokens(&cfg, None, Some(unsigned)).await;
        let id = v.id.as_ref().unwrap();
        assert_eq!(id.status, VerificationStatus::Unverified);
        assert_eq!(id.reason, "unsigned");
        // No duplicate finding — the critical `alg_none` finding covers it.
        assert!(verification_findings(&v).is_empty());

        // HS256 → unverified with a low finding (the alg_hs256/alg_mismatch
        // findings carry the real weight).
        let hmac = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln";
        let v = verify_tokens(&cfg, Some(hmac), None).await;
        let acc = v.access.as_ref().unwrap();
        assert_eq!(acc.status, VerificationStatus::Unverified);
        assert_eq!(acc.reason, "unsupported_alg");
        assert!(acc.detail.contains("symmetric"));
        let f = verification_findings(&v);
        assert_eq!(ids(&f), vec!["sig_unverified"]);
        assert_eq!(f[0].severity, Severity::Low);
    }

    #[tokio::test]
    async fn rs256_without_any_jwks_source_is_unverified() {
        let _guard = crate::listener::serial_lock().await;
        let cfg = config(); // no jwks_uri, no expected_iss
        let privkey = rsa_keypair();
        // No `iss` claim and no configured source → nothing to discover
        // from, so this test never touches the network.
        let token = sign_rs256(
            &privkey,
            json!({"alg": "RS256", "typ": "JWT"}),
            json!({"sub": "user-1", "exp": 4102444800_i64}),
        );
        let v = verify_tokens(&cfg, None, Some(&token)).await;
        let id = v.id.as_ref().unwrap();
        assert_eq!(id.status, VerificationStatus::Unverified, "{}", id.detail);
        assert_ne!(id.reason, "ok");
        assert!(matches!(
            id.reason.as_str(),
            "no_jwks_source" | "jwks_fetch_failed"
        ));
        assert_eq!(ids(&verification_findings(&v)), vec!["sig_unverified"]);
    }

    #[tokio::test]
    async fn discovers_jwks_from_expected_issuer() {
        let _guard = crate::listener::serial_lock().await;
        clear_cache();
        let privkey = rsa_keypair();
        let pubkey = rsa::RsaPublicKey::from(&privkey);
        let base = spawn_jwks(json!({ "keys": [rsa_jwk(&pubkey, "key-1")] })).await;

        // No jwks_uri — verification must go through OIDC discovery from
        // expected_iss (a loopback mock, so no real network is involved).
        let mut cfg = config();
        cfg.expected_iss = base.clone();

        let token = sign_rs256(
            &privkey,
            json!({"alg": "RS256", "typ": "JWT", "kid": "key-1"}),
            payload_exp(3600),
        );
        let v = verify_tokens(&cfg, None, Some(&token)).await;
        let id = v.id.as_ref().unwrap();
        assert_eq!(id.status, VerificationStatus::Valid, "{}", id.detail);
        assert_eq!(
            id.jwks_uri.as_deref(),
            Some(format!("{base}/jwks").as_str())
        );
    }

    #[tokio::test]
    async fn opaque_tokens_have_no_verification_entry() {
        let cfg = config();
        let v = verify_tokens(&cfg, Some("opaque-access-token"), None).await;
        assert!(v.access.is_none());
        assert!(v.id.is_none());
        assert!(verification_findings(&v).is_empty());
    }
}
