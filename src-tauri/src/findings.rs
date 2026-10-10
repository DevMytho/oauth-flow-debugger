//! Automated security checks for a flow, with severity ratings.
//!
//! These are the checks the README promises: they run in Rust while the flow
//! executes (config → callback → token response) and are collected into a
//! findings summary that the UI renders and can export.
//!
//! Each check has a stable `id` so reports and tests can reference it:
//!
//! | id                          | severity | what                                   |
//! |-----------------------------|----------|----------------------------------------|
//! | `state_mismatch`            | critical | callback state ≠ the state we sent     |
//! | `missing_state`             | high     | no state in the callback               |
//! | `nonce_mismatch`            | critical | id_token nonce ≠ the nonce we sent     |
//! | `missing_nonce`             | high     | OIDC flow/id_token without a nonce     |
//! | `pkce_missing`              | high     | authorization code flow without PKCE   |
//! | `pkce_plain`                | high     | PKCE `plain` instead of `S256`         |
//! | `implicit_flow`             | high     | tokens delivered in the URL fragment   |
//! | `alg_none`                  | critical | unsigned token                         |
//! | `alg_mismatch`              | high     | alg ≠ the expected alg (e.g. HS256 vs RS256) |
//! | `alg_hs256`                 | medium   | HMAC alg with no expectation pinned    |
//! | `expired_token`             | high     | exp in the past                        |
//! | `missing_exp`               | medium   | no exp claim                           |
//! | `aud_mismatch`              | high     | aud ≠ client_id                        |
//! | `missing_aud`               | medium   | no aud claim                           |
//! | `iss_mismatch`              | high     | iss ≠ expected issuer                  |
//! | `missing_iss`               | medium   | no iss claim                           |
//! | `non_https_endpoint`        | high     | remote endpoint over plain http        |
//! | `non_https_loopback`        | low      | loopback endpoint over plain http      |
//! | `scope_broader_than_requested` | medium | granted scope ⊄ requested scope        |
//! | `sig_verified`              | info     | JWKS signature verification succeeded   |
//! | `sig_invalid`               | critical | signature does not match the JWKS key   |
//! | `sig_kid_not_found`         | high     | token `kid` is absent from the JWKS     |
//! | `sig_unverified`            | low      | signature could not be checked          |

use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::decode::DecodedJwt;
use crate::FlowConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Severity::Critical => "🛑",
            Severity::High => "❌",
            Severity::Medium => "⚠️",
            Severity::Low => "🟡",
            Severity::Info => "ℹ️",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
}

impl Finding {
    pub fn new(
        id: &str,
        severity: Severity,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id: id.to_string(),
            severity,
            title: title.into(),
            detail: detail.into(),
        }
    }
}

/// Counts by severity, ordered worst-first — the payload behind the
/// "findings summary" chip row.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}

impl Summary {
    pub fn from(findings: &[Finding]) -> Self {
        let mut s = Self::default();
        for f in findings {
            match f.severity {
                Severity::Critical => s.critical += 1,
                Severity::High => s.high += 1,
                Severity::Medium => s.medium += 1,
                Severity::Low => s.low += 1,
                Severity::Info => s.info += 1,
            }
            s.total += 1;
        }
        s
    }
}

/// Expectations for token-level checks, derived from the flow configuration.
#[derive(Debug, Clone, Default)]
pub struct Expectations {
    pub client_id: String,
    /// `exp`/`iat`/nonce reference point for the checks.
    pub expected_iss: String,
    pub expected_alg: String,
    pub nonce: Option<String>,
    pub requested_scope: String,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn is_loopback_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    h == "localhost" || h.ends_with(".localhost") || h == "127.0.0.1" || h == "[::1]"
}

pub fn endpoint_findings(label: &str, raw: &str) -> Vec<Finding> {
    let url = raw.trim();
    if url.is_empty() {
        return Vec::new();
    }
    match url::Url::parse(url) {
        Ok(u) => match (u.scheme(), u.host_str()) {
            ("https", _) => Vec::new(),
            ("http", Some(host)) if is_loopback_host(host) => vec![Finding::new(
                "non_https_loopback",
                Severity::Low,
                format!("{label} is plain HTTP (loopback)"),
                format!(
                    "{url} — acceptable for a local mock provider (RFC 8252 loopback), \
                     never for a real provider"
                ),
            )],
            ("http", _) => vec![Finding::new(
                "non_https_endpoint",
                Severity::High,
                format!("{label} is not HTTPS"),
                format!(
                    "{url} — authorization codes, tokens and client secrets would cross \
                     the network in clear text"
                ),
            )],
            (other, _) => vec![Finding::new(
                "non_https_endpoint",
                Severity::High,
                format!("{label} uses unsupported scheme `{other}`"),
                url.to_string(),
            )],
        },
        Err(e) => vec![Finding::new(
            "non_https_endpoint",
            Severity::Medium,
            format!("{label} is not a valid URL"),
            format!("{url}: {e}"),
        )],
    }
}

/// PKCE checks for the method actually used in the authorization request.
pub fn pkce_findings(method: &str, used: bool) -> Vec<Finding> {
    if !used {
        return Vec::new();
    }
    match method {
        "S256" => Vec::new(),
        "plain" => vec![Finding::new(
            "pkce_plain",
            Severity::High,
            "PKCE uses the `plain` code_challenge_method",
            "`plain` sends the verifier unhashed — anyone who can observe the \
             authorization request learns the verifier. Use S256.",
        )],
        other => vec![Finding::new(
            "pkce_plain",
            Severity::Medium,
            format!("PKCE uses unknown code_challenge_method `{other}`"),
            "Only `S256` is safe to rely on.",
        )],
    }
}

/// Checks that can be made the moment a flow is configured / started.
pub fn config_findings(cfg: &FlowConfig) -> Vec<Finding> {
    let mut out = Vec::new();

    out.extend(endpoint_findings(
        "authorization endpoint",
        &cfg.authorization_endpoint,
    ));
    out.extend(endpoint_findings("token endpoint", &cfg.token_endpoint));
    out.extend(endpoint_findings("JWKS URI", &cfg.jwks_uri));

    if cfg.flow_type == crate::FlowType::Implicit {
        out.push(Finding::new(
            "implicit_flow",
            Severity::High,
            "Implicit flow is in use",
            "response_type=token/id_token puts tokens in the URL fragment — they land \
             in browser history, proxy logs and Referer headers, and there is no \
             refresh token. Authorization Code + PKCE is the replacement.",
        ));
    }

    if cfg.flow_type == crate::FlowType::AuthorizationCode {
        if cfg.pkce {
            out.extend(pkce_findings("S256", true));
        } else {
            out.push(Finding::new(
                "pkce_missing",
                Severity::High,
                "PKCE is disabled for an authorization code flow",
                "Without PKCE a stolen authorization code can be redeemed by whoever \
                 holds it. Toggle PKCE (S256) on for public clients.",
            ));
        }
    }

    let wants_oidc = cfg
        .scope
        .split_whitespace()
        .any(|s| s.eq_ignore_ascii_case("openid"));
    // Device Authorization has no authorization request to carry a nonce, and
    // Client Credentials issues no ID token — neither can bind one.
    let nonce_applicable = cfg.flow_type != crate::FlowType::ClientCredentials
        && cfg.flow_type != crate::FlowType::DeviceAuthorization;
    if wants_oidc && !cfg.include_nonce && nonce_applicable {
        out.push(Finding::new(
            "missing_nonce",
            Severity::High,
            "OIDC flow started without a nonce",
            "`scope` contains `openid` but no nonce was generated, so the ID token \
             cannot be bound to this request (replay protection is lost).",
        ));
    }

    out
}

/// Checks made against the intercepted callback (query/fragment params).
pub fn callback_findings(
    params: &HashMap<String, String>,
    state_valid: Option<bool>,
    state_was_sent: bool,
) -> Vec<Finding> {
    let mut out = Vec::new();

    match state_valid {
        Some(false) => out.push(Finding::new(
            "state_mismatch",
            Severity::Critical,
            "Callback `state` does not match the value sent",
            "The callback was rejected. A mismatch here is either a CSRF attempt or a \
             replayed/stale callback.",
        )),
        Some(true) => {}
        None => {
            if state_was_sent && !params.contains_key("state") {
                out.push(Finding::new(
                    "missing_state",
                    Severity::High,
                    "Callback has no `state` parameter",
                    "A callback without state cannot be bound to this request — the \
                     provider (or an interceptor) dropped the CSRF token.",
                ));
            }
        }
    }

    out
}

/// Checks made against a decoded token from the response.
pub fn token_findings(token: &DecodedJwt, role: &str, exp: &Expectations) -> Vec<Finding> {
    let mut out = Vec::new();

    // --- algorithm -------------------------------------------------------
    if token.alg.is_empty() || token.alg == "none" {
        out.push(Finding::new(
            "alg_none",
            Severity::Critical,
            format!("{role} token uses `alg: none`"),
            "The token is unsigned — anyone can mint one. The provider must sign \
             tokens with a real asymmetric algorithm.",
        ));
    } else if !exp.expected_alg.is_empty() && !token.alg.eq_ignore_ascii_case(&exp.expected_alg) {
        let expected = exp.expected_alg.to_ascii_uppercase();
        let detail = if token.alg.starts_with("HS") && expected.starts_with('R') {
            format!(
                "Expected {} but the provider signed with {}. HMAC tokens are keyed by \
                 a shared secret — if the API accepts them where RS/ES was expected, \
                 anyone with the client secret can forge tokens.",
                exp.expected_alg, token.alg
            )
        } else {
            format!(
                "Expected {} but got {} — algorithm substitution is a classic JWT attack.",
                exp.expected_alg, token.alg
            )
        };
        out.push(Finding::new(
            "alg_mismatch",
            Severity::High,
            format!(
                "{role} token alg is {}, expected {}",
                token.alg, exp.expected_alg
            ),
            detail,
        ));
    } else if token.alg.starts_with("HS") {
        out.push(Finding::new(
            "alg_hs256",
            Severity::Medium,
            format!("{role} token is HMAC-signed ({})", token.alg),
            "HMAC is only safe if the signing secret is never shared with the client. \
             Pin an expected alg (e.g. RS256) to confirm what you actually get.",
        ));
    }

    // --- lifetime --------------------------------------------------------
    match token.exp {
        None => out.push(Finding::new(
            "missing_exp",
            Severity::Medium,
            format!("{role} token has no `exp` claim"),
            "A token without exp never expires — revocation becomes impossible.",
        )),
        Some(e) if e <= now_secs() => out.push(Finding::new(
            "expired_token",
            Severity::High,
            format!("{role} token is already expired"),
            format!(
                "exp={e} ({}s ago) — the provider issued an expired token.",
                now_secs() - e
            ),
        )),
        Some(_) => {}
    }

    // --- audience --------------------------------------------------------
    let aud = token.payload.get("aud");
    match aud {
        None => out.push(Finding::new(
            "missing_aud",
            Severity::Medium,
            format!("{role} token has no `aud` claim"),
            "Without an audience the token can be replayed against any API that \
             shares the issuer's keys.",
        )),
        Some(v) if !exp.client_id.is_empty() => {
            let ok = match v {
                Value::String(s) => s == &exp.client_id,
                Value::Array(items) => items
                    .iter()
                    .any(|i| i.as_str() == Some(exp.client_id.as_str())),
                _ => false,
            };
            if !ok {
                out.push(Finding::new(
                    "aud_mismatch",
                    Severity::High,
                    format!("{role} token audience does not match this client"),
                    format!("aud={v} but client_id={} — this token was minted for a different audience.", exp.client_id),
                ));
            }
        }
        Some(_) => {}
    }

    // --- issuer ----------------------------------------------------------
    let iss = token
        .payload
        .get("iss")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if iss.is_empty() {
        out.push(Finding::new(
            "missing_iss",
            Severity::Medium,
            format!("{role} token has no `iss` claim"),
            "Issuer cannot be checked, so any provider sharing your keys could mint \
             accepted tokens.",
        ));
    } else if !exp.expected_iss.is_empty() {
        let normalize = |s: &str| s.trim().trim_end_matches('/').to_ascii_lowercase();
        if normalize(&iss) != normalize(&exp.expected_iss) {
            out.push(Finding::new(
                "iss_mismatch",
                Severity::High,
                format!("{role} token issuer does not match the expected issuer"),
                format!(
                    "iss={iss}, expected {} — possible mix-up or wrong tenant.",
                    exp.expected_iss
                ),
            ));
        }
    }

    // --- nonce (OIDC replay binding) -------------------------------------
    let nonce_claim = token.payload.get("nonce").and_then(Value::as_str);
    match (&exp.nonce, nonce_claim) {
        (Some(_), None) => out.push(Finding::new(
            "missing_nonce",
            Severity::High,
            format!("{role} token has no `nonce` claim"),
            "A nonce was sent for this OIDC flow but the ID token is not bound to it, \
             so the token could be replayed into another session.",
        )),
        (Some(expected), Some(got)) if got != expected.as_str() => out.push(Finding::new(
            "nonce_mismatch",
            Severity::Critical,
            format!("{role} token nonce does not match"),
            "The ID token was not issued for this request — replay or mix-up likely.",
        )),
        _ => {}
    }

    out
}

/// Granted-vs-requested scope check (`scope` in the token response).
pub fn scope_findings(requested: &str, granted: Option<&str>) -> Vec<Finding> {
    let Some(granted) = granted else {
        return Vec::new();
    };
    let want: Vec<&str> = requested.split_whitespace().collect();
    if want.is_empty() {
        return Vec::new();
    }
    let extra: Vec<&str> = granted
        .split_whitespace()
        .filter(|g| !want.iter().any(|w| w.eq_ignore_ascii_case(g)))
        .collect();
    if extra.is_empty() {
        return Vec::new();
    }
    vec![Finding::new(
        "scope_broader_than_requested",
        Severity::Medium,
        "Token response granted scopes that were never requested",
        format!(
            "requested: {requested} · granted: {granted} · extra: {}",
            extra.join(", ")
        ),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClientAuth, FlowType};

    fn cfg() -> FlowConfig {
        FlowConfig {
            flow_type: FlowType::AuthorizationCode,
            authorization_endpoint: "https://provider.example/authorize".into(),
            token_endpoint: "https://provider.example/token".into(),
            client_id: "client-123".into(),
            client_secret: String::new(),
            redirect_uri: String::new(),
            scope: "openid profile email".into(),
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

    fn id(token: &str) -> DecodedJwt {
        crate::decode::decode_jwt(token).expect("token should decode")
    }

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.id.as_str()).collect()
    }

    // {"alg":"RS256","typ":"JWT"} / iss, aud, exp(2033), nonce
    const GOOD: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5leGFtcGxlIiwiYXVkIjoiY2xpZW50LTEyMyIsImV4cCI6MTk5OTk5OTk5OSwiaWF0IjoxOTAwMDAwMDAwLCJub25jZSI6ImFiYzEyMyJ9.signature";
    // {"alg":"none"} / sub
    const UNSIGNED: &str = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.";
    // {"alg":"HS256"} / exp: 1000000000 (2001), no iss/aud/nonce
    const HMAC_EXPIRED: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4IiwiZXhwIjoxMDAwMDAwMDAwfQ.sig";

    #[test]
    fn clean_config_has_no_findings() {
        assert!(config_findings(&cfg()).is_empty());
    }

    #[test]
    fn flags_non_https_and_plain_http_endpoints() {
        let mut c = cfg();
        c.authorization_endpoint = "http://provider.example/authorize".into();
        c.token_endpoint = "http://127.0.0.1:9099/token".into();
        let found = config_findings(&c);
        assert_eq!(
            ids(&found),
            vec!["non_https_endpoint", "non_https_loopback"]
        );
        assert_eq!(found[0].severity, Severity::High);
        assert_eq!(found[1].severity, Severity::Low);
    }

    #[test]
    fn flags_implicit_pkce_off_and_missing_nonce() {
        let mut c = cfg();
        c.flow_type = FlowType::Implicit;
        c.pkce = false;
        c.include_nonce = false;
        let found = config_findings(&c);
        let i = ids(&found);
        assert!(i.contains(&"implicit_flow"));
        assert!(i.contains(&"missing_nonce"));
        assert!(
            !i.contains(&"pkce_missing"),
            "PKCE does not apply to implicit"
        );

        let mut c2 = cfg();
        c2.pkce = false;
        let f2 = config_findings(&c2);
        assert_eq!(ids(&f2), vec!["pkce_missing"]);
        assert_eq!(f2[0].severity, Severity::High);
    }

    #[test]
    fn flags_pkce_plain_method() {
        let found = pkce_findings("plain", true);
        assert_eq!(ids(&found), vec!["pkce_plain"]);
        assert_eq!(found[0].severity, Severity::High);
        assert!(pkce_findings("S256", true).is_empty());
        assert!(pkce_findings("plain", false).is_empty());
    }

    #[test]
    fn flags_state_missing_and_mismatched() {
        let mut params = HashMap::new();
        params.insert("code".into(), "abc".into());

        let missing = callback_findings(&params, None, true);
        assert_eq!(ids(&missing), vec!["missing_state"]);
        assert_eq!(missing[0].severity, Severity::High);

        let mismatch = callback_findings(&params, Some(false), true);
        assert_eq!(ids(&mismatch), vec!["state_mismatch"]);
        assert_eq!(mismatch[0].severity, Severity::Critical);

        // state present and valid → nothing
        assert!(callback_findings(&params, Some(true), true).is_empty());
        // no state was ever sent → the check doesn't apply
        assert!(callback_findings(&params, None, false).is_empty());
    }

    #[test]
    fn flags_alg_none_and_expected_alg_mismatch() {
        let exp = Expectations {
            expected_alg: "RS256".into(),
            ..Default::default()
        };
        let unsigned = token_findings(&id(UNSIGNED), "id_token", &exp);
        assert!(ids(&unsigned).contains(&"alg_none"));
        assert_eq!(unsigned[0].severity, Severity::Critical);

        let hmac = token_findings(&id(HMAC_EXPIRED), "access_token", &exp);
        let i = ids(&hmac);
        assert!(i.contains(&"alg_mismatch"), "{i:?}");
        assert!(i.contains(&"expired_token"));
        assert!(i.contains(&"missing_aud"));
        assert!(i.contains(&"missing_iss"));

        // HS256 without a pinned expectation → medium, not high
        let unpinned = token_findings(&id(HMAC_EXPIRED), "access_token", &Expectations::default());
        assert!(ids(&unpinned).contains(&"alg_hs256"));
        assert!(!ids(&unpinned).contains(&"alg_mismatch"));
    }

    #[test]
    fn flags_aud_and_iss_mismatch() {
        let exp = Expectations {
            client_id: "other-client".into(),
            expected_iss: "https://accounts.example.com".into(),
            ..Default::default()
        };
        let found = token_findings(&id(GOOD), "id_token", &exp);
        let i = ids(&found);
        assert!(i.contains(&"aud_mismatch"), "{i:?}");
        assert!(i.contains(&"iss_mismatch"), "{i:?}");
    }

    #[test]
    fn flags_nonce_missing_and_mismatched() {
        let with_nonce = Expectations {
            nonce: Some("abc123".into()),
            client_id: "client-123".into(),
            ..Default::default()
        };
        assert!(token_findings(&id(GOOD), "id_token", &with_nonce).is_empty());

        let wrong = Expectations {
            nonce: Some("other".into()),
            client_id: "client-123".into(),
            ..Default::default()
        };
        let found = token_findings(&id(GOOD), "id_token", &wrong);
        assert_eq!(ids(&found), vec!["nonce_mismatch"]);
        assert_eq!(found[0].severity, Severity::Critical);

        let missing = Expectations {
            nonce: Some("abc123".into()),
            client_id: "client-123".into(),
            ..Default::default()
        };
        let found = token_findings(&id(HMAC_EXPIRED), "id_token", &missing);
        assert!(ids(&found).contains(&"missing_nonce"));
    }

    #[test]
    fn flags_scope_broader_than_requested() {
        let found = scope_findings(
            "openid profile",
            Some("openid profile email offline_access"),
        );
        assert_eq!(ids(&found), vec!["scope_broader_than_requested"]);
        assert_eq!(found[0].severity, Severity::Medium);
        assert!(scope_findings("openid profile", Some("openid")).is_empty());
        assert!(scope_findings("openid", None).is_empty());
        assert!(scope_findings("", Some("openid")).is_empty());
    }

    #[test]
    fn summary_counts_by_severity() {
        let f = vec![
            Finding::new("a", Severity::Critical, "a", "a"),
            Finding::new("b", Severity::High, "b", "b"),
            Finding::new("c", Severity::High, "c", "c"),
            Finding::new("d", Severity::Info, "d", "d"),
        ];
        let s = Summary::from(&f);
        assert_eq!(
            (s.critical, s.high, s.medium, s.low, s.info, s.total),
            (1, 2, 0, 0, 1, 4)
        );
    }
}
