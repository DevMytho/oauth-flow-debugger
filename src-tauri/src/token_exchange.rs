//! Authorization code → token exchange and Client Credentials grant.
//!
//! All network I/O happens here (reqwest + rustls). Every request/response is
//! emitted as a `flow-step` event so the frontend timeline stays purely
//! display-side. `client_secret` values are redacted before emitting.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::decode::{self, DecodedJwt};
use crate::findings::{self, Expectations};
use crate::{
    emit_step, store, ClientAuth, FlowConfig, PendingFlow, StepKind, StepStatus, TokenBundle,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

fn epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Authorization Code grant: POST code + verifier to the token endpoint.
pub async fn exchange_authorization_code<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    pending: &PendingFlow,
    code: &str,
) -> Result<TokenBundle, String> {
    let config = &pending.config;
    let url = config.token_endpoint.trim();
    if url.is_empty() {
        return Err("token endpoint is not configured".into());
    }

    let mut fields: Vec<(String, String)> = vec![
        ("grant_type".into(), "authorization_code".into()),
        ("code".into(), code.to_string()),
        ("redirect_uri".into(), pending.redirect_uri.clone()),
    ];
    if let Some(verifier) = &pending.code_verifier {
        fields.push(("code_verifier".into(), verifier.clone()));
    }

    let expectations = Expectations {
        client_id: config.client_id.clone(),
        expected_iss: config.expected_iss.clone(),
        expected_alg: config.expected_alg.clone(),
        nonce: pending.nonce.clone(),
        requested_scope: config.scope.clone(),
    };

    let body = token_request(app, url, config, fields, "Authorization Code grant").await?;
    let raw = body
        .as_object()
        .cloned()
        .ok_or_else(|| "token endpoint returned a non-object JSON body".to_string())?;
    let verification = verify_raw(config, &raw).await;
    Ok(finalize_bundle(
        app,
        raw,
        "Token exchange",
        expectations,
        verification,
    ))
}

/// Run JWKS signature verification over the JWTs in a raw token response.
pub(crate) async fn verify_raw(
    config: &FlowConfig,
    raw: &serde_json::Map<String, Value>,
) -> crate::jwks::BundleVerification {
    let get = |k: &str| raw.get(k).and_then(Value::as_str);
    crate::jwks::verify_tokens(config, get("access_token"), get("id_token")).await
}

/// Client Credentials grant: no browser, direct token POST.
pub async fn client_credentials<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    config: &FlowConfig,
) -> Result<TokenBundle, String> {
    let url = config.token_endpoint.trim();
    if url.is_empty() {
        return Err("token endpoint is not configured".into());
    }
    if config.authorization_endpoint.trim().is_empty() && config.client_id.trim().is_empty() {
        return Err("client_id is required for the Client Credentials grant".into());
    }

    let mut fields: Vec<(String, String)> =
        vec![("grant_type".into(), "client_credentials".into())];
    if !config.scope.trim().is_empty() {
        fields.push(("scope".into(), config.scope.trim().to_string()));
    }

    let expectations = Expectations {
        client_id: config.client_id.clone(),
        expected_iss: config.expected_iss.clone(),
        expected_alg: config.expected_alg.clone(),
        nonce: None,
        requested_scope: config.scope.clone(),
    };

    let body = token_request(app, url, config, fields, "Client Credentials grant").await?;
    let raw = match body.as_object() {
        Some(map) => map.clone(),
        None => return Err("token endpoint returned a non-object JSON body".into()),
    };
    let verification = verify_raw(config, &raw).await;
    Ok(finalize_bundle(
        app,
        raw,
        "Client Credentials",
        expectations,
        verification,
    ))
}

/// Build the form POST, apply client authentication, emit request/response
/// steps, and surface OAuth-level errors as `Err`.
async fn token_request<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    url: &str,
    config: &FlowConfig,
    mut fields: Vec<(String, String)>,
    grant_label: &str,
) -> Result<Value, String> {
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        // "No outbound data leaves your machine except the OAuth calls you
        // initiate" — so ignore any HTTP_PROXY/HTTPS_PROXY env vars that would
        // silently route the code + secret + verifier through a proxy.
        .no_proxy()
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let mut req = client.post(url);
    let auth_label = match config.client_auth {
        ClientAuth::None => {
            fields.push(("client_id".into(), config.client_id.clone()));
            "client_id in body (public client)"
        }
        ClientAuth::ClientSecretBasic => {
            req = req.basic_auth(config.client_id.clone(), Some(config.client_secret.clone()));
            "HTTP Basic (client_secret_basic)"
        }
        ClientAuth::ClientSecretPost => {
            fields.push(("client_id".into(), config.client_id.clone()));
            fields.push(("client_secret".into(), config.client_secret.clone()));
            "client_secret in body (client_secret_post)"
        }
    };

    // Redacted view of the body for the timeline.
    let mut body_view = serde_json::Map::new();
    for (k, v) in &fields {
        // Secrets never reach the timeline (and therefore never an export).
        let val = if k == "client_secret" || k == "code_verifier" {
            "••••••••".to_string()
        } else {
            v.clone()
        };
        body_view.insert(k.clone(), Value::String(val));
    }

    emit_step(
        app,
        StepKind::TokenRequest,
        format!("{grant_label} → token endpoint"),
        StepStatus::Info,
        json!({
            "method": "POST",
            "url": url,
            "grant_type": fields
                .iter()
                .find(|(k, _)| k == "grant_type")
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
            "client_auth": auth_label,
            "body": Value::Object(body_view),
            "timeout_secs": REQUEST_TIMEOUT.as_secs(),
        }),
    );

    let resp = req
        .form(&fields)
        .send()
        .await
        .map_err(|e| format!("token request failed: {e}"))?;

    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("failed reading token response: {e}"))?;
    let body: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw_body": text }));

    let http_ok = status.is_success();
    let oauth_error = body.get("error").is_some();
    emit_step(
        app,
        StepKind::TokenResponse,
        if http_ok && !oauth_error {
            "Token endpoint responded".to_string()
        } else {
            "Token endpoint returned an error".to_string()
        },
        if http_ok && !oauth_error {
            StepStatus::Ok
        } else {
            StepStatus::Error
        },
        json!({
            "status": status.as_u16(),
            "ok": http_ok && !oauth_error,
            "body": body,
        }),
    );

    if !http_ok || oauth_error {
        let err = body
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("request_failed");
        let desc = body
            .get("error_description")
            .and_then(Value::as_str)
            .unwrap_or("");
        let msg = match (err, desc) {
            ("", "") => format!("HTTP {}", status.as_u16()),
            (e, "") => e.to_string(),
            (e, d) => format!("{e}: {d}"),
        };
        return Err(msg);
    }
    Ok(body)
}

/// Normalize a token response (JSON body or implicit-fragment params) into a
/// `TokenBundle`, decode any JWTs, and emit the `tokens` step.
pub fn finalize_bundle<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    raw: serde_json::Map<String, Value>,
    origin: &str,
    expectations: Expectations,
    verification: crate::jwks::BundleVerification,
) -> TokenBundle {
    let get_str = |k: &str| -> Option<String> {
        raw.get(k).and_then(|v| match v {
            Value::String(s) => Some(s.clone()),
            Value::Null => None,
            other => Some(other.to_string()),
        })
    };
    let expires_in = raw.get("expires_in").and_then(|v| {
        v.as_i64()
            .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
    });

    let access_token = get_str("access_token");
    let id_token = get_str("id_token");
    let decoded_access: Option<DecodedJwt> = access_token
        .as_deref()
        .and_then(|t| decode::decode_jwt(t).ok());
    let decoded_id: Option<DecodedJwt> =
        id_token.as_deref().and_then(|t| decode::decode_jwt(t).ok());

    let warnings: Vec<String> = {
        let mut w = Vec::new();
        if let Some(d) = &decoded_access {
            for x in &d.warnings {
                w.push(format!("access_token: {x}"));
            }
        }
        if let Some(d) = &decoded_id {
            for x in &d.warnings {
                w.push(format!("id_token: {x}"));
            }
        }
        if access_token.is_none() && id_token.is_none() {
            w.push("response contains no access_token or id_token".into());
        }
        w
    };

    // Last uses of the `raw` borrow before it is moved into the bundle.
    let token_type = get_str("token_type");
    let refresh_token = get_str("refresh_token");
    let scope = get_str("scope");

    // Automated checks: alg / exp / iss / aud / nonce per token, the
    // granted-vs-requested scope comparison, and JWKS signature verification.
    {
        let mut access_exp = expectations.clone();
        // The nonce binds the ID token only — an access token has no nonce.
        access_exp.nonce = None;
        let mut found = Vec::new();
        if let Some(d) = &decoded_access {
            found.extend(findings::token_findings(d, "access_token", &access_exp));
        }
        if let Some(d) = &decoded_id {
            found.extend(findings::token_findings(d, "id_token", &expectations));
        }
        found.extend(findings::scope_findings(
            &expectations.requested_scope,
            scope.as_deref(),
        ));
        found.extend(crate::jwks::verification_findings(&verification));
        store::record_findings(&found);
        crate::emit_findings(app);
    }

    let bundle = TokenBundle {
        raw: Value::Object(raw),
        access_token,
        id_token,
        token_type,
        expires_in,
        refresh_token,
        scope: scope.clone(),
        decoded_access,
        decoded_id,
        expires_at: expires_in.map(|e| epoch_secs() + e),
        verification,
    };

    emit_step(
        app,
        StepKind::Tokens,
        format!("{origin} — tokens decoded"),
        if warnings.is_empty() {
            StepStatus::Ok
        } else {
            StepStatus::Warn
        },
        json!({
            "bundle": bundle.clone(),
            "warnings": warnings,
        }),
    );

    bundle
}

/// Convenience for the implicit flow: params arrive as a flat string map
/// (signature verification already happened in `process_callback`).
pub fn bundle_from_params<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    params: &HashMap<String, String>,
    expectations: Expectations,
    verification: crate::jwks::BundleVerification,
) -> TokenBundle {
    let mut raw = serde_json::Map::new();
    for (k, v) in params {
        raw.insert(k.clone(), Value::String(v.clone()));
    }
    finalize_bundle(app, raw, "Implicit flow", expectations, verification)
}
