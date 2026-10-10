//! Device Authorization Grant (RFC 8628) — the flow behind smart-TV and
//! CLI logins: no browser on this machine, the user types a short code at
//! the provider's `verification_uri`, and the app polls the token endpoint
//! until they approve.
//!
//! Shape of the flow:
//!
//! 1. [`start`] POSTs `client_id` (+ `scope`) to the device authorization
//!    endpoint, stores the `device_code` **in memory only**, and returns the
//!    user-facing parts (`user_code`, `verification_uri`, …) for the UI.
//! 2. [`poll`] posts `grant_type=urn:ietf:params:oauth:grant-type:device_code`
//!    every `interval` seconds, turning RFC answers into timeline steps:
//!    `authorization_pending` → info step and keep waiting, `slow_down` →
//!    widen the interval, anything else → fatal (state cleared).
//! 3. On success the response goes through the same
//!    decode → JWKS verify → findings pipeline as every other grant.
//!
//! The device code never leaves the backend: the UI only ever sees the
//! user-facing `user_code` and verification URL.

use serde::Serialize;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::findings::{Finding, Severity};
use crate::token_exchange;
use crate::{
    emit_findings, emit_step, store, ClientAuth, FlowConfig, StepKind, StepStatus, TokenBundle,
};

/// Poll cadence when the provider does not send an `interval` (RFC 8628 §3.2:
/// "If absent, the default is 5 seconds").
const DEFAULT_INTERVAL_SECS: u64 = 5;
/// Default lifetime when the provider omits `expires_in`.
const DEFAULT_EXPIRES_IN: i64 = 600;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// What the frontend displays while the user is authorizing.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceAuthStart {
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: i64,
    pub interval: u64,
}

/// Backend-side state for an in-flight device flow. Never serialized to the
/// frontend or to disk — only the `user_code`/URI go out.
#[derive(Debug, Clone)]
pub struct DeviceFlow {
    pub config: FlowConfig,
    pub device_code: String,
    pub interval: u64,
    /// epoch seconds
    pub expires_at: i64,
}

pub type SharedDeviceFlow = Arc<Mutex<Option<DeviceFlow>>>;

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn as_i64(v: Option<&Value>) -> Option<i64> {
    v.and_then(|v| {
        v.as_i64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    })
}

/// Form POST to the provider with client authentication applied the same way
/// as every other grant (Basic header, or `client_id`/`client_secret` in the
/// body), no env proxy, hard timeout.
async fn post_form(
    config: &FlowConfig,
    url: &str,
    mut form: Vec<(String, String)>,
) -> Result<Value, String> {
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .no_proxy()
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;
    let mut req = client.post(url);
    match config.client_auth {
        ClientAuth::None => {
            form.push(("client_id".into(), config.client_id.clone()));
        }
        ClientAuth::ClientSecretBasic => {
            req = req.basic_auth(config.client_id.clone(), Some(config.client_secret.clone()));
        }
        ClientAuth::ClientSecretPost => {
            form.push(("client_id".into(), config.client_id.clone()));
            form.push(("client_secret".into(), config.client_secret.clone()));
        }
    }

    let resp = req
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("failed reading response: {e}"))?;
    let body: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw_body": text }));
    if !status.is_success() && body.get("error").is_none() {
        return Err(format!("HTTP {}", status.as_u16()));
    }
    Ok(body)
}

// ---------------------------------------------------------------------------
// 1. Device authorization request
// ---------------------------------------------------------------------------

/// Step 1: request a `device_code` + `user_code` from the provider.
pub async fn start<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    shared: &SharedDeviceFlow,
    config: FlowConfig,
) -> Result<DeviceAuthStart, String> {
    let endpoint = config.device_authorization_endpoint.trim().to_string();
    if endpoint.is_empty() {
        return Err("device authorization endpoint is required".into());
    }
    if config.client_id.trim().is_empty() {
        return Err("client_id is required".into());
    }

    // Fresh run: transcript/findings/config, same as `start_flow`.
    store::reset();
    store::set_config(&config);
    store::record_findings(&config_and_device_findings(&config));
    store::record_findings(&[Finding::new(
        "device_flow",
        Severity::Info,
        "Device Authorization grant in use",
        "A short `user_code` must be entered at the provider's verification URI. \
         Confirm the URL in the user's browser matches the real provider — this flow \
         is a common phishing target.",
    )]);
    emit_findings(app);

    let mut form = Vec::new();
    let scope = config.scope.trim().to_string();
    if !scope.is_empty() {
        form.push(("scope".to_string(), scope.clone()));
    }

    // Redacted request step (mirrors `token_exchange::token_request`).
    let mut body_view = serde_json::Map::new();
    body_view.insert("scope".into(), json!(scope));
    body_view.insert("client_id".into(), json!(config.client_id));
    if config.client_auth == ClientAuth::ClientSecretPost {
        body_view.insert("client_secret".into(), json!("••••••••"));
    }
    emit_step(
        app,
        StepKind::TokenRequest,
        "Device authorization request → provider",
        StepStatus::Info,
        json!({
            "method": "POST",
            "url": endpoint,
            "body": Value::Object(body_view),
            "timeout_secs": REQUEST_TIMEOUT.as_secs(),
        }),
    );

    let body = post_form(&config, &endpoint, form).await?;

    if let Some(code) = body.get("error").and_then(Value::as_str) {
        let desc = body
            .get("error_description")
            .and_then(Value::as_str)
            .unwrap_or("");
        emit_step(
            app,
            StepKind::Error,
            "Device authorization request failed",
            StepStatus::Error,
            json!({ "error": code, "error_description": desc }),
        );
        return Err(if desc.is_empty() {
            code.to_string()
        } else {
            format!("{code}: {desc}")
        });
    }

    let device_code = body
        .get("device_code")
        .and_then(Value::as_str)
        .ok_or("device authorization response has no `device_code`")?
        .to_string();
    let user_code = body
        .get("user_code")
        .and_then(Value::as_str)
        .ok_or("device authorization response has no `user_code`")?
        .to_string();
    let verification_uri = body
        .get("verification_uri")
        .and_then(Value::as_str)
        .ok_or("device authorization response has no `verification_uri`")?
        .to_string();
    let verification_uri_complete = body
        .get("verification_uri_complete")
        .and_then(Value::as_str)
        .map(str::to_string);
    let expires_in = as_i64(body.get("expires_in")).unwrap_or(DEFAULT_EXPIRES_IN);
    let interval = as_i64(body.get("interval"))
        .map(|i| i.max(0) as u64)
        .unwrap_or(DEFAULT_INTERVAL_SECS);

    *shared
        .lock()
        .map_err(|_| "internal device-flow lock poisoned".to_string())? = Some(DeviceFlow {
        config,
        device_code,
        interval,
        expires_at: now_secs() + expires_in,
    });

    emit_step(
        app,
        StepKind::Info,
        "Device code issued — enter it at the verification URI",
        StepStatus::Info,
        json!({
            "user_code": user_code,
            "verification_uri": verification_uri,
            "verification_uri_complete": verification_uri_complete,
            "expires_in": expires_in,
            "interval_secs": interval,
            // The device code itself stays backend-side.
            "device_code": "••••••••",
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        }),
    );
    emit_findings(app);

    Ok(DeviceAuthStart {
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in,
        interval,
    })
}

/// Config-time findings plus the device-endpoint HTTPS check.
fn config_and_device_findings(cfg: &FlowConfig) -> Vec<Finding> {
    let mut out = crate::findings::config_findings(cfg);
    out.extend(crate::findings::endpoint_findings(
        "device authorization endpoint",
        &cfg.device_authorization_endpoint,
    ));
    out
}

// ---------------------------------------------------------------------------
// 2. Poll the token endpoint
// ---------------------------------------------------------------------------

/// Step 2: poll until the user approves (or the code dies).
pub async fn poll<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    shared: &SharedDeviceFlow,
) -> Result<TokenBundle, String> {
    let mut poll_no: u64 = 0;
    let mut first = true;
    loop {
        let (config, device_code, interval, expires_at) = {
            let guard = shared
                .lock()
                .map_err(|_| "internal device-flow lock poisoned".to_string())?;
            match guard.as_ref() {
                Some(f) => (
                    f.config.clone(),
                    f.device_code.clone(),
                    f.interval,
                    f.expires_at,
                ),
                None => return Err("device flow was reset — start it again".into()),
            }
        };

        if now_secs() >= expires_at {
            clear(shared);
            emit_step(
                app,
                StepKind::Error,
                "Device code expired",
                StepStatus::Error,
                json!({ "message": "the user did not authorize in time" }),
            );
            return Err("device code expired before the user authorized — start again".into());
        }

        if first {
            first = false;
            emit_step(
                app,
                StepKind::TokenRequest,
                "Device code polling started",
                StepStatus::Info,
                json!({
                    "method": "POST",
                    "url": config.token_endpoint,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": "••••••••",
                    "interval_secs": interval,
                    "expires_in": expires_at - now_secs(),
                }),
            );
        }

        poll_no += 1;
        let url = config.token_endpoint.trim().to_string();
        if url.is_empty() {
            return Err("token endpoint is not configured".into());
        }
        let form = vec![
            (
                "grant_type".to_string(),
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            ),
            ("device_code".to_string(), device_code.clone()),
        ];
        let body = post_form(&config, &url, form).await?;

        if let Some(code) = body.get("error").and_then(Value::as_str) {
            let desc = body
                .get("error_description")
                .and_then(Value::as_str)
                .unwrap_or("");
            match code {
                "authorization_pending" => {
                    emit_step(
                        app,
                        StepKind::Info,
                        format!("Poll {poll_no}: waiting for the user to authorize"),
                        StepStatus::Info,
                        json!({ "error": "authorization_pending", "interval_secs": interval }),
                    );
                    tokio::time::sleep(Duration::from_secs(interval)).await;
                    continue;
                }
                "slow_down" => {
                    let next = interval + 5;
                    if let Ok(mut guard) = shared.lock() {
                        if let Some(f) = guard.as_mut() {
                            f.interval = next;
                        }
                    }
                    emit_step(
                        app,
                        StepKind::Info,
                        format!("Poll {poll_no}: slow_down — backing off to {next}s"),
                        StepStatus::Warn,
                        json!({ "error": "slow_down", "interval_secs": next }),
                    );
                    tokio::time::sleep(Duration::from_secs(next)).await;
                    continue;
                }
                other => {
                    clear(shared);
                    let msg = if desc.is_empty() {
                        other.to_string()
                    } else {
                        format!("{other}: {desc}")
                    };
                    emit_step(
                        app,
                        StepKind::Error,
                        "Device flow rejected",
                        StepStatus::Error,
                        json!({ "error": other, "error_description": desc }),
                    );
                    return Err(msg);
                }
            }
        }

        // ---- granted ----------------------------------------------------
        emit_step(
            app,
            StepKind::TokenResponse,
            "Device code granted — tokens issued",
            StepStatus::Ok,
            json!({ "ok": true, "status": 200, "body": body }),
        );
        let raw = body
            .as_object()
            .cloned()
            .ok_or_else(|| "token endpoint returned a non-object JSON body".to_string())?;

        let expectations = crate::findings::Expectations {
            client_id: config.client_id.clone(),
            expected_iss: config.expected_iss.clone(),
            expected_alg: config.expected_alg.clone(),
            nonce: None, // no authorization request → no nonce to bind
            requested_scope: config.scope.clone(),
        };
        let verification = token_exchange::verify_raw(&config, &raw).await;
        let bundle = token_exchange::finalize_bundle(
            app,
            raw,
            "Device Authorization",
            expectations,
            verification,
        );
        clear(shared);
        return Ok(bundle);
    }
}

fn clear(shared: &SharedDeviceFlow) {
    if let Ok(mut guard) = shared.lock() {
        *guard = None;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{listener, ClientAuth, FlowType};

    /// Mock provider: `/device` issues a code, `/token` answers
    /// `authorization_pending` once and grants tokens on the second poll.
    async fn spawn_mock() -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        let polls: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();

        let device_polls = polls.clone();
        let router = axum::Router::new()
            .route(
                "/device",
                axum::routing::post(
                    move |axum::extract::Form(_form): axum::extract::Form<
                        std::collections::HashMap<String, String>,
                    >| async move {
                        axum::Json(json!({
                            "device_code": "dev-code-123",
                            "user_code": "ABCD-EFGH",
                            "verification_uri": format!("http://127.0.0.1:{port}/activate"),
                            "verification_uri_complete":
                                format!("http://127.0.0.1:{port}/activate?user_code=ABCD-EFGH"),
                            "expires_in": 600,
                            "interval": 0,
                        }))
                    },
                ),
            )
            .route(
                "/token",
                axum::routing::post(
                    move |axum::extract::Form(form): axum::extract::Form<
                        std::collections::HashMap<String, String>,
                    >| {
                        let polls = device_polls.clone();
                        async move {
                            assert_eq!(
                                form.get("grant_type").map(String::as_str),
                                Some("urn:ietf:params:oauth:grant-type:device_code")
                            );
                            assert_eq!(
                                form.get("device_code").map(String::as_str),
                                Some("dev-code-123")
                            );
                            assert_eq!(
                                form.get("client_id").map(String::as_str),
                                Some("tv-client")
                            );
                            let n = polls.fetch_add(1, Ordering::SeqCst);
                            if n == 0 {
                                (
                                    axum::http::StatusCode::BAD_REQUEST,
                                    axum::Json(json!({ "error": "authorization_pending" })),
                                )
                            } else {
                                (
                                    axum::http::StatusCode::OK,
                                    axum::Json(json!({
                                        "access_token": "dev-access-token",
                                        "token_type": "Bearer",
                                        "expires_in": 1800,
                                        "scope": "read write",
                                    })),
                                )
                            }
                        }
                    },
                ),
            );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://127.0.0.1:{port}")
    }

    fn test_config(base: &str) -> FlowConfig {
        FlowConfig {
            flow_type: FlowType::DeviceAuthorization,
            authorization_endpoint: String::new(),
            token_endpoint: format!("{base}/token"),
            client_id: "tv-client".into(),
            client_secret: String::new(),
            redirect_uri: String::new(),
            scope: "read".into(),
            pkce: false,
            include_nonce: false,
            client_auth: ClientAuth::None,
            listener_port: 0,
            expected_iss: String::new(),
            expected_alg: String::new(),
            jwks_uri: String::new(),
            device_authorization_endpoint: format!("{base}/device"),
        }
    }

    #[tokio::test]
    async fn device_flow_polls_until_authorized() {
        let _guard = listener::serial_lock().await;
        store::reset();
        let base = spawn_mock().await;
        let config = test_config(&base);

        let shared: SharedDeviceFlow = Arc::new(Mutex::new(None));
        let app = tauri::test::mock_app();
        let handle = app.handle().clone();

        // Step 1: user-facing parts come back, device code stays backend-side.
        let start = start(&handle, &shared, config).await.expect("start");
        assert_eq!(start.user_code, "ABCD-EFGH");
        assert_eq!(start.verification_uri, format!("{base}/activate"));
        assert_eq!(start.expires_in, 600);
        assert_eq!(start.interval, 0);
        {
            let guard = shared.lock().unwrap();
            let flow = guard.as_ref().expect("device flow armed");
            assert_eq!(flow.device_code, "dev-code-123");
            assert!(flow.expires_at > now_secs());
        }

        // The info finding for the flow type fired.
        let findings = store::findings();
        assert!(
            findings.iter().any(|f| f.id == "device_flow"),
            "device_flow finding expected"
        );

        // Step 2: first poll → authorization_pending, second → tokens.
        let bundle = poll(&handle, &shared).await.expect("poll until granted");
        assert_eq!(bundle.access_token.as_deref(), Some("dev-access-token"));
        assert!(bundle.expires_at.is_some());
        // State released after success.
        assert!(shared.lock().unwrap().is_none());

        // Both the pending wait and the grant are in the transcript.
        let steps = store::steps();
        assert!(
            steps
                .iter()
                .any(|s| s.detail.to_string().contains("authorization_pending")),
            "pending poll must be visible in the timeline"
        );
        assert!(steps.iter().any(|s| s.title.contains("tokens issued")));

        store::reset();
    }

    #[tokio::test]
    async fn device_flow_rejects_access_denied() {
        let _guard = listener::serial_lock().await;
        store::reset();

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let router = axum::Router::new()
            .route(
                "/device",
                axum::routing::post(
                    |axum::extract::Form(_f): axum::extract::Form<
                        std::collections::HashMap<String, String>,
                    >| async move {
                        axum::Json(json!({
                            "device_code": "dev-code-x",
                            "user_code": "WXYZ-9876",
                            "verification_uri": "http://127.0.0.1/activate",
                            "expires_in": 600,
                            "interval": 0,
                        }))
                    },
                ),
            )
            .route(
                "/token",
                axum::routing::post(
                    |axum::extract::Form(_f): axum::extract::Form<
                        std::collections::HashMap<String, String>,
                    >| async move {
                        (
                            axum::http::StatusCode::BAD_REQUEST,
                            axum::Json(json!({
                                "error": "access_denied",
                                "error_description": "the user denied the request"
                            })),
                        )
                    },
                ),
            );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let base = format!("http://127.0.0.1:{port}");
        let shared: SharedDeviceFlow = Arc::new(Mutex::new(None));
        let app = tauri::test::mock_app();
        let handle = app.handle().clone();

        start(&handle, &shared, test_config(&base))
            .await
            .expect("start");
        let err = poll(&handle, &shared).await.expect_err("denied");
        assert!(err.contains("access_denied"), "{err}");
        assert!(err.contains("denied the request"), "{err}");
        // Rejected flow clears its state.
        assert!(shared.lock().unwrap().is_none());
        store::reset();
    }

    #[tokio::test]
    async fn missing_endpoints_are_rejected_upfront() {
        let app = tauri::test::mock_app();
        let handle = app.handle().clone();
        let shared: SharedDeviceFlow = Arc::new(Mutex::new(None));

        let mut config = FlowConfig {
            flow_type: FlowType::DeviceAuthorization,
            authorization_endpoint: String::new(),
            token_endpoint: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            redirect_uri: String::new(),
            scope: String::new(),
            pkce: false,
            include_nonce: false,
            client_auth: ClientAuth::None,
            listener_port: 0,
            expected_iss: String::new(),
            expected_alg: String::new(),
            jwks_uri: String::new(),
            device_authorization_endpoint: String::new(),
        };
        let err = start(&handle, &shared, config.clone())
            .await
            .expect_err("endpoint required");
        assert!(err.contains("device authorization endpoint"), "{err}");

        config.device_authorization_endpoint = "https://provider.example/device".into();
        let err = start(&handle, &shared, config)
            .await
            .expect_err("client_id required");
        assert!(err.contains("client_id"), "{err}");
    }
}
