//! OAuth Flow Debugger — Tauri entry point.
//!
//! Owns the flow state machine: builds authorization URLs, processes the
//! intercepted callback (state validation, code capture, implicit token
//! capture), and registers the Tauri commands the frontend calls.
//!
//! Modules:
//!   * `listener`        — local axum server capturing the provider redirect
//!   * `pkce`            — RFC 7636 verifier/challenge + state/nonce randomness
//!   * `token_exchange`  — token endpoint POSTs (auth code, client credentials)
//!   * `decode`          — JWT header/payload decoding (no signature verify)
//!   * `jwks`            — JWKS fetch + RS256/ES256 signature verification
//!   * `findings`        — automated security checks with severity ratings
//!   * `export`          — Markdown/JSON report export (tokens redacted)
//!   * `store`           — in-memory transcript/finding store (never on disk)

mod decode;
mod device_flow;
mod export;
mod findings;
mod jwks;
mod listener;
#[cfg(test)]
mod mock_oidc_tests;
mod pkce;
mod store;
mod token_exchange;

use decode::DecodedJwt;
use findings::{Expectations, Finding, Summary};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{Emitter, Manager};

const AUTH_WINDOW_LABEL: &str = "oauth-auth";

// ---------------------------------------------------------------------------
// Types shared with the frontend (src/types.ts mirrors these)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowType {
    AuthorizationCode,
    Implicit,
    ClientCredentials,
    DeviceAuthorization,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuth {
    None,
    ClientSecretBasic,
    ClientSecretPost,
}

/// The flow configuration submitted by the FlowConfig form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowConfig {
    pub flow_type: FlowType,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scope: String,
    pub pkce: bool,
    pub include_nonce: bool,
    pub client_auth: ClientAuth,
    /// Preferred loopback port for the redirect listener (0 = 9004). Ignored
    /// when `redirect_uri` is set — that port is fixed by provider
    /// registration, so a conflict there is reported as an error instead.
    #[serde(default)]
    pub listener_port: u16,
    /// Explicit JWKS endpoint for signature verification. When empty, the
    /// backend falls back to OIDC discovery from `expected_iss` (and then the
    /// token's own `iss` claim).
    #[serde(default)]
    pub jwks_uri: String,
    /// Optional expected issuer for `iss` checks (trailing slash ignored).
    #[serde(default)]
    pub expected_iss: String,
    /// Optional expected JWT alg (e.g. `RS256`) — enables the
    /// "HS256 where RS256 was expected" check.
    #[serde(default)]
    pub expected_alg: String,
    /// Device Authorization Grant (RFC 8628) endpoint.
    #[serde(default)]
    pub device_authorization_endpoint: String,
}

/// Secret per-attempt flow state kept in the backend between launch and
/// callback. Never emitted wholesale to the frontend (the secret and verifier
/// are only exposed through explicit step details).
#[derive(Debug, Clone)]
pub struct PendingFlow {
    pub config: FlowConfig,
    pub state: String,
    pub nonce: Option<String>,
    pub code_verifier: Option<String>,
    pub redirect_uri: String,
    pub code: Option<String>,
}

/// Returned by `start_flow` so the UI can show what was generated.
#[derive(Debug, Clone, Serialize)]
pub struct FlowStart {
    pub auth_url: String,
    pub state: String,
    pub nonce: Option<String>,
    pub code_verifier: Option<String>,
    pub code_challenge: Option<String>,
    pub listener_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    Info,
    AuthUrl,
    Callback,
    TokenRequest,
    TokenResponse,
    Tokens,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Info,
    Ok,
    Warn,
    Error,
}

impl StepStatus {
    pub fn icon(&self) -> &'static str {
        match self {
            StepStatus::Info => "ℹ️",
            StepStatus::Ok => "✅",
            StepStatus::Warn => "⚠️",
            StepStatus::Error => "❌",
        }
    }
}

/// One entry in the frontend timeline, emitted on the `flow-step` event.
#[derive(Debug, Clone, Serialize)]
pub struct FlowStep {
    pub id: String,
    pub kind: StepKind,
    pub title: String,
    pub status: StepStatus,
    pub detail: Value,
    /// epoch milliseconds
    pub ts: u64,
}

/// Token endpoint response (raw + decoded JWTs), shared by all grants.
#[derive(Debug, Clone, Serialize)]
pub struct TokenBundle {
    pub raw: Value,
    pub access_token: Option<String>,
    pub id_token: Option<String>,
    pub token_type: Option<String>,
    pub expires_in: Option<i64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub decoded_access: Option<DecodedJwt>,
    pub decoded_id: Option<DecodedJwt>,
    /// epoch seconds, derived from `expires_in`
    pub expires_at: Option<i64>,
    /// JWKS signature verification results (per token, if they are JWTs).
    pub verification: jwks::BundleVerification,
}

#[derive(Default)]
pub struct AppState {
    pub pending: Arc<Mutex<Option<PendingFlow>>>,
    /// In-flight Device Authorization flow (device_code stays backend-side).
    pub device: device_flow::SharedDeviceFlow,
}

// ---------------------------------------------------------------------------
// Step emission
// ---------------------------------------------------------------------------

/// Emit a `flow-step` event to the frontend. Failures (no listeners) are
/// expected and ignored.
pub fn emit_step<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    kind: StepKind,
    title: impl Into<String>,
    status: StepStatus,
    detail: Value,
) {
    static STEP_COUNTER: AtomicU64 = AtomicU64::new(1);
    let step = FlowStep {
        id: format!("step-{}", STEP_COUNTER.fetch_add(1, Ordering::Relaxed)),
        kind,
        title: title.into(),
        status,
        detail,
        ts: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    };
    // Keep an in-memory transcript for the report export (redacted on export).
    store::record_step(&step);
    let _ = app.emit("flow-step", &step);
}

/// Payload behind the `findings-updated` event.
#[derive(Debug, Clone, Serialize)]
pub struct FindingsReport {
    pub findings: Vec<Finding>,
    pub summary: Summary,
}

/// Push the current findings (and summary) to the frontend.
pub fn emit_findings<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let _ = app.emit(
        "findings-updated",
        FindingsReport {
            findings: store::findings(),
            summary: store::summary(),
        },
    );
}

/// Navigation policy for the controlled auth window: only the provider's
/// authorization host (and its parent / sub-domain relatives, so a login
/// redirect like `accounts.google.com` → `google.com` keeps working) plus the
/// loopback redirect may load. Anything else is refused before it renders.
pub fn navigation_allowed(target: &url::Url, auth_host: &str) -> bool {
    let Some(host) = target.host_str() else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    match target.scheme() {
        "https" => {}
        "http" if is_loopback(&host) => return true,
        _ => return false,
    }
    if auth_host.is_empty() {
        return false;
    }
    host == auth_host
        || host.ends_with(&format!(".{auth_host}"))
        || auth_host.ends_with(&format!(".{host}"))
}

pub(crate) fn is_loopback(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1" || host == "[::1]"
}

// ---------------------------------------------------------------------------
// Callback processing (called from the listener)
// ---------------------------------------------------------------------------

/// Process an intercepted callback: validate `state`, capture the code (auth
/// code flow) or decode tokens straight from the fragment (implicit flow).
/// Async because implicit-flow tokens are verified against the JWKS before
/// the result is handed to the UI.
pub async fn process_callback<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    pending_store: &Arc<Mutex<Option<PendingFlow>>>,
    params: HashMap<String, String>,
    raw_url: String,
) {
    if params.is_empty() {
        return;
    }

    let pending: Option<PendingFlow> = pending_store.lock().ok().and_then(|g| g.clone());

    let expected_state = pending.as_ref().map(|p| p.state.clone());
    let got_state = params.get("state").cloned();
    let state_valid: Option<bool> = match (&expected_state, &got_state) {
        (Some(exp), Some(got)) => Some(got == exp),
        (Some(_), None) => Some(false),
        (None, _) => None,
    };

    let has_code = params.contains_key("code");
    let has_error = params.contains_key("error");
    let has_tokens = params.contains_key("access_token") || params.contains_key("id_token");
    let pkce = pending
        .as_ref()
        .map(|p| p.code_verifier.is_some())
        .unwrap_or(false);
    let nonce_expected = pending.as_ref().and_then(|p| p.nonce.clone());
    let provider_error = params.get("error").cloned();
    let provider_error_description = params.get("error_description").cloned();

    let title = if has_error {
        "Provider returned an error"
    } else if has_tokens {
        "Callback intercepted (implicit flow)"
    } else if has_code {
        "Authorization Code received"
    } else {
        "Callback intercepted"
    };
    let status = if has_error || state_valid == Some(false) {
        StepStatus::Error
    } else if has_code || has_tokens {
        StepStatus::Ok
    } else {
        StepStatus::Info
    };

    emit_step(
        app,
        StepKind::Callback,
        title,
        status,
        json!({
            "raw_url": raw_url,
            "params": params,
            "state": got_state,
            "state_valid": state_valid,
            "has_code": has_code,
            "has_tokens": has_tokens,
            "has_error": has_error,
            "pkce": pkce,
            "nonce_expected": nonce_expected,
            "provider_error": provider_error,
            "provider_error_description": provider_error_description,
        }),
    );

    // Automated checks for this callback (state present / matching).
    store::record_findings(&findings::callback_findings(
        &params,
        state_valid,
        expected_state.is_some(),
    ));
    emit_findings(app);

    if has_error {
        schedule_auth_window_close(app, 2500);
        return;
    }
    if state_valid == Some(false) {
        // CSRF check failed — refuse to continue the flow.
        schedule_auth_window_close(app, 2500);
        return;
    }
    if has_code {
        if let Ok(mut guard) = pending_store.lock() {
            if let Some(p) = guard.as_mut() {
                p.code = params.get("code").cloned();
            }
        }
        schedule_auth_window_close(app, 1500);
        return;
    }
    if has_tokens {
        // Implicit flow: validate nonce/aud/iss against what we sent, and
        // verify token signatures against the JWKS.
        let expectations = Expectations {
            client_id: pending
                .as_ref()
                .map(|p| p.config.client_id.clone())
                .unwrap_or_default(),
            expected_iss: pending
                .as_ref()
                .map(|p| p.config.expected_iss.clone())
                .unwrap_or_default(),
            expected_alg: pending
                .as_ref()
                .map(|p| p.config.expected_alg.clone())
                .unwrap_or_default(),
            nonce: nonce_expected.clone(),
            requested_scope: pending
                .as_ref()
                .map(|p| p.config.scope.clone())
                .unwrap_or_default(),
        };
        let verification = match pending.as_ref() {
            Some(p) => {
                jwks::verify_tokens(
                    &p.config,
                    params.get("access_token").map(String::as_str),
                    params.get("id_token").map(String::as_str),
                )
                .await
            }
            None => jwks::BundleVerification::default(),
        };
        token_exchange::bundle_from_params(app, &params, expectations, verification);
        schedule_auth_window_close(app, 2500);
    }
}

fn schedule_auth_window_close<R: tauri::Runtime>(app: &tauri::AppHandle<R>, delay_ms: u64) {
    // Nothing to close (e.g. headless integration tests) — skip the timer.
    if app.get_webview_window(AUTH_WINDOW_LABEL).is_none() {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        if let Some(win) = app.get_webview_window(AUTH_WINDOW_LABEL) {
            let _ = win.close();
        }
    });
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Build the authorization URL exactly the way the app does in production —
/// shared with the mock-OIDC integration tests so they exercise the real
/// request shape (response_type, PKCE, nonce, state).
///
/// Returns the URL and the `response_type` used.
pub fn build_auth_url(
    config: &FlowConfig,
    redirect_uri: &str,
    state: &str,
    nonce: Option<&str>,
    code_challenge: Option<&str>,
) -> Result<(url::Url, &'static str), String> {
    let mut auth_url = url::Url::parse(config.authorization_endpoint.trim())
        .map_err(|e| format!("invalid authorization endpoint: {e}"))?;
    if auth_url.scheme() != "http" && auth_url.scheme() != "https" {
        return Err("authorization endpoint must be an http(s) URL".into());
    }
    // Remote authorization endpoints must be HTTPS (plain http is accepted for
    // loopback mock providers only).
    if auth_url.scheme() == "http" {
        let host = auth_url.host_str().unwrap_or_default().to_ascii_lowercase();
        if !is_loopback(&host) {
            return Err(format!(
                "authorization endpoint must be https — refusing plain http for `{host}`"
            ));
        }
    }

    let response_type = match config.flow_type {
        FlowType::Implicit if nonce.is_some() => "id_token token",
        FlowType::Implicit => "token",
        _ => "code",
    };

    {
        let mut q = auth_url.query_pairs_mut();
        q.append_pair("response_type", response_type);
        q.append_pair("client_id", config.client_id.trim());
        q.append_pair("redirect_uri", redirect_uri);
        let scope = config.scope.trim();
        if !scope.is_empty() {
            q.append_pair("scope", scope);
        }
        q.append_pair("state", state);
        if let Some(n) = nonce {
            q.append_pair("nonce", n);
        }
        if let Some(c) = code_challenge {
            q.append_pair("code_challenge", c);
            q.append_pair("code_challenge_method", "S256");
        }
    }
    Ok((auth_url, response_type))
}

/// Launch a browser-based flow (authorization code or implicit):
/// arms the redirect listener, stores pending state, builds the authorization
/// URL, and opens it in a controlled webview.
#[tauri::command]
async fn start_flow(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    config: FlowConfig,
) -> Result<FlowStart, String> {
    if config.flow_type == FlowType::ClientCredentials {
        return Err(
            "Client Credentials does not use a browser — call client_credentials_flow".into(),
        );
    }
    if config.flow_type == FlowType::DeviceAuthorization {
        return Err("Device Authorization does not use a browser — call start_device_flow".into());
    }
    let auth_endpoint = config.authorization_endpoint.trim();
    if auth_endpoint.is_empty() {
        return Err("authorization endpoint is required".into());
    }
    if config.client_id.trim().is_empty() {
        return Err("client_id is required".into());
    }

    // Fresh run: drop the previous transcript/findings, record this config and
    // run the config-time checks (HTTPS, implicit flow, PKCE, nonce).
    store::reset();
    store::set_config(&config);
    store::record_findings(&findings::config_findings(&config));

    // Where does the redirect listener bind? An explicit redirect_uri pins the
    // port (the provider has that exact URI registered), so a conflict there is
    // an error; otherwise we generate the URI from whatever port we get.
    let explicit_redirect = config.redirect_uri.trim().to_string();
    let (preferred_port, allow_fallback) = if explicit_redirect.is_empty() {
        (
            if config.listener_port == 0 {
                listener::DEFAULT_PORT
            } else {
                config.listener_port
            },
            true,
        )
    } else {
        match url::Url::parse(&explicit_redirect) {
            Ok(u) if u.port().is_some() => (u.port().unwrap(), false),
            Ok(_) => {
                return Err("redirect_uri must include an explicit port (e.g. \
                     http://localhost:9004/callback)"
                    .into())
            }
            Err(e) => return Err(format!("invalid redirect_uri: {e}")),
        }
    };

    // Bind the redirect listener before anything can redirect to it.
    listener::ensure_started(
        app.clone(),
        state.pending.clone(),
        preferred_port,
        allow_fallback,
    )
    .await?;
    emit_findings(&app);

    let redirect_uri = if explicit_redirect.is_empty() {
        listener::redirect_uri()
    } else {
        explicit_redirect
    };

    let use_pkce = config.pkce && config.flow_type == FlowType::AuthorizationCode;
    let state_val = pkce::generate_state();
    let nonce = if config.include_nonce {
        Some(pkce::generate_nonce())
    } else {
        None
    };
    let (verifier, challenge) = if use_pkce {
        let v = pkce::generate_verifier();
        let c = pkce::challenge_s256(&v);
        (Some(v), Some(c))
    } else {
        (None, None)
    };

    let (auth_url, response_type) = build_auth_url(
        &config,
        &redirect_uri,
        &state_val,
        nonce.as_deref(),
        challenge.as_deref(),
    )?;
    let auth_url_str = auth_url.to_string();

    let pending = PendingFlow {
        config: config.clone(),
        state: state_val.clone(),
        nonce: nonce.clone(),
        code_verifier: verifier.clone(),
        redirect_uri: redirect_uri.clone(),
        code: None,
    };
    *state
        .pending
        .lock()
        .map_err(|_| "internal state lock poisoned".to_string())? = Some(pending);

    // Controlled webview with a navigation allowlist. The window is recreated
    // on every start so a remote provider page can never keep a stale (or no)
    // policy, and it can never navigate somewhere we did not intend.
    let web_url: url::Url = auth_url_str
        .parse()
        .map_err(|e| format!("failed to parse authorization url: {e}"))?;
    let allowed_host = web_url.host_str().unwrap_or_default().to_ascii_lowercase();
    if let Some(win) = app.get_webview_window(AUTH_WINDOW_LABEL) {
        let _ = win.close();
    }
    {
        let nav_app = app.clone();
        let nav_host = allowed_host.clone();
        tauri::WebviewWindowBuilder::new(
            &app,
            AUTH_WINDOW_LABEL,
            tauri::WebviewUrl::External(web_url),
        )
        .title("Authenticate — OAuth Flow Debugger")
        .inner_size(960.0, 760.0)
        .center()
        .on_navigation(move |target| {
            let allowed = navigation_allowed(target, &nav_host);
            if !allowed {
                emit_step(
                    &nav_app,
                    StepKind::Error,
                    "Blocked navigation from the auth window",
                    StepStatus::Warn,
                    json!({
                        "url": target.to_string(),
                        "allowed_host": nav_host,
                        "reason": "outside the configured authorization host",
                    }),
                );
            }
            allowed
        })
        .build()
        .map_err(|e| format!("failed to open auth window: {e}"))?;
    }

    emit_step(
        &app,
        StepKind::AuthUrl,
        "Authorization URL opened in webview",
        StepStatus::Info,
        json!({
            "url": auth_url_str,
            "response_type": response_type,
            "redirect_uri": redirect_uri,
            "state": state_val,
            "nonce": nonce,
            "pkce": use_pkce,
            "code_challenge_method": if use_pkce { Some("S256") } else { None::<&str> },
            "code_challenge": challenge,
            "code_verifier": verifier,
            "scope": config.scope.trim(),
        }),
    );

    Ok(FlowStart {
        auth_url: auth_url_str,
        state: state_val,
        nonce,
        code_verifier: verifier,
        code_challenge: challenge,
        listener_port: listener::active_port().unwrap_or(listener::DEFAULT_PORT),
    })
}

/// Exchange the captured authorization code for tokens (backend-side POST).
#[tauri::command]
async fn exchange_code(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<TokenBundle, String> {
    let pending = {
        let guard = state
            .pending
            .lock()
            .map_err(|_| "internal state lock poisoned".to_string())?;
        guard.clone()
    }
    .ok_or("no active flow — start a flow first")?;
    let code = pending
        .code
        .clone()
        .ok_or("no authorization code captured yet")?;

    match token_exchange::exchange_authorization_code(&app, &pending, &code).await {
        Ok(bundle) => Ok(bundle),
        Err(e) => {
            emit_step(
                &app,
                StepKind::Error,
                "Token exchange failed",
                StepStatus::Error,
                json!({ "message": e }),
            );
            Err(e)
        }
    }
}

/// Client Credentials grant — direct token POST, no browser.
#[tauri::command]
async fn client_credentials_flow(
    app: tauri::AppHandle,
    config: FlowConfig,
) -> Result<TokenBundle, String> {
    match token_exchange::client_credentials(&app, &config).await {
        Ok(bundle) => Ok(bundle),
        Err(e) => {
            emit_step(
                &app,
                StepKind::Error,
                "Client Credentials request failed",
                StepStatus::Error,
                json!({ "message": e }),
            );
            Err(e)
        }
    }
}

/// Device Authorization Grant (RFC 8628): request a device code + user code.
/// The device code stays in the backend; only the user-facing parts return.
#[tauri::command]
async fn start_device_flow(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    config: FlowConfig,
) -> Result<device_flow::DeviceAuthStart, String> {
    device_flow::start(&app, &state.device, config).await
}

/// Poll the token endpoint for the Device Authorization grant until the user
/// approves (or the code is rejected / expires).
#[tauri::command]
async fn poll_device_token(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<TokenBundle, String> {
    device_flow::poll(&app, &state.device).await
}

/// Close the controlled auth webview (manual user action in the UI).
#[tauri::command]
fn close_auth_window(app: tauri::AppHandle) {
    if let Some(win) = app.get_webview_window(AUTH_WINDOW_LABEL) {
        let _ = win.close();
    }
}

/// Clear pending flow state (start of a new attempt / Reset button), the
/// in-memory transcript/findings, and release the redirect listener.
#[tauri::command]
fn reset_flow(app: tauri::AppHandle, state: tauri::State<'_, AppState>) -> Result<(), String> {
    *state
        .pending
        .lock()
        .map_err(|_| "internal state lock poisoned".to_string())? = None;
    if let Ok(mut guard) = state.device.lock() {
        *guard = None;
    }
    listener::shutdown();
    store::reset();
    emit_findings(&app);
    Ok(())
}

/// Current findings + severity summary for the UI panel.
#[tauri::command]
fn get_findings() -> FindingsReport {
    FindingsReport {
        findings: store::findings(),
        summary: store::summary(),
    }
}

/// Export the flow transcript as Markdown or JSON with tokens redacted.
#[tauri::command]
fn export_flow(format: String) -> Result<String, String> {
    match format.as_str() {
        "json" => Ok(export::to_json()),
        "markdown" | "md" => Ok(export::to_markdown()),
        other => Err(format!(
            "unknown export format `{other}` (use json or markdown)"
        )),
    }
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            start_flow,
            exchange_code,
            client_credentials_flow,
            start_device_flow,
            poll_device_token,
            close_auth_window,
            reset_flow,
            get_findings,
            export_flow
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// ---------------------------------------------------------------------------
// Integration test: real listener → callback capture → state validation →
// token exchange against an in-test mock token endpoint.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod e2e_tests {
    use super::*;

    /// RS256-shaped token whose `iss` points at a dead loopback port: the
    /// signature-verification step attempts OIDC discovery against it, gets
    /// an instant connection refused, and records `sig_unverified` — all
    /// without touching the real network.
    const ID_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cDovLzEyNy4wLjAuMTo5IiwiYXVkIjoiY2xpZW50LTEyMyIsImV4cCI6MTk5OTk5OTk5OSwiaWF0IjoxOTAwMDAwMDAwLCJub25jZSI6ImFiYzEyMyJ9.signature";

    #[tokio::test]
    async fn callback_capture_state_check_and_token_exchange() {
        // Shares global listener + store state with the other tests.
        let _guard = listener::serial_lock().await;
        let app = tauri::test::mock_app();
        let handle = app.handle().clone();

        // ---- mock token endpoint that records every form field it receives ----
        let seen: Arc<Mutex<Vec<HashMap<String, String>>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_route = seen.clone();
        let token_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token_port = token_listener.local_addr().unwrap().port();
        let token_router = axum::Router::new().route(
            "/token",
            axum::routing::post(
                move |axum::extract::Form(form): axum::extract::Form<HashMap<String, String>>| {
                    let seen = seen_route.clone();
                    async move {
                        seen.lock().unwrap().push(form);
                        axum::Json(json!({
                            "access_token": "mock-access-token",
                            "token_type": "Bearer",
                            "expires_in": 3600,
                            "id_token": ID_TOKEN,
                            "scope": "openid profile email",
                        }))
                    }
                },
            ),
        );
        tokio::spawn(async move {
            axum::serve(token_listener, token_router).await.unwrap();
        });

        // ---- pending flow exactly as start_flow would create it ----
        // The port is chosen up front so the registered redirect_uri and the
        // listener agree; allow_fallback=false mirrors an explicit redirect_uri.
        const FLOW_PORT: u16 = 9014;
        let redirect_uri = listener::redirect_uri_for(FLOW_PORT);
        let config = FlowConfig {
            flow_type: FlowType::AuthorizationCode,
            authorization_endpoint: "https://provider.example/authorize".into(),
            token_endpoint: format!("http://127.0.0.1:{token_port}/token"),
            client_id: "client-123".into(),
            client_secret: String::new(),
            redirect_uri: redirect_uri.clone(),
            scope: "openid profile email".into(),
            pkce: true,
            include_nonce: true,
            client_auth: ClientAuth::None,
            listener_port: FLOW_PORT,
            expected_iss: String::new(),
            expected_alg: "RS256".into(),
            jwks_uri: String::new(),
            device_authorization_endpoint: String::new(),
        };
        let verifier = pkce::generate_verifier();
        // The mock id_token carries nonce=abc123 — the value a real flow would
        // have sent.
        let store: Arc<Mutex<Option<PendingFlow>>> = Arc::new(Mutex::new(Some(PendingFlow {
            config,
            state: "state-good".into(),
            nonce: Some("abc123".into()),
            code_verifier: Some(verifier.clone()),
            redirect_uri: redirect_uri.clone(),
            code: None,
        })));

        // ---- arm the real listener (127.0.0.1 only, one-shot) ----
        listener::ensure_started(handle.clone(), store.clone(), FLOW_PORT, false)
            .await
            .unwrap();
        assert!(listener::active_port().is_some());

        let http = reqwest::Client::new();

        // 1. Provider redirects back with a matching state → code captured,
        //    and the one-shot listener releases the port.
        let url =
            format!("http://127.0.0.1:{FLOW_PORT}/callback?code=auth-code-1&state=state-good");
        let resp = http.get(&url).send().await.unwrap();
        assert!(resp.status().is_success());
        assert_eq!(
            store.lock().unwrap().as_ref().unwrap().code.as_deref(),
            Some("auth-code-1")
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            listener::active_port().is_none(),
            "listener must be one-shot"
        );

        // 2. Mismatched state → callback rejected, no code stored. The listener
        //    is re-armed first, exactly as a second flow attempt would.
        {
            let mut guard = store.lock().unwrap();
            let mut pending = guard.clone().unwrap();
            pending.state = "state-good-2".into();
            pending.code = None;
            *guard = Some(pending);
        }
        listener::ensure_started(handle.clone(), store.clone(), FLOW_PORT, false)
            .await
            .unwrap();
        let url = format!("http://127.0.0.1:{FLOW_PORT}/callback?code=injected-code&state=WRONG");
        let resp = http.get(&url).send().await.unwrap();
        assert!(resp.status().is_success());
        assert!(store.lock().unwrap().as_ref().unwrap().code.is_none());
        assert!(
            store::findings().iter().any(|f| f.id == "state_mismatch"),
            "the mismatched state must raise a critical finding"
        );

        // 3. Exchange the captured code against the mock token endpoint.
        let pending = store.lock().unwrap().clone().unwrap();
        let bundle = token_exchange::exchange_authorization_code(&handle, &pending, "auth-code-1")
            .await
            .unwrap();
        assert_eq!(bundle.access_token.as_deref(), Some("mock-access-token"));
        let id = bundle.decoded_id.as_ref().expect("id_token should decode");
        assert_eq!(id.alg, "RS256");
        assert_eq!(id.payload["sub"], "1234567890");
        assert!(bundle.expires_at.is_some());

        // 4. The token POST carried exactly what an auth-code exchange must.
        let recorded = seen.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        let form = &recorded[0];
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("authorization_code")
        );
        assert_eq!(form.get("code").map(String::as_str), Some("auth-code-1"));
        assert_eq!(form.get("redirect_uri").unwrap(), &redirect_uri);
        assert_eq!(form.get("code_verifier").unwrap(), &verifier);
        assert_eq!(
            form.get("client_id").map(String::as_str),
            Some("client-123")
        );
        // 5. The id_token was bound to this flow (nonce) and issued for this
        //    client (aud) → no nonce/aud findings.
        let recorded = store::findings();
        let ids: Vec<&str> = recorded.iter().map(|f| f.id.as_str()).collect();
        assert!(!ids.contains(&"nonce_mismatch"), "{ids:?}");
        assert!(!ids.contains(&"missing_nonce"), "{ids:?}");
        assert!(!ids.contains(&"aud_mismatch"), "{ids:?}");
        assert!(!ids.contains(&"alg_mismatch"), "{ids:?}");
    }

    /// Client Credentials grant end to end: the README marks it ✅, so this
    /// test is what keeps that claim honest.
    #[tokio::test]
    async fn client_credentials_grant_works() {
        let app = tauri::test::mock_app();
        let handle = app.handle().clone();

        let seen: Arc<Mutex<Vec<HashMap<String, String>>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_route = seen.clone();
        let token_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token_port = token_listener.local_addr().unwrap().port();
        let token_router = axum::Router::new().route(
            "/token",
            axum::routing::post(
                move |axum::extract::Form(form): axum::extract::Form<HashMap<String, String>>| {
                    let seen = seen_route.clone();
                    async move {
                        seen.lock().unwrap().push(form);
                        axum::Json(json!({
                            "access_token": "cc-access-token",
                            "token_type": "Bearer",
                            "expires_in": 1800,
                            "scope": "read write",
                        }))
                    }
                },
            ),
        );
        tokio::spawn(async move {
            axum::serve(token_listener, token_router).await.unwrap();
        });

        let config = FlowConfig {
            flow_type: FlowType::ClientCredentials,
            authorization_endpoint: String::new(),
            token_endpoint: format!("http://127.0.0.1:{token_port}/token"),
            client_id: "service-client".into(),
            client_secret: "shh".into(),
            redirect_uri: String::new(),
            scope: "read".into(),
            pkce: false,
            include_nonce: false,
            client_auth: ClientAuth::ClientSecretPost,
            listener_port: 0,
            expected_iss: String::new(),
            expected_alg: String::new(),
            jwks_uri: String::new(),
            device_authorization_endpoint: String::new(),
        };

        let bundle = token_exchange::client_credentials(&handle, &config)
            .await
            .expect("client credentials grant should succeed");
        assert_eq!(bundle.access_token.as_deref(), Some("cc-access-token"));
        assert!(bundle.expires_at.is_some());

        let recorded = seen.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        let form = &recorded[0];
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("client_credentials")
        );
        assert_eq!(
            form.get("client_id").map(String::as_str),
            Some("service-client")
        );
        assert_eq!(form.get("client_secret").map(String::as_str), Some("shh"));
        assert_eq!(form.get("scope").map(String::as_str), Some("read"));
        // No browser flow means no redirect_uri / code / verifier.
        assert!(!form.contains_key("redirect_uri"));
        assert!(!form.contains_key("code"));
        assert!(!form.contains_key("code_verifier"));
    }
}
