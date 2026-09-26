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

mod decode;
mod listener;
mod pkce;
mod token_exchange;

use decode::DecodedJwt;
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
}

#[derive(Default)]
pub struct AppState {
    pub pending: Arc<Mutex<Option<PendingFlow>>>,
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
    let _ = app.emit("flow-step", &step);
}

// ---------------------------------------------------------------------------
// Callback processing (called from the listener)
// ---------------------------------------------------------------------------

/// Process an intercepted callback: validate `state`, capture the code (auth
/// code flow) or decode tokens straight from the fragment (implicit flow).
pub fn process_callback<R: tauri::Runtime>(
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
    let has_tokens =
        params.contains_key("access_token") || params.contains_key("id_token");
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
        token_exchange::bundle_from_params(app, &params);
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
    let auth_endpoint = config.authorization_endpoint.trim();
    if auth_endpoint.is_empty() {
        return Err("authorization endpoint is required".into());
    }
    if config.client_id.trim().is_empty() {
        return Err("client_id is required".into());
    }
    let mut auth_url =
        url::Url::parse(auth_endpoint).map_err(|e| format!("invalid authorization endpoint: {e}"))?;
    if auth_url.scheme() != "http" && auth_url.scheme() != "https" {
        return Err("authorization endpoint must be an http(s) URL".into());
    }

    let redirect_uri = {
        let r = config.redirect_uri.trim();
        if r.is_empty() {
            listener::redirect_uri()
        } else {
            r.to_string()
        }
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
    let response_type = match config.flow_type {
        FlowType::Implicit if nonce.is_some() => "id_token token",
        FlowType::Implicit => "token",
        _ => "code",
    };

    {
        let mut q = auth_url.query_pairs_mut();
        q.append_pair("response_type", response_type);
        q.append_pair("client_id", config.client_id.trim());
        q.append_pair("redirect_uri", &redirect_uri);
        let scope = config.scope.trim();
        if !scope.is_empty() {
            q.append_pair("scope", scope);
        }
        q.append_pair("state", &state_val);
        if let Some(n) = &nonce {
            q.append_pair("nonce", n);
        }
        if let Some(c) = &challenge {
            q.append_pair("code_challenge", c);
            q.append_pair("code_challenge_method", "S256");
        }
    }
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

    // Bind the redirect listener before anything can redirect to it.
    listener::ensure_started(app.clone(), state.pending.clone()).await?;

    // Controlled webview: reuse if already open, otherwise create.
    let web_url: url::Url = auth_url_str
        .parse()
        .map_err(|e| format!("failed to parse authorization url: {e}"))?;
    match app.get_webview_window(AUTH_WINDOW_LABEL) {
        Some(win) => {
            win.navigate(web_url)
                .map_err(|e| format!("failed to load authorization url: {e}"))?;
            let _ = win.set_focus();
        }
        None => {
            tauri::WebviewWindowBuilder::new(
                &app,
                AUTH_WINDOW_LABEL,
                tauri::WebviewUrl::External(web_url),
            )
            .title("Authenticate — OAuth Flow Debugger")
            .inner_size(960.0, 760.0)
            .center()
            .build()
            .map_err(|e| format!("failed to open auth window: {e}"))?;
        }
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
        listener_port: listener::LISTENER_PORT,
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

/// Close the controlled auth webview (manual user action in the UI).
#[tauri::command]
fn close_auth_window(app: tauri::AppHandle) {
    if let Some(win) = app.get_webview_window(AUTH_WINDOW_LABEL) {
        let _ = win.close();
    }
}

/// Clear pending flow state (start of a new attempt / Reset button).
#[tauri::command]
fn reset_flow(state: tauri::State<'_, AppState>) -> Result<(), String> {
    *state
        .pending
        .lock()
        .map_err(|_| "internal state lock poisoned".to_string())? = None;
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            start_flow,
            exchange_code,
            client_credentials_flow,
            close_auth_window,
            reset_flow
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

    /// Same known-good RS256 token as the decode tests.
    const ID_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5leGFtcGxlIiwiYXVkIjoiY2xpZW50LTEyMyIsImV4cCI6MTk5OTk5OTk5OSwiaWF0IjoxOTAwMDAwMDAwLCJub25jZSI6ImFiYzEyMyJ9.signature";

    #[tokio::test]
    async fn callback_capture_state_check_and_token_exchange() {
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
        let config = FlowConfig {
            flow_type: FlowType::AuthorizationCode,
            authorization_endpoint: "https://provider.example/authorize".into(),
            token_endpoint: format!("http://127.0.0.1:{token_port}/token"),
            client_id: "demo-client".into(),
            client_secret: String::new(),
            redirect_uri: listener::redirect_uri(),
            scope: "openid profile email".into(),
            pkce: true,
            include_nonce: true,
            client_auth: ClientAuth::None,
        };
        let verifier = pkce::generate_verifier();
        let store: Arc<Mutex<Option<PendingFlow>>> = Arc::new(Mutex::new(Some(PendingFlow {
            config,
            state: "state-good".into(),
            nonce: Some(pkce::generate_nonce()),
            code_verifier: Some(verifier.clone()),
            redirect_uri: listener::redirect_uri(),
            code: None,
        })));

        // ---- arm the real listener on :9004 ----
        listener::ensure_started(handle.clone(), store.clone())
            .await
            .unwrap();

        let http = reqwest::Client::new();

        // 1. Provider redirects back with a matching state → code captured.
        let url = format!(
            "http://127.0.0.1:{}/callback?code=auth-code-1&state=state-good",
            listener::LISTENER_PORT
        );
        let resp = http.get(&url).send().await.unwrap();
        assert!(resp.status().is_success());
        assert_eq!(
            store.lock().unwrap().as_ref().unwrap().code.as_deref(),
            Some("auth-code-1")
        );

        // 2. Mismatched state → callback rejected, no code stored.
        {
            let mut guard = store.lock().unwrap();
            let mut pending = guard.clone().unwrap();
            pending.state = "state-good-2".into();
            pending.code = None;
            *guard = Some(pending);
        }
        let url = format!(
            "http://127.0.0.1:{}/callback?code=injected-code&state=WRONG",
            listener::LISTENER_PORT
        );
        let resp = http.get(&url).send().await.unwrap();
        assert!(resp.status().is_success());
        assert!(store.lock().unwrap().as_ref().unwrap().code.is_none());

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
        assert_eq!(form.get("redirect_uri").unwrap(), &listener::redirect_uri());
        assert_eq!(form.get("code_verifier").unwrap(), &verifier);
        assert_eq!(
            form.get("client_id").map(String::as_str),
            Some("demo-client")
        );
    }
}
