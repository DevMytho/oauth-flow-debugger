//! In-process mock OIDC provider used by the integration tests: `authorize`
//! (302 back to the redirect URI), `token` (issues an RS256-signed ID token
//! bound to the nonce it saw at authorize), a JWKS endpoint, and a discovery
//! document.
//!
//! This is the Rust equivalent of pointing the app at `oauth2-mock-server` or
//! Keycloak in Docker — everything under test is real: the authorization URL
//! builder, the loopback listener, the redirect capture, the state check, the
//! token exchange, and JWKS signature verification. Only the provider is
//! simulated — and it signs with a genuine RSA key, so the verification path
//! is exercised end to end.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::json;
use sha2::Sha256;

use crate::findings::Severity;
use crate::{
    findings, jwks, listener, pkce, store, token_exchange, ClientAuth, FlowConfig, FlowType,
    PendingFlow,
};

struct MockProvider {
    base: String,
    /// Nonce observed at /authorize (what a real provider would bind).
    seen_nonce: Arc<Mutex<Option<String>>>,
}

/// The provider's RSA key + kid used to sign every ID token it issues.
fn signing_material() -> &'static (rsa::RsaPrivateKey, String) {
    use std::sync::OnceLock;
    static KEY: OnceLock<(rsa::RsaPrivateKey, String)> = OnceLock::new();
    KEY.get_or_init(|| {
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("keygen");
        (key, "mock-key-1".to_string())
    })
}

fn rsa_jwk(pubkey: &rsa::RsaPublicKey, kid: &str) -> serde_json::Value {
    use rsa::traits::PublicKeyParts;
    json!({
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": URL_SAFE_NO_PAD.encode(pubkey.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(pubkey.e().to_bytes_be()),
    })
}

/// A genuinely RS256-signed JWT with the provider's key.
fn sign_jwt(header: serde_json::Value, payload: serde_json::Value) -> String {
    use rsa::signature::{SignatureEncoding, Signer};
    let (key, kid) = signing_material();
    let enc = |data: &[u8]| URL_SAFE_NO_PAD.encode(data);
    let mut header = header;
    header["kid"] = json!(kid);
    let msg = format!(
        "{}.{}",
        enc(header.to_string().as_bytes()),
        enc(payload.to_string().as_bytes())
    );
    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone());
    let sig: rsa::pkcs1v15::Signature = signing_key.sign(msg.as_bytes());
    format!("{msg}.{}", enc(sig.to_bytes().as_ref()))
}

/// Spawn the mock provider on a free loopback port.
///
/// * `wrong_nonce` — issue ID tokens carrying a nonce the client never sent
///   (used to prove the mismatch check fires).
async fn spawn(wrong_nonce: bool) -> MockProvider {
    let seen_nonce: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let wrong = Arc::new(AtomicBool::new(wrong_nonce));

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();

    // ---- /authorize: record the nonce, 302 back to redirect_uri with code+state
    let auth_nonce = seen_nonce.clone();
    let authorize = axum::routing::get(
        move |axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>| {
            let seen_nonce = auth_nonce.clone();
            async move {
                *seen_nonce.lock().unwrap() = q.get("nonce").cloned();
                let state = q.get("state").cloned().unwrap_or_default();
                let redirect = q.get("redirect_uri").cloned().unwrap_or_default();
                let sep = if redirect.contains('?') { "&" } else { "?" };
                let location = format!("{redirect}{sep}code=mock-code-1&state={state}");
                axum::response::Redirect::to(&location)
            }
        },
    );

    // ---- /token: issue access_token + id_token bound to the authorize nonce
    let tok_nonce = seen_nonce.clone();
    let token = axum::routing::post(
        move |axum::extract::Form(form): axum::extract::Form<HashMap<String, String>>| {
            let seen_nonce = tok_nonce.clone();
            let wrong = wrong.clone();
            async move {
                let issued = seen_nonce.lock().unwrap().clone().unwrap_or_default();
                let nonce = if wrong.load(Ordering::SeqCst) {
                    "nonce-from-another-request".to_string()
                } else {
                    issued
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                // Signed with the provider's real RSA key; `iss` points at
                // this very mock so JWKS discovery stays on loopback.
                let id_token = sign_jwt(
                    json!({"alg": "RS256", "typ": "JWT"}),
                    json!({
                        "iss": format!("http://127.0.0.1:{port}"),
                        "sub": "user-42",
                        "aud": form.get("client_id").cloned().unwrap_or_else(|| "unknown".into()),
                        "exp": now + 3600,
                        "iat": now,
                        "nonce": nonce,
                    }),
                );
                axum::Json(json!({
                    "access_token": "mock-opaque-access-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "id_token": id_token,
                    "scope": "openid profile email",
                }))
            }
        },
    );

    // The public key every ID token is signed with.
    let (signing_key, kid) = signing_material();
    let jwks = json!({
        "keys": [rsa_jwk(&rsa::RsaPublicKey::from(signing_key), kid)]
    });

    let router = axum::Router::new()
        .route("/authorize", authorize)
        .route("/token", token)
        .route(
            "/jwks",
            axum::routing::get(move || async move { axum::Json(jwks) }),
        )
        .route(
            "/.well-known/openid-configuration",
            axum::routing::get(move || async move {
                axum::Json(json!({
                    "issuer": format!("http://127.0.0.1:{port}"),
                    "authorization_endpoint": format!("http://127.0.0.1:{port}/authorize"),
                    "token_endpoint": format!("http://127.0.0.1:{port}/token"),
                    "jwks_uri": format!("http://127.0.0.1:{port}/jwks"),
                    "response_types_supported": ["code"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                }))
            }),
        );

    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    MockProvider {
        base: format!("http://127.0.0.1:{port}"),
        seen_nonce,
    }
}

fn test_config(provider: &MockProvider) -> FlowConfig {
    FlowConfig {
        flow_type: FlowType::AuthorizationCode,
        authorization_endpoint: format!("{}/authorize", provider.base),
        token_endpoint: format!("{}/token", provider.base),
        client_id: "client-123".into(),
        client_secret: String::new(),
        redirect_uri: String::new(),
        scope: "openid profile email".into(),
        pkce: true,
        include_nonce: true,
        client_auth: ClientAuth::None,
        listener_port: 9054,
        expected_iss: provider.base.clone(),
        expected_alg: "RS256".into(),
        // No explicit jwks_uri — the app must find it through OIDC
        // discovery from `expected_iss`, exactly like it would in production.
        jwks_uri: String::new(),
        device_authorization_endpoint: String::new(),
    }
}

/// Run the real chain against the mock provider: authorization URL →
/// listener capture → state validation → token exchange → ID token checks.
async fn run_flow(wrong_nonce: bool) -> (crate::TokenBundle, Vec<findings::Finding>) {
    let _guard = listener::serial_lock().await;
    store::reset();

    let provider = spawn(wrong_nonce).await;
    let config = test_config(&provider);

    let state_val = pkce::generate_state();
    let nonce = pkce::generate_nonce();
    let verifier = pkce::generate_verifier();
    let challenge = pkce::challenge_s256(&verifier);

    let pending: Arc<Mutex<Option<PendingFlow>>> = Arc::new(Mutex::new(Some(PendingFlow {
        config: config.clone(),
        state: state_val.clone(),
        nonce: Some(nonce.clone()),
        code_verifier: Some(verifier.clone()),
        redirect_uri: String::new(),
        code: None,
    })));

    let app = tauri::test::mock_app();
    let handle = app.handle().clone();

    // Arm the real listener on its configured port (explicit URI semantics).
    let port = listener::ensure_started(handle.clone(), pending.clone(), 9054, false)
        .await
        .unwrap();
    assert_eq!(port, 9054);
    let redirect_uri = listener::redirect_uri_for(port);

    // The provider must have seen the nonce we are about to send.
    let (auth_url, response_type) = crate::build_auth_url(
        &config,
        &redirect_uri,
        &state_val,
        Some(&nonce),
        Some(&challenge),
    )
    .unwrap();
    assert_eq!(response_type, "code");

    // Follow the authorize → 302 → listener chain exactly as a browser would.
    let http = reqwest::Client::new();
    let resp = http.get(auth_url.to_string()).send().await.unwrap();
    assert!(
        resp.status().is_success(),
        "listener should answer the redirect"
    );
    assert_eq!(
        provider.seen_nonce.lock().unwrap().as_deref(),
        Some(nonce.as_str())
    );

    // The listener is one-shot: it must have released the port already.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        listener::active_port().is_none(),
        "listener must be one-shot"
    );

    // The code was captured and the state matched (otherwise no code would be stored).
    let captured = {
        let guard = pending.lock().unwrap();
        let p = guard.as_ref().unwrap();
        assert_eq!(p.state, state_val);
        p.code
            .clone()
            .expect("authorization code should be captured")
    };
    assert_eq!(captured, "mock-code-1");

    // Store the config the way start_flow does, then exchange.
    store::set_config(&config);
    let pending_flow = pending.lock().unwrap().clone().unwrap();
    let bundle = token_exchange::exchange_authorization_code(&handle, &pending_flow, &captured)
        .await
        .expect("exchange against the mock provider should succeed");

    let recorded = store::findings();
    (bundle, recorded)
}

fn has(findings: &[findings::Finding], id: &str) -> Option<findings::Finding> {
    findings.iter().find(|f| f.id == id).cloned()
}

#[tokio::test]
async fn full_authorization_code_flow_against_mock_oidc() {
    let (bundle, findings) = run_flow(false).await;

    let id_token = bundle.decoded_id.as_ref().expect("id_token should decode");
    assert_eq!(id_token.alg, "RS256");
    assert_eq!(id_token.payload["aud"], "client-123");
    assert!(
        id_token.payload["iss"]
            .as_str()
            .unwrap()
            .starts_with("http://127.0.0.1:"),
        "iss should point at the mock provider"
    );
    assert!(bundle.access_token.is_some());

    // The ID token must have been verified against the JWKS the mock serves
    // (found via OIDC discovery from expected_iss) — this is the claim the
    // README makes about signature verification.
    let id_ver = bundle
        .verification
        .id
        .as_ref()
        .expect("id_token verification result");
    assert_eq!(
        id_ver.status,
        jwks::VerificationStatus::Valid,
        "{}",
        id_ver.detail
    );
    assert_eq!(id_ver.alg, "RS256");
    assert_eq!(id_ver.kid.as_deref(), Some("mock-key-1"));
    let verified = has(&findings, "sig_verified").expect("sig_verified finding");
    assert_eq!(verified.severity, Severity::Info);
    // The opaque access token produces no verification entry (nothing to check).
    assert!(bundle.verification.access.is_none());

    // No security findings for a correctly configured, correctly issued flow.
    for id in [
        "nonce_mismatch",
        "missing_nonce",
        "aud_mismatch",
        "iss_mismatch",
        "alg_mismatch",
        "alg_none",
        "expired_token",
        "scope_broader_than_requested",
        "missing_state",
        "state_mismatch",
        "sig_invalid",
        "sig_kid_not_found",
        "sig_unverified",
    ] {
        assert!(
            has(&findings, id).is_none(),
            "unexpected finding `{id}`: {:?}",
            has(&findings, id)
        );
    }
}

#[tokio::test]
async fn provider_issuing_wrong_nonce_is_flagged_critical() {
    let (bundle, findings) = run_flow(true).await;

    let finding = has(&findings, "nonce_mismatch").expect("nonce mismatch must be detected");
    assert_eq!(finding.severity, Severity::Critical);
    assert!(finding.detail.contains("replay"), "{}", finding.detail);

    // A wrong nonce is a claims problem, not a signature problem — the token
    // still verifies against the JWKS.
    assert_eq!(
        bundle.verification.id.as_ref().map(|v| v.status),
        Some(jwks::VerificationStatus::Valid)
    );
}
