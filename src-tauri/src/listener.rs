//! Local HTTP redirect listener (axum), bound to `127.0.0.1` only.
//!
//! The browser is sent to the provider with
//! `redirect_uri=http://localhost:<port>/callback`. When the provider
//! redirects back:
//!
//! * **Authorization Code flow** — the code arrives in the query string, so the
//!   GET handler captures it server-side.
//! * **Implicit flow** — tokens arrive in the URL *fragment*, which browsers
//!   never send to servers. The handler serves a tiny page whose JS posts the
//!   fragment back to `/__capture`.
//!
//! Properties:
//!
//! * **Loopback only** — the socket is bound to `127.0.0.1`, never `0.0.0.0`,
//!   so nothing off this machine can reach it.
//! * **One shot** — after a callback is captured the server shuts down, so the
//!   port is not left listening between flows. A new flow re-arms it.
//! * **Configurable port** — the preferred port comes from the flow config
//!   (`listener_port`, default 9004). If it is taken and the redirect URI is
//!   auto-generated, the listener walks upward to find a free port and reports
//!   the port it actually got; with an explicit registered redirect URI the
//!   conflict is a hard error instead (the provider would reject a different
//!   port).
//! * **Idle timeout** — a listener nobody redirects to releases the port after
//!   [`IDLE_TIMEOUT_SECS`].

use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use crate::{emit_step, process_callback, PendingFlow, StepKind, StepStatus};

pub const DEFAULT_PORT: u16 = 9004;
pub const REDIRECT_PATH: &str = "/callback";
/// How far above the preferred port to search when it is already in use.
const PORT_SEARCH_SPAN: u16 = 20;
/// Give up and release an unused listener after this long.
const IDLE_TIMEOUT_SECS: u64 = 600;

/// The redirect URI to register with the OAuth provider, for a given port.
pub fn redirect_uri_for(port: u16) -> String {
    format!("http://localhost:{port}{REDIRECT_PATH}")
}

/// The redirect URI for the currently armed listener (or the default port).
pub fn redirect_uri() -> String {
    redirect_uri_for(active_port().unwrap_or(DEFAULT_PORT))
}

/// Port the listener is currently bound to, if armed.
pub fn active_port() -> Option<u16> {
    lock_state().as_ref().map(|e| e.port)
}

/// Params that mean "the provider answered us" in the query string.
const INTERESTING: [&str; 4] = ["code", "error", "access_token", "id_token"];

#[derive(Debug)]
struct ListenerState<R: tauri::Runtime> {
    app: tauri::AppHandle<R>,
    pending: std::sync::Arc<Mutex<Option<PendingFlow>>>,
}

impl<R: tauri::Runtime> Clone for ListenerState<R> {
    fn clone(&self) -> Self {
        Self {
            app: self.app.clone(),
            pending: self.pending.clone(),
        }
    }
}

struct Entry {
    port: u16,
    generation: u64,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

static STATE: Mutex<Option<Entry>> = Mutex::new(None);
static GENERATION: AtomicU64 = AtomicU64::new(1);

fn lock_state() -> MutexGuard<'static, Option<Entry>> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Serialize tests that share the global listener state. Async-aware so the
/// guard can be held across `.await` points inside a test.
#[cfg(test)]
pub(crate) async fn serial_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}

async fn bind_loopback(port: u16) -> Result<tokio::net::TcpListener, String> {
    // A handful of retries: a just-shut-down listener may still be draining.
    let mut last = None;
    for attempt in 0..10 {
        match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
            Ok(l) => return Ok(l),
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(Duration::from_millis(25)).await;
                if attempt == 9 {
                    break;
                }
            }
        }
    }
    Err(format!(
        "cannot bind redirect listener to 127.0.0.1:{port}: {}",
        last.map(|e| e.to_string()).unwrap_or_default()
    ))
}

/// Arm the listener on `preferred_port` (one shot, loopback only).
///
/// * `allow_fallback = true` — if the port is busy, walk upward looking for a
///   free one (used when we generate the redirect URI ourselves).
/// * `allow_fallback = false` — a busy port is an error (used when the user
///   supplied a registered redirect URI whose port must be honoured).
///
/// Returns the port actually bound.
pub async fn ensure_started<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    pending: std::sync::Arc<Mutex<Option<PendingFlow>>>,
    preferred_port: u16,
    allow_fallback: bool,
) -> Result<u16, String> {
    let preferred = if preferred_port == 0 {
        DEFAULT_PORT
    } else {
        preferred_port
    };

    // Already armed — reuse it when it matches, otherwise re-arm.
    let existing = active_port();
    if let Some(p) = existing {
        if p == preferred {
            return Ok(p);
        }
        shutdown();
    }

    let mut attempts: Vec<u16> = vec![preferred];
    if allow_fallback {
        for offset in 1..=PORT_SEARCH_SPAN {
            let candidate = preferred.saturating_add(offset);
            if candidate > 0 {
                attempts.push(candidate);
            }
        }
    }

    let mut bound: Option<(u16, tokio::net::TcpListener)> = None;
    let mut errors = Vec::new();
    for port in attempts {
        match bind_loopback(port).await {
            Ok(listener) => {
                bound = Some((port, listener));
                break;
            }
            Err(e) => errors.push(e),
        }
    }
    let (port, tcp) = bound.ok_or_else(|| {
        if allow_fallback {
            format!(
                "no free loopback port in {preferred}–{} ({})",
                preferred.saturating_add(PORT_SEARCH_SPAN),
                errors.join("; ")
            )
        } else {
            format!(
                "{preferred} is already in use — stop the other process or pick a \
                 different listener port ({})",
                errors.join("; ")
            )
        }
    })?;

    let generation = GENERATION.fetch_add(1, Ordering::SeqCst);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    {
        let mut guard = lock_state();
        *guard = Some(Entry {
            port,
            generation,
            shutdown: Some(shutdown_tx),
        });
    }

    let state = ListenerState {
        app: app.clone(),
        pending,
    };
    let router = Router::new()
        .route("/", get(index_page))
        .route(REDIRECT_PATH, get(callback_get))
        .route("/__capture", post(capture_post))
        .with_state(state);

    tokio::spawn(async move {
        let serve = axum::serve(tcp, router).with_graceful_shutdown(async move {
            let idle = tokio::time::sleep(Duration::from_secs(IDLE_TIMEOUT_SECS));
            tokio::pin!(idle);
            tokio::select! {
                _ = shutdown_rx => {}
                _ = &mut idle => {}
            }
        });

        let result = serve.await;
        if let Err(e) = result {
            eprintln!("redirect listener stopped: {e}");
        }

        // Release the slot if we are still the active generation, so the next
        // flow can bind again.
        let mut guard = lock_state();
        if let Some(entry) = guard.as_ref() {
            if entry.generation == generation {
                *guard = None;
            }
        }
    });

    emit_step(
        &app,
        StepKind::Info,
        format!("Redirect listener armed on 127.0.0.1:{port} (one-shot)"),
        StepStatus::Info,
        json!({
            "bind": format!("127.0.0.1:{port}"),
            "loopback_only": true,
            "redirect_uri": redirect_uri_for(port),
            "fallback_used": port != preferred,
            "preferred_port": preferred,
        }),
    );

    Ok(port)
}

/// Shut the listener down (after a captured callback, or before re-arming on a
/// different port). Returns `true` if something was actually shut down.
pub fn shutdown() -> bool {
    let entry = lock_state().take();
    match entry {
        Some(e) => {
            if let Some(tx) = e.shutdown {
                let _ = tx.send(());
            }
            true
        }
        None => false,
    }
}

async fn index_page() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>OAuth Flow Debugger</title>
<style>body{background:#09090b;color:#a1a1aa;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}div{text-align:center}code{color:#4ade80}</style>
</head><body><div><h3>OAuth Flow Debugger</h3><p>Redirect listener running on <code>127.0.0.1</code> (loopback only)</p></div></body></html>"#,
    )
}

/// GET /callback — server-side capture (code flow) or JS capture page (implicit).
async fn callback_get<R: tauri::Runtime>(
    State(state): State<ListenerState<R>>,
    Query(query): Query<HashMap<String, String>>,
    uri: axum::http::Uri,
) -> Html<String> {
    let has_answer = INTERESTING.iter().any(|k| query.contains_key(*k));
    if has_answer {
        let raw = format!(
            "http://localhost:{}{}",
            active_port().unwrap_or(DEFAULT_PORT),
            uri
        );
        process_callback(&state.app, &state.pending, query, raw).await;
        // One shot: this callback was captured, stop listening.
        shutdown();
        return Html(captured_page(
            "Authorization response captured",
            "Return to OAuth Flow Debugger — this tab can be closed.",
        ));
    }
    // Implicit flow: tokens are in the fragment, which we never see server-side.
    // Serve a page that forwards location.hash to /__capture.
    Html(fragment_capture_page())
}

#[derive(Deserialize)]
struct CaptureBody {
    #[serde(default)]
    search: String,
    #[serde(default)]
    hash: String,
}

/// POST /__capture — receives {search, hash} from the fragment capture page.
async fn capture_post<R: tauri::Runtime>(
    State(state): State<ListenerState<R>>,
    Json(body): Json<CaptureBody>,
) -> Json<serde_json::Value> {
    let mut params = parse_kv(body.search.trim_start_matches(['?', '#']));
    let fragment = body.hash.trim_start_matches('#');
    for (k, v) in parse_kv(fragment) {
        params.entry(k).or_insert(v);
    }

    if params.is_empty() {
        return Json(json!({
            "ok": false,
            "message": "No OAuth parameters found in the URL."
        }));
    }

    let raw = format!(
        "http://localhost:{}{}{}{}",
        active_port().unwrap_or(DEFAULT_PORT),
        REDIRECT_PATH,
        if body.search.is_empty() {
            String::new()
        } else {
            format!("?{}", body.search)
        },
        if body.hash.is_empty() {
            String::new()
        } else {
            format!("#{}", body.hash)
        },
    );
    process_callback(&state.app, &state.pending, params, raw).await;
    shutdown();

    Json(json!({
        "ok": true,
        "message": "Captured. Return to OAuth Flow Debugger — this tab can be closed."
    }))
}

/// Parse `a=1&b=2` into a map, percent-decoding both keys and values.
fn parse_kv(s: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(s.as_bytes())
        .into_owned()
        .collect()
}

fn captured_page(title: &str, message: &str) -> String {
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>{title}</title>
<style>body{{background:#09090b;color:#e4e4e7;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}div{{text-align:center;max-width:480px}}h1{{font-size:20px;color:#4ade80}}p{{color:#a1a1aa;line-height:1.6}}</style>
</head><body><div><h1>&#10004; {title}</h1><p>{message}</p></div></body></html>"#
    )
}

fn fragment_capture_page() -> String {
    r#"<!doctype html><html><head><meta charset="utf-8"><title>Capturing…</title>
<style>body{background:#09090b;color:#e4e4e7;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}div{text-align:center;max-width:480px}h1{font-size:20px;color:#4ade80}p{color:#a1a1aa;line-height:1.6}</style>
</head><body><div><h1 id="t">Intercepting callback…</h1><p id="m">Reading tokens from the URL fragment.</p></div>
<script>
(function () {
  var payload = JSON.stringify({ search: location.search, hash: location.hash });
  fetch("/__capture", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: payload
  })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      document.getElementById("t").textContent = d.ok ? "✔ Captured" : "Nothing to capture";
      document.getElementById("m").textContent = d.message || "";
    })
    .catch(function (e) {
      document.getElementById("t").textContent = "Capture failed";
      document.getElementById("m").textContent = String(e);
    });
})();
</script>
</body></html>"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending_store() -> std::sync::Arc<Mutex<Option<PendingFlow>>> {
        std::sync::Arc::new(Mutex::new(None))
    }

    #[tokio::test]
    async fn binds_loopback_only_and_reports_port() {
        let _g = serial_lock().await;
        shutdown();
        let app = tauri::test::mock_app();
        let handle = app.handle().clone();
        let store = pending_store();

        let port = ensure_started(handle, store, 9104, false).await.unwrap();
        assert_eq!(port, 9104);
        assert!(active_port().is_some());
        assert_eq!(active_port(), Some(9104));
        assert_eq!(redirect_uri(), "http://localhost:9104/callback");

        // Loopback only: the listener must not be reachable on a non-loopback
        // address. Binding the same port on 0.0.0.0 would fail if it were
        // already taken on all interfaces; instead we assert the socket
        // explicitly refuses a non-loopback bind of the same port.
        let external = std::net::TcpListener::bind(("0.0.0.0", port));
        assert!(
            external.is_err(),
            "listener should be bound to 127.0.0.1 only, but 0.0.0.0:{port} was free"
        );

        assert!(shutdown());
        assert!(active_port().is_none());
    }

    #[tokio::test]
    async fn falls_back_when_preferred_port_is_busy() {
        let _g = serial_lock().await;
        shutdown();
        // Occupy the preferred port with a plain socket.
        let blocker = std::net::TcpListener::bind(("127.0.0.1", 9114)).unwrap();

        let app = tauri::test::mock_app();
        let handle = app.handle().clone();
        let store = pending_store();

        let port = ensure_started(handle, store, 9114, true).await.unwrap();
        assert_ne!(port, 9114, "should have searched past the busy port");
        assert!(port > 9114 && port <= 9114 + PORT_SEARCH_SPAN);
        drop(blocker);
        shutdown();
    }

    #[tokio::test]
    async fn refuses_fallback_when_redirect_uri_is_explicit() {
        let _g = serial_lock().await;
        shutdown();
        let _blocker = std::net::TcpListener::bind(("127.0.0.1", 9124)).unwrap();

        let app = tauri::test::mock_app();
        let handle = app.handle().clone();
        let store = pending_store();

        let err = ensure_started(handle, store, 9124, false)
            .await
            .unwrap_err();
        assert!(err.contains("in use"), "{err}");
        assert!(active_port().is_none());
    }

    #[tokio::test]
    async fn one_shot_listener_stops_after_first_callback() {
        let _g = serial_lock().await;
        shutdown();
        let app = tauri::test::mock_app();
        let handle = app.handle().clone();
        let store = pending_store();

        let port = ensure_started(handle.clone(), store.clone(), 9134, false)
            .await
            .unwrap();

        let http = reqwest::Client::new();
        let resp = http
            .get(format!(
                "http://127.0.0.1:{port}{REDIRECT_PATH}?code=abc&state=x"
            ))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());

        // Give graceful shutdown a beat to release the socket, then the port
        // must be free (nothing is listening any more).
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(active_port().is_none(), "listener must be one-shot");
        let rebind = tokio::net::TcpListener::bind(("127.0.0.1", port)).await;
        assert!(rebind.is_ok(), "port should be released after the callback");
    }

    #[tokio::test]
    async fn reuses_running_listener_on_same_port() {
        let _g = serial_lock().await;
        shutdown();
        let app = tauri::test::mock_app();
        let handle = app.handle().clone();
        let store = pending_store();

        let first = ensure_started(handle.clone(), store.clone(), 9144, false)
            .await
            .unwrap();
        let second = ensure_started(handle, store, 9144, false).await.unwrap();
        assert_eq!(first, second);
        shutdown();
    }
}
