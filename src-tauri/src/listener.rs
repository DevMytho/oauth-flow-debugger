//! Local HTTP redirect listener (axum) bound to 127.0.0.1:9004.
//!
//! The browser is sent to the provider with `redirect_uri=http://localhost:9004/callback`.
//! When the provider redirects back:
//!
//! * **Authorization Code flow** — the code arrives in the query string, so the
//!   GET handler captures it directly, before any other app touches it.
//! * **Implicit flow** — tokens arrive in the URL *fragment*, which browsers
//!   never send to servers. The handler serves a tiny page whose JS posts the
//!   fragment back to `/__capture`.
//!
//! Everything stays on loopback; the server never accepts connections from
//! outside this machine.

use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::{process_callback, PendingFlow};

pub const LISTENER_PORT: u16 = 9004;
pub const REDIRECT_PATH: &str = "/callback";

/// The redirect URI to register with the OAuth provider.
pub fn redirect_uri() -> String {
    format!("http://localhost:{LISTENER_PORT}{REDIRECT_PATH}")
}

/// Params that mean "the provider answered us" in the query string.
const INTERESTING: [&str; 4] = ["code", "error", "access_token", "id_token"];

#[derive(Debug)]
struct ListenerState<R: tauri::Runtime> {
    app: tauri::AppHandle<R>,
    pending: Arc<Mutex<Option<PendingFlow>>>,
}

impl<R: tauri::Runtime> Clone for ListenerState<R> {
    fn clone(&self) -> Self {
        Self {
            app: self.app.clone(),
            pending: self.pending.clone(),
        }
    }
}

static STARTED: AtomicBool = AtomicBool::new(false);

/// Bind the listener (once) and spawn the server task.
pub async fn ensure_started<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    pending: Arc<Mutex<Option<PendingFlow>>>,
) -> Result<(), String> {
    if STARTED.load(Ordering::SeqCst) {
        return Ok(());
    }
    let tcp = tokio::net::TcpListener::bind(("127.0.0.1", LISTENER_PORT))
        .await
        .map_err(|e| format!("cannot bind redirect listener on port {LISTENER_PORT}: {e}"))?;
    if STARTED.swap(true, Ordering::SeqCst) {
        // Lost a race with a concurrent start; the other task is serving.
        return Ok(());
    }

    let state = ListenerState { app, pending };
    let router = Router::new()
        .route("/", get(index_page))
        .route(REDIRECT_PATH, get(callback_get))
        .route("/__capture", post(capture_post))
        .with_state(state);

    tokio::spawn(async move {
        if let Err(e) = axum::serve(tcp, router).await {
            eprintln!("redirect listener stopped: {e}");
        }
    });
    Ok(())
}

async fn index_page() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>OAuth Flow Debugger</title>
<style>body{background:#09090b;color:#a1a1aa;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}div{text-align:center}code{color:#4ade80}</style>
</head><body><div><h3>OAuth Flow Debugger</h3><p>Redirect listener running on <code>127.0.0.1:9004</code></p></div></body></html>"#,
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
        let raw = format!("http://localhost:{}{}", LISTENER_PORT, uri);
        process_callback(&state.app, &state.pending, query, raw);
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
        LISTENER_PORT,
        REDIRECT_PATH,
        if body.search.is_empty() { String::new() } else { format!("?{}", body.search) },
        if body.hash.is_empty() { String::new() } else { format!("#{}", body.hash) },
    );
    process_callback(&state.app, &state.pending, params, raw);

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
      document.getElementById("t").textContent = d.ok ? "\u2714 Captured" : "Nothing to capture";
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
