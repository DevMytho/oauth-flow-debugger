//! Flow report export: Markdown or JSON, with every secret redacted.
//!
//! The report is generated in memory and handed to the frontend as a string —
//! the backend never writes tokens to disk. Redaction happens *before* the
//! string exists, so a token can't leak into an export:
//!
//! * values under secret keys (`access_token`, `refresh_token`, `id_token`,
//!   `client_secret`, `code`, `code_verifier`, `password`, `assertion`, …)
//! * any string that looks like a JWT (three base64url segments)
//! * secret query parameters embedded in URLs (`?code=…`, `#access_token=…`)

use serde_json::{json, Map, Value};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{findings, store, FlowStep};

/// Object keys whose values are always replaced with `[REDACTED]`.
const SECRET_KEYS: [&str; 12] = [
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "code",
    "code_verifier",
    "password",
    "assertion",
    "device_code",
    "user_code",
    "session_key",
    "secret",
];

/// Query/fragment parameters redacted when they appear inside a URL string.
const SECRET_PARAMS: [&str; 6] = [
    "code",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "code_verifier",
];

const REDACTED: &str = "[REDACTED]";

fn is_jwt_like(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() >= 4
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

/// Redact `key=value&…` pairs whose key is secret-aware, preserving the rest.
fn redact_url_string(s: &str) -> String {
    let (prefix, query) = match s.find(['?', '#']) {
        Some(i) => (&s[..i], &s[i..]),
        None => return s.to_string(),
    };
    let sep = query.chars().next().unwrap_or('?');
    let pairs: Vec<String> = query[1..]
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) if SECRET_PARAMS.contains(&k) && !v.is_empty() => {
                format!("{k}={REDACTED}")
            }
            _ => pair.to_string(),
        })
        .collect();
    format!("{prefix}{sep}{}", pairs.join("&"))
}

/// Deep-redact a JSON value in place.
pub fn redact_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                match v {
                    Value::String(s) => {
                        if (SECRET_KEYS.contains(&k.as_str()) && !s.is_empty()) || is_jwt_like(s) {
                            *s = REDACTED.to_string();
                        } else if s.contains('?') || s.contains('#') {
                            *s = redact_url_string(s);
                        }
                    }
                    _ => redact_value(v),
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_value),
        Value::String(s) => {
            if is_jwt_like(s) {
                *s = REDACTED.to_string();
            } else if s.contains('?') || s.contains('#') {
                *s = redact_url_string(s);
            }
        }
        _ => {}
    }
}

fn now_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Deliberately dependency-free: seconds since epoch is unambiguous.
    format!("unix:{secs}")
}

/// JSON report (secrets already redacted).
pub fn to_json() -> String {
    let mut steps: Vec<Value> = store::steps().iter().map(step_json).collect();
    steps.iter_mut().for_each(redact_value);

    let mut config = match store::config() {
        Some(c) => serde_json::to_value(&c).unwrap_or(Value::Null),
        None => Value::Null,
    };
    redact_value(&mut config);

    let report = json!({
        "tool": "oauth-flow-debugger",
        "generated_at": now_iso(),
        "summary": findings::Summary::from(&store::findings()),
        "findings": store::findings(),
        "config": config,
        "steps": steps,
        "redaction": "tokens, codes, verifiers and client secrets are replaced with [REDACTED]",
    });
    serde_json::to_string_pretty(&report).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

fn step_json(step: &FlowStep) -> Value {
    json!({
        "id": step.id,
        "kind": format!("{:?}", step.kind),
        "title": step.title,
        "status": format!("{:?}", step.status),
        "ts": step.ts,
        "detail": step.detail,
    })
}

/// Markdown report (secrets already redacted).
pub fn to_markdown() -> String {
    let summary = findings::Summary::from(&store::findings());
    let findings = store::findings();
    let steps = store::steps();

    let mut out = String::new();
    out.push_str("# OAuth flow report\n\n");
    out.push_str(&format!("- Generated: `{}`\n", now_iso()));
    out.push_str(&format!(
        "- Findings: **{}** ({} critical, {} high, {} medium, {} low, {} info)\n",
        summary.total, summary.critical, summary.high, summary.medium, summary.low, summary.info
    ));
    out.push_str(
        "- Redaction: tokens, authorization codes, PKCE verifiers and client secrets\n  are replaced with `[REDACTED]`.\n\n",
    );

    out.push_str("## Findings\n\n");
    if findings.is_empty() {
        out.push_str("No findings.\n\n");
    } else {
        out.push_str("| Severity | ID | Finding | Detail |\n");
        out.push_str("|---|---|---|---|\n");
        for f in &findings {
            out.push_str(&format!(
                "| {} {} | `{}` | {} | {} |\n",
                f.severity.icon(),
                f.severity.as_str(),
                f.id,
                f.title.replace('|', "\\|"),
                f.detail.replace('|', "\\|").replace('\n', " "),
            ));
        }
        out.push('\n');
    }

    out.push_str("## Flow configuration\n\n");
    match store::config() {
        Some(c) => {
            let mut v = serde_json::to_value(&c).unwrap_or(Value::Null);
            redact_value(&mut v);
            if let Value::Object(map) = &v {
                out.push_str("| Setting | Value |\n|---|---|\n");
                for (k, val) in sorted_entries(map) {
                    out.push_str(&format!("| `{k}` | {} |\n", render_cell(val)));
                }
                out.push('\n');
            }
        }
        None => out.push_str("_no flow configured_\n\n"),
    }

    out.push_str("## Timeline\n\n");
    if steps.is_empty() {
        out.push_str("_no steps recorded_\n");
    }
    for (i, step) in steps.iter().enumerate() {
        let mut detail = step.detail.clone();
        redact_value(&mut detail);
        out.push_str(&format!(
            "### {}. {} (`{}`)\n\n- status: {} `{}`\n\n```json\n{}\n```\n\n",
            i + 1,
            step.title,
            format!("{:?}", step.kind).to_lowercase(),
            step.status.icon(),
            format!("{:?}", step.status).to_lowercase(),
            serde_json::to_string_pretty(&detail).unwrap_or_default(),
        ));
    }
    out
}

fn sorted_entries(map: &Map<String, Value>) -> Vec<(String, &Value)> {
    let mut entries: Vec<(String, &Value)> = map.iter().map(|(k, v)| (k.clone(), v)).collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

fn render_cell(value: &Value) -> String {
    match value {
        Value::String(s) => s.replace('|', "\\|").replace('\n', " "),
        Value::Null => "—".into(),
        other => other.to_string().replace('|', "\\|"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StepKind, StepStatus};

    #[test]
    fn redacts_secret_keys_recursively() {
        let mut v = json!({
            "access_token": "abc.def.ghi",
            "nested": { "refresh_token": "rt", "token_type": "Bearer" },
            "list": [{ "id_token": "aaa.bbb.ccc" }],
        });
        redact_value(&mut v);
        assert_eq!(v["access_token"], REDACTED);
        assert_eq!(v["nested"]["refresh_token"], REDACTED);
        assert_eq!(v["nested"]["token_type"], "Bearer");
        assert_eq!(v["list"][0]["id_token"], REDACTED);
    }

    #[test]
    fn jwt_like_detection() {
        assert!(is_jwt_like("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig-part"));
        assert!(!is_jwt_like("not a token"));
        // Too few segments / too-short segments → not a token.
        assert!(!is_jwt_like("only.two"));
        assert!(!is_jwt_like("1.2.3"));
    }

    #[test]
    fn redacts_jwt_looking_strings_anywhere() {
        let mut v = json!({ "message": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig-part" });
        redact_value(&mut v);
        assert_eq!(v["message"], REDACTED);

        let mut plain = json!({ "message": "not a token" });
        redact_value(&mut plain);
        assert_eq!(plain["message"], "not a token");
    }

    #[test]
    fn redacts_tokens_inside_urls() {
        let mut v = json!({
            "raw_url": "http://localhost:9004/callback?code=SECRET123&state=ok",
            "auth_url": "https://p.example/authorize?client_id=c&state=xyz",
        });
        redact_value(&mut v);
        assert_eq!(
            v["raw_url"],
            "http://localhost:9004/callback?code=[REDACTED]&state=ok"
        );
        assert_eq!(
            v["auth_url"],
            "https://p.example/authorize?client_id=c&state=xyz"
        );

        let mut frag =
            json!({ "u": "http://localhost:9004/callback#access_token=tok123&token_type=Bearer" });
        redact_value(&mut frag);
        assert_eq!(
            frag["u"],
            "http://localhost:9004/callback#access_token=[REDACTED]&token_type=Bearer"
        );
    }

    #[tokio::test]
    async fn markdown_and_json_exports_contain_no_tokens() {
        let _guard = crate::listener::serial_lock().await;
        store::reset();
        let mut cfg = crate::FlowConfig {
            flow_type: crate::FlowType::AuthorizationCode,
            authorization_endpoint: "https://provider.example/authorize".into(),
            token_endpoint: "https://provider.example/token".into(),
            client_id: "client-123".into(),
            client_secret: "super-secret-value".into(),
            redirect_uri: "http://localhost:9004/callback".into(),
            scope: "openid".into(),
            pkce: true,
            include_nonce: true,
            client_auth: crate::ClientAuth::ClientSecretPost,
            expected_iss: String::new(),
            expected_alg: "RS256".into(),
            jwks_uri: String::new(),
            device_authorization_endpoint: String::new(),
            listener_port: 9004,
        };
        cfg.client_secret = "super-secret-value".into();
        store::set_config(&cfg);
        store::record_step(&FlowStep {
            id: "step-1".into(),
            kind: StepKind::TokenResponse,
            title: "Token endpoint responded".into(),
            status: StepStatus::Ok,
            detail: json!({
                "body": {
                    "access_token": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.signature",
                    "refresh_token": "rt-secret",
                    "token_type": "Bearer"
                },
                "url": "http://localhost:9004/callback?code=auth-code-secret&state=ok"
            }),
            ts: 1,
        });
        store::record_findings(&[findings::Finding::new(
            "pkce_missing",
            findings::Severity::High,
            "PKCE is disabled",
            "detail",
        )]);

        for report in [to_json(), to_markdown()] {
            assert!(
                !report.contains("super-secret-value"),
                "client_secret leaked"
            );
            assert!(!report.contains("rt-secret"), "refresh token leaked");
            assert!(!report.contains("auth-code-secret"), "auth code leaked");
            assert!(!report.contains("eyJhbGciOiJSUzI1NiJ9"), "JWT leaked");
            assert!(report.contains("pkce_missing"));
        }
        store::reset();
    }
}
