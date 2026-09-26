# oauth-flow-debugger

Step through OAuth 2.0 and OIDC flows visually — intercept callbacks, decode tokens, and inspect every exchange in a native desktop app.

Built with Tauri (Rust) + React + TypeScript.

---

## The problem

Debugging OAuth is miserable. You're decoding base64 in your browser console, checking token expiry against a Unix timestamp converter, trying to figure out why `state` didn't match or why the `nonce` claim is missing. And pentesting OAuth? You're doing it all in Burp, manually.

`oauth-flow-debugger` gives you a visual, step-by-step breakdown of any OAuth 2.0 or OIDC flow — in real time, on your machine, with no proxies needed.

---

## Screenshots

> _coming soon_

---

## What it does

1. **Configure the flow** — paste in your client ID, authorization endpoint, redirect URI, scope, and PKCE settings
2. **Launch** — the app opens the authorization URL in a controlled webview and starts a local redirect listener on `localhost:9004`
3. **Intercept** — when the provider redirects back, the Rust backend captures the full callback URL before the browser touches it
4. **Decode** — authorization code, state, tokens, and all JWT claims are parsed and displayed
5. **Inspect** — see every step annotated with what happened, what to look for, and what a bug or attack at this step looks like

---

## Supported flows

| Flow | Status |
|---|---|
| Authorization Code | ✅ |
| Authorization Code + PKCE | ✅ |
| Implicit (legacy) | ✅ (read-only, flagged as insecure) |
| Client Credentials | ✅ |
| Device Authorization | 🔜 |

---

## Architecture

```
oauth-flow-debugger/
├── src-tauri/
│   ├── src/
│   │   ├── main.rs            # Tauri entry, command registration
│   │   ├── listener.rs        # Local HTTP server (tokio) for redirect capture
│   │   ├── pkce.rs            # Code verifier/challenge generation (SHA-256)
│   │   ├── token_exchange.rs  # Authorization code → token POST
│   │   └── decode.rs          # JWT decode + claims parsing
│   └── Cargo.toml
├── src/
│   ├── App.tsx
│   ├── components/
│   │   ├── FlowConfig.tsx     # Client ID, endpoints, scope, PKCE toggle
│   │   ├── FlowTimeline.tsx   # Step-by-step visual of the exchange
│   │   ├── TokenInspector.tsx # Claims table, expiry countdown, alg flag
│   │   └── SecurityNotes.tsx  # Per-step attack surface annotations
│   └── lib/
│       └── invoke.ts
├── index.html
├── vite.config.ts
└── package.json
```

**Key design:** the Rust backend handles all network operations — local redirect listener, token exchange POST, PKCE generation. The frontend is purely display. No outbound data leaves your machine except the OAuth calls you initiate.

---

## Install / Run

```bash
git clone https://github.com/devmytho/oauth-flow-debugger.git
cd oauth-flow-debugger
npm install
npm run tauri dev
```

**Prerequisites:** Rust toolchain (`rustup`), Node 18+

---

## Usage

### Basic flow

```
1. Fill in your provider's details:
   - Authorization endpoint  (e.g. https://accounts.google.com/o/oauth2/v2/auth)
   - Token endpoint          (e.g. https://oauth2.googleapis.com/token)
   - Client ID
   - Redirect URI            → set this to http://localhost:9004/callback in your provider

2. Toggle PKCE on (recommended)
3. Click "Start Flow"
4. Authenticate in the webview
5. Watch the timeline populate in real time
```

### Security annotations

Each step in the timeline includes a **Security Notes** panel:

```
Step 3 — Authorization Code received
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅  state matches — CSRF protection working
✅  PKCE code_challenge was set
⚠️  code lifetime: check your provider's docs (usually 30–60s)

Attack surface at this step:
• Authorization code injection — if state wasn't validated, an attacker
  could swap a victim's code into their own session
• Open redirect — if redirect_uri wasn't exact-matched by the provider,
  it could be stolen
```

---

## Token inspector

Decoded JWT display for access tokens and ID tokens:

```
Header
  alg:  RS256  ✅
  typ:  JWT

Payload
  iss:  https://accounts.google.com
  sub:  1234567890
  aud:  your-client-id
  exp:  2025-09-14T10:30:00Z  ✅  (expires in 58 minutes)
  iat:  2025-09-14T09:30:00Z
  nonce: abc123  ✅  (matches)

Signature
  Verification: ✅ valid (RS256, public key fetched from JWKS endpoint)
```

---

## Tech stack

**Backend (Rust):** `tokio`, `axum` (local redirect server), `sha2` (PKCE), `reqwest` (token exchange), `base64`, Tauri v2

**Frontend:** React 18, TypeScript, Vite, Tailwind CSS

---

## Roadmap

- [ ] Token refresh flow visualization
- [ ] JWKS endpoint fetcher + offline key verification
- [ ] Built-in test providers (GitHub, Google, Auth0, Supabase)
- [ ] Export full flow transcript as a pentest evidence artifact
- [ ] Detect common misconfigs automatically (missing PKCE, implicit flow, weak state)

---

## ⚠️ Disclaimer

Built for security engineers debugging their own implementations and for authorized OAuth security assessments. All traffic stays local — the app never proxies or logs your tokens.

---

## License

MIT
