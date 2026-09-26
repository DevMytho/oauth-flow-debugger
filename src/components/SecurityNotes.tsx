import type { FlowStep, TokenBundle } from "../types";

/**
 * Security Notes panel rendered under every timeline step: what is being
 * checked right now, and what a bug or attack at this step looks like.
 */

interface Check {
  icon: "ok" | "warn" | "error" | "info";
  text: string;
}

interface Props {
  step: FlowStep;
  /** nonce generated for the current flow, if any (for id_token comparison) */
  flowNonce: string | null;
}

function checksFor(step: FlowStep, flowNonce: string | null): Check[] {
  const d = step.detail as Record<string, unknown>;
  switch (step.kind) {
    case "auth_url": {
      const checks: Check[] = [];
      checks.push({ icon: "ok", text: "Unique state generated for this attempt (CSRF protection)" });
      if (d.pkce) {
        checks.push({
          icon: "ok",
          text: "PKCE enabled — code_challenge S256 attached, verifier stays on this machine",
        });
      } else if (d.response_type === "code") {
        checks.push({
          icon: "warn",
          text: "PKCE is off — a stolen authorization code can be redeemed without it",
        });
      }
      if (d.nonce) {
        checks.push({ icon: "ok", text: "nonce generated — will be checked against the ID token" });
      }
      checks.push({
        icon: "info",
        text: "Verify the provider exact-matches this redirect_uri — wildcards enable open redirects",
      });
      return checks;
    }
    case "callback": {
      const checks: Check[] = [];
      const valid = d.state_valid as boolean | null;
      if (valid === true) {
        checks.push({ icon: "ok", text: "state matches — CSRF protection working" });
      } else if (valid === false) {
        checks.push({
          icon: "error",
          text: "state mismatch or missing — this callback is rejected (possible CSRF or replay)",
        });
      } else {
        checks.push({ icon: "info", text: "No pending flow — state could not be checked" });
      }
      if (d.pkce) {
        checks.push({ icon: "ok", text: "PKCE code_challenge was set for this flow" });
      }
      if (d.has_error) {
        checks.push({
          icon: "error",
          text: `Provider error: ${String(d.provider_error ?? "unknown")}${
            d.provider_error_description ? ` — ${String(d.provider_error_description)}` : ""
          }`,
        });
      } else if (d.has_code) {
        checks.push({
          icon: "info",
          text: "Authorization code lifetime is usually 30–60s and single-use — exchange it now",
        });
      }
      if (d.has_tokens) {
        checks.push({
          icon: "warn",
          text: "Tokens traveled in the URL fragment — they land in browser history and logs",
        });
      }
      return checks;
    }
    case "token_request": {
      const checks: Check[] = [
        { icon: "ok", text: "Request goes directly from this machine to the token endpoint (no proxy)" },
        { icon: "info", text: `Client authentication: ${String(d.client_auth)}` },
      ];
      if (String(d.grant_type) === "authorization_code") {
        checks.push({
          icon: "ok",
          text: "code_verifier sent — the code is bound to the client that started the flow",
        });
      }
      return checks;
    }
    case "token_response": {
      const ok = d.ok === true;
      return ok
        ? [
            { icon: "ok", text: "Token endpoint accepted the grant" },
            {
              icon: "info",
              text: "Errors here are diagnostic: invalid_grant usually means expired code, redirect_uri mismatch, or failed PKCE",
            },
          ]
        : [
            { icon: "error", text: `Token endpoint rejected the request: ${JSON.stringify(d.body)}` },
            {
              icon: "info",
              text: "Check code expiry, redirect_uri exact match, PKCE verifier, and client authentication method",
            },
          ];
    }
    case "tokens": {
      const bundle = (d.bundle ?? {}) as TokenBundle;
      const warnings = (d.warnings as string[] | undefined) ?? [];
      const checks: Check[] = [];
      const access = bundle.decoded_access;
      const id = bundle.decoded_id;
      const jwt = id ?? access;
      if (jwt) {
        const alg = jwt.alg;
        if (alg === "none" || !alg) {
          checks.push({ icon: "error", text: "alg: none — token is unsigned and forgeable" });
        } else if (alg.startsWith("HS")) {
          checks.push({ icon: "warn", text: `alg: ${alg} — HMAC; a leaked client secret lets attackers mint tokens` });
        } else {
          checks.push({ icon: "ok", text: `alg: ${alg} — asymmetric signature` });
        }
        if (jwt.exp == null) {
          checks.push({ icon: "warn", text: "No exp claim — token never expires" });
        }
        if (id) {
          const nonceClaim = id.payload.nonce;
          if (flowNonce) {
            if (nonceClaim === flowNonce) {
              checks.push({ icon: "ok", text: "nonce matches — ID token replay is blocked" });
            } else if (nonceClaim == null) {
              checks.push({ icon: "warn", text: "ID token has no nonce claim" });
            } else {
              checks.push({ icon: "error", text: "nonce mismatch — possible ID token replay" });
            }
          }
          if (id.payload.aud == null) {
            checks.push({ icon: "warn", text: "No aud claim — audience confusion possible" });
          }
        }
      } else {
        checks.push({ icon: "info", text: "Access token is opaque (not a JWT) — inspect it at the provider's userinfo endpoint" });
      }
      if (bundle.refresh_token) {
        checks.push({ icon: "info", text: "refresh_token returned — store it like a password" });
      }
      for (const w of warnings) {
        checks.push({ icon: "warn", text: w });
      }
      return checks;
    }
    case "error":
      return [
        { icon: "error", text: String(d.message ?? "Flow failed") },
        { icon: "info", text: "The flow stopped here — adjust the configuration and start again" },
      ];
    default:
      return [];
  }
}

const ATTACK_SURFACE: Record<string, string[]> = {
  auth_url: [
    "CSRF — if the provider doesn't enforce the state you sent, an attacker can start a flow in your session and push their account into yours (login CSRF)",
    "Open redirect — if redirect_uri isn't exact-matched, the code can be forwarded to an attacker-controlled host",
    "PKCE downgrade — a public client that accepts the flow without PKCE loses code-interception protection",
    "Scope escalation — requested scopes are visible here; the consent screen is not a security boundary",
  ],
  callback: [
    "Authorization code injection — with state unvalidated, an attacker can swap a victim's code into your session and bind their account",
    "Code interception — stolen codes are redeemed within seconds; PKCE (S256) makes them useless without the verifier",
    "Open redirect chain — if the provider matches redirect_uri loosely, the code leaks via Referer or a forwarded URL",
    "Replay — codes are single-use; a second redeem attempt should fail, and a success here means weak provider hygiene",
    "Implicit leakage — tokens in the fragment persist in browser history, screenshots, and proxy logs",
  ],
  token_request: [
    "TLS only — the code + verifier + secret travel together; a network observer wins everything if this isn't HTTPS",
    "Client secret exposure — client_secret_post puts the secret in the body; make sure it can't end up in logs",
    "Mix-up attacks — when using multiple providers, ensure the token request goes to the issuer that returned the code",
  ],
  token_response: [
    "Error leakage — verbose error_description can reveal whether codes exist or which client they belong to",
    "Downgrade — a provider returning an unsigned or HS256 token where RS256 was expected is a red flag",
    "Refresh token theft — this response is high-value; anything logging it (including this tool) must stay local",
  ],
  tokens: [
    "alg:none / algorithm confusion — forging a token the API will accept if it doesn't pin allowed algorithms",
    "aud/iss mix-up — a token minted for another client or tenant accepted as yours",
    "ID token replay — without nonce binding, an observed ID token can be replayed into your session",
    "Expired token acceptance — an API that ignores exp lets stolen tokens live forever",
    "Missing claims — no iss/aud/exp means nothing about the token can be verified",
  ],
  error: [
    "Distinguish auth errors (user denied, invalid_client) from implementation bugs before assuming an attack",
  ],
};

const ICON: Record<Check["icon"], string> = {
  ok: "✅",
  warn: "⚠️",
  error: "❌",
  info: "ℹ️",
};

export default function SecurityNotes({ step, flowNonce }: Props) {
  const checks = checksFor(step, flowNonce);
  const attacks = ATTACK_SURFACE[step.kind] ?? [];
  if (checks.length === 0 && attacks.length === 0) return null;

  return (
    <div className="mt-3 rounded-lg border border-zinc-800 bg-zinc-900/60 p-3">
      <div className="text-[11px] font-semibold tracking-wider text-zinc-500 uppercase">
        Security Notes
      </div>
      <ul className="mt-2 space-y-1.5">
        {checks.map((c, i) => (
          <li key={i} className="flex gap-2 text-[13px] leading-snug text-zinc-300">
            <span aria-hidden>{ICON[c.icon]}</span>
            <span>{c.text}</span>
          </li>
        ))}
      </ul>
      {attacks.length > 0 && (
        <>
          <div className="mt-3 text-[11px] font-semibold tracking-wider text-zinc-500 uppercase">
            Attack surface at this step
          </div>
          <ul className="mt-1.5 space-y-1.5">
            {attacks.map((a, i) => (
              <li key={i} className="flex gap-2 text-[13px] leading-snug text-zinc-400">
                <span className="text-rose-500">•</span>
                <span>{a}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
