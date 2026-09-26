import { useEffect, useMemo, useState } from "react";
import type { DecodedJwt, TokenBundle } from "../types";

interface Props {
  bundle: TokenBundle | null;
  flowNonce: string | null;
}

function fmtAbsolute(epochSec: number): string {
  return new Date(epochSec * 1000).toLocaleString();
}

function fmtRemaining(seconds: number): string {
  if (seconds <= 0) return `expired ${Math.abs(seconds)}s ago`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function algFlag(alg: string | undefined): { icon: string; cls: string; note: string } {
  if (!alg || alg === "none")
    return { icon: "❌", cls: "text-rose-400", note: "unsigned — forgeable" };
  if (alg.startsWith("HS"))
    return { icon: "⚠️", cls: "text-amber-400", note: "HMAC — secret-based" };
  if (/^(RS|PS|ES)/.test(alg))
    return { icon: "✅", cls: "text-emerald-400", note: "asymmetric" };
  return { icon: "⚠️", cls: "text-amber-400", note: "uncommon algorithm" };
}

function formatClaimValue(key: string, value: unknown): { text: string; muted?: boolean } {
  if (value == null) return { text: "—", muted: true };
  if (key === "exp" || key === "iat" || key === "nbf") {
    if (typeof value === "number")
      return { text: `${fmtAbsolute(value)}  (${value})`, muted: true };
  }
  if (Array.isArray(value)) return { text: value.map(String).join(", ") };
  if (typeof value === "object") return { text: JSON.stringify(value) };
  return { text: String(value) };
}

export default function TokenInspector({ bundle, flowNonce }: Props) {
  const [tab, setTab] = useState<"access" | "id">("id");
  const [, setTick] = useState(0);

  // 1 Hz tick for the countdowns
  useEffect(() => {
    if (!bundle) return;
    const t = window.setInterval(() => setTick((n) => n + 1), 1000);
    return () => window.clearInterval(t);
  }, [bundle]);

  const nowSec = Math.floor(Date.now() / 1000);

  const hasAccess = !!bundle?.access_token;
  const hasId = !!bundle?.id_token;
  const active: "access" | "id" = hasId && tab === "id" ? "id" : hasAccess ? "access" : "id";
  const token = active === "id" ? bundle?.id_token : bundle?.access_token;
  const jwt: DecodedJwt | null =
    active === "id" ? bundle?.decoded_id ?? null : bundle?.decoded_access ?? null;

  const visibleClaims = useMemo(() => {
    if (!jwt) return [];
    return Object.entries(jwt.payload);
  }, [jwt]);

  if (!bundle) {
    return (
      <div className="flex h-full min-h-40 items-center justify-center rounded-xl border border-dashed border-zinc-800 p-6 text-center text-sm text-zinc-600">
        Token Inspector — decoded claims appear once tokens are received.
      </div>
    );
  }

  const responseExpires =
    bundle.expires_at != null ? fmtRemaining(bundle.expires_at - nowSec) : null;

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-xs font-semibold tracking-widest text-zinc-400 uppercase">
          Token Inspector
        </h2>
        <div className="flex gap-1">
          {hasId && (
            <button
              type="button"
              onClick={() => setTab("id")}
              className={`rounded px-2 py-0.5 text-[11px] ${
                active === "id"
                  ? "bg-emerald-700 text-white"
                  : "bg-zinc-800 text-zinc-400 hover:text-zinc-200"
              }`}
            >
              ID token
            </button>
          )}
          {hasAccess && (
            <button
              type="button"
              onClick={() => setTab("access")}
              className={`rounded px-2 py-0.5 text-[11px] ${
                active === "access"
                  ? "bg-sky-700 text-white"
                  : "bg-zinc-800 text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Access token
            </button>
          )}
        </div>
        {responseExpires && (
          <span className="ml-auto text-[11px] text-zinc-500">
            response expires in{" "}
            <span
              className={
                (bundle.expires_at ?? 0) - nowSec <= 300
                  ? (bundle.expires_at ?? 0) - nowSec > 0
                    ? "text-amber-400"
                    : "text-rose-400"
                  : "text-emerald-400"
              }
            >
              {responseExpires}
            </span>
          </span>
        )}
      </div>

      {!token && (
        <p className="mt-3 text-sm text-zinc-500">No {active} token in the response.</p>
      )}

      {token && !jwt && (
        <div className="mt-3 space-y-2">
          <div className="rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-[12px] text-zinc-400">
            Not a JWT ({token.length} chars, opaque) — header/payload can't be decoded locally.
            Query your provider's userinfo/introspection endpoint to inspect it.
          </div>
          <pre className="scroll-thin max-h-24 overflow-auto rounded-md border border-zinc-800 bg-zinc-950 p-2.5 text-[12px] break-all text-zinc-500">
            {token.slice(0, 300)}
            {token.length > 300 ? "…" : ""}
          </pre>
        </div>
      )}

      {token && jwt && (
        <div className="mt-3 grid gap-3 lg:grid-cols-2">
          {/* ---------- Header ---------- */}
          <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3">
            <div className="mb-2 flex items-center gap-2">
              <span className="text-[11px] font-semibold tracking-wider text-zinc-500 uppercase">
                Header
              </span>
              <span className={`text-[12px] ${algFlag(jwt.alg).cls}`}>
                {algFlag(jwt.alg).icon} alg: {jwt.alg || "none"} — {algFlag(jwt.alg).note}
              </span>
            </div>
            <table className="w-full text-left text-[12px]">
              <tbody>
                {Object.entries(jwt.header).map(([k, v]) => (
                  <tr key={k} className="border-b border-zinc-800/60 last:border-0">
                    <td className="w-24 py-1 pr-2 font-mono text-zinc-500">{k}</td>
                    <td className="break-all py-1 font-mono text-zinc-300">
                      {formatClaimValue(k, v).text}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* ---------- Payload ---------- */}
          <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3">
            <div className="mb-2 text-[11px] font-semibold tracking-wider text-zinc-500 uppercase">
              Payload
            </div>
            <div className="scroll-thin max-h-72 overflow-auto">
              <table className="w-full text-left text-[12px]">
                <tbody>
                  {visibleClaims.map(([k, v]) => {
                    const { text, muted } = formatClaimValue(k, v);
                    let suffix = "";
                    let cls = "text-zinc-300";
                    if (k === "exp" && typeof v === "number") {
                      const left = v - nowSec;
                      suffix = `  ${fmtRemaining(left)}`;
                      cls = left <= 0 ? "text-rose-400" : left <= 300 ? "text-amber-400" : "text-emerald-400";
                    }
                    if (k === "nonce" && flowNonce) {
                      if (v === flowNonce) {
                        suffix = "  ✅ matches";
                        cls = "text-emerald-400";
                      } else {
                        suffix = "  ❌ mismatch";
                        cls = "text-rose-400";
                      }
                    }
                    if (k === "nonce" && !flowNonce && v != null) {
                      suffix = "  ⚠️ no flow nonce to compare";
                      cls = "text-amber-400";
                    }
                    return (
                      <tr key={k} className="border-b border-zinc-800/60 last:border-0">
                        <td className="w-28 py-1 pr-2 align-top font-mono text-zinc-500">{k}</td>
                        <td className={`break-all py-1 font-mono ${muted ? "text-zinc-500" : cls}`}>
                          {text}
                          {suffix && <span className="ml-1">{suffix}</span>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* ---------- Signature ---------- */}
          <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 lg:col-span-2">
            <div className="text-[11px] font-semibold tracking-wider text-zinc-500 uppercase">
              Signature
            </div>
            <div className="mt-1 text-[12px] text-zinc-400">
              Verification: ⏳ not verified — decode only. JWKS endpoint fetcher + offline key
              verification is on the roadmap.
            </div>
            {jwt.warnings.length > 0 && (
              <ul className="mt-2 space-y-1 text-[12px] text-amber-400">
                {jwt.warnings.map((w, i) => (
                  <li key={i}>⚠️ {w}</li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
