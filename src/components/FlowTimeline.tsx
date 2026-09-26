import { useEffect, useRef } from "react";
import type { FlowStep, TokenBundle } from "../types";
import SecurityNotes from "./SecurityNotes";

interface Props {
  steps: FlowStep[];
  flowNonce: string | null;
}

const STATUS_ICON = { info: "ℹ️", ok: "✅", warn: "⚠️", error: "❌" } as const;
const STATUS_RING = {
  info: "border-l-sky-500",
  ok: "border-l-emerald-500",
  warn: "border-l-amber-500",
  error: "border-l-rose-500",
} as const;

function fmtTime(ts: number): string {
  const d = new Date(ts);
  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

function JsonView({ value, maxLines = 40 }: { value: unknown; maxLines?: number }) {
  const text = JSON.stringify(value, null, 2) ?? "";
  const lines = text.split("\n");
  const shown = lines.length > maxLines ? lines.slice(0, maxLines).join("\n") + "\n  …" : text;
  return (
    <pre className="scroll-thin mt-2 max-h-64 overflow-auto rounded-md border border-zinc-800 bg-zinc-950 p-2.5 text-[12px] leading-relaxed text-zinc-400">
      {shown}
    </pre>
  );
}

function Entries({ data }: { data: Record<string, unknown> }) {
  const entries = Object.entries(data);
  if (entries.length === 0) return null;
  return (
    <table className="mt-2 w-full text-left text-[12px]">
      <tbody>
        {entries.map(([k, v]) => (
          <tr key={k} className="border-b border-zinc-800/60 last:border-0">
            <td className="w-44 py-1 pr-2 align-top font-mono text-zinc-500">{k}</td>
            <td className="break-all py-1 font-mono text-zinc-300">
              {typeof v === "string" ? v : String(v)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function StateBanner({ valid }: { valid: boolean | null }) {
  if (valid === true)
    return (
      <div className="mt-2 rounded-md border border-emerald-800/60 bg-emerald-950/40 px-2.5 py-1.5 text-[12px] text-emerald-400">
        ✅ state matches — callback accepted
      </div>
    );
  if (valid === false)
    return (
      <div className="mt-2 rounded-md border border-rose-800/60 bg-rose-950/40 px-2.5 py-1.5 text-[12px] text-rose-400">
        ❌ state mismatch or missing — callback rejected (possible CSRF / replay)
      </div>
    );
  return null;
}

function Detail({ step }: { step: FlowStep }) {
  const d = step.detail as Record<string, unknown>;

  switch (step.kind) {
    case "auth_url": {
      const notable = Object.fromEntries(
        [
          "response_type",
          "redirect_uri",
          "scope",
          "state",
          "nonce",
          "code_challenge_method",
          "code_challenge",
          "code_verifier",
        ]
          .filter((k) => d[k] != null && d[k] !== "")
          .map((k) => [k, d[k]])
      );
      return (
        <>
          <div className="scroll-thin mt-2 max-h-32 overflow-auto rounded-md border border-zinc-800 bg-zinc-950 p-2.5 text-[12px] break-all text-sky-300">
            {String(d.url ?? "")}
          </div>
          <Entries data={notable} />
        </>
      );
    }
    case "callback":
      return (
        <>
          <StateBanner valid={(d.state_valid as boolean | null) ?? null} />
          {d.has_error && (
            <div className="mt-2 rounded-md border border-rose-800/60 bg-rose-950/40 px-2.5 py-1.5 text-[12px] text-rose-400">
              {String(d.provider_error ?? "error")}
              {d.provider_error_description ? ` — ${String(d.provider_error_description)}` : ""}
            </div>
          )}
          <Entries data={(d.params as Record<string, unknown>) ?? {}} />
          <details className="mt-2">
            <summary className="cursor-pointer text-[11px] tracking-wider text-zinc-500 uppercase select-none">
              Raw callback URL
            </summary>
            <div className="scroll-thin mt-1 max-h-32 overflow-auto rounded-md border border-zinc-800 bg-zinc-950 p-2.5 text-[12px] break-all text-zinc-400">
              {String(d.raw_url ?? "")}
            </div>
          </details>
        </>
      );
    case "token_request":
      return (
        <>
          <div className="mt-2 text-[12px] text-zinc-400">
            <span className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-[11px] text-zinc-300">
              {String(d.method)}
            </span>{" "}
            <span className="font-mono break-all">{String(d.url)}</span>
          </div>
          <Entries data={(d.body as Record<string, unknown>) ?? {}} />
          <div className="mt-1.5 text-[11px] text-zinc-500">
            client auth: {String(d.client_auth)}
          </div>
        </>
      );
    case "token_response":
      return (
        <>
          <div className="mt-2 text-[12px]">
            <span
              className={`rounded px-1.5 py-0.5 font-mono ${
                d.ok === true
                  ? "bg-emerald-950 text-emerald-400"
                  : "bg-rose-950 text-rose-400"
              }`}
            >
              HTTP {String(d.status)}
            </span>
          </div>
          <JsonView value={d.body} />
        </>
      );
    case "tokens": {
      const bundle = (d.bundle ?? {}) as TokenBundle;
      const warnings = (d.warnings as string[] | undefined) ?? [];
      const jwtCount = (bundle.decoded_access ? 1 : 0) + (bundle.decoded_id ? 1 : 0);
      const fields: Record<string, unknown> = {};
      if (bundle.token_type) fields.token_type = bundle.token_type;
      if (bundle.expires_in != null) fields.expires_in = `${bundle.expires_in}s`;
      if (bundle.scope) fields.scope = bundle.scope;
      fields.jwts_decoded = jwtCount;
      fields.access_token = bundle.access_token
        ? `${bundle.access_token.length} chars${bundle.access_token.split(".").length === 3 ? " (JWT)" : " (opaque)"}`
        : "—";
      fields.id_token = bundle.id_token ? `${bundle.id_token.length} chars (JWT)` : "—";
      if (bundle.refresh_token) fields.refresh_token = "present";
      return (
        <>
          <Entries data={fields} />
          {warnings.length > 0 && (
            <ul className="mt-2 space-y-1 text-[12px] text-amber-400">
              {warnings.map((w, i) => (
                <li key={i}>⚠️ {w}</li>
              ))}
            </ul>
          )}
          <div className="mt-1.5 text-[11px] text-zinc-500">
            Full claims → Token Inspector below
          </div>
        </>
      );
    }
    case "error":
      return (
        <div className="mt-2 rounded-md border border-rose-800/60 bg-rose-950/40 px-2.5 py-1.5 text-[12px] text-rose-400">
          {String(d.message ?? "Unknown error")}
        </div>
      );
    default:
      return <JsonView value={d} />;
  }
}

export default function FlowTimeline({ steps, flowNonce }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [steps.length]);

  if (steps.length === 0) {
    return (
      <div className="flex h-full min-h-64 items-center justify-center rounded-xl border border-dashed border-zinc-800 p-8 text-center">
        <div>
          <div className="text-3xl">🛰️</div>
          <p className="mt-2 text-sm text-zinc-500">
            No steps yet — configure a flow on the left and press{" "}
            <span className="text-zinc-300">Start Flow</span>.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {steps.map((step, i) => (
        <div
          key={step.id}
          className={`rounded-xl border border-zinc-800 border-l-2 bg-zinc-900/50 p-3.5 ${STATUS_RING[step.status]}`}
        >
          <div className="flex items-center gap-3">
            <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-zinc-700 bg-zinc-950 text-[11px] font-semibold text-zinc-400">
              {i + 1}
            </span>
            <span className="text-sm" aria-hidden>
              {STATUS_ICON[step.status]}
            </span>
            <span className="flex-1 text-[13px] font-semibold text-zinc-100">{step.title}</span>
            <span className="font-mono text-[11px] text-zinc-600">{fmtTime(step.ts)}</span>
          </div>
          <div className="mt-1 pl-9 text-[11px] tracking-wider text-zinc-600 uppercase">
            {step.kind.replace(/_/g, " ")}
          </div>
          <div className="mt-1 pl-9">
            <Detail step={step} />
            <SecurityNotes step={step} flowNonce={flowNonce} />
          </div>
        </div>
      ))}
      <div ref={bottomRef} />
    </div>
  );
}
