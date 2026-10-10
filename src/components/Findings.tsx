import { useState } from "react";
import type { ExportFormat, FindingsReport, Severity } from "../types";
import { exportFlow } from "../lib/invoke";

/**
 * Findings panel: severity-rated results of the automated checks that run in
 * the Rust backend (state, nonce, PKCE, alg, iss/aud/exp, HTTPS, scope), plus
 * Markdown/JSON export with tokens redacted.
 */

const SEVERITIES: { key: Severity; label: string; cls: string }[] = [
  { key: "critical", label: "critical", cls: "bg-rose-950 text-rose-300 border-rose-800" },
  { key: "high", label: "high", cls: "bg-orange-950 text-orange-300 border-orange-800" },
  { key: "medium", label: "medium", cls: "bg-amber-950 text-amber-300 border-amber-800" },
  { key: "low", label: "low", cls: "bg-yellow-950 text-yellow-300 border-yellow-800" },
  { key: "info", label: "info", cls: "bg-zinc-800 text-zinc-300 border-zinc-700" },
];

const SEVERITY_ICON: Record<Severity, string> = {
  critical: "🛑",
  high: "❌",
  medium: "⚠️",
  low: "🟡",
  info: "ℹ️",
};

interface Props {
  report: FindingsReport | null;
}

export default function Findings({ report }: Props) {
  const [preview, setPreview] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const doExport = async (format: ExportFormat) => {
    setMessage(null);
    try {
      const text = await exportFlow(format);
      setPreview(text);
      const ext = format === "json" ? "json" : "md";
      const type = format === "json" ? "application/json" : "text/markdown";
      const url = URL.createObjectURL(new Blob([text], { type }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `oauth-flow-report.${ext}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setMessage(`Exported oauth-flow-report.${ext} — tokens, codes and secrets redacted.`);
    } catch (e) {
      setMessage(`Export failed: ${String(e)}`);
    }
  };

  const copy = async () => {
    if (!preview) return;
    try {
      await navigator.clipboard.writeText(preview);
      setMessage("Copied to clipboard.");
    } catch {
      setMessage("Clipboard unavailable — select the text below and copy manually.");
    }
  };

  const findings = report?.findings ?? [];
  const summary = report?.summary;
  const clean = !summary || summary.total === 0;

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-xs font-semibold tracking-widest text-zinc-400 uppercase">
          Security findings
        </h2>

        <div className="flex flex-wrap gap-1.5">
          {SEVERITIES.map((s) => {
            const count = summary ? summary[s.key] : 0;
            return (
              <span
                key={s.key}
                className={`rounded border px-1.5 py-0.5 font-mono text-[11px] ${
                  count > 0 ? s.cls : "border-zinc-800 bg-zinc-950 text-zinc-600"
                }`}
                title={`${count} ${s.label} finding(s)`}
              >
                {count} {s.label}
              </span>
            );
          })}
        </div>

        <div className="ml-auto flex gap-2">
          <button
            type="button"
            onClick={() => void doExport("markdown")}
            className="rounded-md border border-zinc-700 px-2.5 py-1 text-[12px] text-zinc-300 transition hover:border-emerald-600 hover:text-emerald-300"
            title="Markdown report with tokens redacted"
          >
            Export .md
          </button>
          <button
            type="button"
            onClick={() => void doExport("json")}
            className="rounded-md border border-zinc-700 px-2.5 py-1 text-[12px] text-zinc-300 transition hover:border-emerald-600 hover:text-emerald-300"
            title="JSON report with tokens redacted"
          >
            Export .json
          </button>
        </div>
      </div>

      {message && <p className="mt-2 text-[12px] text-emerald-400">{message}</p>}

      <div className="mt-3">
        {clean ? (
          <p className="text-[13px] text-zinc-500">
            No findings yet — checks run in the backend as the flow progresses
            (state, nonce, PKCE, algorithm, iss/aud/exp, HTTPS, granted scopes).
          </p>
        ) : (
          <ul className="space-y-2">
            {findings.map((f, i) => (
              <li
                key={`${f.id}-${i}`}
                className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-2.5"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span aria-hidden>{SEVERITY_ICON[f.severity]}</span>
                  <span
                    className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase ${
                      SEVERITIES.find((s) => s.key === f.severity)?.cls
                    }`}
                  >
                    {f.severity}
                  </span>
                  <span className="font-mono text-[11px] text-zinc-500">{f.id}</span>
                  <span className="text-[13px] font-medium text-zinc-200">{f.title}</span>
                </div>
                <p className="mt-1 text-[12px] leading-snug text-zinc-400">{f.detail}</p>
              </li>
            ))}
          </ul>
        )}
      </div>

      {preview && (
        <details className="mt-3" open>
          <summary className="cursor-pointer text-[11px] tracking-wider text-zinc-500 uppercase select-none">
            Export preview (redacted)
          </summary>
          <div className="mt-2 flex gap-2">
            <button
              type="button"
              onClick={() => void copy()}
              className="rounded-md border border-zinc-700 px-2 py-1 text-[11px] text-zinc-300 transition hover:border-emerald-600 hover:text-emerald-300"
            >
              Copy
            </button>
          </div>
          <textarea
            readOnly
            value={preview}
            onFocus={(e) => e.currentTarget.select()}
            className="scroll-thin mt-2 h-56 w-full resize-y rounded-md border border-zinc-800 bg-zinc-950 p-2.5 font-mono text-[11px] text-zinc-400 focus:border-emerald-700 focus:outline-none"
          />
        </details>
      )}
    </div>
  );
}
