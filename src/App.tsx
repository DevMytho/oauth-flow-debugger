import { useEffect, useRef, useState } from "react";
import FlowConfigForm from "./components/FlowConfig";
import FlowTimeline from "./components/FlowTimeline";
import TokenInspector from "./components/TokenInspector";
import type { FlowConfig as FlowConfigType, FlowStep, TokenBundle } from "./types";
import {
  clientCredentialsFlow,
  closeAuthWindow,
  exchangeCode,
  onFlowStep,
  resetFlow,
  startFlow,
} from "./lib/invoke";

const DEFAULT_CONFIG: FlowConfigType = {
  flow_type: "authorization_code",
  authorization_endpoint: "",
  token_endpoint: "",
  client_id: "",
  client_secret: "",
  redirect_uri: "http://localhost:9004/callback",
  scope: "openid profile email",
  pkce: true,
  include_nonce: true,
  client_auth: "none",
};

export default function App() {
  const [config, setConfig] = useState<FlowConfigType>(DEFAULT_CONFIG);
  const [steps, setSteps] = useState<FlowStep[]>([]);
  const [tokens, setTokens] = useState<TokenBundle | null>(null);
  const [flowNonce, setFlowNonce] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [running, setRunning] = useState(false);
  const [banner, setBanner] = useState<string | null>(null);

  const exchangeStartedRef = useRef(false);

  const addLocalErrorStep = (message: string) => {
    setSteps((prev) => [
      ...prev,
      {
        id: `local-${Date.now()}-${prev.length}`,
        kind: "error",
        title: "Flow failed",
        status: "error",
        detail: { message },
        ts: Date.now(),
      },
    ]);
  };

  // Auto-exchange the code as soon as the callback step confirms it.
  const doExchange = async () => {
    try {
      const bundle = await exchangeCode();
      setTokens(bundle);
    } catch (e) {
      setBanner(`Token exchange failed: ${e}`);
    } finally {
      setRunning(false);
    }
  };

  const exchangeRef = useRef(doExchange);
  exchangeRef.current = doExchange;

  const handleStep = (step: FlowStep) => {
    setSteps((prev) => [...prev, step]);
    if (step.kind === "tokens") {
      const bundle = (step.detail as { bundle?: TokenBundle }).bundle;
      if (bundle) setTokens(bundle);
    }
    if (step.kind === "callback") {
      const d = step.detail as { has_code?: boolean; state_valid?: boolean | null };
      if (d.has_code && d.state_valid === true && !exchangeStartedRef.current) {
        exchangeStartedRef.current = true;
        void exchangeRef.current();
      }
      if (d.has_code && d.state_valid === false) {
        setRunning(false);
      }
    }
    if (step.kind === "error") {
      setRunning(false);
    }
  };

  // Subscribe to backend flow events once.
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    let cancelled = false;
    onFlowStep(handleStep)
      .then((fn) => {
        if (cancelled) fn();
        else unlisten = fn;
      })
      .catch((e) => setBanner(`Event subscription failed: ${String(e)}`));
    return () => {
      cancelled = true;
      unlisten?.();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleStart = async () => {
    setBusy(true);
    setBanner(null);
    exchangeStartedRef.current = false;
    try {
      if (config.flow_type === "client_credentials") {
        const bundle = await clientCredentialsFlow(config);
        setTokens(bundle);
      } else {
        await resetFlow().catch(() => undefined);
        const start = await startFlow(config);
        setFlowNonce(start.nonce);
        setRunning(true);
      }
    } catch (e) {
      addLocalErrorStep(String(e));
      setBanner(String(e));
    } finally {
      setBusy(false);
    }
  };

  const handleReset = async () => {
    exchangeStartedRef.current = false;
    setSteps([]);
    setTokens(null);
    setFlowNonce(null);
    setRunning(false);
    setBanner(null);
    await resetFlow().catch(() => undefined);
    await closeAuthWindow().catch(() => undefined);
  };

  const status = running
    ? { text: "flow running", cls: "text-emerald-400", dot: "bg-emerald-500 animate-pulse" }
    : steps.length > 0
      ? { text: "last flow complete", cls: "text-zinc-400", dot: "bg-zinc-500" }
      : { text: "idle", cls: "text-zinc-500", dot: "bg-zinc-600" };

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center gap-4 border-b border-zinc-800 bg-zinc-950/80 px-5 py-3 backdrop-blur">
        <div className="flex items-center gap-2.5">
          <span className="text-xl" aria-hidden>
            🛡️
          </span>
          <div>
            <h1 className="text-[15px] leading-tight font-semibold text-zinc-100">
              OAuth Flow Debugger
            </h1>
            <p className="text-[11px] leading-tight text-zinc-500">
              OAuth 2.0 / OIDC · step-by-step · everything stays local
            </p>
          </div>
        </div>
        <div className={`ml-auto flex items-center gap-2 text-[12px] ${status.cls}`}>
          <span className={`h-2 w-2 rounded-full ${status.dot}`} />
          {status.text}
        </div>
        <div className="rounded-md border border-zinc-800 bg-zinc-900 px-2 py-1 font-mono text-[11px] text-zinc-500">
          listener 127.0.0.1:9004
        </div>
      </header>

      {banner && (
        <div className="flex items-start gap-3 border-b border-rose-900/60 bg-rose-950/50 px-5 py-2 text-[12px] text-rose-300">
          <span aria-hidden>❌</span>
          <span className="flex-1 break-all">{banner}</span>
          <button
            type="button"
            onClick={() => setBanner(null)}
            className="text-rose-500 hover:text-rose-300"
            aria-label="Dismiss"
          >
            ✕
          </button>
        </div>
      )}

      <main className="grid min-h-0 flex-1 grid-cols-[340px_minmax(0,1fr)]">
        <aside className="border-r border-zinc-800 p-4">
          <FlowConfigForm
            config={config}
            onChange={setConfig}
            onStart={handleStart}
            onReset={handleReset}
            busy={busy}
            running={running}
          />
        </aside>
        <section className="scroll-thin space-y-4 overflow-y-auto p-5">
          <FlowTimeline steps={steps} flowNonce={flowNonce} />
          <TokenInspector bundle={tokens} flowNonce={flowNonce} />
        </section>
      </main>
    </div>
  );
}
