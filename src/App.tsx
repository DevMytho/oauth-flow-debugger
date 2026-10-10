import { useEffect, useRef, useState } from "react";
import FlowConfigForm from "./components/FlowConfig";
import Findings from "./components/Findings";
import FlowTimeline from "./components/FlowTimeline";
import TokenInspector from "./components/TokenInspector";
import type {
  DeviceAuthStart,
  FindingsReport,
  FlowConfig as FlowConfigType,
  FlowStep,
  TokenBundle,
} from "./types";
import {
  clientCredentialsFlow,
  closeAuthWindow,
  exchangeCode,
  onFindingsUpdated,
  onFlowStep,
  pollDeviceToken,
  resetFlow,
  startDeviceFlow,
  startFlow,
} from "./lib/invoke";

const DEFAULT_CONFIG: FlowConfigType = {
  flow_type: "authorization_code",
  authorization_endpoint: "http://127.0.0.1:9099/authorize",
  token_endpoint: "http://127.0.0.1:9099/token",
  client_id: "screenshot-client",
  client_secret: "",
  redirect_uri: "http://localhost:9004/callback",
  scope: "openid profile email",
  pkce: true,
  include_nonce: true,
  client_auth: "none",
  listener_port: 9004,
  expected_iss: "http://127.0.0.1:9099",
  expected_alg: "RS256",
  jwks_uri: "",
  device_authorization_endpoint: "",
};

export default function App() {
  const [config, setConfig] = useState<FlowConfigType>(DEFAULT_CONFIG);
  const [steps, setSteps] = useState<FlowStep[]>([]);
  const [tokens, setTokens] = useState<TokenBundle | null>(null);
  const [report, setReport] = useState<FindingsReport | null>(null);
  const [flowNonce, setFlowNonce] = useState<string | null>(null);
  const [listenerPort, setListenerPort] = useState<number>(9004);
  const [device, setDevice] = useState<DeviceAuthStart | null>(null);
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

  // Subscribe to backend flow + findings events once.
  useEffect(() => {
    let unlistenSteps: (() => void) | null = null;
    let unlistenFindings: (() => void) | null = null;
    let cancelled = false;
    Promise.all([
      onFlowStep(handleStep),
      onFindingsUpdated((next) => setReport(next)),
    ])
      .then(([stopSteps, stopFindings]) => {
        if (cancelled) {
          stopSteps();
          stopFindings();
        } else {
          unlistenSteps = stopSteps;
          unlistenFindings = stopFindings;
        }
      })
      .catch((e) => setBanner(`Event subscription failed: ${String(e)}`));
    return () => {
      cancelled = true;
      unlistenSteps?.();
      unlistenFindings?.();
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
      } else if (config.flow_type === "device_authorization") {
        // RFC 8628: show the user_code, then poll in the background — the
        // promise resolves only when the user approves (or the code dies).
        const start = await startDeviceFlow(config);
        setDevice(start);
        setRunning(true);
        void pollDeviceToken()
          .then((bundle) => {
            setTokens(bundle);
            setDevice(null);
            setRunning(false);
          })
          .catch((e) => {
            const msg = String(e);
            // A reset mid-poll cancels the flow — that's not an error.
            if (!msg.includes("reset")) {
              addLocalErrorStep(msg);
              setBanner(`Device flow failed: ${msg}`);
            }
            setRunning(false);
          });
      } else {
        await resetFlow().catch(() => undefined);
        const start = await startFlow(config);
        setFlowNonce(start.nonce);
        setListenerPort(start.listener_port);
        setRunning(true);
      }
    } catch (e) {
      addLocalErrorStep(String(e));
      setBanner(String(e));
    } finally {
      setBusy(false);
    }
  };

  // TEMP (screenshot session): start the flow on mount so it can be captured
  // without manual input. Reverted after capture.
  useEffect(() => {
    const t = setTimeout(() => {
      void handleStart();
    }, 1500);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleReset = async () => {
    exchangeStartedRef.current = false;
    setSteps([]);
    setTokens(null);
    setReport(null);
    setFlowNonce(null);
    setDevice(null);
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
          listener 127.0.0.1:{listenerPort}
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
          {device && (
            <div className="rounded-xl border border-emerald-800/60 bg-emerald-950/30 p-4">
              <h2 className="text-xs font-semibold tracking-widest text-emerald-400 uppercase">
                Device Authorization — enter this code
              </h2>
              <div className="mt-3 flex flex-wrap items-center gap-4">
                <span className="rounded-lg border border-emerald-700 bg-black/40 px-5 py-3 font-mono text-3xl tracking-[0.25em] text-emerald-300">
                  {device.user_code}
                </span>
                <div className="min-w-0 text-[13px] text-zinc-300">
                  <p>
                    1. Open{" "}
                    <span className="font-mono break-all text-emerald-300">
                      {device.verification_uri_complete ?? device.verification_uri}
                    </span>{" "}
                    in a browser
                  </p>
                  <p className="text-zinc-400">
                    2. Enter the code and approve. Polling every {device.interval}s · code
                    expires in {device.expires_in}s.
                  </p>
                </div>
                <span className="ml-auto flex items-center gap-2 text-[12px] text-emerald-400">
                  <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
                  waiting for authorization…
                </span>
              </div>
            </div>
          )}
          <Findings report={report} />
          <FlowTimeline steps={steps} flowNonce={flowNonce} />
          <TokenInspector bundle={tokens} flowNonce={flowNonce} />
        </section>
      </main>
    </div>
  );
}
