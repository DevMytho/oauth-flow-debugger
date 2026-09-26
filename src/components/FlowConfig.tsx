import type { FlowConfig, FlowType } from "../types";

interface Props {
  config: FlowConfig;
  onChange: (config: FlowConfig) => void;
  onStart: () => void;
  onReset: () => void;
  busy: boolean;
  running: boolean;
}

const FLOW_OPTIONS: { value: FlowType; label: string }[] = [
  { value: "authorization_code", label: "Authorization Code" },
  { value: "implicit", label: "Implicit (legacy)" },
  { value: "client_credentials", label: "Client Credentials" },
];

function Label({ children }: { children: React.ReactNode }) {
  return <label className="mb-1 block text-[11px] font-medium tracking-wider text-zinc-500 uppercase">{children}</label>;
}

function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  const { className = "", ...rest } = props;
  return (
    <input
      {...rest}
      className={`w-full rounded-md border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 font-mono text-[13px] text-zinc-200 placeholder:text-zinc-600 focus:border-emerald-600 focus:outline-none disabled:opacity-40 ${className}`}
    />
  );
}

function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  const { className = "", ...rest } = props;
  return (
    <select
      {...rest}
      className={`w-full rounded-md border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 text-[13px] text-zinc-200 focus:border-emerald-600 focus:outline-none ${className}`}
    />
  );
}

function Toggle({
  checked,
  onChange,
  disabled,
  label,
  hint,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  label: string;
  hint?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className="flex w-full items-start gap-2.5 rounded-md border border-zinc-800 bg-zinc-950 px-2.5 py-2 text-left transition disabled:opacity-40"
    >
      <span
        className={`mt-0.5 flex h-4 w-7 shrink-0 items-center rounded-full p-0.5 transition ${
          checked ? "bg-emerald-600" : "bg-zinc-700"
        }`}
      >
        <span
          className={`h-3 w-3 rounded-full bg-white transition ${checked ? "translate-x-3" : ""}`}
        />
      </span>
      <span>
        <span className="block text-[13px] text-zinc-200">{label}</span>
        {hint && <span className="block text-[11px] leading-snug text-zinc-500">{hint}</span>}
      </span>
    </button>
  );
}

export default function FlowConfig({ config, onChange, onStart, onReset, busy, running }: Props) {
  const set = <K extends keyof FlowConfig>(key: K, value: FlowConfig[K]) =>
    onChange({ ...config, [key]: value });

  const isCode = config.flow_type === "authorization_code";
  const isImplicit = config.flow_type === "implicit";
  const isCc = config.flow_type === "client_credentials";

  const canStart = isCc
    ? config.token_endpoint.trim() !== "" && config.client_id.trim() !== ""
    : config.authorization_endpoint.trim() !== "" && config.client_id.trim() !== "";

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto scroll-thin">
      <section className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
        <h2 className="mb-3 text-xs font-semibold tracking-widest text-zinc-400 uppercase">
          1 · Configure the flow
        </h2>

        <div className="space-y-3">
          <div>
            <Label>Flow type</Label>
            <Select
              value={config.flow_type}
              onChange={(e) => set("flow_type", e.target.value as FlowType)}
              disabled={busy}
            >
              {FLOW_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>
          </div>

          {!isCc && (
            <div>
              <Label>Authorization endpoint</Label>
              <Input
                autoFocus
                value={config.authorization_endpoint}
                onChange={(e) => set("authorization_endpoint", e.target.value)}
                placeholder="https://provider.example/authorize"
                disabled={busy}
                spellCheck={false}
              />
            </div>
          )}

          {!isImplicit && (
            <div>
              <Label>Token endpoint</Label>
              <Input
                value={config.token_endpoint}
                onChange={(e) => set("token_endpoint", e.target.value)}
                placeholder="https://provider.example/oauth/token"
                disabled={busy}
                spellCheck={false}
              />
            </div>
          )}

          <div>
            <Label>Client ID</Label>
            <Input
              value={config.client_id}
              onChange={(e) => set("client_id", e.target.value)}
              placeholder="your-client-id"
              disabled={busy}
              spellCheck={false}
            />
          </div>

          {!isImplicit && (
            <div>
              <Label>Client secret {isCode && "(optional for public clients)"}</Label>
              <Input
                type="password"
                value={config.client_secret}
                onChange={(e) => set("client_secret", e.target.value)}
                placeholder="••••••••"
                disabled={busy}
                autoComplete="off"
              />
            </div>
          )}

          {!isCc && (
            <div>
              <Label>Redirect URI</Label>
              <Input
                value={config.redirect_uri}
                onChange={(e) => set("redirect_uri", e.target.value)}
                placeholder="http://localhost:9004/callback"
                disabled={busy}
                spellCheck={false}
              />
              <p className="mt-1 text-[11px] leading-snug text-zinc-500">
                Register this exact URI with your provider. The built-in listener captures it on
                port 9004.
              </p>
            </div>
          )}

          <div>
            <Label>Scope {isCc && "(optional)"}</Label>
            <Input
              value={config.scope}
              onChange={(e) => set("scope", e.target.value)}
              placeholder="openid profile email"
              disabled={busy}
              spellCheck={false}
            />
          </div>
        </div>
      </section>

      <section className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
        <h2 className="mb-3 text-xs font-semibold tracking-widest text-zinc-400 uppercase">
          2 · Hardening
        </h2>
        <div className="space-y-2.5">
          <Toggle
            checked={config.pkce}
            onChange={(v) => set("pkce", v)}
            disabled={!isCode || busy}
            label="PKCE (S256)"
            hint={isCode ? "code_verifier stays local; challenge goes in the URL" : "Applies to the Authorization Code flow only"}
          />
          <Toggle
            checked={config.include_nonce}
            onChange={(v) => set("include_nonce", v)}
            disabled={isCc || busy}
            label="OIDC nonce"
            hint={
              isImplicit
                ? "Adds nonce and requests an id_token (response_type=id_token token)"
                : "Checked against the ID token's nonce claim"
            }
          />
          {!isImplicit && (
            <div>
              <Label>Client authentication</Label>
              <Select
                value={config.client_auth}
                onChange={(e) => set("client_auth", e.target.value as FlowConfig["client_auth"])}
                disabled={busy}
              >
                <option value="none">none (public client — client_id in body)</option>
                <option value="client_secret_basic">client_secret_basic (HTTP Basic)</option>
                <option value="client_secret_post">client_secret_post (body)</option>
              </Select>
            </div>
          )}
        </div>
      </section>

      <section className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
        <h2 className="mb-3 text-xs font-semibold tracking-widest text-zinc-400 uppercase">
          3 · Launch
        </h2>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={onStart}
            disabled={!canStart || busy}
            className="flex-1 rounded-md bg-emerald-600 px-3 py-2 text-sm font-semibold text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:bg-zinc-700 disabled:text-zinc-500"
          >
            {busy ? "Working…" : isCc ? "Get Token" : running ? "Flow running…" : "Start Flow"}
          </button>
          <button
            type="button"
            onClick={onReset}
            disabled={busy}
            className="rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-300 transition hover:border-zinc-500 hover:text-white disabled:opacity-40"
          >
            Reset
          </button>
        </div>
        <p className="mt-2 text-[11px] leading-snug text-zinc-500">
          {isCc
            ? "No browser needed — the client credentials grant posts straight to the token endpoint."
            : "A controlled webview opens at the provider; the redirect is intercepted locally before it reaches the network stack."}
        </p>
      </section>
    </div>
  );
}
