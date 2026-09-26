import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { FlowConfig, FlowStart, FlowStep, TokenBundle } from "../types";

/** Start a browser-based flow (authorization code or implicit).
 *  Opens the provider's authorization page in a controlled webview and
 *  arms the local redirect listener on 127.0.0.1:9004. */
export function startFlow(config: FlowConfig): Promise<FlowStart> {
  return invoke<FlowStart>("start_flow", { config });
}

/** Exchange the captured authorization code for tokens (Rust-side POST). */
export function exchangeCode(): Promise<TokenBundle> {
  return invoke<TokenBundle>("exchange_code");
}

/** Client Credentials grant — no browser involved, direct token POST. */
export function clientCredentialsFlow(
  config: FlowConfig
): Promise<TokenBundle> {
  return invoke<TokenBundle>("client_credentials_flow", { config });
}

/** Close the controlled auth webview (if still open). */
export function closeAuthWindow(): Promise<void> {
  return invoke<void>("close_auth_window");
}

/** Clear the pending flow state in the backend. */
export function resetFlow(): Promise<void> {
  return invoke<void>("reset_flow");
}

/** Subscribe to flow step events emitted by the Rust backend. */
export function onFlowStep(
  handler: (step: FlowStep) => void
): Promise<UnlistenFn> {
  return listen<FlowStep>("flow-step", (event) => handler(event.payload));
}
