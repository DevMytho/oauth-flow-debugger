import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  DeviceAuthStart,
  ExportFormat,
  FindingsReport,
  FlowConfig,
  FlowStart,
  FlowStep,
  TokenBundle,
} from "../types";

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

/** Device Authorization Grant (RFC 8628) — request a device/user code.
 *  Returns only the user-facing parts; the device code stays in Rust. */
export function startDeviceFlow(
  config: FlowConfig
): Promise<DeviceAuthStart> {
  return invoke<DeviceAuthStart>("start_device_flow", { config });
}

/** Poll the token endpoint for the device grant until the user authorizes
 *  (resolves with tokens, rejects on denial/expiry/reset). */
export function pollDeviceToken(): Promise<TokenBundle> {
  return invoke<TokenBundle>("poll_device_token");
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

/** Current security findings + severity summary (computed in Rust). */
export function getFindings(): Promise<FindingsReport> {
  return invoke<FindingsReport>("get_findings");
}

/** Export the flow transcript as Markdown or JSON — tokens are redacted
 *  in the Rust backend before the string is ever built. */
export function exportFlow(format: ExportFormat): Promise<string> {
  return invoke<string>("export_flow", { format });
}

/** Subscribe to findings updates emitted by the Rust backend. */
export function onFindingsUpdated(
  handler: (report: FindingsReport) => void
): Promise<UnlistenFn> {
  return listen<FindingsReport>("findings-updated", (event) =>
    handler(event.payload)
  );
}
