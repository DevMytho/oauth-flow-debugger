// Shared types mirroring the Rust backend (src-tauri/src/main.rs et al.)

export type FlowType = "authorization_code" | "implicit" | "client_credentials";

export type ClientAuth = "none" | "client_secret_basic" | "client_secret_post";

export interface FlowConfig {
  flow_type: FlowType;
  authorization_endpoint: string;
  token_endpoint: string;
  client_id: string;
  client_secret: string;
  redirect_uri: string;
  scope: string;
  pkce: boolean;
  include_nonce: boolean;
  client_auth: ClientAuth;
}

export interface FlowStart {
  auth_url: string;
  state: string;
  nonce: string | null;
  code_verifier: string | null;
  code_challenge: string | null;
  listener_port: number;
}

export type StepKind =
  | "auth_url"
  | "callback"
  | "token_request"
  | "token_response"
  | "tokens"
  | "error";

export type StepStatus = "info" | "ok" | "warn" | "error";

export interface FlowStep {
  id: string;
  kind: StepKind;
  title: string;
  status: StepStatus;
  detail: Record<string, unknown>;
  ts: number; // epoch milliseconds
}

export interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  alg: string;
  exp: number | null; // epoch seconds
  iat: number | null; // epoch seconds
  warnings: string[];
}

export interface TokenBundle {
  raw: Record<string, unknown>;
  access_token?: string;
  id_token?: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
  decoded_access?: DecodedJwt;
  decoded_id?: DecodedJwt;
  expires_at?: number | null; // epoch seconds, derived from expires_in
}
