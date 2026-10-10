// Shared types mirroring the Rust backend (src-tauri/src/main.rs et al.)

export type FlowType =
  | "authorization_code"
  | "implicit"
  | "client_credentials"
  | "device_authorization";

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
  /** Preferred loopback port for the redirect listener (0 = 9004). */
  listener_port: number;
  /** Explicit JWKS endpoint for signature verification (empty = OIDC discovery
   *  from expected_iss, then the token's own iss claim). */
  jwks_uri: string;
  /** Device Authorization Grant (RFC 8628) endpoint. */
  device_authorization_endpoint: string;
  /** Optional expected issuer for `iss` checks. */
  expected_iss: string;
  /** Optional expected JWT alg (e.g. RS256) for the alg checks. */
  expected_alg: string;
}

export interface FlowStart {
  auth_url: string;
  state: string;
  nonce: string | null;
  code_verifier: string | null;
  code_challenge: string | null;
  listener_port: number;
}

/** Device Authorization Grant (RFC 8628): what the user needs to see. The
 *  device_code itself never leaves the Rust backend. */
export interface DeviceAuthStart {
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string | null;
  expires_in: number;
  interval: number;
}

export type StepKind =
  | "info"
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

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
}

export interface FindingsSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface FindingsReport {
  findings: Finding[];
  summary: FindingsSummary;
}

export type ExportFormat = "markdown" | "json";

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
  /** JWKS signature verification results (per token, if they are JWTs). */
  verification: BundleVerification;
}

export type VerificationStatus = "valid" | "invalid" | "unverified";

export interface TokenVerification {
  role: "access_token" | "id_token";
  status: VerificationStatus;
  alg: string;
  kid: string | null;
  jwks_uri: string | null;
  /** Stable reason code: ok | bad_signature | kid_not_found | unsigned |
   *  unsupported_alg | no_jwks_source | jwks_fetch_failed | … */
  reason: string;
  detail: string;
}

export interface BundleVerification {
  access: TokenVerification | null;
  id: TokenVerification | null;
}
