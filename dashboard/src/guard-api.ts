import {
  GUARD_ACTION_TYPES,
  GUARD_DECISION_V2_ACTIONS,
  GUARD_DECISION_V2_CONFIDENCES,
  GUARD_RISK_SIGNAL_V2_CATEGORIES,
  GUARD_RISK_SIGNAL_V2_REDACTION_LEVELS,
  GUARD_RISK_SIGNAL_V2_SEVERITIES,
  CODEX_RESUME_STATUSES
} from "./guard-types";
import { computeTrendBuckets } from "./evidence/evidence-metrics";
import { normalizeProtectionHealth, protectionHeadlineFor } from "./protection-health";
import {
  AUTHORITATIVE_DECISION_INCONSISTENT,
  guardActionDisposition,
  guardDecisionV2Action,
  isActionBearingKey,
  isGuardAction,
  isRecognizedGuardActionInput,
  mostRestrictiveGuardAction,
  normalizeGuardAction,
} from "./guard-action";
import { parseTemporaryMcpApproval } from "./temporary-mcp-approval";
import { isConnectableAppHarness } from "./apps/harness-setup-target";
import type {
  GuardActionEnvelope,
  GuardAction,
  GuardActionType,
  GuardApprovalPage,
  GuardApprovalPageFilters,
  GuardApprovalPageStatus,
  PackageFirewallActionResponse,
  PackageFirewallActionState,
  PackageFirewallActionType,
  PackageFirewallCliFallback,
  PackageFirewallEntitlement,
  PackageFirewallGlobalActionType,
  PackageFirewallReceipt,
  PackageShimEntry,
  PackageFirewallStatusResponse,
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardDecisionV2,
  GuardInventoryItem,
  GuardHarnessAction,
  GuardHarnessActionErrorPayload,
  GuardHarnessActionResult,
  GuardManagedInstall,
  GuardNotificationSetupResult,
  GuardPolicyDecision,
  GuardCloudException,
  PackageManagerProtection,
  CodexResumeStatus,
  GuardCodexResumeResult,
  GuardQueueResolutionCopy,
  GuardQueueResolutionResult,
  GuardQueueSummary,
  GuardReceipt,
  GuardReceiptAnalytics,
  GuardInsightsShareResult,
  GuardReceiptAnalyticsBucket,
  GuardReceiptArtifactStat,
  GuardReceiptDailyActivity,
  GuardReceiptHarnessStat,
  GuardRuntimeState,
  GuardRuntimeSnapshot,
  GuardCloudConnectStatusResponse,
  SupplyChainBundle,
  SupplyChainSnapshot,
  GuardSettingsPayload,
  GuardSettingsExport,
  GuardSettings,
  GuardUpdateScheduleResult,
  GuardDaemonReconnectAuthorization,
  GuardUpdateReconnectOptions,
  GuardUpdateStatus,
  GuardUpdateVersionCheck,
  DecisionScope,
  GuardApprovalResolutionInput,
  RiskSignalV2,
  RiskSignalV2Category,
  RiskSignalV2RedactionLevel,
  RiskSignalV2Severity
} from "./guard-types";
import {
  getDemoDiff,
  getDemoPolicy,
  getDemoReceipts,
  getDemoRequest,
  getDemoRequests,
  isGuardDemoMode
} from "./guard-demo";

const GUARD_TOKEN_PARAM = "guard-token";
const GUARD_DAEMON_PARAM = "guardDaemon";
const GUARD_SURFACE_PROTOCOL_VERSIONS = ["1.1", "1.0"] as const;
const DEFAULT_GUARD_DAEMON_PORT = 4781;
const GUARD_DAEMON_PORT_RANGE = 1000;
const GUARD_DAEMON_DISCOVERY_PROBE_COUNT = 25;
const GUARD_DAEMON_DISCOVERY_PROBE_BATCH_SIZE = 5;
const GUARD_DAEMON_PROBE_TIMEOUT_MS = 800;
const GUARD_DAEMON_RECONNECT_PROTOCOL_VERSION = 1;
const GUARD_DAEMON_RECONNECT_NONCE_BYTES = 32;
const RUNTIME_HEARTBEAT_MAX_AGE_MS = 30_000;
const RUNTIME_HEARTBEAT_FUTURE_TOLERANCE_MS = 5_000;
let guardTokenOverride: string | null = null;
let guardTokenLocationKey: string | null = null;
let guardDaemonReconnectDiagnostic = "dashboard_reconnect_not_started";

type RawGuardApprovalRequest = Omit<
  GuardApprovalRequest,
  | "action_envelope_json"
  | "decision_v2_json"
  | "policy_action"
  | "decision_contract_error"
  | "recommended_scope"
  | "allowed_scopes"
  | "scope_contract_version"
  | "scope_contract_digest"
  | "allowed_scopes_by_action"
  | "recommended_scope_by_action"
  | "scope_restrictions"
  | "task_capability_eligibility"
  | "temporary_mcp_approval"
> & {
  action_envelope_json?: unknown;
  decision_v2_json?: unknown;
  policy_action?: unknown;
  decision_contract_error?: unknown;
  recommended_scope?: unknown;
  allowed_scopes?: unknown;
  scope_contract_version?: unknown;
  scope_contract_digest?: unknown;
  allowed_scopes_by_action?: unknown;
  recommended_scope_by_action?: unknown;
  scope_restrictions?: unknown;
  task_capability_eligibility?: unknown;
  temporary_mcp_approval?: unknown;
};

type RawGuardReceipt = Omit<GuardReceipt, "action_envelope_json" | "policy_decision"> & {
  action_envelope_json?: unknown;
  policy_decision?: unknown;
};

type RawGuardInventoryItem = Omit<GuardInventoryItem, "last_policy_action"> & {
  last_policy_action?: unknown;
};

type ApprovalRequestListPayload = {
  items?: RawGuardApprovalRequest[] | null;
  next_cursor?: unknown;
  total_pending_count?: unknown;
  total_count?: unknown;
  status?: unknown;
};

type RuntimeSnapshotPayload = Omit<
  GuardRuntimeSnapshot,
  | "items"
  | "queue_summary"
  | "supply_chain"
  | "managed_installs"
  | "cloud_command_capability"
  | "protection_health"
  | "runtime_state"
  | "latest_receipts"
  | "inventory"
> & {
  items?: RawGuardApprovalRequest[] | null;
  latest_receipts?: RawGuardReceipt[] | null;
  inventory?: RawGuardInventoryItem[] | null;
  queue_summary?: unknown;
  supply_chain?: unknown;
  managed_installs?: unknown;
  cloud_command_capability?: unknown;
  protection_health?: unknown;
  runtime_state?: unknown;
};

type QueueResolutionPayload = Omit<
  GuardQueueResolutionResult,
  | "item"
  | "resolved_request"
  | "remaining_pending_summaries"
  | "resolved_duplicate_ids"
  | "resolved_scope_ids"
  | "copy"
  | "codex_resume"
> & {
  item?: RawGuardApprovalRequest | null;
  resolved_request?: RawGuardApprovalRequest | null;
  remaining_pending_summaries?: RawGuardApprovalRequest[] | null;
  resolved_duplicate_ids?: unknown;
  resolved_scope_ids?: unknown;
  copy?: unknown;
  codex_resume?: unknown;
};

async function readJson<T>(input: RequestInfo, init?: RequestInit): Promise<T> {
  const response = await fetchWithGuardAuth(input, init);
  if (!response.ok) {
    throw new Error(await requestErrorMessage(response, `Request failed with ${response.status}`));
  }
  return (await response.json()) as T;
}

async function requestErrorMessage(response: Response, fallback: string): Promise<string> {
  try {
    const payload = await response.clone().json();
    if (!isRecord(payload)) {
      return fallback;
    }
    const message = payload["message"];
    if (typeof message === "string" && message.trim()) {
      return message;
    }
    const error = payload["error"];
    if (typeof error === "string" && error.trim()) {
      return `${error} (${response.status})`;
    }
  } catch {
    return fallback;
  }
  return fallback;
}

export class GuardHarnessActionError extends Error {
  readonly status: number;
  readonly payload: GuardHarnessActionErrorPayload | null;

  constructor(status: number, payload: GuardHarnessActionErrorPayload | null) {
    super(payload?.message ?? payload?.error ?? `Harness action failed with ${status}`);
    this.name = "GuardHarnessActionError";
    this.status = status;
    this.payload = payload;
  }
}

function guardParams(): URLSearchParams {
  const params = new URLSearchParams(window.location.search);
  const fragment = window.location.hash.startsWith("#") ? window.location.hash.slice(1) : window.location.hash;
  for (const [key, value] of new URLSearchParams(fragment)) {
    params.set(key, value);
  }
  return params;
}

function guardParam(name: string): string | null {
  return guardParams().get(name);
}

function readBrowserStorage(getStorage: () => Storage, name: string): string | null {
  try {
    return getStorage().getItem(name);
  } catch {
    return null;
  }
}

function readGuardStorage(name: string): string | null {
  return readBrowserStorage(() => window.sessionStorage, name) ?? readBrowserStorage(() => window.localStorage, name);
}

function saveBrowserStorage(getStorage: () => Storage, name: string, value: string): void {
  try {
    getStorage().setItem(name, value);
  } catch {
    // Fall back to whichever storage remains available.
  }
}

function saveGuardStorage(name: string, value: string): void {
  saveBrowserStorage(() => window.sessionStorage, name, value);
  saveBrowserStorage(() => window.localStorage, name, value);
}

export function readGuardToken(): string | null {
  const locationKey = `${window.location.origin}${window.location.pathname}${window.location.search}${window.location.hash}`;
  if (guardTokenLocationKey !== locationKey) {
    guardTokenOverride = null;
    guardTokenLocationKey = locationKey;
  }
  if (guardTokenOverride !== null) {
    return guardTokenOverride;
  }
  const guardToken = guardParam(GUARD_TOKEN_PARAM);
  if (guardToken) {
    saveGuardStorage(GUARD_TOKEN_PARAM, guardToken);
    return guardToken;
  }
  return readGuardStorage(GUARD_TOKEN_PARAM);
}

function saveGuardToken(guardToken: string): void {
  guardTokenOverride = guardToken;
  saveGuardStorage(GUARD_TOKEN_PARAM, guardToken);
}

function saveGuardDaemonOrigin(daemonOrigin: string): void {
  saveGuardStorage(GUARD_DAEMON_PARAM, daemonOrigin);
}

function preferredGuardDaemonPort(): number {
  const establishedOrigin = establishedGuardDaemonOriginForReconnect();
  const rawDaemonUrl = guardParam(GUARD_DAEMON_PARAM);
  const suppliedToken = guardParam(GUARD_TOKEN_PARAM);
  const mayUseUnboundHint = Boolean(suppliedToken?.trim()) || !readGuardStorage(GUARD_TOKEN_PARAM);
  const fromOrigin =
    establishedOrigin ??
    (rawDaemonUrl && mayUseUnboundHint ? localGuardDaemonOrigin(rawDaemonUrl) : null) ??
    (() => {
      const storedDaemonUrl = readGuardStorage(GUARD_DAEMON_PARAM);
      return storedDaemonUrl ? localGuardDaemonOrigin(storedDaemonUrl) : null;
    })();
  if (fromOrigin) {
    try {
      const port = Number(new URL(fromOrigin).port);
      if (Number.isInteger(port) && port > 0) {
        return port;
      }
    } catch {
      // fall through
    }
  }
  const port = Number(window.location.port);
  if (Number.isInteger(port) && port > 0) {
    return port;
  }
  return DEFAULT_GUARD_DAEMON_PORT;
}

export function buildGuardDaemonCandidatePorts(preferredPort: number): number[] {
  const ports: number[] = [];
  const inStandardRange =
    preferredPort >= DEFAULT_GUARD_DAEMON_PORT &&
    preferredPort < DEFAULT_GUARD_DAEMON_PORT + GUARD_DAEMON_PORT_RANGE;
  for (let step = 0; step < GUARD_DAEMON_DISCOVERY_PROBE_COUNT; step += 1) {
    if (inStandardRange) {
      const offset = preferredPort - DEFAULT_GUARD_DAEMON_PORT;
      const candidateOffset =
        ((offset + step) % GUARD_DAEMON_PORT_RANGE + GUARD_DAEMON_PORT_RANGE) % GUARD_DAEMON_PORT_RANGE;
      ports.push(DEFAULT_GUARD_DAEMON_PORT + candidateOffset);
    } else {
      ports.push(preferredPort + step);
    }
  }
  return ports;
}

async function probeGuardDaemonHealth(origin: string): Promise<boolean> {
  const candidateOrigin = localGuardDaemonOrigin(origin);
  if (!candidateOrigin) {
    return false;
  }
  try {
    const { response, payload } = await fetchGuardDaemonCandidateJson(`${candidateOrigin}/healthz`, {
      redirect: "error",
    });
    if (!response.ok) {
      return false;
    }
    if (!isRecord(payload)) {
      return false;
    }
    return payload.ok === true && payload.compatibility_version === 2;
  } catch {
    return false;
  }
}

async function fetchGuardDaemonCandidateJson(
  input: RequestInfo,
  init: RequestInit,
): Promise<{ response: Response; payload: unknown }> {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), GUARD_DAEMON_PROBE_TIMEOUT_MS);
  try {
    const response = await fetch(input, { ...init, signal: controller.signal });
    const payload: unknown = await response.json();
    return { response, payload };
  } finally {
    window.clearTimeout(timeoutId);
  }
}

async function probeGuardDaemonCandidatePortsInBatches(
  ports: number[],
  probe: (port: number, origin: string) => Promise<boolean>,
): Promise<string | null> {
  for (let index = 0; index < ports.length; index += GUARD_DAEMON_DISCOVERY_PROBE_BATCH_SIZE) {
    const batch = ports.slice(index, index + GUARD_DAEMON_DISCOVERY_PROBE_BATCH_SIZE);
    const results = await Promise.all(
      batch.map(async (port) => {
        const origin = `http://127.0.0.1:${port}`;
        const ok = await probe(port, origin);
        return { port, origin, ok };
      }),
    );
    const active = results.find((result) => result.ok);
    if (active) {
      return active.origin;
    }
  }
  return null;
}

export async function discoverGuardDaemonOrigin(preferredPort = preferredGuardDaemonPort()): Promise<string | null> {
  const ports = buildGuardDaemonCandidatePorts(preferredPort);
  return probeGuardDaemonCandidatePortsInBatches(ports, async (_port, origin) => probeGuardDaemonHealth(origin));
}

export function updateReconnectSucceeded(
  status: GuardUpdateStatus,
  options: GuardUpdateReconnectOptions,
): boolean {
  if (!options.expectedPreviousVersion) {
    return true;
  }
  if (status.update_in_progress === true) {
    return false;
  }
  if (status.update_available !== true) {
    return true;
  }
  if (
    options.expectedLatestVersion &&
    status.current_version === options.expectedLatestVersion
  ) {
    return true;
  }
  if (status.current_version !== options.expectedPreviousVersion) {
    return true;
  }
  return options.sawUpdateInProgress === true;
}

type GuardDaemonReconnectChallenge = {
  protocol_version: 1;
  reconnect_id: string;
  client_nonce: string;
  server_nonce: string;
  state_id: string;
  candidate_origin: string;
  installation_id: string;
  guard_home_id: string;
  surface: "dashboard";
  issued_at_ms: number;
  expires_at_ms: number;
};

function isHexDigest(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function randomHex(bytes: number): string {
  const value = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(value);
  return [...value].map((item) => item.toString(16).padStart(2, "0")).join("");
}

function hexBytes(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < value.length; index += 2) {
    bytes[index / 2] = Number.parseInt(value.slice(index, index + 2), 16);
  }
  return bytes;
}

function canonicalReconnectPayload(value: Record<string, string | number>): string {
  const entries = Object.entries(value).sort(([left], [right]) => {
    if (left < right) return -1;
    if (left > right) return 1;
    return 0;
  });
  return JSON.stringify(Object.fromEntries(entries));
}

async function dashboardReconnectProof(
  verifier: string,
  proofContext: "server" | "client",
  challenge: GuardDaemonReconnectChallenge,
): Promise<string> {
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    hexBytes(verifier).buffer as ArrayBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const message = new TextEncoder().encode(
    canonicalReconnectPayload({ proof_context: proofContext, ...challenge }),
  ).buffer as ArrayBuffer;
  const signature = await globalThis.crypto.subtle.sign("HMAC", key, message);
  return [...new Uint8Array(signature)].map((item) => item.toString(16).padStart(2, "0")).join("");
}

function constantTimeHexEqual(left: string, right: string): boolean {
  if (!isHexDigest(left) || !isHexDigest(right)) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

function parseReconnectAuthorization(payload: unknown): GuardDaemonReconnectAuthorization | null {
  if (!isRecord(payload)) {
    return null;
  }
  if (
    payload["protocol_version"] !== GUARD_DAEMON_RECONNECT_PROTOCOL_VERSION ||
    payload["surface"] !== "dashboard" ||
    !isHexDigest(payload["reconnect_id"]) ||
    !isHexDigest(payload["verifier"]) ||
    !isHexDigest(payload["installation_id"]) ||
    !isHexDigest(payload["guard_home_id"]) ||
    typeof payload["issued_at_ms"] !== "number" ||
    typeof payload["expires_at_ms"] !== "number" ||
    payload["expires_at_ms"] <= payload["issued_at_ms"]
  ) {
    return null;
  }
  const now = Date.now();
  if (payload["issued_at_ms"] > now + 5_000 || payload["expires_at_ms"] > now + 305_000) {
    return null;
  }
  return {
    protocolVersion: 1,
    reconnectId: payload["reconnect_id"],
    verifier: payload["verifier"],
    surface: "dashboard",
    issuedAtMs: payload["issued_at_ms"],
    expiresAtMs: payload["expires_at_ms"],
    installationId: payload["installation_id"],
    guardHomeId: payload["guard_home_id"],
  };
}

function parseReconnectChallenge(
  payload: unknown,
  authorization: GuardDaemonReconnectAuthorization,
  candidateOrigin: string,
  clientNonce: string,
): { challenge: GuardDaemonReconnectChallenge; proof: string } | null {
  if (!isRecord(payload)) {
    return null;
  }
  const stringFields = ["state_id"] as const;
  if (
    payload["protocol_version"] !== GUARD_DAEMON_RECONNECT_PROTOCOL_VERSION ||
    payload["reconnect_id"] !== authorization.reconnectId ||
    payload["client_nonce"] !== clientNonce ||
    payload["candidate_origin"] !== candidateOrigin ||
    payload["installation_id"] !== authorization.installationId ||
    payload["guard_home_id"] !== authorization.guardHomeId ||
    payload["surface"] !== authorization.surface ||
    !isHexDigest(payload["server_nonce"]) ||
    !isHexDigest(payload["proof"]) ||
    !stringFields.every((field) => typeof payload[field] === "string" && payload[field].length > 0) ||
    typeof payload["issued_at_ms"] !== "number" ||
    typeof payload["expires_at_ms"] !== "number"
  ) {
    return null;
  }
  const challenge: GuardDaemonReconnectChallenge = {
    protocol_version: 1,
    reconnect_id: authorization.reconnectId,
    client_nonce: clientNonce,
    server_nonce: payload["server_nonce"],
    state_id: payload["state_id"] as string,
    candidate_origin: candidateOrigin,
    installation_id: authorization.installationId,
    guard_home_id: authorization.guardHomeId,
    surface: "dashboard",
    issued_at_ms: payload["issued_at_ms"],
    expires_at_ms: payload["expires_at_ms"],
  };
  const now = Date.now();
  if (
    challenge.issued_at_ms > now + 5_000 ||
    challenge.expires_at_ms < now ||
    challenge.expires_at_ms > authorization.expiresAtMs
  ) {
    return null;
  }
  return { challenge, proof: payload["proof"] };
}

export async function prepareGuardDaemonReconnect(): Promise<GuardDaemonReconnectAuthorization> {
  const daemonOrigin = establishedGuardDaemonOriginForReconnect();
  const guardToken = readGuardToken();
  if (!daemonOrigin || !guardToken) {
    guardDaemonReconnectDiagnostic = "dashboard_reconnect_prepare_origin_unavailable";
    throw new Error("Guard could not identify the authenticated daemon for a secure reconnect.");
  }
  let response = await fetch(`${daemonOrigin}/v1/update/reconnect/prepare`, withGuardAuthForToken({
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
    redirect: "error",
  }, guardToken));
  if (response.status === 401) {
    const refreshedToken = await initializeGuardDashboardSessionAtOrigin(daemonOrigin, guardToken);
    if (refreshedToken && refreshedToken !== guardToken) {
      saveGuardToken(refreshedToken);
      response = await fetch(`${daemonOrigin}/v1/update/reconnect/prepare`, withGuardAuthForToken({
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
        redirect: "error",
      }, refreshedToken));
    }
  }
  const authorization = response.ok ? parseReconnectAuthorization(await response.json()) : null;
  if (!authorization || authorization.expiresAtMs <= Date.now()) {
    guardDaemonReconnectDiagnostic = "dashboard_reconnect_prepare_failed";
    throw new Error("Guard could not prepare a secure dashboard reconnect.");
  }
  guardDaemonReconnectDiagnostic = "dashboard_reconnect_prepared";
  return authorization;
}

function establishedGuardDaemonOriginForReconnect(): string | null {
  const pageOrigin = localGuardDaemonOrigin(window.location.origin);
  if (pageOrigin) {
    return pageOrigin;
  }
  const suppliedToken = guardParam(GUARD_TOKEN_PARAM);
  if (suppliedToken?.trim()) {
    const suppliedDaemon = guardParam(GUARD_DAEMON_PARAM);
    const suppliedOrigin = suppliedDaemon ? localGuardDaemonOrigin(suppliedDaemon) : null;
    if (suppliedOrigin) {
      return suppliedOrigin;
    }
  }
  const storedDaemon = readGuardStorage(GUARD_DAEMON_PARAM);
  return storedDaemon ? localGuardDaemonOrigin(storedDaemon) : null;
}

export function readGuardDaemonReconnectDiagnostic(): string {
  return guardDaemonReconnectDiagnostic;
}

async function authenticateGuardDaemonCandidate(
  origin: string,
  authorization: GuardDaemonReconnectAuthorization,
): Promise<boolean> {
  const candidateOrigin = localGuardDaemonOrigin(origin);
  if (!candidateOrigin || authorization.expiresAtMs <= Date.now()) {
    guardDaemonReconnectDiagnostic = "dashboard_reconnect_authorization_expired";
    return false;
  }
  const clientNonce = randomHex(GUARD_DAEMON_RECONNECT_NONCE_BYTES);
  try {
    const { response: challengeResponse, payload: challengePayload } = await fetchGuardDaemonCandidateJson(`${candidateOrigin}/v1/update/reconnect/challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        protocol_version: GUARD_DAEMON_RECONNECT_PROTOCOL_VERSION,
        reconnect_id: authorization.reconnectId,
        client_nonce: clientNonce,
        candidate_origin: candidateOrigin,
      }),
      redirect: "error",
    });
    if (!challengeResponse.ok) {
      guardDaemonReconnectDiagnostic = "dashboard_reconnect_candidate_unavailable";
      return false;
    }
    const parsed = parseReconnectChallenge(
      challengePayload,
      authorization,
      candidateOrigin,
      clientNonce,
    );
    if (!parsed) {
      guardDaemonReconnectDiagnostic = "dashboard_reconnect_challenge_invalid";
      return false;
    }
    const expectedServerProof = await dashboardReconnectProof(
      authorization.verifier,
      "server",
      parsed.challenge,
    );
    if (!constantTimeHexEqual(parsed.proof, expectedServerProof)) {
      guardDaemonReconnectDiagnostic = "dashboard_reconnect_server_proof_invalid";
      return false;
    }
    const clientProof = await dashboardReconnectProof(
      authorization.verifier,
      "client",
      parsed.challenge,
    );
    const { response: verificationResponse, payload: verificationPayload } = await fetchGuardDaemonCandidateJson(`${candidateOrigin}/v1/update/reconnect/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        protocol_version: GUARD_DAEMON_RECONNECT_PROTOCOL_VERSION,
        challenge: parsed.challenge,
        proof: clientProof,
      }),
      redirect: "error",
    });
    if (!verificationResponse.ok) {
      guardDaemonReconnectDiagnostic = "dashboard_reconnect_client_proof_rejected";
      return false;
    }
    if (!isRecord(verificationPayload) || verificationPayload["verified"] !== true) {
      guardDaemonReconnectDiagnostic = "dashboard_reconnect_client_proof_rejected";
      return false;
    }
    guardDaemonReconnectDiagnostic = "dashboard_reconnect_proof_accepted";
    return true;
  } catch {
    guardDaemonReconnectDiagnostic = "dashboard_reconnect_candidate_unavailable";
    return false;
  }
}

async function initializeGuardDashboardSessionAtOrigin(
  origin: string,
  guardToken: string | null,
): Promise<string | null> {
  const candidateOrigin = localGuardDaemonOrigin(origin);
  if (!candidateOrigin) {
    return null;
  }
  try {
    const { response, payload } = await fetchGuardDaemonCandidateJson(`${candidateOrigin}/v1/initialize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(guardToken ? { "X-Guard-Dashboard-Session": guardToken } : {}),
      },
      body: JSON.stringify({
        client_name: "guard-dashboard-web",
        surface: "dashboard",
        supported_protocol_versions: [...GUARD_SURFACE_PROTOCOL_VERSIONS],
      }),
      redirect: "error",
    });
    if (!response.ok) {
      return null;
    }
    return parseDashboardSessionToken(payload);
  } catch {
    return null;
  }
}

export async function fetchGuardUpdateStatusAtOrigin(
  origin: string,
  guardToken: string | null,
): Promise<GuardUpdateStatus> {
  const candidateOrigin = localGuardDaemonOrigin(origin);
  if (!candidateOrigin) {
    throw new Error("Invalid Guard daemon origin");
  }
  const { response, payload } = await fetchGuardDaemonCandidateJson(`${candidateOrigin}/v1/update/status`, {
    headers: guardToken ? { "X-Guard-Dashboard-Session": guardToken } : {},
    redirect: "error",
  });
  if (!response.ok) {
    throw new Error(`Update status failed with ${response.status}`);
  }
  return normalizeGuardUpdateStatus(payload);
}

export function redirectToGuardDaemonOrigin(
  origin: string,
  guardToken: string | null,
): void {
  const candidateOrigin = localGuardDaemonOrigin(origin);
  if (!candidateOrigin) {
    guardDaemonReconnectDiagnostic = "dashboard_reconnect_origin_invalid";
    return;
  }
  const url = new URL(candidateOrigin);
  url.pathname = window.location.pathname;
  url.search = window.location.search;
  const fragmentPairs: string[] = [];
  if (guardToken) {
    fragmentPairs.push(`${GUARD_TOKEN_PARAM}=${encodeURIComponent(guardToken)}`);
  }
  fragmentPairs.push(`${GUARD_DAEMON_PARAM}=${encodeURIComponent(candidateOrigin)}`);
  url.hash = fragmentPairs.join("&");
  window.location.replace(url.toString());
}

export async function reconnectGuardDaemonAfterUpdate(
  options?: GuardUpdateReconnectOptions,
): Promise<{ origin: string | null; status: GuardUpdateStatus | null; sawUpdateInProgress: boolean } | null> {
  const reconnectOptions = options ?? {};
  const authorization = reconnectOptions.authorization;
  if (!authorization) {
    guardDaemonReconnectDiagnostic = "dashboard_reconnect_authorization_missing";
    return null;
  }
  const guardToken = readGuardToken();
  const awaitingVersionChange = Boolean(reconnectOptions.expectedPreviousVersion);
  const ports = buildGuardDaemonCandidatePorts(preferredGuardDaemonPort());
  let sawUpdateInProgress = reconnectOptions.sawUpdateInProgress === true;

  for (let index = 0; index < ports.length; index += GUARD_DAEMON_DISCOVERY_PROBE_BATCH_SIZE) {
    const batch = ports.slice(index, index + GUARD_DAEMON_DISCOVERY_PROBE_BATCH_SIZE);
    const results = await Promise.all(
      batch.map(async (port) => {
        const origin = `http://127.0.0.1:${port}`;
        if (!(await probeGuardDaemonHealth(origin))) {
          return null;
        }
        if (!(await authenticateGuardDaemonCandidate(origin, authorization))) {
          return null;
        }
        try {
          const status = await fetchGuardUpdateStatusAtOrigin(origin, guardToken);
          if (status.update_in_progress === true) {
            return { origin: null, status: null, sawUpdateInProgress: true };
          }
          if (awaitingVersionChange && !updateReconnectSucceeded(status, { ...reconnectOptions, sawUpdateInProgress })) {
            return { origin: null, status: null, sawUpdateInProgress };
          }
          return { origin, status, sawUpdateInProgress };
        } catch {
          return null;
        }
      }),
    );

    const active = results.find((result) => result !== null && result.origin !== null && result.status !== null);
    if (active?.origin && active.status) {
      const refreshedToken = await initializeGuardDashboardSessionAtOrigin(active.origin, guardToken);
      if (refreshedToken) {
        saveGuardToken(refreshedToken);
      }
      saveGuardDaemonOrigin(active.origin);
      return {
        origin: active.origin,
        status: active.status,
        sawUpdateInProgress: active.sawUpdateInProgress,
      };
    }

    const partial = results.find((result) => result !== null);
    if (partial) {
      sawUpdateInProgress = partial.sawUpdateInProgress;
      return { origin: null, status: null, sawUpdateInProgress };
    }
  }

  return null;
}

function readGuardDaemonOrigin(): string | null {
  const storedDaemonUrl = readGuardStorage(GUARD_DAEMON_PARAM);
  const storedDaemonOrigin = storedDaemonUrl ? localGuardDaemonOrigin(storedDaemonUrl) : null;
  const rawDaemonUrl = guardParam(GUARD_DAEMON_PARAM);
  if (rawDaemonUrl) {
    const daemonOrigin = localGuardDaemonOrigin(rawDaemonUrl);
    const suppliedToken = guardParam(GUARD_TOKEN_PARAM);
    const hasStoredToken = Boolean(readGuardStorage(GUARD_TOKEN_PARAM));
    if (daemonOrigin && (Boolean(suppliedToken?.trim()) || !hasStoredToken)) {
      saveGuardStorage(GUARD_DAEMON_PARAM, daemonOrigin);
      return daemonOrigin;
    }
  }
  return storedDaemonOrigin;
}

export function canonicalizeGuardDaemonOrigin(rawUrl: string): string | null {
  try {
    const rawOrigin = rawUrl.trim();
    const url = new URL(rawOrigin);
    if (url.protocol !== "http:" || !["127.0.0.1", "[::1]"].includes(url.hostname)) {
      return null;
    }
    if (
      url.username ||
      url.password ||
      (url.pathname && url.pathname !== "/") ||
      url.search ||
      url.hash ||
      !url.port
    ) {
      return null;
    }
    const port = Number(url.port);
    if (!Number.isInteger(port) || port < 1 || port > 65_535) {
      return null;
    }
    const canonicalHost = url.hostname === "[::1]" ? "[::1]" : "127.0.0.1";
    const canonical = `http://${canonicalHost}:${port}`;
    return url.origin === canonical && (rawOrigin === canonical || rawOrigin === `${canonical}/`) ? canonical : null;
  } catch {
    return null;
  }
}

function localGuardDaemonOrigin(rawUrl: string): string | null {
  return canonicalizeGuardDaemonOrigin(rawUrl);
}

function guardApiInput(input: RequestInfo): RequestInfo {
  const daemonOrigin = readGuardDaemonOrigin();
  if (!daemonOrigin || typeof input !== "string" || !input.startsWith("/")) {
    return input;
  }
  return `${daemonOrigin}${input}`;
}

function withGuardAuth(init?: RequestInit): RequestInit | undefined {
  return withGuardAuthForToken(init, readGuardToken());
}

function withGuardAuthForToken(
  init: RequestInit | undefined,
  guardToken: string | null,
): RequestInit | undefined {
  if (!guardToken) {
    return init;
  }
  const headers = new Headers(init?.headers);
  headers.set("X-Guard-Dashboard-Session", guardToken);
  return {
    ...init,
    headers
  };
}

async function fetchWithGuardAuth(input: RequestInfo, init?: RequestInit): Promise<Response> {
  const requestInput = guardApiInput(input);
  const guardToken = readGuardToken();
  const response = await fetch(requestInput, withGuardAuthForToken(init, guardToken));
  if (response.status !== 401 || !guardToken || input instanceof Request) {
    return response;
  }
  const refreshedGuardToken = await refreshGuardDashboardSession(guardToken);
  if (!refreshedGuardToken || refreshedGuardToken === guardToken) {
    return response;
  }
  saveGuardToken(refreshedGuardToken);
  return fetch(requestInput, withGuardAuthForToken(init, refreshedGuardToken));
}

export async function fetchCommandActivityApi(input: RequestInfo, init?: RequestInit): Promise<Response> {
  const approvedPath =
    typeof input === "string" &&
    /^\/v1\/(?:command-activity(?:\/(?:analytics|diagnostics|events|feedback))?|command-extensions)(?:\?[^#]*)?$/.test(
      input,
    );
  if (!approvedPath) {
    throw new Error("Invalid command activity API path");
  }
  return fetchWithGuardAuth(input, init);
}

function guardAuthHeaders(): HeadersInit {
  const guardToken = readGuardToken();
  return guardToken ? { "X-Guard-Dashboard-Session": guardToken } : {};
}

function guardAuthHeadersForToken(guardToken: string | null): HeadersInit {
  return guardToken ? { "X-Guard-Dashboard-Session": guardToken } : {};
}

function parseDashboardSessionToken(payload: unknown): string | null {
  if (!isRecord(payload)) {
    return null;
  }
  const dashboardSessionToken = payload["dashboard_session_token"];
  return typeof dashboardSessionToken === "string" && dashboardSessionToken.trim() ? dashboardSessionToken : null;
}

async function refreshGuardDashboardSession(guardToken: string): Promise<string | null> {
  try {
    const response = await fetch(guardApiInput("/v1/initialize"), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...guardAuthHeadersForToken(guardToken)
      },
      body: JSON.stringify({
        client_name: "guard-dashboard-web",
        surface: "dashboard",
        supported_protocol_versions: [...GUARD_SURFACE_PROTOCOL_VERSIONS]
      }),
      redirect: "error",
    });
    if (!response.ok) {
      return null;
    }
    return parseDashboardSessionToken(await response.json());
  } catch {
    return null;
  }
}

export function guardAwareHref(href: string): string {
  const guardToken = readGuardToken();
  if (!guardToken) {
    return href;
  }

  const url = new URL(href, window.location.origin);
  const daemonOrigin = readGuardDaemonOrigin();
  if (url.origin !== window.location.origin && url.origin !== daemonOrigin) {
    return href;
  }

  const fragmentPairs = [[GUARD_TOKEN_PARAM, guardToken]];
  if (daemonOrigin) {
    fragmentPairs.push([GUARD_DAEMON_PARAM, daemonOrigin]);
  }
  url.hash = new URLSearchParams(fragmentPairs).toString();
  if (href.startsWith("http://") || href.startsWith("https://")) {
    return url.toString();
  }
  return `${url.pathname}${url.search}${url.hash}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isGuardActionType(value: unknown): value is GuardActionType {
  return typeof value === "string" && GUARD_ACTION_TYPES.some((actionType) => actionType === value);
}

function isStringOrNull(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item): item is string => typeof item === "string");
}

function normalizeStringArray(value: unknown): string[] {
  return isStringArray(value) ? value : [];
}

function isNonNegativeNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isGuardHarnessActionErrorPayload(value: unknown): value is GuardHarnessActionErrorPayload {
  return isRecord(value) && isNonEmptyString(value["error"]);
}

function isApprovalPageStatus(value: unknown): value is GuardApprovalPageStatus {
  return value === "pending" || value === "resolved" || value === "all";
}

function matchingAliasedField(
  raw: Record<string, unknown>,
  snakeKey: string,
  camelKey: string,
): { matches: boolean; value: unknown } {
  const hasSnake = Object.prototype.hasOwnProperty.call(raw, snakeKey);
  const hasCamel = Object.prototype.hasOwnProperty.call(raw, camelKey);
  if (hasSnake && hasCamel && raw[snakeKey] !== raw[camelKey]) {
    return { matches: false, value: undefined };
  }
  return { matches: true, value: hasSnake ? raw[snakeKey] : raw[camelKey] };
}

export function parseActionEnvelope(raw: unknown): GuardActionEnvelope | null {
  if (!isRecord(raw)) {
    return null;
  }
  const allowedActionFields = new Set([
    "action_id",
    "action_type",
    "pre_execution_result",
    "policy_action",
    "actionId",
    "actionType",
    "preExecutionResult",
    "policyAction",
  ]);
  if (Object.keys(raw).some((key) => isActionBearingKey(key) && !allowedActionFields.has(key))) {
    return null;
  }
  const aliasedActionId = matchingAliasedField(raw, "action_id", "actionId");
  const aliasedActionType = matchingAliasedField(raw, "action_type", "actionType");
  const aliasedPreExecutionResult = matchingAliasedField(
    raw,
    "pre_execution_result",
    "preExecutionResult",
  );
  const aliasedPolicyAction = matchingAliasedField(raw, "policy_action", "policyAction");
  if (
    !aliasedActionId.matches ||
    !aliasedActionType.matches ||
    !aliasedPreExecutionResult.matches ||
    !aliasedPolicyAction.matches
  ) {
    return null;
  }
  const schemaVersion = raw["schema_version"];
  const actionId = aliasedActionId.value;
  const harness = raw["harness"];
  const eventName = raw["event_name"];
  const actionType = aliasedActionType.value;
  const workspace = raw["workspace"];
  const workspaceHash = raw["workspace_hash"];
  const toolName = raw["tool_name"];
  const command = raw["command"];
  const promptExcerpt = raw["prompt_excerpt"];
  const promptText = raw["prompt_text"];
  const targetPaths = raw["target_paths"];
  const networkHosts = raw["network_hosts"];
  const mcpServer = raw["mcp_server"];
  const mcpTool = raw["mcp_tool"];
  const packageManager = raw["package_manager"];
  const packageName = raw["package_name"];
  const commandCategory = raw["command_category"];
  const packageIntentKind = raw["package_intent_kind"];
  const packageTargets = raw["package_targets"];
  const preExecutionResult = aliasedPreExecutionResult.value;
  const policyAction = aliasedPolicyAction.value;
  const scriptName = raw["script_name"];
  const rawPayloadRedacted = raw["raw_payload_redacted"];
  if (
    typeof schemaVersion !== "number" ||
    typeof actionId !== "string" ||
    typeof harness !== "string" ||
    typeof eventName !== "string" ||
    !isGuardActionType(actionType)
  ) {
    return null;
  }
  if (
    !isStringOrNull(workspace) ||
    !isStringOrNull(workspaceHash) ||
    !isStringOrNull(toolName) ||
    !isStringOrNull(command) ||
    !isStringOrNull(promptExcerpt) ||
    (promptText !== undefined && !isStringOrNull(promptText)) ||
    !isStringOrNull(mcpServer) ||
    !isStringOrNull(mcpTool) ||
    !isStringOrNull(packageManager) ||
    !isStringOrNull(packageName) ||
    (commandCategory !== undefined && !isStringOrNull(commandCategory)) ||
    (packageIntentKind !== undefined && !isStringOrNull(packageIntentKind)) ||
    (preExecutionResult !== undefined && preExecutionResult !== null && !isGuardAction(preExecutionResult)) ||
    (policyAction !== undefined && policyAction !== null && !isGuardAction(policyAction)) ||
    !isStringOrNull(scriptName)
  ) {
    return null;
  }
  if (
    !isStringArray(targetPaths) ||
    !isStringArray(networkHosts) ||
    (packageTargets !== undefined && !isStringArray(packageTargets))
  ) {
    return null;
  }
  if (!isRecord(rawPayloadRedacted)) {
    return null;
  }
  return {
    schema_version: schemaVersion,
    action_id: actionId,
    harness,
    event_name: eventName,
    action_type: actionType,
    workspace,
    workspace_hash: workspaceHash,
    tool_name: toolName,
    command,
    prompt_excerpt: promptExcerpt,
    prompt_text: isStringOrNull(promptText) ? promptText : null,
    target_paths: targetPaths,
    network_hosts: networkHosts,
    mcp_server: mcpServer,
    mcp_tool: mcpTool,
    package_manager: packageManager,
    package_name: packageName,
    command_category: isStringOrNull(commandCategory) ? commandCategory : null,
    package_intent_kind: isStringOrNull(packageIntentKind) ? packageIntentKind : null,
    package_targets: isStringArray(packageTargets) ? packageTargets : [],
    pre_execution_result: isGuardAction(preExecutionResult) ? preExecutionResult : null,
    ...(policyAction === undefined
      ? {}
      : { policy_action: isGuardAction(policyAction) ? policyAction : null }),
    script_name: scriptName,
    raw_payload_redacted: rawPayloadRedacted
  };
}

function isDecisionV2Action(value: unknown): value is GuardDecisionV2["action"] {
  return typeof value === "string" && GUARD_DECISION_V2_ACTIONS.some((a) => a === value);
}

function isDecisionV2Confidence(value: unknown): value is GuardDecisionV2["confidence"] {
  return typeof value === "string" && GUARD_DECISION_V2_CONFIDENCES.some((c) => c === value);
}

function isRiskSignalV2Category(value: unknown): value is RiskSignalV2Category {
  return typeof value === "string" && GUARD_RISK_SIGNAL_V2_CATEGORIES.some((category) => category === value);
}

function isRiskSignalV2Severity(value: unknown): value is RiskSignalV2Severity {
  return typeof value === "string" && GUARD_RISK_SIGNAL_V2_SEVERITIES.some((s) => s === value);
}

function isRiskSignalV2RedactionLevel(value: unknown): value is RiskSignalV2RedactionLevel {
  return typeof value === "string" && GUARD_RISK_SIGNAL_V2_REDACTION_LEVELS.some((level) => level === value);
}

function isRiskSignalV2Array(value: unknown): value is RiskSignalV2[] {
  if (!Array.isArray(value)) {
    return false;
  }
  return value.every((item) => {
    if (!isRecord(item)) {
      return false;
    }
    return (
      isNonEmptyString(item["signal_id"]) &&
      isRiskSignalV2Category(item["category"]) &&
      isRiskSignalV2Severity(item["severity"]) &&
      isDecisionV2Confidence(item["confidence"]) &&
      isNonEmptyString(item["detector"]) &&
      isNonEmptyString(item["title"]) &&
      isNonEmptyString(item["plain_reason"]) &&
      isStringOrNull(item["technical_detail"]) &&
      isStringOrNull(item["evidence_ref"]) &&
      isRiskSignalV2RedactionLevel(item["redaction_level"]) &&
      isStringOrNull(item["false_positive_hint"]) &&
      isStringOrNull(item["advisory_id"])
    );
  });
}

export function parseDecisionV2(raw: unknown): GuardDecisionV2 | null {
  if (!isRecord(raw)) {
    return null;
  }
  const allowedActionFields = new Set(["guard_action", "action"]);
  if (Object.keys(raw).some((key) => isActionBearingKey(key) && !allowedActionFields.has(key))) {
    return null;
  }
  const guardAction = raw["guard_action"];
  const action = raw["action"];
  const reason = raw["reason"];
  const userTitle = raw["user_title"];
  const userBody = raw["user_body"];
  const harnessMessage = raw["harness_message"];
  const dashboardPrimaryDetail = raw["dashboard_primary_detail"];
  const approvalScopes = raw["approval_scopes"];
  const retryInstruction = raw["retry_instruction"];
  const signals = raw["signals"];
  const confidence = raw["confidence"];
  if (
    !isGuardAction(guardAction) ||
    !isDecisionV2Action(action) ||
    action !== guardDecisionV2Action(guardAction) ||
    !isNonEmptyString(reason) ||
    !isNonEmptyString(userTitle) ||
    !isNonEmptyString(userBody) ||
    !isNonEmptyString(harnessMessage) ||
    !isNonEmptyString(dashboardPrimaryDetail) ||
    !isStringArray(approvalScopes) ||
    !isStringOrNull(retryInstruction) ||
    !isRiskSignalV2Array(signals) ||
    !isDecisionV2Confidence(confidence)
  ) {
    return null;
  }
  return {
    guard_action: guardAction,
    action,
    reason,
    user_title: userTitle,
    user_body: userBody,
    harness_message: harnessMessage,
    dashboard_primary_detail: dashboardPrimaryDetail,
    approval_scopes: approvalScopes,
    retry_instruction: retryInstruction,
    signals,
    confidence
  };
}

type LegacyPackageActionMetadata = Readonly<{
  recognized: boolean;
  action: GuardAction | null;
}>;

/** Recognize the historical package-receipt metadata shape without treating it as a typed action envelope. */
function parseLegacyPackageActionMetadata(raw: unknown): LegacyPackageActionMetadata {
  if (
    !isRecord(raw) ||
    raw["schema_version"] !== undefined ||
    !("policy_action" in raw) ||
    typeof raw["package_manager"] !== "string" ||
    !isStringArray(raw["package_targets"]) ||
    typeof raw["redacted_command"] !== "string"
  ) {
    return { recognized: false, action: null };
  }
  if (Object.keys(raw).some((key) => isActionBearingKey(key) && key !== "policy_action")) {
    return { recognized: false, action: null };
  }
  const action = raw["policy_action"];
  return { recognized: true, action: isRecognizedGuardActionInput(action) ? normalizeGuardAction(action) : null };
}

const DECISION_SCOPE_VALUES: ReadonlySet<string> = new Set([
  "artifact",
  "workspace",
  "publisher",
  "harness",
  "global",
]);

function isDecisionScope(value: unknown): value is DecisionScope {
  return typeof value === "string" && DECISION_SCOPE_VALUES.has(value);
}

function parseDecisionScopeList(value: unknown): DecisionScope[] | null {
  if (!Array.isArray(value) || !value.every(isDecisionScope)) {
    return null;
  }
  return [...new Set(value)];
}

function parseStringList(value: unknown): string[] | null {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    return null;
  }
  return [...new Set(value)];
}

function parseOptionalString(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

export function normalizeApprovalRequest(item: RawGuardApprovalRequest): GuardApprovalRequest {
  const { decision_contract_error: rawContractError, ...baseItem } = item;
  const policyAction = normalizeGuardAction(item.policy_action);
  const decisionV2 = parseDecisionV2(item.decision_v2_json);
  const actionEnvelope = parseActionEnvelope(item.action_envelope_json);
  const legacyActionMetadata = parseLegacyPackageActionMetadata(item.action_envelope_json);
  const hasUnknownPolicyAction = !isRecognizedGuardActionInput(item.policy_action);
  const hasMalformedActionEnvelope =
    item.action_envelope_json !== undefined &&
    item.action_envelope_json !== null &&
    actionEnvelope === null &&
    !(legacyActionMetadata.recognized && legacyActionMetadata.action !== null);
  const hasContradictoryActionEnvelope =
    (actionEnvelope !== null &&
      [actionEnvelope.pre_execution_result, actionEnvelope.policy_action].some(
        (action) => action !== undefined && action !== null && action !== policyAction,
      )) ||
    (legacyActionMetadata.recognized && legacyActionMetadata.action !== policyAction);
  const hasDecisionContractError =
    rawContractError !== undefined ||
    hasUnknownPolicyAction ||
    hasMalformedActionEnvelope ||
    hasContradictoryActionEnvelope ||
    (item.decision_v2_json !== undefined && item.decision_v2_json !== null && decisionV2 === null) ||
    (decisionV2 !== null &&
      (decisionV2.guard_action !== policyAction || decisionV2.action !== guardDecisionV2Action(policyAction)));
  const failClosedPolicyAction = hasDecisionContractError
    ? mostRestrictiveGuardAction(
        policyAction,
        "require-reapproval",
        decisionV2?.guard_action,
        actionEnvelope?.pre_execution_result,
        actionEnvelope?.policy_action,
        legacyActionMetadata.action,
      )
    : policyAction;
  const hasScopeContract = [
    item.scope_contract_version,
    item.scope_contract_digest,
    item.allowed_scopes_by_action,
    item.recommended_scope_by_action,
    item.scope_restrictions,
    item.task_capability_eligibility,
  ].some((value) => value !== undefined && value !== null);
  const scopeContractVersion = parseOptionalString(item.scope_contract_version);
  const scopeContractDigest = parseOptionalString(item.scope_contract_digest);
  const hasCompleteScopeContract = scopeContractVersion !== null && scopeContractDigest !== null;
  const rawAllowedByAction = isRecord(item.allowed_scopes_by_action)
    ? item.allowed_scopes_by_action
    : {};
  const rawRecommendedByAction = isRecord(item.recommended_scope_by_action)
    ? item.recommended_scope_by_action
    : {};
  const rawTaskEligibility = isRecord(item.task_capability_eligibility)
    ? item.task_capability_eligibility
    : null;
  const taskReasonCodes = parseStringList(rawTaskEligibility?.reason_codes);
  const taskCapabilityEligibility =
    typeof rawTaskEligibility?.eligible === "boolean" && taskReasonCodes !== null
      ? {
          eligible: rawTaskEligibility.eligible,
          reason_codes: taskReasonCodes,
        }
      : undefined;
  const allowedScopes = parseDecisionScopeList(item.allowed_scopes);
  const scopeRestrictions = parseStringList(item.scope_restrictions);
  return {
    ...baseItem,
    policy_action: failClosedPolicyAction,
    recommended_scope: isDecisionScope(item.recommended_scope) ? item.recommended_scope : null,
    allowed_scopes: allowedScopes ?? undefined,
    scope_contract_version: hasScopeContract ? scopeContractVersion : undefined,
    scope_contract_digest: hasScopeContract ? scopeContractDigest : undefined,
    allowed_scopes_by_action: hasScopeContract
      ? {
          allow: hasCompleteScopeContract ? parseDecisionScopeList(rawAllowedByAction.allow) ?? [] : [],
          block: hasCompleteScopeContract ? parseDecisionScopeList(rawAllowedByAction.block) ?? [] : [],
        }
      : undefined,
    recommended_scope_by_action: hasScopeContract
      ? {
          allow:
            hasCompleteScopeContract && isDecisionScope(rawRecommendedByAction.allow)
              ? rawRecommendedByAction.allow
              : null,
          block:
            hasCompleteScopeContract && isDecisionScope(rawRecommendedByAction.block)
              ? rawRecommendedByAction.block
              : null,
        }
      : undefined,
    scope_restrictions: hasScopeContract ? scopeRestrictions ?? [] : undefined,
    task_capability_eligibility: hasScopeContract ? taskCapabilityEligibility : undefined,
    temporary_mcp_approval: parseTemporaryMcpApproval(item.temporary_mcp_approval),
    action_envelope_json: hasDecisionContractError ? null : actionEnvelope,
    decision_v2_json: hasDecisionContractError ? null : decisionV2,
    ...(hasDecisionContractError
      ? { decision_contract_error: AUTHORITATIVE_DECISION_INCONSISTENT }
      : {}),
  };
}

function normalizeApprovalRequests(items: RawGuardApprovalRequest[] | null | undefined): GuardApprovalRequest[] {
  if (!Array.isArray(items)) {
    return [];
  }
  return items.map(normalizeApprovalRequest);
}

function normalizeOptionalApprovalRequest(item: RawGuardApprovalRequest | null | undefined): GuardApprovalRequest | null {
  return isRecord(item) ? normalizeApprovalRequest(item) : null;
}

function normalizeApprovalPage(
  payload: ApprovalRequestListPayload,
  statusFallback: GuardApprovalPageStatus = "pending"
): GuardApprovalPage {
  return {
    items: normalizeApprovalRequests(payload.items),
    next_cursor: isStringOrNull(payload.next_cursor) ? payload.next_cursor : null,
    total_pending_count: isNonNegativeNumber(payload.total_pending_count) ? payload.total_pending_count : 0,
    total_count: isNonNegativeNumber(payload.total_count) ? payload.total_count : 0,
    status: isApprovalPageStatus(payload.status) ? payload.status : statusFallback
  };
}

function normalizeQueueSummary(raw: unknown, pendingCount: number): GuardQueueSummary {
  if (!isRecord(raw)) {
    return {
      active_request_id: null,
      next_request_id: null,
      remaining_pending_count: pendingCount,
      next_selectable_request_id: null
    };
  }
  const remainingPendingCount = raw["remaining_pending_count"];
  return {
    active_request_id: isStringOrNull(raw["active_request_id"]) ? raw["active_request_id"] : null,
    next_request_id: isStringOrNull(raw["next_request_id"]) ? raw["next_request_id"] : null,
    remaining_pending_count: isNonNegativeNumber(remainingPendingCount) ? remainingPendingCount : pendingCount,
    next_selectable_request_id: isStringOrNull(raw["next_selectable_request_id"]) ? raw["next_selectable_request_id"] : null
  };
}

function normalizePackageManagerProtection(raw: unknown): PackageManagerProtection | undefined {
  if (!isRecord(raw)) {
    return undefined;
  }
  const pathStatus =
    raw["path_status"] === "in_path"
      ? "in_path"
      : raw["path_status"] === "restart_required"
      ? "restart_required"
      : "missing_from_path";
  const shimDir = typeof raw["shim_dir"] === "string" ? raw["shim_dir"] : "";
  return {
    path_status: pathStatus,
    path_contains_shim_dir: raw["path_contains_shim_dir"] === true,
    restart_shell_required: raw["restart_shell_required"] === true,
    shell_profile_configured: raw["shell_profile_configured"] === true,
    shell_profile_path: isStringOrNull(raw["shell_profile_path"]) ? raw["shell_profile_path"] : null,
    shim_dir: shimDir,
    supported_managers: normalizeStringArray(raw["supported_managers"]),
    installed_managers: normalizeStringArray(raw["installed_managers"]),
    active_managers: normalizeStringArray(raw["active_managers"]),
    missing_shims: normalizeStringArray(raw["missing_shims"]),
    protected_managers: normalizeStringArray(raw["protected_managers"]),
    unprotected_managers: normalizeStringArray(raw["unprotected_managers"]),
  };
}

function normalizeSupplyChainSnapshot(raw: unknown): SupplyChainSnapshot | undefined {
  if (!isRecord(raw)) {
    return undefined;
  }
  const packageManagerProtection = normalizePackageManagerProtection(raw["package_manager_protection"]);
  if (!packageManagerProtection) {
    return undefined;
  }
  return {
    package_manager_protection: packageManagerProtection,
  };
}

function normalizeManagedInstall(raw: unknown): GuardManagedInstall | undefined {
  if (!isRecord(raw)) {
    return undefined;
  }
  const harness = raw["harness"];
  if (typeof harness !== "string") {
    return undefined;
  }
  const active = raw["active"] === true;
  const workspace = isStringOrNull(raw["workspace"]) ? raw["workspace"] : null;
  const manifest = isRecord(raw["manifest"]) ? raw["manifest"] : {};
  const updatedAt = typeof raw["updated_at"] === "string" ? raw["updated_at"] : "";
  return {
    harness,
    active,
    workspace,
    manifest,
    updated_at: updatedAt,
  };
}

function normalizeManagedInstalls(raw: unknown): GuardManagedInstall[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const result: GuardManagedInstall[] = [];
  for (const item of raw) {
    const normalized = normalizeManagedInstall(item);
    if (normalized !== undefined) {
      result.push(normalized);
    }
  }
  return result;
}

function normalizeCloudCommandCapability(raw: unknown): GuardRuntimeSnapshot["cloud_command_capability"] {
  if (!isRecord(raw)) {
    return undefined;
  }
  const pending = Array.isArray(raw["pending_commands"])
    ? raw["pending_commands"].flatMap((item) => {
        if (!isRecord(item)) return [];
        const id = item["id"];
        const operation = item["operation"];
        const issuer = item["issuer"];
        const expiresAt = item["expiresAt"];
        const approveCommand = item["approveCommand"];
        if (
          typeof id !== "string" ||
          typeof operation !== "string" ||
          typeof issuer !== "string" ||
          typeof expiresAt !== "string" ||
          typeof approveCommand !== "string"
        ) {
          return [];
        }
        return [{ id, operation, issuer, expiresAt, approveCommand }];
      })
    : [];
  const operations = Array.isArray(raw["operations"])
    ? raw["operations"].filter((operation): operation is string => typeof operation === "string")
    : [];
  return {
    enabled: raw["enabled"] === true,
    capability_valid: raw["capability_valid"] === true || raw["enabled"] === true,
    reason: typeof raw["reason"] === "string" ? raw["reason"] : null,
    issuer: typeof raw["issuer"] === "string" ? raw["issuer"] : null,
    issued_at: typeof raw["issued_at"] === "string" ? raw["issued_at"] : null,
    expires_at: typeof raw["expires_at"] === "string" ? raw["expires_at"] : null,
    device_id: typeof raw["device_id"] === "string" ? raw["device_id"] : null,
    workspace_id: typeof raw["workspace_id"] === "string" ? raw["workspace_id"] : null,
    operations,
    pending_commands: pending,
    enable_command:
      typeof raw["enable_command"] === "string"
        ? raw["enable_command"]
        : "hol-guard commands enable --operations read-only",
    revoke_command:
      typeof raw["revoke_command"] === "string"
        ? raw["revoke_command"]
        : "hol-guard commands revoke --confirm revoke",
  };
}

export function normalizeRuntimeSnapshot(snapshot: RuntimeSnapshotPayload): GuardRuntimeSnapshot {
  const protectionHealth = normalizeProtectionHealth(snapshot.protection_health);
  const runtimeState = normalizeRuntimeState(snapshot.runtime_state);
  const headline = protectionHeadlineFor({
    health: protectionHealth,
    runtimeActive: runtimeState !== null,
    pendingCount: snapshot.pending_count,
  });
  return {
    ...snapshot,
    ...headline,
    runtime_state: runtimeState,
    items: normalizeApprovalRequests(snapshot.items),
    latest_receipts: normalizeReceipts(snapshot.latest_receipts),
    inventory: normalizeInventory(snapshot.inventory),
    queue_summary: normalizeQueueSummary(snapshot.queue_summary, snapshot.pending_count),
    supply_chain: normalizeSupplyChainSnapshot(snapshot.supply_chain),
    managed_installs: normalizeManagedInstalls(snapshot.managed_installs),
    cloud_command_capability: normalizeCloudCommandCapability(snapshot.cloud_command_capability),
    protection_health: protectionHealth,
  };
}

function normalizeRuntimeState(raw: unknown): GuardRuntimeState | null {
  if (!isRecord(raw)) {
    return null;
  }
  const sessionId = raw["session_id"];
  const daemonHost = raw["daemon_host"];
  const daemonPort = raw["daemon_port"];
  const startedAt = raw["started_at"];
  const lastHeartbeatAt = raw["last_heartbeat_at"];
  const approvalCenterUrl = raw["approval_center_url"];
  if (
    typeof sessionId !== "string" ||
    sessionId.length === 0 ||
    typeof daemonHost !== "string" ||
    !isLoopbackRuntimeHost(daemonHost) ||
    typeof daemonPort !== "number" ||
    !Number.isInteger(daemonPort) ||
    daemonPort <= 0 ||
    daemonPort > 65_535 ||
    typeof startedAt !== "string" ||
    parseAwareTimestamp(startedAt) === null ||
    typeof lastHeartbeatAt !== "string" ||
    !isFreshAwareTimestamp(lastHeartbeatAt) ||
    typeof approvalCenterUrl !== "string" ||
    !isMatchingRuntimeUrl(approvalCenterUrl, daemonHost, daemonPort)
  ) {
    return null;
  }
  return {
    session_id: sessionId,
    daemon_host: daemonHost,
    daemon_port: daemonPort,
    started_at: startedAt,
    last_heartbeat_at: lastHeartbeatAt,
    approval_center_url: approvalCenterUrl,
  };
}

function parseAwareTimestamp(value: string): number | null {
  if (!/(?:Z|[+-]\d{2}:\d{2})$/u.test(value)) {
    return null;
  }
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : null;
}

function isFreshAwareTimestamp(value: string): boolean {
  const timestamp = parseAwareTimestamp(value);
  if (timestamp === null) {
    return false;
  }
  const now = Date.now();
  return (
    timestamp >= now - RUNTIME_HEARTBEAT_MAX_AGE_MS &&
    timestamp <= now + RUNTIME_HEARTBEAT_FUTURE_TOLERANCE_MS
  );
}

function isLoopbackRuntimeHost(value: string): boolean {
  return value === "127.0.0.1" || value === "localhost" || value === "::1";
}

function isMatchingRuntimeUrl(value: string, daemonHost: string, daemonPort: number): boolean {
  try {
    const url = new URL(value);
    const hostname = url.hostname.startsWith("[") ? url.hostname.slice(1, -1) : url.hostname;
    return (
      url.protocol === "http:" &&
      hostname === daemonHost &&
      Number(url.port) === daemonPort &&
      url.username.length === 0 &&
      url.password.length === 0 &&
      url.pathname === "/" &&
      url.search.length === 0 &&
      url.hash.length === 0
    );
  } catch {
    return false;
  }
}

function normalizeQueueCopy(raw: unknown): GuardQueueResolutionCopy | null {
  if (!isRecord(raw)) {
    return null;
  }
  const title = raw["title"];
  const body = raw["body"];
  if (typeof title !== "string" || typeof body !== "string") {
    return null;
  }
  return { title, body };
}

function isCodexResumeStatus(value: unknown): value is CodexResumeStatus {
  return typeof value === "string" && CODEX_RESUME_STATUSES.some((s) => s === value);
}

function normalizeCodexResume(raw: unknown): GuardCodexResumeResult | null {
  if (!isRecord(raw)) {
    return null;
  }
  const status = raw["status"];
  if (!isCodexResumeStatus(status)) {
    return null;
  }
  return {
    request_id: isStringOrNull(raw["request_id"]) ? raw["request_id"] : null,
    operation_id: isStringOrNull(raw["operation_id"]) ? raw["operation_id"] : null,
    harness: isStringOrNull(raw["harness"]) ? raw["harness"] : null,
    resolution_action: isStringOrNull(raw["resolution_action"]) ? raw["resolution_action"] : null,
    strategy: isStringOrNull(raw["strategy"]) ? raw["strategy"] : null,
    supported: raw["supported"] === true,
    status,
    thread_id: isStringOrNull(raw["thread_id"]) ? raw["thread_id"] : null,
    reason: isStringOrNull(raw["reason"]) ? raw["reason"] : null,
    message: isStringOrNull(raw["message"]) ? raw["message"] : null,
    last_error: isStringOrNull(raw["last_error"]) ? raw["last_error"] : null,
    attempt_count: isNonNegativeNumber(raw["attempt_count"]) ? raw["attempt_count"] : 0,
    created_at: isStringOrNull(raw["created_at"]) ? raw["created_at"] : null,
    updated_at: isStringOrNull(raw["updated_at"]) ? raw["updated_at"] : null,
    last_attempt_at: isStringOrNull(raw["last_attempt_at"]) ? raw["last_attempt_at"] : null,
    sent_at: isStringOrNull(raw["sent_at"]) ? raw["sent_at"] : null,
  };
}

function normalizeQueueResolution(payload: QueueResolutionPayload): GuardQueueResolutionResult {
  return {
    resolved: payload.resolved === true,
    item: normalizeOptionalApprovalRequest(payload.item),
    resolved_request: normalizeOptionalApprovalRequest(payload.resolved_request),
    remaining_pending_count: isNonNegativeNumber(payload.remaining_pending_count) ? payload.remaining_pending_count : 0,
    next_selectable_request_id: isStringOrNull(payload.next_selectable_request_id)
      ? payload.next_selectable_request_id
      : null,
    remaining_pending_summaries: normalizeApprovalRequests(payload.remaining_pending_summaries),
    resolved_duplicate_ids: isStringArray(payload.resolved_duplicate_ids) ? payload.resolved_duplicate_ids : [],
    resolved_scope_ids: isStringArray(payload.resolved_scope_ids) ? payload.resolved_scope_ids : undefined,
    resolution_summary: typeof payload.resolution_summary === "string" ? payload.resolution_summary : "",
    retry_hint: isStringOrNull(payload.retry_hint) ? payload.retry_hint : null,
    copy: normalizeQueueCopy(payload.copy),
    codex_resume: normalizeCodexResume(payload.codex_resume)
  };
}

function queueSearchParams(input: GuardApprovalPageFilters): URLSearchParams {
  const params = new URLSearchParams();
  if (input.status) {
    params.set("status", input.status);
  }
  if (input.harness) {
    params.set("harness", input.harness);
  }
  if (input.search) {
    params.set("search", input.search);
  }
  if (input.cursor) {
    params.set("cursor", input.cursor);
  }
  if (typeof input.limit === "number") {
    params.set("limit", String(input.limit));
  }
  if (input.includeTotals === false) {
    params.set("include_totals", "0");
  }
  return params;
}

function queuePath(basePath: string, params: URLSearchParams): string {
  const query = params.toString();
  return query ? `${basePath}?${query}` : basePath;
}

const PENDING_QUEUE_PAGE_LIMIT = 200;
const MAX_PENDING_QUEUE_PAGES = 50;

type PendingRequestPageCallback = (items: GuardApprovalRequest[]) => void;

export async function fetchAllPendingRequests(onPage?: PendingRequestPageCallback): Promise<GuardApprovalRequest[]> {
  if (isGuardDemoMode()) {
    const demoRequests = getDemoRequests();
    onPage?.(demoRequests);
    return demoRequests;
  }
  const items: GuardApprovalRequest[] = [];
  let cursor: string | undefined;
  for (let pageIndex = 0; pageIndex < MAX_PENDING_QUEUE_PAGES; pageIndex += 1) {
    const page = await fetchApprovalPage({
      status: "pending",
      limit: PENDING_QUEUE_PAGE_LIMIT,
      cursor,
      includeTotals: pageIndex === 0,
    });
    items.push(...page.items);
    onPage?.([...items]);
    if (!page.next_cursor || page.next_cursor === cursor) {
      return items;
    }
    cursor = page.next_cursor;
  }
  return items;
}

function runtimeSnapshotSearchParams(
  input: { activeRequestId?: string; includeItems?: boolean; includeReceipts?: boolean } = {},
): URLSearchParams {
  const params = new URLSearchParams();
  if (input.activeRequestId) {
    params.set("active_request_id", input.activeRequestId);
  }
  if (input.includeItems === false) {
    params.set("include_items", "0");
  }
  if (input.includeReceipts === false) {
    params.set("include_receipts", "0");
  }
  return params;
}

export async function fetchInboxState(input: { activeRequestId?: string } = {}): Promise<{
  snapshot: GuardRuntimeSnapshot;
  items: GuardApprovalRequest[];
}> {
  if (isGuardDemoMode()) {
    const snapshot = buildDemoRuntimeSnapshot();
    return { snapshot, items: snapshot.items };
  }
  const [snapshotPayload, items] = await Promise.all([
    readJson<RuntimeSnapshotPayload>(
      queuePath("/v1/runtime", runtimeSnapshotSearchParams({ ...input, includeItems: false, includeReceipts: false })),
    ),
    fetchAllPendingRequests(),
  ]);
  return {
    snapshot: normalizeRuntimeSnapshot(snapshotPayload),
    items,
  };
}

export async function fetchRequests(): Promise<GuardApprovalRequest[]> {
  return fetchAllPendingRequests();
}

export async function fetchApprovalPage(input: GuardApprovalPageFilters = {}): Promise<GuardApprovalPage> {
  if (isGuardDemoMode()) {
    const items = getDemoRequests();
    return {
      items,
      next_cursor: null,
      total_pending_count: items.filter((item) => item.status === "pending").length,
      total_count: items.length,
      status: input.status ?? "pending"
    };
  }
  const payload = await readJson<ApprovalRequestListPayload>(queuePath("/v1/requests", queueSearchParams(input)));
  return normalizeApprovalPage(payload, input.status ?? "pending");
}

export async function fetchRuntimeSnapshot(
  input: { includeItems?: boolean; includeReceipts?: boolean } = {},
): Promise<GuardRuntimeSnapshot> {
  if (isGuardDemoMode()) {
    return buildDemoRuntimeSnapshot();
  }
  const params = runtimeSnapshotSearchParams(input);
  const query = params.toString();
  const path = query.length > 0 ? `/v1/runtime?${query}` : "/v1/runtime";
  const snapshot = await readJson<RuntimeSnapshotPayload>(path);
  return normalizeRuntimeSnapshot(snapshot);
}

export async function fetchQueueSummary(input: { activeRequestId?: string } = {}): Promise<GuardQueueSummary> {
  if (isGuardDemoMode()) {
    return buildDemoRuntimeSnapshot().queue_summary ?? normalizeQueueSummary(null, getDemoRequests().length);
  }
  const params = new URLSearchParams();
  if (input.activeRequestId) {
    params.set("active_request_id", input.activeRequestId);
  }
  params.set("include_receipts", "0");
  const snapshot = await readJson<RuntimeSnapshotPayload>(queuePath("/v1/runtime", params));
  return normalizeQueueSummary(snapshot.queue_summary, snapshot.pending_count);
}

export type GuardReadStatePayload = { ids: string[] };

export async function fetchReadState(): Promise<GuardReadStatePayload> {
  if (isGuardDemoMode()) {
    return { ids: [] };
  }
  return readJson<GuardReadStatePayload>("/v1/read-state");
}

export async function postReadStateMarkRead(requestId: string): Promise<GuardReadStatePayload> {
  if (isGuardDemoMode()) {
    return { ids: [] };
  }
  return readJson<GuardReadStatePayload>("/v1/read-state", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...guardAuthHeaders() },
    body: JSON.stringify({ action: "mark_read", request_id: requestId }),
  });
}

export async function postReadStateMarkUnread(requestId: string): Promise<GuardReadStatePayload> {
  if (isGuardDemoMode()) {
    return { ids: [] };
  }
  return readJson<GuardReadStatePayload>("/v1/read-state", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...guardAuthHeaders() },
    body: JSON.stringify({ action: "mark_unread", request_id: requestId }),
  });
}

export async function postReadStateMarkAllRead(requestIds: string[]): Promise<GuardReadStatePayload> {
  if (isGuardDemoMode()) {
    return { ids: [] };
  }
  return readJson<GuardReadStatePayload>("/v1/read-state", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...guardAuthHeaders() },
    body: JSON.stringify({ action: "mark_all_read", request_ids: requestIds }),
  });
}

export function buildDemoRuntimeSnapshot(): GuardRuntimeSnapshot {
  const demoRequests = getDemoRequests();
  const demoReceipts = getDemoReceipts();
  const now = new Date().toISOString();
  const cloudState = "paired_waiting";
  const cloudLabel = "Connected";
  const cloudDetail =
    "This machine is connected to Guard Cloud, but the first protected session has not landed yet. Open Watched Apps while the first sync settles.";
  const dashboardUrl = "https://hol.org/guard";
  const inboxUrl = "https://hol.org/guard/inbox";
  const fleetUrl = "https://hol.org/guard/protect";
  const connectUrl = "https://hol.org/guard/connect";
  return {
    generated_at: now,
    approval_center_url: "http://127.0.0.1:4455",
    runtime_state: {
      session_id: "demo-runtime",
      daemon_host: "127.0.0.1",
      daemon_port: 4455,
      started_at: now,
      last_heartbeat_at: now,
      approval_center_url: "http://127.0.0.1:4455"
    },
    device: {
      installation_id: "demo-device-7f4a9c2d",
      device_label: "Demo MacBook Pro",
      local_registered: true
    },
    latest_connect_state: {
      request_id: "demo-connect-request",
      status: "connected",
      milestone: "first_sync_pending",
      reason: "waiting_for_first_sync",
      created_at: now,
      updated_at: now,
      expires_at: now,
      completed_at: now,
      proof: {
        pairing_completed_at: now,
        first_synced_at: null,
        receipts_stored: 0,
        inventory_items: 0,
        runtime_session_id: "demo-runtime",
        runtime_session_synced_at: null
      }
    },
    proof_status: {
      state: "pending",
      label: "First proof pending",
      detail: "Browser pairing finished. Local Guard will retry the first proof sync automatically while the daemon is running, or you can run hol-guard sync now.",
      request_id: "demo-connect-request",
      pairing_completed_at: now,
      first_synced_at: null,
      receipts_stored: 0,
      inventory_items: 0,
      runtime_session_id: "demo-runtime",
      runtime_session_synced_at: null
    },
    pending_count: demoRequests.length,
    receipt_count: demoReceipts.length,
    headline_state: demoRequests.length > 0 ? "needs_decision" : "connected",
    headline_label: demoRequests.length > 0 ? "Decision needed" : "Connected",
    headline_detail:
      demoRequests.length > 0
        ? "An action is waiting for a decision in the review queue."
        : "This machine is connected to Guard Cloud and waiting for the first protected session to appear.",
    sync_configured: true,
    cloud_user_profile: {
      email: "demo@hol.org",
      display_name: "Demo User",
      avatar_url: "",
    },
    cloud_workspace_id: "demo-workspace-282f6ff2",
    cloud_state: cloudState,
    cloud_state_label: cloudLabel,
    cloud_state_detail: cloudDetail,
    cloud_pairing_state: {
      state: cloudState,
      label: cloudLabel,
      detail: cloudDetail,
      sync_configured: true,
      cloud_user_profile: {
        email: "demo@hol.org",
        display_name: "Demo User",
        avatar_url: "",
      },
      workspace_id: "demo-workspace-282f6ff2",
      plan_id: "team",
      dashboard_url: dashboardUrl,
      inbox_url: inboxUrl,
      fleet_url: fleetUrl,
      connect_url: connectUrl
    },
    cloud_sync_health: {
      state: "pending",
      label: "Cloud sync pending",
      detail: "Waiting for the first shared Cloud proof from this machine.",
      pending_events: 1,
      last_synced_at: null,
      next_retry_after: null
    },
    dashboard_url: dashboardUrl,
    inbox_url: inboxUrl,
    fleet_url: fleetUrl,
    connect_url: connectUrl,
    items: demoRequests,
    queue_summary: {
      active_request_id: null,
      next_request_id: demoRequests[0]?.request_id ?? null,
      remaining_pending_count: demoRequests.length,
      next_selectable_request_id: demoRequests[0]?.request_id ?? null
    },
    latest_receipts: demoReceipts.slice(0, 10)
  };
}

export async function fetchInventory(): Promise<GuardInventoryItem[]> {
  if (isGuardDemoMode()) {
    return [];
  }
  const payload = await readJson<{ items: RawGuardInventoryItem[] }>("/v1/inventory");
  return normalizeInventory(payload.items);
}

export async function fetchSettings(): Promise<GuardSettingsPayload> {
  if (isGuardDemoMode()) {
    return {
      guard_home: "~/.hol-guard",
      config_path: "~/.hol-guard/config.toml",
      settings: {
        mode: "prompt",
        security_level: "balanced",
        default_action: "warn",
        unknown_publisher_action: "review",
        changed_hash_action: "require-reapproval",
        new_network_domain_action: "warn",
        subprocess_action: "warn",
        risk_actions: {
          local_secret_read: "require-reapproval",
          credential_exfiltration: "require-reapproval",
          data_flow_exfiltration: "require-reapproval",
          destructive_shell: "require-reapproval",
          encoded_execution: "require-reapproval",
          network_egress: "warn"
        },
        risk_action_overrides: {},
        harness_risk_actions: {
          codex: {}
        },
        approval_wait_timeout_seconds: 120,
        approval_surface_policy: "attention-aware",
        approval_browser_delay_seconds: 20,
        approval_browser_immediate_severity: "critical",
        telemetry: false,
        sync: false,
        billing: false
      }
    };
  }
  return readJson<GuardSettingsPayload>("/v1/settings");
}

export async function updateSettings(settings: Partial<GuardSettings>): Promise<GuardSettingsPayload> {
  if (isGuardDemoMode()) {
    const current = await fetchSettings();
    return { ...current, settings: { ...current.settings, ...settings } };
  }
  return readJson<GuardSettingsPayload>("/v1/settings", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...guardAuthHeaders()
    },
    body: JSON.stringify({ settings })
  });
}

export async function exportSettings(): Promise<GuardSettingsExport> {
  if (isGuardDemoMode()) {
    const current = await fetchSettings();
    return {
      schema_version: 1,
      privacy_warning: "Exports include local Guard preferences but not secrets or receipt evidence.",
      settings: current.settings
    };
  }
  return readJson<GuardSettingsExport>("/v1/settings/export");
}

export type ApprovalGateWriteProof = {
  approval_password?: string;
  approval_totp_code?: string;
};

export async function importSettings(
  settingsExport: GuardSettingsExport,
  proof?: ApprovalGateWriteProof,
): Promise<GuardSettingsPayload> {
  if (isGuardDemoMode()) {
    return { guard_home: "~/.hol-guard", config_path: "~/.hol-guard/config.toml", settings: settingsExport.settings };
  }
  return readJson<GuardSettingsPayload>("/v1/settings/import", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...guardAuthHeaders()
    },
    body: JSON.stringify({
      ...settingsExport,
      ...(proof?.approval_password ? { approval_password: proof.approval_password } : {}),
      ...(proof?.approval_totp_code ? { approval_totp_code: proof.approval_totp_code } : {}),
    })
  });
}

export async function resetSettings(proof?: ApprovalGateWriteProof): Promise<GuardSettingsPayload> {
  if (isGuardDemoMode()) {
    return fetchSettings();
  }
  return readJson<GuardSettingsPayload>("/v1/settings/reset", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...guardAuthHeaders()
    },
    body: JSON.stringify({
      confirm: "reset-local-settings",
      ...(proof?.approval_password ? { approval_password: proof.approval_password } : {}),
      ...(proof?.approval_totp_code ? { approval_totp_code: proof.approval_totp_code } : {}),
    })
  });
}

export async function fetchRequest(requestId: string): Promise<GuardApprovalRequest> {
  if (isGuardDemoMode()) {
    return getDemoRequest(requestId);
  }
  const payload = await readJson<RawGuardApprovalRequest>(`/v1/requests/${requestId}`);
  return normalizeApprovalRequest(payload);
}

function normalizeReceipt(item: RawGuardReceipt): GuardReceipt {
  const policyAction = normalizeGuardAction(item.policy_decision);
  const actionEnvelope = parseActionEnvelope(item.action_envelope_json);
  const legacyActionMetadata = parseLegacyPackageActionMetadata(item.action_envelope_json);
  const hasUnknownPolicyAction = !isRecognizedGuardActionInput(item.policy_decision);
  const hasMalformedActionEnvelope =
    item.action_envelope_json !== undefined &&
    item.action_envelope_json !== null &&
    actionEnvelope === null &&
    !(legacyActionMetadata.recognized && legacyActionMetadata.action !== null);
  const hasContradictoryActionEnvelope =
    (actionEnvelope !== null &&
      [actionEnvelope.pre_execution_result, actionEnvelope.policy_action].some(
        (action) => action !== undefined && action !== null && action !== policyAction,
      )) ||
    (legacyActionMetadata.recognized && legacyActionMetadata.action !== policyAction);
  const hasDecisionContractError =
    item.decision_contract_error !== undefined ||
    hasUnknownPolicyAction ||
    hasMalformedActionEnvelope ||
    hasContradictoryActionEnvelope;
  const failClosedPolicyAction = hasDecisionContractError
    ? mostRestrictiveGuardAction(
        policyAction,
        "require-reapproval",
        actionEnvelope?.pre_execution_result,
        actionEnvelope?.policy_action,
        legacyActionMetadata.action,
      )
    : policyAction;
  return {
    ...item,
    policy_decision: failClosedPolicyAction,
    action_envelope_json: hasDecisionContractError ? null : actionEnvelope,
    ...(hasDecisionContractError
      ? { decision_contract_error: AUTHORITATIVE_DECISION_INCONSISTENT }
      : {}),
  };
}

function normalizeReceipts(items: RawGuardReceipt[] | null | undefined): GuardReceipt[] {
  if (!Array.isArray(items)) {
    return [];
  }
  return items.map(normalizeReceipt);
}

function normalizeInventory(items: RawGuardInventoryItem[] | null | undefined): GuardInventoryItem[] {
  if (!Array.isArray(items)) {
    return [];
  }
  return items.map((item) => {
    const hasDecisionContractError =
      item.decision_contract_error !== undefined || !isRecognizedGuardActionInput(item.last_policy_action);
    return {
      ...item,
      last_policy_action: hasDecisionContractError
        ? mostRestrictiveGuardAction(item.last_policy_action, "require-reapproval")
        : normalizeGuardAction(item.last_policy_action),
      ...(hasDecisionContractError
        ? { decision_contract_error: AUTHORITATIVE_DECISION_INCONSISTENT }
        : {}),
    };
  });
}

export async function fetchReceipts(): Promise<GuardReceipt[]> {
  if (isGuardDemoMode()) {
    return getDemoReceipts();
  }
  const payload = await readJson<{ items: RawGuardReceipt[] }>("/v1/receipts");
  return normalizeReceipts(payload.items);
}

function normalizeReceiptAnalyticsBucket(raw: unknown): GuardReceiptAnalyticsBucket | null {
  if (!isRecord(raw)) return null;
  const dateKey = raw["date_key"];
  const label = raw["label"];
  if (typeof dateKey !== "string" || typeof label !== "string") return null;
  return {
    date_key: dateKey,
    label: label,
    allowed: isNonNegativeNumber(raw["allowed"]) ? raw["allowed"] : 0,
    blocked: isNonNegativeNumber(raw["blocked"]) ? raw["blocked"] : 0,
    reviewed: isNonNegativeNumber(raw["reviewed"]) ? raw["reviewed"] : 0,
  };
}

export function normalizeReceiptAnalytics(raw: unknown): GuardReceiptAnalytics | null {
  if (!isRecord(raw)) return null;
  const dailyRaw = raw["daily_activity"];
  const trendRaw = raw["trend_buckets"];
  const harnessRaw = raw["by_harness"];
  const artifactRaw = raw["top_artifacts"];
  const daily_activity = Array.isArray(dailyRaw)
    ? dailyRaw
        .map((entry) => {
          if (!isRecord(entry) || typeof entry["date_key"] !== "string") return null;
          return {
            date_key: entry["date_key"],
            total: isNonNegativeNumber(entry["total"]) ? entry["total"] : 0,
          };
        })
        .filter((entry): entry is GuardReceiptDailyActivity => entry !== null)
    : [];
  const trend_buckets = Array.isArray(trendRaw)
    ? trendRaw.map(normalizeReceiptAnalyticsBucket).filter((entry): entry is GuardReceiptAnalyticsBucket => entry !== null)
    : [];
  const by_harness = Array.isArray(harnessRaw)
    ? harnessRaw
        .map((entry) => {
          if (!isRecord(entry) || typeof entry["harness"] !== "string") return null;
          return {
            harness: entry["harness"],
            total: isNonNegativeNumber(entry["total"]) ? entry["total"] : 0,
            allowed: isNonNegativeNumber(entry["allowed"]) ? entry["allowed"] : 0,
            blocked: isNonNegativeNumber(entry["blocked"]) ? entry["blocked"] : 0,
          };
        })
        .filter((entry): entry is GuardReceiptHarnessStat => entry !== null)
    : [];
  const top_artifacts = Array.isArray(artifactRaw)
    ? artifactRaw
        .map((entry) => {
          if (!isRecord(entry) || typeof entry["name"] !== "string") return null;
          return {
            name: entry["name"],
            total: isNonNegativeNumber(entry["total"]) ? entry["total"] : 0,
            allowed: isNonNegativeNumber(entry["allowed"]) ? entry["allowed"] : 0,
            blocked: isNonNegativeNumber(entry["blocked"]) ? entry["blocked"] : 0,
          };
        })
        .filter((entry): entry is GuardReceiptArtifactStat => entry !== null)
    : [];

  return {
    total: isNonNegativeNumber(raw["total"]) ? raw["total"] : 0,
    allowed: isNonNegativeNumber(raw["allowed"]) ? raw["allowed"] : 0,
    blocked: isNonNegativeNumber(raw["blocked"]) ? raw["blocked"] : 0,
    reviewed: isNonNegativeNumber(raw["reviewed"]) ? raw["reviewed"] : 0,
    first_activity_at: isStringOrNull(raw["first_activity_at"]) ? raw["first_activity_at"] : null,
    last_activity_at: isStringOrNull(raw["last_activity_at"]) ? raw["last_activity_at"] : null,
    active_day_streak: isNonNegativeNumber(raw["active_day_streak"]) ? raw["active_day_streak"] : 0,
    peak_day_total: isNonNegativeNumber(raw["peak_day_total"]) ? raw["peak_day_total"] : 0,
    daily_activity,
    trend_buckets,
    by_harness,
    top_artifacts,
    loaded_sample_limit: isNonNegativeNumber(raw["loaded_sample_limit"]) ? raw["loaded_sample_limit"] : 200,
  };
}

function buildReceiptAnalyticsFromSample(receipts: GuardReceipt[]): GuardReceiptAnalytics {
  const allowed = receipts.filter((r) => guardActionDisposition(r.policy_decision) === "allowed").length;
  const blocked = receipts.filter((r) => guardActionDisposition(r.policy_decision) === "blocked").length;
  const reviewed = receipts.length - allowed - blocked;
  const timestamps = receipts.map((r) => r.timestamp).sort();
  const trend_buckets: GuardReceiptAnalyticsBucket[] = computeTrendBuckets(receipts, 7).map((bucket) => ({
    date_key: bucket.dateKey,
    label: bucket.label,
    allowed: bucket.allowed,
    blocked: bucket.blocked,
    reviewed: bucket.reviewed,
  }));
  const dailyMap = new Map<string, number>();
  for (const receipt of receipts) {
    const d = new Date(receipt.timestamp);
    const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
    dailyMap.set(key, (dailyMap.get(key) ?? 0) + 1);
  }
  const daily_activity: GuardReceiptDailyActivity[] = [];
  const oneDay = 24 * 60 * 60 * 1000;
  const nowMs = Date.now();
  for (let offset = 89; offset >= 0; offset -= 1) {
    const d = new Date(nowMs - offset * oneDay);
    const date_key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
    daily_activity.push({ date_key, total: dailyMap.get(date_key) ?? 0 });
  }
  let active_day_streak = 0;
  const streakEntries = [...daily_activity].reverse();
  if (streakEntries[0]?.total === 0) {
    streakEntries.shift();
  }
  for (const entry of streakEntries) {
    if (entry.total > 0) active_day_streak += 1;
    else break;
  }
  return {
    total: receipts.length,
    allowed,
    blocked,
    reviewed,
    first_activity_at: timestamps[0] ?? null,
    last_activity_at: timestamps[timestamps.length - 1] ?? null,
    active_day_streak,
    peak_day_total: Math.max(...daily_activity.map((entry) => entry.total), 0),
    daily_activity,
    trend_buckets,
    by_harness: [],
    top_artifacts: [],
    loaded_sample_limit: receipts.length,
  };
}

export async function fetchReceiptAnalytics(): Promise<GuardReceiptAnalytics> {
  if (isGuardDemoMode()) {
    return buildReceiptAnalyticsFromSample(getDemoReceipts());
  }
  const payload = await readJson<unknown>("/v1/receipts/analytics?activity_days=90&trend_days=7&top_limit=8");
  const normalized = normalizeReceiptAnalytics(payload);
  if (!normalized) {
    throw new Error("Invalid receipt analytics payload");
  }
  return normalized;
}

export async function publishInsightsShare(input: {
  includeTopArtifacts?: boolean;
  showDisplayName?: boolean;
  displayName?: string;
}): Promise<GuardInsightsShareResult> {
  if (isGuardDemoMode()) {
    return {
      slug: "demo-share",
      publicUrl: "https://hol.org/guard/insights/demo-share",
      ogImageUrl: "https://hol.org/hol-og-image.jpg",
      expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
    };
  }
  const payload = await readJson<unknown>("/v1/insights/share", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      includeTopArtifacts: input.includeTopArtifacts ?? false,
      showDisplayName: input.showDisplayName ?? false,
      displayName: input.displayName,
    }),
  });
  if (!payload || typeof payload !== "object") {
    throw new Error("Invalid insights share response");
  }
  const record = payload as Record<string, unknown>;
  const slug = record.slug;
  const publicUrl = record.publicUrl;
  const ogImageUrl = record.ogImageUrl;
  const expiresAt = record.expiresAt;
  if (
    typeof slug === "string" &&
    typeof publicUrl === "string" &&
    typeof ogImageUrl === "string" &&
    typeof expiresAt === "string"
  ) {
    return { slug, publicUrl, ogImageUrl, expiresAt };
  }
  if (typeof record.message === "string" && record.message.trim()) {
    throw new Error(record.message);
  }
  if (typeof record.error === "string" && record.error.trim()) {
    throw new Error(record.error);
  }
  throw new Error("Invalid insights share response");
}

function normalizeGuardCloudConnectStatus(value: unknown): GuardCloudConnectStatusResponse {
  if (!isRecord(value)) {
    return { connect_required: false, connect_flow: null };
  }
  return {
    connect_required: value.connect_required === true,
    connect_flow: normalizePackageFirewallConnectFlow(value.connect_flow),
  };
}

export async function fetchGuardCloudConnectStatus(): Promise<GuardCloudConnectStatusResponse> {
  return normalizeGuardCloudConnectStatus(await readJson<unknown>("/v1/cloud/connect"));
}

export async function startGuardCloudConnect(): Promise<GuardCloudConnectStatusResponse> {
  return normalizeGuardCloudConnectStatus(
    await readJson<unknown>("/v1/cloud/connect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    }),
  );
}

export async function fetchLatestReceipt(
  artifactId: string,
  harness: string
): Promise<GuardReceipt | null> {
  if (isGuardDemoMode()) {
    return getDemoReceipts().find((entry) => entry.artifact_id === artifactId) ?? null;
  }
  const response = await fetchGuardApi(
    `/v1/receipts/latest?harness=${encodeURIComponent(harness)}&artifact_id=${encodeURIComponent(artifactId)}`
  );
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(`Receipt request failed with ${response.status}`);
  }
  return normalizeReceipt((await response.json()) as RawGuardReceipt);
}

export async function fetchPolicy(harness: string): Promise<GuardPolicyDecision[]> {
  if (isGuardDemoMode()) {
    return getDemoPolicy(harness);
  }
  const payload = await readJson<{ items: GuardPolicyDecision[] }>(
    `/v1/policy?harness=${encodeURIComponent(harness)}`
  );
  return payload.items;
}


export async function fetchCloudExceptions(harness?: string): Promise<GuardCloudException[]> {
  if (isGuardDemoMode()) {
    return [];
  }
  const query = harness ? `?harness=${encodeURIComponent(harness)}` : "";
  const payload = await readJson<{ items: GuardCloudException[] }>(`/v1/policy/cloud-exceptions${query}`);
  return payload.items;
}

export type GuardCloudExceptionRequestCreateInput = {
  scope: "artifact" | "publisher" | "harness" | "workspace";
  harness?: string | null;
  artifactId?: string | null;
  publisher?: string | null;
  requestedBy: string;
  reason: string;
  owner: string;
  requestedExpiresAt: string;
  sourceReceiptId?: string | null;
  sourceReviewItemId?: string | null;
  projectId?: string | null;
  workspaceId?: string | null;
  workingDirectory?: string | null;
  teamId?: string | null;
  stepUpChallengeId?: string | null;
};

export type GuardCloudExceptionRequestItem = {
  requestId: string;
  scope: GuardCloudExceptionRequestCreateInput["scope"];
  status: "pending" | "approved" | "rejected";
  reason: string;
  owner: string;
  requestedAt: string;
  requestedExpiresAt: string;
};

export type GuardCloudExceptionRequestListResponse = {
  generatedAt: string;
  items: GuardCloudExceptionRequestItem[];
};

export async function fetchCloudExceptionRequests(): Promise<GuardCloudExceptionRequestListResponse> {
  if (isGuardDemoMode()) {
    return { generatedAt: new Date().toISOString(), items: [] };
  }
  return readJson<GuardCloudExceptionRequestListResponse>("/v1/policy/cloud-exception-requests");
}

export async function createCloudExceptionRequest(
  input: GuardCloudExceptionRequestCreateInput,
): Promise<GuardCloudExceptionRequestListResponse> {
  if (isGuardDemoMode()) {
    return {
      generatedAt: new Date().toISOString(),
      items: [
        {
          requestId: "demo-exception-request",
          scope: input.scope,
          status: "pending",
          reason: input.reason,
          owner: input.owner,
          requestedAt: new Date().toISOString(),
          requestedExpiresAt: input.requestedExpiresAt,
        },
      ],
    };
  }
  return readJson<GuardCloudExceptionRequestListResponse>("/v1/policy/cloud-exception-requests", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...guardAuthHeaders(),
    },
    body: JSON.stringify(input),
  });
}

export async function fetchPolicies(): Promise<GuardPolicyDecision[]> {
  if (isGuardDemoMode()) {
    return getDemoPolicy("codex");
  }
  const payload = await readJson<{ items: GuardPolicyDecision[] }>("/v1/policy");
  return payload.items;
}

export async function savePolicyDecision(input: {
  harness: string;
  scope: DecisionScope;
  action: string;
  artifact_id?: string;
  workspace?: string;
  publisher?: string;
  reason?: string;
  approval_password?: string;
  approval_totp_code?: string;
}): Promise<{ saved: boolean }> {
  if (isGuardDemoMode()) {
    return { saved: true };
  }
  return readJson<{ saved: boolean }>("/v1/policy/decisions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...guardAuthHeaders(),
    },
    body: JSON.stringify(input),
  });
}

export async function clearPolicy(input: {
  harness?: string;
  all?: boolean;
  source?: string;
  scope?: DecisionScope;
  artifact_id?: string;
  artifact_hash?: string;
  artifact_id_is_null?: boolean;
  artifact_hash_is_null?: boolean;
  workspace?: string;
  publisher?: string;
  approval_password?: string;
  approval_totp_code?: string;
}): Promise<{ cleared: number; harness: string | null; source: string | null }> {
  if (isGuardDemoMode()) {
    return { cleared: 0, harness: input.harness ?? null, source: input.source ?? null };
  }
  return readJson<{ cleared: number; harness: string | null; source: string | null }>("/v1/policy/clear", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...guardAuthHeaders()
    },
    body: JSON.stringify({
      harness: input.harness,
      all: input.all ?? false,
      source: input.source,
      scope: input.scope,
      artifact_id: input.artifact_id,
      artifact_hash: input.artifact_hash,
      artifact_id_is_null: input.artifact_id_is_null,
      artifact_hash_is_null: input.artifact_hash_is_null,
      workspace: input.workspace,
      publisher: input.publisher,
      approval_password: input.approval_password,
      approval_totp_code: input.approval_totp_code
    })
  });
}

export async function clearReviewQueue(input: {
  status?: "pending" | "resolved" | "expired";
  harness?: string;
  approval_password?: string;
  approval_totp_code?: string;
}): Promise<{ cleared: number; status: string; harness: string | null }> {
  if (isGuardDemoMode()) {
    return { cleared: 0, status: input.status ?? "pending", harness: input.harness ?? null };
  }
  return readJson<{ cleared: number; status: string; harness: string | null }>("/v1/requests/clear", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...guardAuthHeaders()
    },
    body: JSON.stringify({
      status: input.status ?? "pending",
      harness: input.harness,
      approval_gate:
        input.approval_password || input.approval_totp_code
          ? {
              password: input.approval_password,
              totp_code: input.approval_totp_code
            }
          : undefined
    })
  });
}

export function formatHarnessCommand(command: string[]): string {
  return command
    .map((part) => (/\s/.test(part) ? JSON.stringify(part) : part))
    .join(" ");
}

export async function runHarnessAction(input: {
  harness: string;
  action: GuardHarnessAction;
  dryRun?: boolean;
  confirmationPhrase?: string;
}): Promise<GuardHarnessActionResult> {
  if (!isConnectableAppHarness(input.harness)) {
    throw new Error(`${input.harness} is not a connectable AI app.`);
  }
  if (isGuardDemoMode()) {
    return {
      harness: input.harness,
      action: input.action,
      dry_run: input.action === "verify" ? false : input.dryRun ?? true,
      safe: input.action === "verify" ? true : undefined,
      steps: [],
      managed_install:
        input.action === "install" || input.action === "repair"
          ? {
              harness: input.harness,
              active: true,
              workspace: null,
              manifest: { notes: ["Demo mode only."] },
              updated_at: new Date().toISOString()
            }
          : undefined
    };
  }
  const response = await fetchGuardApi(
    `/v1/harnesses/${encodeURIComponent(input.harness)}/${input.action}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...guardAuthHeaders()
      },
      body: JSON.stringify({
        dry_run: input.dryRun ?? input.action !== "verify",
        confirmation_phrase: input.confirmationPhrase
      })
    }
  );
  const payload = (await response.json().catch(() => null)) as unknown;
  if (!response.ok) {
    throw new GuardHarnessActionError(
      response.status,
      isGuardHarnessActionErrorPayload(payload) ? payload : null
    );
  }
  return payload as GuardHarnessActionResult;
}

export async function fetchDiff(
  artifactId: string,
  harness: string
): Promise<GuardArtifactDiff | null> {
  if (isGuardDemoMode()) {
    return getDemoDiff(artifactId, harness);
  }
  const response = await fetchGuardApi(
    `/v1/artifacts/${encodeURIComponent(artifactId)}/diff?harness=${encodeURIComponent(harness)}`
  );
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(`Diff request failed with ${response.status}`);
  }
  return (await response.json()) as GuardArtifactDiff;
}

function fetchGuardApi(input: RequestInfo, init?: RequestInit): Promise<Response> {
  return fetchWithGuardAuth(input, init);
}

export async function resolveRequest(input: GuardApprovalResolutionInput): Promise<void> {
  await resolveRequestWithQueueResult(input);
}

export type GuardApprovalGateTotpEnrollment = {
  manual_key: string;
  otpauth_uri: string;
  expires_at: string;
};

export type GuardApprovalGateTotpSettingsPayload = GuardSettingsPayload & {
  enrollment?: GuardApprovalGateTotpEnrollment;
};

export async function revokeApprovalGateCooldown(password: string, totpCode?: string): Promise<GuardSettingsPayload> {
  if (isGuardDemoMode()) {
    return fetchSettings();
  }
  const response = await fetch(guardApiInput("/v1/approval-gate/cooldown/revoke"), withGuardAuth({
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...guardAuthHeaders()
    },
    body: JSON.stringify({
      approval_gate: {
        ...(password.trim().length > 0 ? { password } : {}),
        ...(totpCode !== undefined && totpCode.trim().length > 0 ? { totp_code: totpCode } : {})
      }
    })
  }));
  if (!response.ok) {
    throw new Error(await requestErrorMessage(response, `Request failed with ${response.status}`));
  }
  return (await response.json()) as GuardSettingsPayload;
}

export async function enrollApprovalGateTotp(
  currentPassword: string,
  deviceLabel: string
): Promise<GuardApprovalGateTotpSettingsPayload> {
  if (isGuardDemoMode()) {
    return {
      ...(await fetchSettings()),
      enrollment: {
        manual_key: "DEMOSECRET123456",
        otpauth_uri:
          "otpauth://totp/HOL%20Guard:local-device?secret=DEMOSECRET123456&issuer=HOL%20Guard&algorithm=SHA1&digits=6&period=30",
        expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString()
      }
    };
  }
  return readJson<GuardApprovalGateTotpSettingsPayload>("/v1/approval-gate/totp/enroll", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...guardAuthHeaders()
    },
    body: JSON.stringify({
      device_label: deviceLabel,
      approval_gate: {
        password: currentPassword
      }
    })
  });
}

export async function verifyApprovalGateTotp(
  currentPassword: string,
  code: string
): Promise<GuardSettingsPayload> {
  if (isGuardDemoMode()) {
    return fetchSettings();
  }
  return readJson<GuardSettingsPayload>("/v1/approval-gate/totp/verify", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...guardAuthHeaders()
    },
    body: JSON.stringify({
      approval_gate: {
        password: currentPassword
      },
      approval_totp_code: code
    })
  });
}

export async function disableApprovalGateTotp(
  currentPassword: string,
  code: string
): Promise<GuardSettingsPayload> {
  if (isGuardDemoMode()) {
    return fetchSettings();
  }
  return readJson<GuardSettingsPayload>("/v1/approval-gate/totp/disable", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...guardAuthHeaders()
    },
    body: JSON.stringify({
      approval_gate: {
        ...(currentPassword.trim().length > 0 ? { password: currentPassword } : {})
      },
      approval_totp_code: code
    })
  });
}

export async function resolveRequestWithQueueResult(input: GuardApprovalResolutionInput): Promise<GuardQueueResolutionResult> {
  if (isGuardDemoMode()) {
    return {
      resolved: true,
      item: null,
      resolved_request: null,
      remaining_pending_count: 0,
      next_selectable_request_id: null,
      remaining_pending_summaries: [],
      resolved_duplicate_ids: [],
      resolution_summary: "Decision saved.",
      retry_hint: null,
      copy: null,
      codex_resume: null
    };
  }
  const actionPath = input.action === "allow" ? "approve" : "block";
  const path = `/v1/requests/${encodeURIComponent(input.requestId)}/${actionPath}`;
  const init = (guardToken: string | null = readGuardToken()): RequestInit => ({
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...guardAuthHeadersForToken(guardToken)
    },
    body: JSON.stringify({
      action: input.action,
      scope: input.scope,
      workspace: input.workspace || undefined,
      reason: input.reason || undefined,
      ...(input.scope_contract_version !== undefined
        ? { scope_contract_version: input.scope_contract_version }
        : {}),
      ...(input.scope_contract_digest !== undefined
        ? { scope_contract_digest: input.scope_contract_digest }
        : {}),
      ...(input.mcp_grant_target !== undefined ? { mcp_grant_target: input.mcp_grant_target } : {}),
      ...(input.mcp_grant_duration !== undefined ? { mcp_grant_duration: input.mcp_grant_duration } : {}),
      ...(input.approval_password !== undefined ? { approval_password: input.approval_password } : {}),
      ...(input.approval_totp_code !== undefined ? { approval_totp_code: input.approval_totp_code } : {}),
      ...(input.approval_gate_use_cooldown !== undefined ? { approval_gate_use_cooldown: input.approval_gate_use_cooldown } : {})
    })
  });
  const response = await fetchGuardApi(path, init());
  if (!response.ok) {
    throw new Error(await requestErrorMessage(response, `Request failed with ${response.status}`));
  }
  const payload = (await response.json()) as QueueResolutionPayload;
  return normalizeQueueResolution(payload);
}

export type BulkAllowReadOnceResult = {
  resolved_count: number;
  failed: Array<{ request_id: string; error: string }>;
  resolution_summary: string;
};

export async function bulkAllowReadOnce(input: {
  requestIds: string[];
  approval_password?: string;
  approval_totp_code?: string;
  approval_gate_use_cooldown?: boolean;
}): Promise<BulkAllowReadOnceResult> {
  if (isGuardDemoMode()) {
    return {
      resolved_count: input.requestIds.length,
      failed: [],
      resolution_summary: `${input.requestIds.length} read-only file reads approved once.`,
    };
  }
  const payload = await readJson<BulkAllowReadOnceResult>("/v1/requests/bulk-allow-once", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...guardAuthHeaders(),
    },
    body: JSON.stringify({
      request_ids: input.requestIds,
      ...(input.approval_password !== undefined ? { approval_password: input.approval_password } : {}),
      ...(input.approval_totp_code !== undefined ? { approval_totp_code: input.approval_totp_code } : {}),
      approval_gate_use_cooldown: input.approval_gate_use_cooldown ?? false,
    }),
  });
  return {
    resolved_count: payload.resolved_count ?? 0,
    failed: Array.isArray(payload.failed) ? payload.failed : [],
    resolution_summary: payload.resolution_summary ?? "",
  };
}

export async function clearEvidence(): Promise<void> {
  if (isGuardDemoMode()) {
    return;
  }
  await readJson<{ deleted: number }>("/v1/evidence", {
    method: "DELETE",
    headers: guardAuthHeaders()
  });
}

export async function exportDiagnostics(): Promise<Blob> {
  if (isGuardDemoMode()) {
    return new Blob([JSON.stringify({ demo: true, generated_at: new Date().toISOString() })], { type: "application/json" });
  }
  const response = await fetchWithGuardAuth("/v1/evidence/export");
  if (!response.ok) {
    throw new Error(`Export diagnostics failed with ${response.status}`);
  }
  return response.blob();
}

export async function repairApprovalCenter(): Promise<{ repaired: boolean; cleared: string[] }> {
  if (isGuardDemoMode()) {
    return { repaired: true, cleared: ["locator", "daemon_state"] };
  }
  const response = await fetchWithGuardAuth("/v1/daemon/repair", { method: "POST" });
  if (!response.ok) {
    throw new Error(`Repair failed with ${response.status}`);
  }
  return response.json() as Promise<{ repaired: boolean; cleared: string[] }>;
}

export type GuardProtectionRepairResult = {
  repaired: boolean;
  check_ids: string[];
  message: string;
};

export async function repairProtectionCheck(checkId: string): Promise<GuardProtectionRepairResult> {
  if (isGuardDemoMode()) {
    return { repaired: true, check_ids: [checkId], message: "Protection restored." };
  }
  const response = await fetchWithGuardAuth("/v1/protection/repair", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ check_id: checkId }),
  });
  const payload = (await response.json().catch(() => null)) as unknown;
  if (!response.ok) {
    const message = isRecord(payload) ? stringValue(payload.message) : null;
    throw new Error(message ?? `Protection repair failed with ${response.status}`);
  }
  if (!isRecord(payload) || payload.repaired !== true || !Array.isArray(payload.check_ids)) {
    throw new Error("Guard returned an invalid protection repair result.");
  }
  return {
    repaired: true,
    check_ids: payload.check_ids.filter((value): value is string => typeof value === "string"),
    message: stringValue(payload.message) ?? "Protection restored.",
  };
}

function normalizeGuardUpdateVersionCheck(raw: unknown): GuardUpdateVersionCheck {
  const value = isRecord(raw) ? raw : {};
  return {
    source: stringValue(value.source) ?? "pypi",
    status: stringValue(value.status) ?? "unavailable",
    current_version: stringValue(value.current_version),
    latest_version: stringValue(value.latest_version),
    update_available:
      typeof value.update_available === "boolean" ? value.update_available : null,
  };
}

export function normalizeGuardUpdateStatus(raw: unknown): GuardUpdateStatus {
  const value = isRecord(raw) ? raw : {};
  const versionCheck = normalizeGuardUpdateVersionCheck(value.version_check);
  const currentVersion = stringValue(value.current_version) ?? versionCheck.current_version ?? "unknown";
  const latestVersion = stringValue(value.latest_version) ?? versionCheck.latest_version;
  return {
    current_version: currentVersion,
    latest_version: latestVersion,
    installer: stringValue(value.installer) ?? "pip",
    version_check: versionCheck,
    auto_updatable: booleanValue(value.auto_updatable),
    update_available: booleanValue(value.update_available),
    blocked_reason: stringValue(value.blocked_reason),
    recovery_reinstall_available:
      value.recovery_reinstall_available === true ? true : undefined,
    recovery_reinstall_command:
      typeof value.recovery_reinstall_command === "string"
        ? value.recovery_reinstall_command
        : undefined,
    update_in_progress:
      typeof value.update_in_progress === "boolean" ? value.update_in_progress : undefined,
    update_suppressed: value.update_suppressed === true ? true : undefined,
    retry_command: typeof value.retry_command === "string" ? value.retry_command : undefined,
    update_attempt_message:
      typeof value.update_attempt_message === "string" ? value.update_attempt_message : undefined,
  };
}

export async function fetchGuardUpdateStatus(): Promise<GuardUpdateStatus> {
  if (isGuardDemoMode()) {
    return normalizeGuardUpdateStatus({
      current_version: "0.0.0-demo",
      latest_version: "0.0.0-demo",
      installer: "pip",
      version_check: {
        source: "pypi",
        status: "current",
        current_version: "0.0.0-demo",
        latest_version: "0.0.0-demo",
        update_available: false,
      },
      auto_updatable: true,
      update_available: false,
      blocked_reason: null,
    });
  }
  const payload = await readJson<unknown>("/v1/update/status");
  return normalizeGuardUpdateStatus(payload);
}

export async function scheduleGuardUpdate(
  options?: { forcePypiReinstall?: boolean },
): Promise<GuardUpdateScheduleResult> {
  if (isGuardDemoMode()) {
    return {
      scheduled: true,
      message: "Demo mode cannot update Guard.",
    };
  }
  const body =
    options?.forcePypiReinstall === true
      ? JSON.stringify({ force_pypi_reinstall: true })
      : undefined;
  const response = await fetchWithGuardAuth("/v1/update", {
    method: "POST",
    redirect: "error",
    ...(body
      ? { headers: { "Content-Type": "application/json" }, body }
      : {}),
  });
  const payload = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  if (!response.ok) {
    const message =
      stringValue(payload.message) ??
      stringValue(payload.error) ??
      `Guard update failed with ${response.status}`;
    throw new Error(message);
  }
  return {
    scheduled: booleanValue(payload.scheduled),
    message: stringValue(payload.message) ?? undefined,
    error: stringValue(payload.error) ?? undefined,
  };
}

export async function setupDesktopNotifications(): Promise<GuardNotificationSetupResult> {
  if (isGuardDemoMode()) {
    return {
      platform: "Darwin",
      supported: true,
      preview_sent: true,
      settings_opened: true,
      settings_url:
        "x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=fr.julienxx.oss.terminal-notifier",
      already_prompted: false,
      notifier_path: "/usr/local/bin/terminal-notifier",
      guidance:
        "macOS may open the general Notifications list. Choose terminal-notifier, enable Allow Notifications, then enable Banners or Alerts plus Sounds."
    };
  }
  return readJson<GuardNotificationSetupResult>("/v1/notifications/setup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  });
}

export async function fetchResumeStatus(requestId: string): Promise<GuardCodexResumeResult | null> {
  if (isGuardDemoMode()) {
    return null;
  }
  const path = `/v1/requests/${encodeURIComponent(requestId)}/resume`;
  const response = await fetchGuardApi(path);
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(`Resume status request failed with ${response.status}`);
  }
  const payload = (await response.json()) as unknown;
  return normalizeCodexResume(payload);
}

export async function retryResume(requestId: string): Promise<GuardCodexResumeResult | null> {
  if (isGuardDemoMode()) {
    return null;
  }
  const path = `/v1/requests/${encodeURIComponent(requestId)}/resume`;
  const init = (guardToken: string | null = readGuardToken()): RequestInit => ({
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...guardAuthHeadersForToken(guardToken)
    },
    body: JSON.stringify({})
  });
  const response = await fetchGuardApi(path, init());
  if (!response.ok) {
    throw new Error(`Resume retry failed with ${response.status}`);
  }
  const payload = (await response.json()) as unknown;
  return normalizeCodexResume(payload);
}

export type StatusPageData = {
  snapshot: GuardRuntimeSnapshot;
};

export async function loadStatusPage(): Promise<StatusPageData> {
  const snapshot = await fetchRuntimeSnapshot();
  return { snapshot };
}

export type SupplyChainPageData = {
  snapshot: GuardRuntimeSnapshot;
};

export async function loadSupplyChainPage(): Promise<SupplyChainPageData> {
  const snapshot = await fetchRuntimeSnapshot();
  return { snapshot };
}

export type AuditPageData = {
  snapshot: GuardRuntimeSnapshot;
  receipts: GuardReceipt[];
};

export async function loadAuditPage(): Promise<AuditPageData> {
  const [snapshot, receipts] = await Promise.all([
    fetchRuntimeSnapshot(),
    fetchReceipts(),
  ]);
  return { snapshot, receipts };
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function booleanValue(value: unknown): boolean {
  return value === true;
}

function numberValue(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function normalizePackageFirewallEntitlement(value: unknown): PackageFirewallEntitlement {
  const record = isRecord(value) ? value : {};
  return {
    allowed: booleanValue(record.allowed),
    reason: stringValue(record.reason) ?? "unknown",
    tier: stringValue(record.tier) ?? "free",
    upgrade_cta: stringValue(record.upgrade_cta),
    upgrade_url: stringValue(record.upgrade_url),
  };
}

function normalizePackageFirewallReceipt(value: unknown): PackageFirewallReceipt | null {
  if (!isRecord(value)) {
    return null;
  }
  const id = stringValue(value.id);
  const operation = stringValue(value.operation);
  const status = stringValue(value.status);
  const timestamp = stringValue(value.timestamp);
  if (id === null || operation === null || status === null || timestamp === null) {
    return null;
  }
  return { id, operation, status, timestamp };
}

function normalizePackageFirewallActions(
  value: unknown,
): PackageFirewallStatusResponse["actions"] {
  if (!isRecord(value)) {
    return {};
  }
  const allowedStates = new Set([
    "available",
    "connect_required",
    "paid_required",
    "reconnect_required",
    "pending",
    "disabled",
  ]);
  const entries = Object.entries(value).filter(
    (entry): entry is [PackageFirewallActionType | PackageFirewallGlobalActionType, PackageFirewallActionState] =>
      typeof entry[1] === "string" && allowedStates.has(entry[1]),
  );
  return Object.fromEntries(entries);
}

function normalizePackageFirewallCliFallback(value: unknown): PackageFirewallCliFallback | null {
  if (!isRecord(value)) {
    return null;
  }
  const fallback: PackageFirewallCliFallback = {};
  const connect = stringValue(value.connect);
  const install = stringValue(value.install);
  const status = stringValue(value.status);
  const remove = stringValue(value.remove);
  if (connect !== null) {
    fallback.connect = connect;
  }
  if (install !== null) {
    fallback.install = install;
  }
  if (status !== null) {
    fallback.status = status;
  }
  if (remove !== null) {
    fallback.remove = remove;
  }
  return Object.keys(fallback).length > 0 ? fallback : null;
}

function normalizePackageFirewallConnectFlow(
  value: unknown,
): PackageFirewallStatusResponse["connect_flow"] {
  if (!isRecord(value)) {
    return null;
  }
  const state = value.state;
  if (state !== "idle" && state !== "starting" && state !== "running" && state !== "failed") {
    return null;
  }
  const title = stringValue(value.title);
  const detail = stringValue(value.detail);
  const actionLabel = stringValue(value.action_label);
  const connectUrl = stringValue(value.connect_url);
  if (title === null || detail === null || actionLabel === null || connectUrl === null) {
    return null;
  }
  return {
    state,
    title,
    detail,
    action_label: actionLabel,
    connect_url: connectUrl,
    authorize_url: isStringOrNull(value.authorize_url) ? value.authorize_url : null,
    browser_opened: value.browser_opened === true ? true : value.browser_opened === false ? false : null,
    request_id: isStringOrNull(value.request_id) ? value.request_id : null,
    poll_after_ms: numberValue(value.poll_after_ms),
  };
}

function readPackageShimField(
  status: Record<string, unknown>,
  snakeKey: string,
  camelKey: string,
): unknown {
  if (status[snakeKey] !== undefined) {
    return status[snakeKey];
  }
  return status[camelKey];
}

function readPackageShimStringArray(
  status: Record<string, unknown>,
  snakeKey: string,
  camelKey: string,
): string[] {
  return normalizeStringArray(readPackageShimField(status, snakeKey, camelKey));
}

function buildPackageShimPathSummary(detail: Record<string, unknown> | null): string | null {
  if (detail === null) {
    return null;
  }
  const shimPath = stringValue(detail.shim_path);
  const realBinaryPath = stringValue(detail.real_binary_path);
  const pathActive = booleanValue(detail.path_active);
  if (shimPath !== null && realBinaryPath !== null) {
    return pathActive
      ? `${shimPath} precedes ${realBinaryPath}`
      : `${realBinaryPath} precedes ${shimPath}`;
  }
  if (shimPath !== null) {
    return shimPath;
  }
  return stringValue(detail.path_state);
}

function readLastInterceptProofAtByManager(status: Record<string, unknown>): Record<string, string> {
  const merged: Record<string, string> = {};
  const sources = [
    readPackageShimField(status, "last_intercept_proof_at", "lastInterceptProofAt"),
    readPackageShimField(status, "last_test_at", "lastTestAt"),
  ];
  for (const source of sources) {
    if (!isRecord(source)) {
      continue;
    }
    for (const [manager, timestamp] of Object.entries(source)) {
      const normalized = stringValue(timestamp);
      if (normalized !== null) {
        merged[manager] = normalized;
      }
    }
  }
  return merged;
}

function normalizePackageShimEntry(
  manager: string,
  detail: Record<string, unknown> | null,
  pathStatus: PackageManagerProtection["path_status"],
  coverage: {
    detected: boolean;
    pathBroken: boolean;
    tested: boolean;
    lastInterceptProofAt: string | null;
  },
): PackageShimEntry {
  const integrity = stringValue(detail?.integrity) ?? "uninstalled";
  const installed = detail !== null && integrity !== "missing";
  const active = booleanValue(detail?.path_active);
  const pathBroken =
    pathStatus !== "restart_required" &&
    (coverage.pathBroken || detail?.path_broken === true);
  let activation_state: PackageShimEntry["activation_state"];
  if (!installed) {
    activation_state = "uninstalled";
  } else if (integrity === "tampered") {
    activation_state = "repair_required";
  } else if (active) {
    activation_state = "protected";
  } else if (pathStatus === "restart_required") {
    activation_state = "restart_required";
  } else {
    activation_state = "repair_required";
  }
  return {
    active,
    activation_state,
    detected: coverage.detected,
    installed,
    integrity,
    last_intercept_proof_at: coverage.lastInterceptProofAt,
    manager,
    path_broken: pathBroken,
    path_index: numberValue(detail?.path_index),
    path_summary: buildPackageShimPathSummary(detail),
    real_binary_found: booleanValue(detail?.real_binary_found),
    real_binary_path: stringValue(detail?.real_binary_path),
    real_binary_path_index: numberValue(detail?.real_binary_path_index),
    shim_path: stringValue(detail?.shim_path),
    tested: coverage.tested,
  };
}

function normalizePackageShimEntries(
  value: unknown,
  supportedManagers: string[],
  pathStatus: PackageManagerProtection["path_status"],
): PackageShimEntry[] {
  const status = isRecord(value) ? value : {};
  const managerDetailsValue = readPackageShimField(status, "manager_details", "managerDetails");
  const detailRows = Array.isArray(managerDetailsValue) ? managerDetailsValue.filter(isRecord) : [];
  const detailByManager = new Map<string, Record<string, unknown>>();
  for (const detail of detailRows) {
    const manager = stringValue(detail.manager);
    if (manager !== null) {
      detailByManager.set(manager, detail);
    }
  }
  const detectedManagers = readPackageShimStringArray(status, "detected_managers", "detectedManagers");
  const installedManagers = readPackageShimStringArray(status, "installed_managers", "installedManagers");
  const testedManagers = readPackageShimStringArray(status, "tested_managers", "testedManagers");
  const pathBrokenManagers = new Set([
    ...readPackageShimStringArray(status, "path_broken_managers", "pathBrokenManagers"),
  ]);
  const bypassesValue = readPackageShimField(status, "bypasses", "bypasses");
  if (Array.isArray(bypassesValue)) {
    for (const entry of bypassesValue) {
      if (!isRecord(entry)) {
        continue;
      }
      const manager = stringValue(entry.manager);
      if (manager !== null) {
        pathBrokenManagers.add(manager);
      }
    }
  }
  const lastInterceptProofAtByManager = readLastInterceptProofAtByManager(status);
  const detectedSet = new Set(detectedManagers);
  const installedSet = new Set(installedManagers);
  const testedSet = new Set(testedManagers);
  const managers = new Set([
    ...detectedManagers,
    ...installedManagers,
    ...testedManagers,
    ...detailByManager.keys(),
  ]);
  return Array.from(managers)
    .filter((manager) => detectedSet.has(manager) || installedSet.has(manager) || testedSet.has(manager))
    .sort()
    .map((manager) =>
      normalizePackageShimEntry(manager, detailByManager.get(manager) ?? null, pathStatus, {
        detected: detectedSet.has(manager),
        pathBroken: pathBrokenManagers.has(manager),
        tested: testedSet.has(manager),
        lastInterceptProofAt: lastInterceptProofAtByManager[manager] ?? null,
      }),
    );
}

function actionResultSummary(operation: string, detail: Record<string, unknown>): string {
  const countKeys = ["installed_now_count", "repaired_count"];
  for (const key of countKeys) {
    const count = numberValue(detail[key]);
    if (count !== null) {
      return `${operation} completed for ${count} manager${count === 1 ? "" : "s"}.`;
    }
  }
  const tested = normalizeStringArray(detail.tested_managers);
  if (tested.length > 0) {
    return `Test completed for ${tested.join(", ")}.`;
  }
  return `${operation} completed.`;
}

export function normalizePackageFirewallStatus(value: unknown): PackageFirewallStatusResponse {
  const record = isRecord(value) ? value : {};
  const supportedManagers = normalizeStringArray(record.supported_managers);
  const shimStatus = isRecord(record.package_shims) ? record.package_shims : {};
  const installedManagers = readPackageShimStringArray(shimStatus, "installed_managers", "installedManagers");
  const activeManagers = readPackageShimStringArray(shimStatus, "active_managers", "activeManagers");
  const missingManagers = readPackageShimStringArray(shimStatus, "missing_managers", "missingManagers");
  const detectedManagers = readPackageShimStringArray(shimStatus, "detected_managers", "detectedManagers");
  const pathStatusValue = readPackageShimField(shimStatus, "path_status", "pathStatus");
  const rawPathStatus =
    pathStatusValue === "in_path"
      ? "in_path"
      : pathStatusValue === "restart_required"
      ? "restart_required"
      : "missing_from_path";
  const packageShims = normalizePackageShimEntries(record.package_shims, supportedManagers, rawPathStatus);
  const protectedManagers = packageShims
    .filter((shim) => shim.activation_state === "protected")
    .map((shim) => shim.manager);
  const protectedSet = new Set(protectedManagers);
  const lastAuditProofAt =
    stringValue(readPackageShimField(shimStatus, "last_audit_proof_at", "lastAuditProofAt")) ?? null;
  const auditWorkspaceDir = stringValue(record.audit_workspace_dir) ?? null;
  const shellProfilePath = readPackageShimField(shimStatus, "shell_profile_path", "shellProfilePath");
  const protection: PackageManagerProtection = {
    path_status: rawPathStatus,
    path_contains_shim_dir:
      readPackageShimField(shimStatus, "path_contains_shim_dir", "pathContainsShimDir") === true,
    restart_shell_required:
      readPackageShimField(shimStatus, "restart_shell_required", "restartShellRequired") === true,
    shell_profile_configured:
      readPackageShimField(shimStatus, "shell_profile_configured", "shellProfileConfigured") === true,
    shell_profile_path: isStringOrNull(shellProfilePath) ? (shellProfilePath as string | null) : null,
    shim_dir: stringValue(readPackageShimField(shimStatus, "shim_dir", "shimDir")) ?? "",
    supported_managers: supportedManagers,
    installed_managers: installedManagers,
    active_managers: activeManagers,
    missing_shims: missingManagers,
    protected_managers: protectedManagers,
    unprotected_managers: supportedManagers.filter((manager) => !protectedSet.has(manager)),
  };
  return {
    actions: normalizePackageFirewallActions(record.actions),
    audit_workspace_dir: auditWorkspaceDir,
    cli_fallback: normalizePackageFirewallCliFallback(record.cli_fallback),
    connect_flow: normalizePackageFirewallConnectFlow(record.connect_flow),
    detected_managers: detectedManagers,
    entitlement: normalizePackageFirewallEntitlement(record.entitlement),
    last_audit_proof_at: lastAuditProofAt,
    operation: stringValue(record.operation) ?? "status",
    package_shims: packageShims,
    protection,
    status: stringValue(record.status) ?? "unknown",
    supported_managers: supportedManagers,
  };
}

function normalizePackageFirewallAction(value: unknown): PackageFirewallActionResponse {
  const record = isRecord(value) ? value : {};
  const result = isRecord(record.result) ? record.result : {};
  const operation = stringValue(record.operation) ?? "unknown";
  return {
    entitlement: normalizePackageFirewallEntitlement(record.entitlement),
    operation,
    receipt: normalizePackageFirewallReceipt(record.receipt),
    result: typeof record.result === "string" ? record.result : actionResultSummary(operation, result),
    result_detail: result,
    status: stringValue(record.status) ?? "unknown",
  };
}

export async function fetchPackageFirewallStatus(): Promise<PackageFirewallStatusResponse> {
  return normalizePackageFirewallStatus(await readJson<unknown>("/v1/supply-chain/package-shims"));
}

export async function startPackageFirewallConnect(): Promise<PackageFirewallStatusResponse["connect_flow"]> {
  return normalizePackageFirewallConnectFlow(
    await readJson<unknown>("/v1/supply-chain/package-shims/connect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    }),
  );
}

export async function fetchSupplyChainBundle(): Promise<SupplyChainBundle | null> {
  const wrapper = await readJson<unknown>("/v1/supply-chain/bundle");
  if (!wrapper || typeof wrapper !== "object") {
    return null;
  }
  const bundle = (wrapper as Record<string, unknown>).bundle;
  if (bundle === null || bundle === undefined) {
    return null;
  }
  return bundle as SupplyChainBundle;
}

export async function runPackageFirewallAction(
  action: PackageFirewallActionType,
  manager: string | null,
  credentials?: { approval_password?: string; approval_totp_code?: string },
): Promise<PackageFirewallActionResponse> {
  const payload = {
    ...(manager !== null ? { managers: [manager] } : {}),
    ...(credentials?.approval_password !== undefined
      ? { approval_password: credentials.approval_password }
      : {}),
    ...(credentials?.approval_totp_code !== undefined
      ? { approval_totp_code: credentials.approval_totp_code }
      : {}),
  };
  const response = await fetchGuardApi(
    `/v1/supply-chain/package-shims/${action}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...guardAuthHeaders(),
      },
      body: JSON.stringify(payload),
    },
  );
  const payloadBody = (await response.json().catch(() => null)) as unknown;
  if (!response.ok) {
    throw new GuardHarnessActionError(
      response.status,
      isGuardHarnessActionErrorPayload(payloadBody) ? payloadBody : null,
    );
  }
  return normalizePackageFirewallAction(payloadBody);
}

export async function activatePackageFirewallRuntime(): Promise<void> {
  const response = await fetchGuardApi("/v1/supply-chain/package-shims/activate", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...guardAuthHeaders(),
    },
    body: JSON.stringify({}),
  });
  if (response.ok) {
    return;
  }
  const payloadBody = (await response.json().catch(() => null)) as unknown;
  if (isRecord(payloadBody) && typeof payloadBody.message === "string" && payloadBody.message.trim()) {
    throw new Error(payloadBody.message);
  }
  throw new Error("Unable to activate package protection.");
}

export type AuditRemediationAction = "package_shim_path";

export type AuditRemediationInput = {
  action: AuditRemediationAction;
  manager: string;
  approval_password?: string;
  approval_totp_code?: string;
};

export async function runAuditRemediation(input: AuditRemediationInput): Promise<PackageFirewallActionResponse> {
  if (isGuardDemoMode()) {
    return {
      entitlement: { allowed: true, reason: "demo", tier: "demo", upgrade_cta: null, upgrade_url: null },
      operation: input.action,
      receipt: null,
      result: `${input.action} completed for ${input.manager}.`,
      result_detail: { manager: input.manager, demo: true },
      status: "completed",
    };
  }
  const response = await fetchGuardApi(
    `/v1/audit/remediations/${input.action}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...guardAuthHeaders(),
      },
      body: JSON.stringify({
        manager: input.manager,
        ...(input.approval_password !== undefined ? { approval_password: input.approval_password } : {}),
        ...(input.approval_totp_code !== undefined ? { approval_totp_code: input.approval_totp_code } : {}),
      }),
    },
  );
  const payload = (await response.json().catch(() => null)) as unknown;
  if (!response.ok) {
    throw new GuardHarnessActionError(
      response.status,
      isGuardHarnessActionErrorPayload(payload) ? payload : null,
    );
  }
  return normalizePackageFirewallAction(payload);
}

export async function runPackageAudit(input?: {
  workspaceDir?: string | null;
}): Promise<PackageFirewallActionResponse> {
  const workspaceDir = input?.workspaceDir?.trim() ?? null;
  const body: Record<string, string> = {};
  if (workspaceDir) {
    body.workspace_dir = workspaceDir;
  }
  const response = await fetchGuardApi("/v1/supply-chain/audit", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...guardAuthHeaders(),
    },
    body: JSON.stringify(body),
  });
  const payloadBody = (await response.json().catch(() => null)) as unknown;
  if (!response.ok) {
    throw new GuardHarnessActionError(
      response.status,
      isGuardHarnessActionErrorPayload(payloadBody) ? payloadBody : null,
    );
  }
  return normalizePackageFirewallAction(payloadBody);
}

export async function runPackageSync(credentials?: {
  approval_password?: string;
  approval_totp_code?: string;
}): Promise<PackageFirewallActionResponse> {
  const response = await fetchGuardApi("/v1/supply-chain/sync", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...guardAuthHeaders(),
    },
    body: JSON.stringify({
      ...(credentials?.approval_password !== undefined
        ? { approval_password: credentials.approval_password }
        : {}),
      ...(credentials?.approval_totp_code !== undefined
        ? { approval_totp_code: credentials.approval_totp_code }
        : {}),
    }),
  });
  const payloadBody = (await response.json().catch(() => null)) as unknown;
  if (!response.ok) {
    throw new GuardHarnessActionError(
      response.status,
      isGuardHarnessActionErrorPayload(payloadBody) ? payloadBody : null,
    );
  }
  return normalizePackageFirewallAction(payloadBody);
}

export type EvidencePageData = {
  receipts: GuardReceipt[];
};

export async function loadEvidencePage(): Promise<EvidencePageData> {
  const receipts = await fetchReceipts();
  return { receipts };
}

export type PolicyPageData = {
  snapshot: GuardRuntimeSnapshot;
  policies: GuardPolicyDecision[];
};

export async function loadPolicyPage(): Promise<PolicyPageData> {
  const [snapshot, policies] = await Promise.all([
    fetchRuntimeSnapshot(),
    fetchPolicies(),
  ]);
  return { snapshot, policies };
}

export type FeedPageData = {
  snapshot: GuardRuntimeSnapshot;
};

export async function loadFeedPage(): Promise<FeedPageData> {
  const snapshot = await fetchRuntimeSnapshot();
  return { snapshot };
}

export {
  derivePackageWorkbenchFromReceipts,
  filterPackageWorkbenchFindings,
  normalizeSupplyChainAuditSnapshot,
  packageWorkbenchEcosystems,
  sortPackageWorkbenchFindings,
} from "./supply-chain-audit-normalize";
