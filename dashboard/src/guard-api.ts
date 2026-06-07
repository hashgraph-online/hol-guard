import {
  GUARD_ACTION_TYPES,
  GUARD_DECISION_V2_ACTIONS,
  GUARD_DECISION_V2_CONFIDENCES,
  GUARD_RISK_SIGNAL_V2_CATEGORIES,
  GUARD_RISK_SIGNAL_V2_REDACTION_LEVELS,
  GUARD_RISK_SIGNAL_V2_SEVERITIES,
  CODEX_RESUME_STATUSES
} from "./guard-types";
import type {
  GuardActionEnvelope,
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
  PackageManagerProtection,
  CodexResumeStatus,
  GuardCodexResumeResult,
  GuardQueueResolutionCopy,
  GuardQueueResolutionResult,
  GuardQueueSummary,
  GuardReceipt,
  GuardRuntimeSnapshot,
  SupplyChainSnapshot,
  GuardSettingsPayload,
  GuardSettingsExport,
  GuardSettings,
  GuardUpdateScheduleResult,
  GuardUpdateReconnectOptions,
  GuardUpdateStatus,
  GuardUpdateVersionCheck,
  DecisionScope,
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
let guardTokenOverride: string | null = null;
let guardTokenLocationKey: string | null = null;

type RawGuardApprovalRequest = Omit<GuardApprovalRequest, "action_envelope_json" | "decision_v2_json"> & {
  action_envelope_json?: unknown;
  decision_v2_json?: unknown;
};

type ApprovalRequestListPayload = {
  items?: RawGuardApprovalRequest[] | null;
  next_cursor?: unknown;
  total_pending_count?: unknown;
  total_count?: unknown;
  status?: unknown;
};

type RuntimeSnapshotPayload = Omit<GuardRuntimeSnapshot, "items" | "supply_chain"> & {
  items?: RawGuardApprovalRequest[] | null;
  queue_summary?: unknown;
  supply_chain?: unknown;
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

function readGuardToken(): string | null {
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
    window.sessionStorage.setItem(GUARD_TOKEN_PARAM, guardToken);
    return guardToken;
  }
  return window.sessionStorage.getItem(GUARD_TOKEN_PARAM);
}

function saveGuardToken(guardToken: string): void {
  guardTokenOverride = guardToken;
  window.sessionStorage.setItem(GUARD_TOKEN_PARAM, guardToken);
}

function saveGuardDaemonOrigin(daemonOrigin: string): void {
  window.sessionStorage.setItem(GUARD_DAEMON_PARAM, daemonOrigin);
}

function preferredGuardDaemonPort(): number {
  const fromOrigin = readGuardDaemonOrigin();
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
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), GUARD_DAEMON_PROBE_TIMEOUT_MS);
  try {
    const response = await fetch(`${origin}/healthz`, { signal: controller.signal });
    if (!response.ok) {
      return false;
    }
    const payload = (await response.json()) as Record<string, unknown>;
    return payload.ok === true && payload.compatibility_version === 2;
  } catch {
    return false;
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

function updateReconnectSucceeded(
  status: GuardUpdateStatus,
  options: GuardUpdateReconnectOptions,
): boolean {
  if (!options.expectedPreviousVersion) {
    return true;
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
  return status.current_version !== options.expectedPreviousVersion;
}

async function initializeGuardDashboardSessionAtOrigin(
  origin: string,
  guardToken: string | null,
): Promise<string | null> {
  try {
    const response = await fetch(`${origin}/v1/initialize`, {
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
    });
    if (!response.ok) {
      return null;
    }
    return parseDashboardSessionToken(await response.json());
  } catch {
    return null;
  }
}

export async function fetchGuardUpdateStatusAtOrigin(
  origin: string,
  guardToken: string | null,
): Promise<GuardUpdateStatus> {
  const response = await fetch(`${origin}/v1/update/status`, {
    headers: guardToken ? { "X-Guard-Dashboard-Session": guardToken } : {},
  });
  if (!response.ok) {
    throw new Error(`Update status failed with ${response.status}`);
  }
  return normalizeGuardUpdateStatus(await response.json());
}

function redirectToGuardDaemonOrigin(
  origin: string,
  guardToken: string | null,
): void {
  const url = new URL(origin);
  url.pathname = window.location.pathname;
  url.search = window.location.search;
  const fragmentPairs: string[] = [];
  if (guardToken) {
    fragmentPairs.push(`${GUARD_TOKEN_PARAM}=${encodeURIComponent(guardToken)}`);
  }
  fragmentPairs.push(`${GUARD_DAEMON_PARAM}=${encodeURIComponent(origin)}`);
  url.hash = fragmentPairs.join("&");
  window.location.replace(url.toString());
}

export async function reconnectGuardDaemonAfterUpdate(
  options?: GuardUpdateReconnectOptions,
): Promise<string | null> {
  const guardToken = readGuardToken();
  const reconnectOptions = options ?? {};
  const awaitingVersionChange = Boolean(reconnectOptions.expectedPreviousVersion);
  const ports = buildGuardDaemonCandidatePorts(preferredGuardDaemonPort());

  for (let index = 0; index < ports.length; index += GUARD_DAEMON_DISCOVERY_PROBE_BATCH_SIZE) {
    const batch = ports.slice(index, index + GUARD_DAEMON_DISCOVERY_PROBE_BATCH_SIZE);
    const results = await Promise.all(
      batch.map(async (port) => {
        const origin = `http://127.0.0.1:${port}`;
        if (!(await probeGuardDaemonHealth(origin))) {
          return null;
        }
        try {
          const status = await fetchGuardUpdateStatusAtOrigin(origin, guardToken);
          if (awaitingVersionChange && !updateReconnectSucceeded(status, reconnectOptions)) {
            return null;
          }
          return { origin, status };
        } catch {
          return null;
        }
      }),
    );

    const active = results.find((result) => result !== null);
    if (!active) {
      continue;
    }

    const { origin } = active;
    saveGuardDaemonOrigin(origin);
    const refreshedToken = await initializeGuardDashboardSessionAtOrigin(origin, guardToken);
    if (refreshedToken) {
      saveGuardToken(refreshedToken);
    }

    if (origin !== window.location.origin) {
      redirectToGuardDaemonOrigin(origin, refreshedToken ?? guardToken);
    }

    return origin;
  }

  return null;
}

function readGuardDaemonOrigin(): string | null {
  const rawDaemonUrl = guardParam(GUARD_DAEMON_PARAM);
  if (rawDaemonUrl) {
    const daemonOrigin = localGuardDaemonOrigin(rawDaemonUrl);
    if (daemonOrigin) {
      window.sessionStorage.setItem(GUARD_DAEMON_PARAM, daemonOrigin);
      return daemonOrigin;
    }
  }
  const storedDaemonUrl = window.sessionStorage.getItem(GUARD_DAEMON_PARAM);
  return storedDaemonUrl ? localGuardDaemonOrigin(storedDaemonUrl) : null;
}

function localGuardDaemonOrigin(rawUrl: string): string | null {
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]", "::1"].includes(url.hostname)) {
      return null;
    }
    if (url.username || url.password || (url.pathname && url.pathname !== "/") || url.search || url.hash) {
      return null;
    }
    return url.origin;
  } catch {
    return null;
  }
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
      })
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

export function parseActionEnvelope(raw: unknown): GuardActionEnvelope | null {
  if (!isRecord(raw)) {
    return null;
  }
  const schemaVersion = raw["schema_version"];
  const actionId = raw["action_id"];
  const harness = raw["harness"];
  const eventName = raw["event_name"];
  const actionType = raw["action_type"];
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
    !isStringOrNull(scriptName)
  ) {
    return null;
  }
  if (!isStringArray(targetPaths) || !isStringArray(networkHosts)) {
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
    !isDecisionV2Action(action) ||
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

export function normalizeApprovalRequest(item: RawGuardApprovalRequest): GuardApprovalRequest {
  return {
    ...item,
    action_envelope_json: parseActionEnvelope(item.action_envelope_json),
    decision_v2_json: parseDecisionV2(item.decision_v2_json)
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

export function normalizeRuntimeSnapshot(snapshot: RuntimeSnapshotPayload): GuardRuntimeSnapshot {
  return {
    ...snapshot,
    items: normalizeApprovalRequests(snapshot.items),
    queue_summary: normalizeQueueSummary(snapshot.queue_summary, snapshot.pending_count),
    supply_chain: normalizeSupplyChainSnapshot(snapshot.supply_chain),
    managed_installs: normalizeManagedInstalls(snapshot.managed_installs),
  };
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
  return params;
}

function queuePath(basePath: string, params: URLSearchParams): string {
  const query = params.toString();
  return query ? `${basePath}?${query}` : basePath;
}

const PENDING_QUEUE_PAGE_LIMIT = 200;
const MAX_PENDING_QUEUE_PAGES = 50;

export async function fetchAllPendingRequests(): Promise<GuardApprovalRequest[]> {
  if (isGuardDemoMode()) {
    return getDemoRequests();
  }
  const items: GuardApprovalRequest[] = [];
  let cursor: string | undefined;
  for (let pageIndex = 0; pageIndex < MAX_PENDING_QUEUE_PAGES; pageIndex += 1) {
    const page = await fetchApprovalPage({
      status: "pending",
      limit: PENDING_QUEUE_PAGE_LIMIT,
      cursor,
    });
    items.push(...page.items);
    if (!page.next_cursor || page.next_cursor === cursor) {
      return items;
    }
    cursor = page.next_cursor;
  }
  return items;
}

export async function fetchInboxState(input: { activeRequestId?: string } = {}): Promise<{
  snapshot: GuardRuntimeSnapshot;
  items: GuardApprovalRequest[];
}> {
  if (isGuardDemoMode()) {
    const snapshot = buildDemoRuntimeSnapshot();
    return { snapshot, items: snapshot.items };
  }
  const params = new URLSearchParams();
  if (input.activeRequestId) {
    params.set("active_request_id", input.activeRequestId);
  }
  const [snapshotPayload, items] = await Promise.all([
    readJson<RuntimeSnapshotPayload>(queuePath("/v1/runtime", params)),
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

export async function fetchRuntimeSnapshot(): Promise<GuardRuntimeSnapshot> {
  if (isGuardDemoMode()) {
    return buildDemoRuntimeSnapshot();
  }
  const snapshot = await readJson<RuntimeSnapshotPayload>("/v1/runtime");
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
  const snapshot = await readJson<RuntimeSnapshotPayload>(queuePath("/v1/runtime", params));
  return normalizeQueueSummary(snapshot.queue_summary, snapshot.pending_count);
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
  const fleetUrl = "https://hol.org/guard/fleet";
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
    headline_state: demoRequests.length > 0 ? "blocked" : "connected",
    headline_label: demoRequests.length > 0 ? "Blocked" : "Connected",
    headline_detail:
      demoRequests.length > 0
        ? "A blocked action is waiting for review."
        : "This machine is connected to Guard Cloud and waiting for the first protected session to appear.",
    sync_configured: true,
    cloud_state: cloudState,
    cloud_state_label: cloudLabel,
    cloud_state_detail: cloudDetail,
    cloud_pairing_state: {
      state: cloudState,
      label: cloudLabel,
      detail: cloudDetail,
      sync_configured: true,
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
  const payload = await readJson<{ items: GuardInventoryItem[] }>("/v1/inventory");
  return payload.items;
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
        approval_surface_policy: "auto-open-once",
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

type RawGuardReceipt = Omit<GuardReceipt, "action_envelope_json"> & {
  action_envelope_json?: unknown;
};

function normalizeReceipt(item: RawGuardReceipt): GuardReceipt {
  return {
    ...item,
    action_envelope_json: parseActionEnvelope(item.action_envelope_json)
  };
}

function normalizeReceipts(items: RawGuardReceipt[] | null | undefined): GuardReceipt[] {
  if (!Array.isArray(items)) {
    return [];
  }
  return items.map(normalizeReceipt);
}

export async function fetchReceipts(): Promise<GuardReceipt[]> {
  if (isGuardDemoMode()) {
    return getDemoReceipts();
  }
  const payload = await readJson<{ items: RawGuardReceipt[] }>("/v1/receipts");
  return normalizeReceipts(payload.items);
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

export async function fetchPolicies(): Promise<GuardPolicyDecision[]> {
  if (isGuardDemoMode()) {
    return getDemoPolicy("codex");
  }
  const payload = await readJson<{ items: GuardPolicyDecision[] }>("/v1/policy");
  return payload.items;
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

export async function resolveRequest(input: {
  requestId: string;
  action: "allow" | "block";
  scope: DecisionScope;
  workspace?: string;
  reason: string;
}): Promise<void> {
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
        password,
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
        password: currentPassword
      },
      approval_totp_code: code
    })
  });
}

export async function resolveRequestWithQueueResult(input: {
  requestId: string;
  action: "allow" | "block";
  scope: DecisionScope;
  workspace?: string;
  reason: string;
  approval_password?: string;
  approval_totp_code?: string;
  approval_gate_use_cooldown?: boolean;
}): Promise<GuardQueueResolutionResult> {
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
    update_in_progress:
      typeof value.update_in_progress === "boolean" ? value.update_in_progress : undefined,
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

export async function scheduleGuardUpdate(): Promise<GuardUpdateScheduleResult> {
  if (isGuardDemoMode()) {
    return {
      scheduled: true,
      message: "Demo mode cannot update Guard.",
    };
  }
  const response = await fetchWithGuardAuth("/v1/update", { method: "POST" });
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
  if (state !== "idle" && state !== "running" && state !== "failed") {
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

function normalizePackageShimEntry(
  manager: string,
  detail: Record<string, unknown> | null,
  pathStatus: PackageManagerProtection["path_status"],
): PackageShimEntry {
  const integrity = stringValue(detail?.integrity) ?? "uninstalled";
  const installed = detail !== null && integrity !== "missing";
  const active = booleanValue(detail?.path_active);
  const activation_state = !installed
    ? "uninstalled"
    : integrity === "tampered"
    ? "repair_required"
    : active
    ? "protected"
    : pathStatus === "restart_required"
    ? "restart_required"
    : "repair_required";
  return {
    active,
    activation_state,
    installed,
    integrity,
    manager,
    path_index: numberValue(detail?.path_index),
    real_binary_found: booleanValue(detail?.real_binary_found),
    real_binary_path: stringValue(detail?.real_binary_path),
    real_binary_path_index: numberValue(detail?.real_binary_path_index),
    shim_path: stringValue(detail?.shim_path),
  };
}

function normalizePackageShimEntries(
  value: unknown,
  supportedManagers: string[],
  pathStatus: PackageManagerProtection["path_status"],
): PackageShimEntry[] {
  const status = isRecord(value) ? value : {};
  const detailRows = Array.isArray(status.manager_details)
    ? status.manager_details.filter(isRecord)
    : [];
  const detailByManager = new Map<string, Record<string, unknown>>();
  for (const detail of detailRows) {
    const manager = stringValue(detail.manager);
    if (manager !== null) {
      detailByManager.set(manager, detail);
    }
  }
  const managers = new Set([
    ...supportedManagers,
    ...normalizeStringArray(status.installed_managers),
    ...normalizeStringArray(status.active_managers),
    ...detailByManager.keys(),
  ]);
  return Array.from(managers)
    .sort()
    .map((manager) => normalizePackageShimEntry(manager, detailByManager.get(manager) ?? null, pathStatus));
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

function normalizePackageFirewallStatus(value: unknown): PackageFirewallStatusResponse {
  const record = isRecord(value) ? value : {};
  const supportedManagers = normalizeStringArray(record.supported_managers);
  const shimStatus = isRecord(record.package_shims) ? record.package_shims : {};
  const installedManagers = normalizeStringArray(shimStatus.installed_managers);
  const activeManagers = normalizeStringArray(shimStatus.active_managers);
  const missingManagers = normalizeStringArray(shimStatus.missing_managers);
  const rawPathStatus =
    shimStatus["path_status"] === "in_path"
      ? "in_path"
      : shimStatus["path_status"] === "restart_required"
      ? "restart_required"
      : "missing_from_path";
  const packageShims = normalizePackageShimEntries(record.package_shims, supportedManagers, rawPathStatus);
  const protectedManagers = packageShims
    .filter((shim) => shim.activation_state === "protected")
    .map((shim) => shim.manager);
  const protectedSet = new Set(protectedManagers);
  const protection: PackageManagerProtection = {
    path_status: rawPathStatus,
    path_contains_shim_dir: shimStatus["path_contains_shim_dir"] === true,
    restart_shell_required: shimStatus["restart_shell_required"] === true,
    shell_profile_configured: shimStatus["shell_profile_configured"] === true,
    shell_profile_path: isStringOrNull(shimStatus["shell_profile_path"]) ? shimStatus["shell_profile_path"] : null,
    shim_dir: stringValue(shimStatus["shim_dir"]) ?? "",
    supported_managers: supportedManagers,
    installed_managers: installedManagers,
    active_managers: activeManagers,
    missing_shims: missingManagers,
    protected_managers: protectedManagers,
    unprotected_managers: supportedManagers.filter((manager) => !protectedSet.has(manager)),
  };
  return {
    actions: normalizePackageFirewallActions(record.actions),
    cli_fallback: normalizePackageFirewallCliFallback(record.cli_fallback),
    connect_flow: normalizePackageFirewallConnectFlow(record.connect_flow),
    entitlement: normalizePackageFirewallEntitlement(record.entitlement),
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

export async function openPackageFirewallShell(): Promise<void> {
  const response = await fetchGuardApi("/v1/supply-chain/package-shims/open-shell", {
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
  throw new Error("Unable to open a new shell.");
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
      entitlement: { allowed: true, tier: "demo" },
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

export async function runPackageAudit(): Promise<PackageFirewallActionResponse> {
  const response = await readJson<unknown>("/v1/supply-chain/audit", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...guardAuthHeaders(),
    },
    body: JSON.stringify({}),
  });
  return normalizePackageFirewallAction(response);
}

export async function runPackageSync(): Promise<PackageFirewallActionResponse> {
  const response = await readJson<unknown>("/v1/supply-chain/sync", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...guardAuthHeaders(),
    },
    body: JSON.stringify({}),
  });
  return normalizePackageFirewallAction(response);
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
