import { renderToStaticMarkup } from "react-dom/server";

import {
  fetchMcpPolicyRequest,
  resolveMcpPolicyRequest,
  GuardHarnessActionError,
} from "./guard-api";
import { McpPolicyRequestPanel } from "./mcp-policy-request-panel";
import type { McpPolicyRequest } from "./guard-api";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

type RecordedFetch = {
  url: string;
  init?: RequestInit;
};

type StorageShape = {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  clear(): void;
  key(index: number): string | null;
  readonly length: number;
};

function createStorage(storage: Map<string, string> | StorageShape): StorageShape {
  if (!(storage instanceof Map)) {
    return storage;
  }
  return {
    getItem(key: string): string | null {
      return storage.get(key) ?? null;
    },
    setItem(key: string, value: string): void {
      storage.set(key, value);
    },
    removeItem(key: string): void {
      storage.delete(key);
    },
    clear(): void {
      storage.clear();
    },
    key(index: number): string | null {
      return Array.from(storage.keys())[index] ?? null;
    },
    get length(): number {
      return storage.size;
    },
  };
}

function installGuardWindow(search: string): void {
  const sessionStorage = createStorage(new Map<string, string>());
  const localStorage = createStorage(new Map<string, string>());
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      location: {
        origin: "http://127.0.0.1:4174",
        pathname: "/",
        search,
        hash: "",
      },
      sessionStorage,
      localStorage,
    },
  });
}

function headerValue(init: RequestInit | undefined, key: string): string | null {
  return new Headers(init?.headers).get(key);
}

function installFetchStub(
  payloads: Record<string, { body: object; status?: number }>,
): RecordedFetch[] {
  const calls: RecordedFetch[] = [];
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = input instanceof Request ? input.url : String(input);
    calls.push({ url, init });
    const parsed = new URL(url, "http://127.0.0.1:4174");
    const key = parsed.pathname;
    const entry = payloads[key];
    if (!entry) {
      return new Response(JSON.stringify({ error: "not_found" }), { status: 404 });
    }
    return new Response(JSON.stringify(entry.body), {
      status: entry.status ?? 200,
      headers: { "Content-Type": "application/json" },
    });
  };
  return calls;
}

const PENDING_PAYLOAD = {
  requestId: "req-mcp-pending-0001",
  status: "pending",
  documentId: "doc-policy-001",
  candidateDigest: "a".repeat(64),
  expectedCurrentDigest: "b".repeat(64),
  expectedPolicyGeneration: 3,
  mode: "merge",
  createdAt: "2026-07-20T10:00:00Z",
  expiresAt: "2026-07-20T11:00:00Z",
  resolvedAt: null,
  failureCode: null,
  isTerminal: false,
  isExpired: false,
  result: { inserted: 0, replaced: 0 },
  writePlan: {
    additions: ["allow tool: fs.read"],
    replacements: ["replace rule: network.http"],
    removals: [],
  },
  semanticDiff: { additionCount: 1, replacementCount: 1, removalCount: 0 },
  activeEnforcementWarning: true,
};

const APPROVED_PAYLOAD = {
  ...PENDING_PAYLOAD,
  requestId: "req-mcp-approved-0002",
  status: "applied",
  resolvedAt: "2026-07-20T10:15:00Z",
  isTerminal: true,
  isExpired: false,
  result: { inserted: 1, replaced: 1 },
  activeEnforcementWarning: false,
};

const DECLINED_PAYLOAD = {
  ...PENDING_PAYLOAD,
  requestId: "req-mcp-declined-0003",
  status: "declined",
  resolvedAt: "2026-07-20T10:16:00Z",
  isTerminal: true,
  isExpired: false,
  activeEnforcementWarning: false,
};

const EXPIRED_PAYLOAD = {
  ...PENDING_PAYLOAD,
  requestId: "req-mcp-expired-0004",
  status: "expired",
  isTerminal: true,
  isExpired: true,
  activeEnforcementWarning: false,
};

// ── Pending: GET loads sanitized detail, no YAML/plan JSON/credentials ──

installGuardWindow("?guard-token=token-mcp-pending&guardDaemon=http%3A%2F%2F127.0.0.1%3A4781");
const pendingCalls = installFetchStub({
  "/v1/mcp-policy/requests/req-mcp-pending-0001": { body: PENDING_PAYLOAD },
});
const pendingRequest = await fetchMcpPolicyRequest("req-mcp-pending-0001");

assert(pendingRequest !== null, "VPC045: pending request loads from GET endpoint");
assert(pendingRequest!.requestId === "req-mcp-pending-0001", "VPC045: requestId preserved");
assert(pendingRequest!.status === "pending", "VPC045: status is pending");
assert(pendingRequest!.mode === "merge", "VPC045: mode is merge");
assert(pendingRequest!.candidateDigest === "a".repeat(64), "VPC045: candidate digest preserved");
assert(pendingRequest!.expectedCurrentDigest === "b".repeat(64), "VPC045: expected current digest preserved");
assert(pendingRequest!.expectedPolicyGeneration === 3, "VPC045: expected policy generation preserved");
assert(pendingRequest!.isTerminal === false, "VPC045: pending is not terminal");
assert(pendingRequest!.isExpired === false, "VPC045: pending is not expired");
assert(pendingRequest!.activeEnforcementWarning === true, "VPC045: active enforcement warning surfaced");
assert(pendingRequest!.writePlan.additions.length === 1, "VPC045: write plan additions surfaced");
assert(pendingRequest!.writePlan.replacements.length === 1, "VPC045: write plan replacements surfaced");
assert(pendingRequest!.semanticDiff.additionCount === 1, "VPC045: semantic diff addition count");
assert(
  headerValue(pendingCalls[0].init, "X-Guard-Dashboard-Session") === "token-mcp-pending",
  "VPC045: GET sends dashboard session token",
);
assert(
  pendingCalls[0].url === "http://127.0.0.1:4781/v1/mcp-policy/requests/req-mcp-pending-0001",
  "VPC045: GET hits authenticated mcp-policy endpoint",
);
// The raw YAML and plan JSON must never appear in the normalized view model.
const pendingJson = JSON.stringify(pendingRequest);
assert(!pendingJson.includes("canonical_policy_yaml"), "VPC045: canonical YAML never surfaces");
assert(!pendingJson.includes("plan_json"), "VPC045: plan JSON never surfaces");
assert(!pendingJson.includes("approval_password"), "VPC045: credentials never surface");

// ── Approved: terminal state with apply result ──

installGuardWindow("?guard-token=token-mcp-approved&guardDaemon=http%3A%2F%2F127.0.0.1%3A4781");
installFetchStub({
  "/v1/mcp-policy/requests/req-mcp-approved-0002": { body: APPROVED_PAYLOAD },
});
const approvedRequest = await fetchMcpPolicyRequest("req-mcp-approved-0002");
assert(approvedRequest !== null, "VPC047: approved request loads");
assert(approvedRequest!.status === "applied", "VPC047: status is applied");
assert(approvedRequest!.isTerminal === true, "VPC047: approved is terminal");
assert(approvedRequest!.result.inserted === 1, "VPC047: apply result inserted count");
assert(approvedRequest!.result.replaced === 1, "VPC047: apply result replaced count");
assert(approvedRequest!.resolvedAt === "2026-07-20T10:15:00Z", "VPC047: resolvedAt preserved");

// ── Declined: terminal state ──

installGuardWindow("?guard-token=token-mcp-declined&guardDaemon=http%3A%2F%2F127.0.0.1%3A4781");
installFetchStub({
  "/v1/mcp-policy/requests/req-mcp-declined-0003": { body: DECLINED_PAYLOAD },
});
const declinedRequest = await fetchMcpPolicyRequest("req-mcp-declined-0003");
assert(declinedRequest !== null, "VPC046: declined request loads");
assert(declinedRequest!.status === "declined", "VPC046: status is declined");
assert(declinedRequest!.isTerminal === true, "VPC046: declined is terminal");

// ── Expired: terminal + expired truth ──

installGuardWindow("?guard-token=token-mcp-expired&guardDaemon=http%3A%2F%2F127.0.0.1%3A4781");
installFetchStub({
  "/v1/mcp-policy/requests/req-mcp-expired-0004": { body: EXPIRED_PAYLOAD },
});
const expiredRequest = await fetchMcpPolicyRequest("req-mcp-expired-0004");
assert(expiredRequest !== null, "VPC056: expired request loads");
assert(expiredRequest!.status === "expired", "VPC056: status is expired");
assert(expiredRequest!.isTerminal === true, "VPC056: expired is terminal");
assert(expiredRequest!.isExpired === true, "VPC056: isExpired truth is visible");

// ── Not found: 404 returns null so route can fall back ──

installGuardWindow("?guard-token=token-mcp-notfound&guardDaemon=http%3A%2F%2F127.0.0.1%3A4781");
const notFoundCalls = installFetchStub({});
const notFoundRequest = await fetchMcpPolicyRequest("req-does-not-exist");
assert(notFoundRequest === null, "VPC045: 404 returns null, not an error");
assert(notFoundCalls[0].url.includes("/v1/mcp-policy/requests/req-does-not-exist"), "VPC045: not-found probes MCP endpoint");

// ── Decision: approve posts to decision endpoint with session ──

installGuardWindow("?guard-token=token-mcp-approve&guardDaemon=http%3A%2F%2F127.0.0.1%3A4781");
const approveCalls = installFetchStub({
  "/v1/mcp-policy/requests/req-mcp-pending-0001/decision": {
    body: { resolved: true, requestId: "req-mcp-pending-0001", status: "applied", resolvedAt: "2026-07-20T10:20:00Z" },
  },
});
const approveResult = await resolveMcpPolicyRequest({
  requestId: "req-mcp-pending-0001",
  action: "approve",
});
assert(approveResult.resolved === true, "VPC047: approve returns resolved=true");
assert(approveResult.status === "applied", "VPC047: approve returns applied status");
assert(approveResult.resolvedAt === "2026-07-20T10:20:00Z", "VPC047: approve returns resolvedAt");
const approveBody = JSON.parse(String(approveCalls[0].init?.body)) as Record<string, unknown>;
assert(approveBody["action"] === "approve", "VPC047: decision body sends action=approve");
assert(
  headerValue(approveCalls[0].init, "X-Guard-Dashboard-Session") === "token-mcp-approve",
  "VPC047: decision sends dashboard session token",
);
assert(
  headerValue(approveCalls[0].init, "Content-Type") === "application/json",
  "VPC047: decision sends JSON content type",
);
assert(
  approveCalls[0].url === "http://127.0.0.1:4781/v1/mcp-policy/requests/req-mcp-pending-0001/decision",
  "VPC047: decision posts to correct endpoint",
);
assert(approveCalls[0].init?.method === "POST", "VPC047: decision uses POST");

// ── Decision: decline ──

installGuardWindow("?guard-token=token-mcp-decline&guardDaemon=http%3A%2F%2F127.0.0.1%3A4781");
const declineCalls = installFetchStub({
  "/v1/mcp-policy/requests/req-mcp-pending-0001/decision": {
    body: { resolved: true, requestId: "req-mcp-pending-0001", status: "declined", resolvedAt: "2026-07-20T10:21:00Z" },
  },
});
const declineResult = await resolveMcpPolicyRequest({
  requestId: "req-mcp-pending-0001",
  action: "decline",
});
assert(declineResult.resolved === true, "VPC046: decline returns resolved=true");
assert(declineResult.status === "declined", "VPC046: decline returns declined status");
const declineBody = JSON.parse(String(declineCalls[0].init?.body)) as Record<string, unknown>;
assert(declineBody["action"] === "decline", "VPC046: decision body sends action=decline");

// ── Idempotent: re-approve on terminal returns resolved=true ──

installGuardWindow("?guard-token=token-mcp-idempotent&guardDaemon=http%3A%2F%2F127.0.0.1%3A4781");
installFetchStub({
  "/v1/mcp-policy/requests/req-mcp-approved-0002/decision": {
    body: { resolved: true, requestId: "req-mcp-approved-0002", status: "applied", resolvedAt: "2026-07-20T10:15:00Z" },
  },
});
const idempotentResult = await resolveMcpPolicyRequest({
  requestId: "req-mcp-approved-0002",
  action: "approve",
});
assert(idempotentResult.resolved === true, "VPC047: re-approve on terminal is idempotent");
assert(idempotentResult.status === "applied", "VPC047: idempotent re-approve returns current status");

// ── Action failure: non-2xx throws GuardHarnessActionError ──

installGuardWindow("?guard-token=token-mcp-failure&guardDaemon=http%3A%2F%2F127.0.0.1%3A4781");
installFetchStub({
  "/v1/mcp-policy/requests/req-mcp-fail-0005/decision": {
    body: { resolved: false, error: "approval_gate_required", message: "Approval gate authentication is required." },
    status: 400,
  },
});
let failureError: unknown = null;
try {
  await resolveMcpPolicyRequest({
    requestId: "req-mcp-fail-0005",
    action: "approve",
  });
} catch (error) {
  failureError = error;
}
assert(failureError instanceof GuardHarnessActionError, "VPC047: action failure throws GuardHarnessActionError");
assert(
  failureError instanceof GuardHarnessActionError && failureError.status === 400,
  "VPC047: action failure preserves status",
);
assert(
  failureError instanceof GuardHarnessActionError && failureError.payload?.error === "approval_gate_required",
  "VPC047: action failure preserves daemon error code",
);

// ── Defensive normalization: unknown keys and bad types never crash ──

installGuardWindow("?guard-token=token-mcp-defensive&guardDaemon=http%3A%2F%2F127.0.0.1%3A4781");
installFetchStub({
  "/v1/mcp-policy/requests/req-mcp-malformed": {
    body: {
      requestId: "req-mcp-malformed",
      status: "pending",
      // Inject hostile fields that must never surface.
      canonical_policy_yaml: "secret-yaml-content",
      plan_json: '{"secret":"plan"}',
      approval_password: "should-not-appear",
      // Malformed types that must fall back safely.
      expectedPolicyGeneration: "not-a-number",
      mode: "invalid-mode",
      isTerminal: "yes",
      isExpired: 1,
      result: { inserted: "x", replaced: null },
      writePlan: { additions: "not-an-array", replacements: 5, removals: null },
      semanticDiff: { additionCount: true, replacementCount: {}, removalCount: undefined },
      unknownExtraField: "ignored",
    },
  },
});
const malformedRequest = await fetchMcpPolicyRequest("req-mcp-malformed");
assert(malformedRequest !== null, "VPC045: malformed payload normalizes without crashing");
assert(malformedRequest!.mode === "merge", "VPC045: invalid mode falls back to merge");
assert(malformedRequest!.expectedPolicyGeneration === null, "VPC045: non-numeric generation falls back to null");
assert(malformedRequest!.isTerminal === false, "VPC045: non-boolean isTerminal falls back to false");
assert(malformedRequest!.isExpired === false, "VPC045: non-boolean isExpired falls back to false");
assert(malformedRequest!.result.inserted === 0, "VPC045: non-numeric inserted falls back to 0");
assert(malformedRequest!.writePlan.additions.length === 0, "VPC045: non-array additions fall back to empty");
assert(malformedRequest!.semanticDiff.replacementCount === 0, "VPC045: non-numeric count falls back to 0");
const malformedJson = JSON.stringify(malformedRequest);
assert(!malformedJson.includes("secret-yaml-content"), "VPC045: hostile YAML content never surfaces");
assert(!malformedJson.includes("should-not-appear"), "VPC045: hostile credentials never surface");

// ── Render: loading state renders skeleton, not raw content ──

installGuardWindow("?guard-token=token-mcp-render&guardDaemon=http%3A%2F%2F127.0.0.1%3A4781");
installFetchStub({
  "/v1/mcp-policy/requests/req-mcp-render-0006": { body: PENDING_PAYLOAD },
});
const loadingMarkup = renderToStaticMarkup(
  <McpPolicyRequestPanel requestId="req-mcp-render-0006" />,
);
assert(loadingMarkup.includes("guard-skeleton"), "VPC045: panel renders loading skeleton initially");
assert(!loadingMarkup.includes("canonical_policy_yaml"), "VPC045: loading state never renders YAML");
assert(loadingMarkup.includes('aria-busy="true"'), "VPC045: loading state is aria-busy");

// ── Request identity is opaque and encoded ──

installGuardWindow("?guard-token=token-mcp-encode&guardDaemon=http%3A%2F%2F127.0.0.1%3A4781");
const encodeCalls = installFetchStub({
  "/v1/mcp-policy/requests/req%20with%20spaces": { body: PENDING_PAYLOAD },
});
await fetchMcpPolicyRequest("req with spaces");
assert(
  encodeCalls[0].url.includes("/v1/mcp-policy/requests/req%20with%20spaces"),
  "VPC045: request id is URL-encoded in the path",
);

console.log("mcp-policy-request-panel.test.tsx: all assertions passed");
