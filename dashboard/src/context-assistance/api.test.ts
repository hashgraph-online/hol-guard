import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { controlContextAssistance, fetchContextAssistance, fetchContextInstallations, ContextAssistanceApiError } from "./api";
import { authorizeContextAgentSession, compileWorkspaceContext, listContextAgentSessions, revokeContextAgentSession } from "./workspaces-api";

const native = JSON.parse(readFileSync(new URL("../../../docs/guard/cigar-integration/evidence/intent-state-verification.json", import.meta.url), "utf8")).native_test.ready_observation;
const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
const originalFetch = globalThis.fetch;
const storage = new Map<string, string>();
const browserStorage = { getItem: (key: string) => storage.get(key) ?? null, setItem: (key: string, value: string) => { storage.set(key, value); } };
Object.defineProperty(globalThis, "window", { configurable: true, value: {
  location: new URL("http://127.0.0.1:4781/guard/settings?guard-token=context-test-session"),
  sessionStorage: browserStorage, localStorage: browserStorage,
} });
const calls: Array<{ url: string; init?: RequestInit }> = [];
let payload: unknown = native;
let status = 200;
globalThis.fetch = async (input, init) => {
  calls.push({ url: String(input), init });
  return new Response(JSON.stringify(payload), { status, headers: { "Content-Type": "application/json" } });
};
try {
  assert.equal((await fetchContextAssistance()).effective_enabled, true);
  assert.equal(calls.length, 1, "a status read must never automatically activate or discover a runtime");
  assert.equal(calls[0].url, "http://127.0.0.1:4781/v1/context-assistance");
  assert.equal(calls[0].init?.cache, "no-store");
  assert.equal(new Headers(calls[0].init?.headers).get("X-Guard-Dashboard-Session"), "context-test-session");
  await fetchContextInstallations();
  assert.match(calls.at(-1)!.url, /\/context-assistance\/installations$/);
  for (const action of ["activate", "recheck", "stop"] as const) {
    await controlContextAssistance(action);
    const request = calls.at(-1)!;
    assert.equal(request.init?.method, "POST");
    assert.equal(request.init?.body, "{}", "public controls never submit executable paths, hashes or runtime facts");
  }
  const count = calls.length;
  await assert.rejects(controlContextAssistance("../settings" as never), /Invalid context assistance action/);
  assert.equal(calls.length, count);
  payload = { enabled: true, python_version: "3.14", ready: true };
  await assert.rejects(fetchContextAssistance(), /incompatible status/);
  const observed = JSON.parse(readFileSync(new URL("../../../docs/guard/cigar-integration/evidence/source-actor-verification.json", import.meta.url), "utf8")).source_test.brief_observation;
  const scope = { scope_id: "scope:granted", workspace: "/workspace", app: "dashboard", policy_revision: "a".repeat(64),
    sources: [], retained_contexts: 1, revoked: false, native_policy_facts: true,
    receipt_window: { enabled: true, retained: 1, dropped: "0", coverage: "bounded_recent_native_receipts" } };
  payload = { schema: "guard-cigar-workspace-result.v1", data_role: true, result: { brief: observed, current: true, scope } };
  const compiled = await compileWorkspaceContext(scope.scope_id, "native recorded decisions");
  assert.equal(compiled.scope?.receipt_window?.retained, 1);
  assert.equal(compiled.brief.snapshot_id, observed.snapshot_id);
  payload = { schema: "guard-cigar-workspace-result.v1", data_role: true, result: { brief: observed, current: true, scope: { ...scope, scope_id: "scope:foreign" } } };
  await assert.rejects(compileWorkspaceContext(scope.scope_id, "native recorded decisions"), /incompatible context data/);
  payload = { schema: "guard-cigar-workspace-result.v1", data_role: true,
    result: { agent_sessions: [{ session_id: "agent:public-code", scope_id: null, phase: "pending", expires_in_seconds: 300 }] } };
  assert.equal((await listContextAgentSessions())[0].phase, "pending");
  assert.deepEqual(JSON.parse(String(calls.at(-1)!.init?.body)), { input: { action: "list_agents" } });
  payload = { schema: "guard-cigar-workspace-result.v1", data_role: true, result: { authorized: true } };
  await authorizeContextAgentSession("agent:public-code", "scope:chosen", { currentPassword: "fixture-proof" });
  assert.deepEqual(JSON.parse(String(calls.at(-1)!.init?.body)), {
    input: { action: "authorize_agent", session_id: "agent:public-code", scope_id: "scope:chosen" }, approval_password: "fixture-proof",
  });
  assert.match(calls.at(-1)!.url, /workspace-grant$/);
  await revokeContextAgentSession("agent:public-code");
  assert.match(calls.at(-1)!.url, /workspace-access$/);
  assert.deepEqual(JSON.parse(String(calls.at(-1)!.init?.body)), { input: { action: "revoke_agent", session_id: "agent:public-code" } });
  payload = { code: "native_context_assistance_context_resource_limit", message: "private-capacity-diagnostic" };
  status = 409;
  const beforePairingRefusal = calls.length;
  await assert.rejects(authorizeContextAgentSession("agent:capacity", "scope:chosen"), (error: unknown) =>
    error instanceof ContextAssistanceApiError && error.code.endsWith("context_resource_limit")
      && error.message.includes("Revoke an unused connection or workspace")
      && error.message.includes("pair its new code") && !error.message.includes("private-capacity"));
  assert.equal(calls.length, beforePairingRefusal + 1, "a refused pairing must never retry itself");
  await assert.rejects(compileWorkspaceContext(scope.scope_id, "native recorded decisions"), (error: unknown) =>
    error instanceof ContextAssistanceApiError && !error.message.includes("client capacity")
      && !error.message.includes("private-capacity"), "other resource limits need their own recovery, not a pairing instruction");
  payload = { code: "native_context_assistance_disabled", message: "private-content-must-not-render" };
  status = 503;
  await assert.rejects(controlContextAssistance("activate"), (error: unknown) =>
    error instanceof ContextAssistanceApiError && error.code === "native_context_assistance_disabled"
      && !error.message.includes("private-content"));
  status = 404;
  await assert.rejects(fetchContextAssistance(), /needs a native core/);
} finally {
  globalThis.fetch = originalFetch;
  if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
  else Reflect.deleteProperty(globalThis, "window");
}
console.log("Authenticated context controls, off-state reads and incompatible native replies passed.");
