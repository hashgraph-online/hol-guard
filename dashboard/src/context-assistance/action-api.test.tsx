import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import type { GuardApprovalRequest } from "../guard-types";
import { parseActionEnvelope } from "../guard-api";
import { attachedNativeDecision, parseNativeDecisionContext, prepareNativeDecisionContext } from "./action-api";
import { ContextBriefView } from "./brief-view";
import { ContextReviewPanel } from "./review-panel";
import type { ContextWorkspaceScope } from "./workspaces-api";

const native = JSON.parse(readFileSync(new URL("./fixtures/native-decision.json", import.meta.url), "utf8")).native_test.observation;
const scope: ContextWorkspaceScope = { scope_id: "scope:fixture", workspace: "/workspace", app: "dashboard",
  policy_revision: native.brief.policy_revision, retained_contexts: 1, revoked: false, native_policy_facts: true,
  sources: native.brief.citations.filter((citation: { source: string }) => citation.source.startsWith("source:"))
    .map((citation: { source: string; document_digest: string }) => ({ source_id: citation.source, path: "README.md", sha256: citation.document_digest, documents: 1 })) };
const expected = { scope, decisionId: native.association.decision_id, harness: "codex" };
const value = { current: true, scope, brief: native.brief, association: native.association, explanation: null };
assert.equal(parseNativeDecisionContext(value, expected).association.execution_binding, "unqualified");
for (const malformed of [
  { ...value, current: false },
  ...[{ ...value.association, data_role: false }, { ...value.association, decision_id: "a".repeat(64) },
    { ...value.association, approval_grant: true }, { ...value.association, execution_binding: "exact" },
    { ...value.association, harness: "cursor" }, { ...value.association, policy_generation: 1 }]
    .map((association) => ({ ...value, association })),
  { ...value, scope: { ...scope, workspace: "/foreign" } },
  { ...value, scope: { ...scope, revoked: true } },
  { ...value, scope: { ...scope, native_policy_facts: false } },
  { ...value, brief: { ...value.brief, policy_revision: "foreign" } },
  { ...value, brief: { ...value.brief, citations: value.brief.citations.filter((citation: { source: string }) => citation.source !== "guard:action") } },
  { ...value, brief: { ...value.brief, citations: [{ ...value.brief.citations[0], source: "foreign" }] } },
]) assert.throws(() => parseNativeDecisionContext(malformed, expected), /incompatible native decision context/);
const envelope = { native_origin_receipt: { schema: "guard-native-hook-decision-receipt.v1", authority: "rust", event_name: "PreToolUse",
  harness: "codex", decision_id: expected.decisionId, origin_authentication: "b".repeat(64) } };
assert.equal(attachedNativeDecision(envelope, "codex"), expected.decisionId);
assert.equal(attachedNativeDecision(envelope, "cursor"), null);
assert.equal(attachedNativeDecision({ action_identity: expected.decisionId }, "codex"), null);
assert.equal(attachedNativeDecision({ native_origin_receipt: { ...envelope.native_origin_receipt, origin_authentication: null } }, "codex"), null);
const rawAction = { schema_version: 1, action_id: "native", harness: "codex", event_name: "PreToolUse", action_type: "shell_command",
  workspace: "/workspace", workspace_hash: null, tool_name: "exec_command", command: "fixture", prompt_excerpt: null, prompt_text: null,
  target_paths: [], network_hosts: [], mcp_server: null, mcp_tool: null, package_manager: null, package_name: null,
  script_name: null, raw_payload_redacted: {}, native_origin_receipt: { ...envelope.native_origin_receipt,
    execution_intent_digest: "private-intent-must-not-be-projected", raw_command: "private-command-must-not-be-projected" } };
const projected = parseActionEnvelope(rawAction);
assert.equal(attachedNativeDecision(projected, "codex"), expected.decisionId, "normal review normalization preserves the optional selector");
assert.deepEqual(projected?.native_origin_receipt, envelope.native_origin_receipt, "only bounded selector metadata survives");
const without = { ...rawAction, native_origin_receipt: undefined };
assert.deepEqual(parseActionEnvelope({ ...rawAction, native_origin_receipt: { ...rawAction.native_origin_receipt, origin_authentication: "invalid" } }),
  parseActionEnvelope(without), "invalid optional metadata cannot break the approval envelope");

const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
const originalFetch = globalThis.fetch;
const storage = { getItem: () => null, setItem: () => {} };
Object.defineProperty(globalThis, "window", { configurable: true, value: { location: new URL("http://127.0.0.1:4781/requests/review?guard-token=decision-fixture"), sessionStorage: storage, localStorage: storage } });
const calls: RequestInit[] = [];
globalThis.fetch = async (_input, init) => { calls.push(init!); return new Response(JSON.stringify({ schema: "guard-cigar-workspace-result.v1", data_role: true, result: value })); };
try {
  const item = { request_id: "review", workspace: "/workspace", harness: "codex", status: "pending", action_envelope_json: envelope } as GuardApprovalRequest;
  const markup = renderToStaticMarkup(<ContextReviewPanel item={item} />);
  assert.match(markup, /Prepare decision context/);
  assert.match(markup, /Manage context access/);
  assert.equal(calls.length, 0, "mounting a review never automatically prepares SDK context");
  await prepareNativeDecisionContext(scope, expected.decisionId, "codex");
  assert.deepEqual(JSON.parse(String(calls[0].body)), { input: { action: "action", scope_id: scope.scope_id, decision_id: expected.decisionId } });
  assert.equal(calls[0].cache, "no-store");
  assert.equal(new Headers(calls[0].headers).get("X-Guard-Dashboard-Session"), "decision-fixture");
  await prepareNativeDecisionContext(scope, expected.decisionId, "codex", undefined, native.brief.snapshot_id);
  assert.equal(JSON.parse(String(calls[1].body)).input.snapshot_id, native.brief.snapshot_id);
  const rendered = renderToStaticMarkup(<ContextBriefView brief={{ ...native.brief, excerpts: [{ text: "<script>untrusted source</script>", citations: [] }] }} scope={scope} />);
  assert.match(rendered, /Authenticated native decision facts/);
  assert.match(rendered, /&lt;script&gt;/);
  assert.equal(rendered.includes("<script>"), false);
} finally {
  globalThis.fetch = originalFetch;
  if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
  else Reflect.deleteProperty(globalThis, "window");
}
console.log("Actual native decision projection, strict associations, lazy review rendering and authenticated framing passed.");
