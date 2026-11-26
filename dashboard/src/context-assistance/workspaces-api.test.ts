import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { contextRefusalFromBody, contextRefusalMessage, parseContextBrief, parseContextScope } from "./workspaces-api";

const observed = JSON.parse(readFileSync(new URL("./fixtures/source-actor.json", import.meta.url), "utf8")).source_test.brief_observation;
const brief = parseContextBrief(observed);
assert.equal(brief.data_role, true);
assert.equal(brief.excerpts.length, 2);
assert.equal(brief.citations.length, 2);
assert.match(brief.excerpts[1].text, /Project alpha/);
for (const malformed of [
  { ...observed, data_role: false },
  { ...observed, rendered: "x".repeat(262_145) },
  { ...observed, graph_revision: Number.MAX_SAFE_INTEGER + 1 },
  { ...observed, excerpts: [{ text: 42, citations: [] }] },
  { ...observed, citations: [{ ...observed.citations[0], start_line: 0 }] },
  { ...observed, citations: [{ ...observed.citations[0], document_digest: "forged" }] },
]) assert.throws(() => parseContextBrief(malformed), /does not understand/);
const scope = { scope_id: "scope:local", workspace: "/workspace", app: "dashboard", policy_revision: "a".repeat(64),
  sources: [], retained_contexts: 0, revoked: false, native_policy_facts: true,
  receipt_window: { enabled: true, retained: 16, dropped: "18446744073709551615", coverage: "bounded_recent_native_receipts" } };
assert.equal(parseContextScope(scope).receipt_window?.retained, 16);
const sharing = { mode: "shared_broker", notes: { read: true, propose: true, documents: 1,
  revision: { epoch: "b".repeat(64), version: "18446744073709551615" } }, client_lease_seconds: 300 };
assert.equal(parseContextScope({ ...scope, sharing }).sharing?.notes.revision?.version, "18446744073709551615");
const privateBroker = { mode: "private_broker", notes: { read: false, propose: false, documents: 0,
  revision: sharing.notes.revision }, client_lease_seconds: null };
assert.equal(parseContextScope({ ...scope, sharing: privateBroker }).sharing?.mode, "private_broker");
for (const malformed of [
  { ...scope, native_policy_facts: "enabled" },
  ...[
    { ...sharing, mode: "private_graph" },
    { ...sharing, mode: "private_broker" },
    { ...sharing, client_lease_seconds: null },
    { ...sharing, notes: { ...sharing.notes, read: false } },
    { ...sharing, notes: { ...sharing.notes, revision: { ...sharing.notes.revision, version: "18446744073709551616" } } },
    { ...sharing, notes: { ...sharing.notes, revision: { ...sharing.notes.revision, version: 9007199254740993 } } },
  ].map((sharing) => ({ ...scope, sharing })),
  ...[{ ...scope.receipt_window, retained: 17 }, { ...scope.receipt_window, dropped: -1 },
    { ...scope.receipt_window, dropped: "-1" }, { ...scope.receipt_window, coverage: "complete_history" }]
    .map((receipt_window) => ({ ...scope, receipt_window })),
]) assert.throws(() => parseContextScope(malformed), /does not understand/);
// A refused pick says why; "read files again" cannot help with a secret-looking file or a private folder.
assert.match(contextRefusalMessage("native_context_assistance_context_scope_denied", "grant", 403), /password or key, a file your settings block, or a folder Guard keeps private/);
assert.match(contextRefusalMessage("native_context_assistance_context_scope_denied", "refresh", 403), /files changed/);
assert.match(contextRefusalMessage("native_context_assistance_context_stale", "grant", 409), /files changed/);
assert.match(contextRefusalMessage("context_request_refused", "grant", 403), /approval password/);
assert.match(contextRefusalMessage("native_context_assistance_runtime_deadline_exceeded", "compile", 503), /Restart CIGAR/);
assert.equal(contextRefusalMessage("native_context_assistance_context_resource_limit", "grant", 429, 2),
  "CIGAR is already working with as many projects as your Context size allows (2). Remove a project, or raise Active workspaces under Custom limits.");
// An unrecognised refusal names its code, so the person can report it.
assert.equal(contextRefusalMessage("native_context_assistance_workspace_input_invalid", "grant", 400),
  "CIGAR could not finish that (native_context_assistance_workspace_input_invalid). Refresh and try again.");
// The approval check's refusal carries `error` and a message; both reach the page.
assert.deepEqual(contextRefusalFromBody({ error: "approval_gate_locked", message: "Approval gate is temporarily locked." }, "grant", 423),
  { code: "approval_gate_locked", message: "Approval gate is temporarily locked." });
assert.deepEqual(contextRefusalFromBody({ error: "native_approval_gate_unavailable", message: "The native approval authority did not answer. Retry the approval." }, "grant", 503),
  { code: "native_approval_gate_unavailable", message: "The native approval authority did not answer. Retry the approval." });
// CIGAR's own refusal keeps its own wording, and an unreadable body still names a code.
assert.match(contextRefusalFromBody({ error: "context_assistance_unavailable", code: "native_context_assistance_context_stale" }, "grant", 409).message, /files changed/);
assert.deepEqual(contextRefusalFromBody(null, "grant", 500),
  { code: "context_request_refused", message: "CIGAR could not finish that (context_request_refused). Refresh and try again." });
assert.match(contextRefusalFromBody({ error: "approval_gate_locked", message: "x".repeat(301) }, "grant", 423).message, /\(approval_gate_locked\)/);
console.log("Actual native cited-context projection and malformed disclosure payload checks passed.");
