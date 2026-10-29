import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseContextBrief, parseContextScope } from "./workspaces-api";

const observed = JSON.parse(readFileSync(new URL("../../../docs/guard/cigar-integration/evidence/source-actor-verification.json", import.meta.url), "utf8")).source_test.brief_observation;
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
]) assert.throws(() => parseContextBrief(malformed), /incompatible context data/);
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
]) assert.throws(() => parseContextScope(malformed), /incompatible context data/);
console.log("Actual native cited-context projection and malformed disclosure payload checks passed.");
