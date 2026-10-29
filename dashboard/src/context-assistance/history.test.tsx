import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { parseContextAssistanceStatus } from "./status";
import { parseContextScope } from "./workspaces-api";
import { parseContextDataSummary, parseContextHistory, parseContextHistoryDetail } from "./history-api";
import { ContextHistoryPanel } from "./history-panel";
import { ContextDataRepairPanel, contextDiagnostics } from "./data-repair-panel";
import { parseSavedEvidence, savedEvidenceCopy } from "./saved-evidence";

const observed = JSON.parse(readFileSync(new URL("../../../docs/guard/cigar-integration/evidence/history-development-verification.json", import.meta.url), "utf8")).native_test.observation;
const history = observed.history_observation;
const nativeDetail = observed.detail_observation;
const scope = parseContextScope(history.scope);
const parsed = parseContextHistory(history, scope);
assert.equal(parsed.entries.length, 1);
const id = parsed.entries[0].history_id;
const detail = parseContextHistoryDetail(nativeDetail, scope, id);
assert.match(detail.brief!.rendered, /original release procedure/);
assert.equal(detail.source_states[0].state, "unchanged");
for (const malformed of [
  { ...history, current: true }, { ...history, historical: false },
  { ...history, entries: [{ ...history.entries[0], historical: false }] },
  { ...history, entries: [{ ...history.entries[0], observation: "execution_confirmed" }] },
  { ...history, entries: Array.from({ length: 9 }, () => history.entries[0]) },
  { ...history, entries: [history.entries[0], history.entries[0]] },
]) assert.throws(() => parseContextHistory(malformed, scope), /incompatible context history/);
assert.throws(() => parseContextHistory(history, { ...scope, workspace: "/foreign" }), /incompatible context history/);
assert.throws(() => parseContextHistory(history, scope, "a".repeat(64)), /incompatible context history/);
for (const malformed of [
  { ...nativeDetail, current: true }, { ...nativeDetail, brief: null },
  { ...nativeDetail, source_states: [] },
  { ...nativeDetail, source_states: [{ ...nativeDetail.source_states[0], source_id: "foreign" }] },
  { ...nativeDetail, brief: { ...nativeDetail.brief, snapshot_id: "a".repeat(64) } },
]) assert.throws(() => parseContextHistoryDetail(malformed, scope, id), /incompatible context history/);
const withheld = parseContextHistoryDetail({ ...nativeDetail, brief: null, source_access: "unavailable",
  source_states: [{ ...nativeDetail.source_states[0], state: "unavailable", current_sha256: null }] }, scope, id);
assert.equal(withheld.brief, null);

const summary = parseContextDataSummary({ schema: "guard-cigar-data-summary.v1", storage: "memory", data_role: true,
  active_scopes: 1, selected_files: 1, current_contexts: 1, history_entries: 1, history_encoded_bytes: 2307, agent_sessions: 0,
  max_history_entries_per_scope: 8, max_history_encoded_bytes_per_scope: 524288, saved_context: "unavailable", cleared_history: false });
assert.throws(() => parseContextDataSummary({ ...summary, history_entries: 65 }), /incompatible context history/);
assert.throws(() => parseContextDataSummary({ ...summary, data_role: false }), /incompatible context history/);
const saved = { schema: "guard-cigar-saved-evidence.v1", status: "saved", slots: 1, active_slots: 0,
  bytes: 8192, max_slots: 8, max_bytes: 553648128, unresolved_writes: 0, invalid_records: 0, expired_slots: 0,
  diagnostic: null, authority_restored: false, storage: "private_posix_files" };
const durable = parseContextDataSummary({ ...summary, schema: "guard-cigar-data-summary.v2", history_storage: "memory", cleared_saved: false, saved_evidence: saved });
assert.equal(durable.saved_evidence?.slots, 1);
assert.match(savedEvidenceCopy(durable.saved_evidence!), /does not restore source or app permissions/);
for (const malformed of [
  { ...saved, authority_restored: true }, { ...saved, slots: 9 }, { ...saved, bytes: 553648129 },
  { ...saved, active_slots: 2 }, { ...saved, unresolved_writes: 1 }, { ...saved, status: "busy", diagnostic: null },
  { ...saved, status: "repair_required", diagnostic: "/private/not-a-diagnostic" },
]) assert.throws(() => parseSavedEvidence(malformed), /incompatible saved-data status/);
assert.throws(() => parseContextDataSummary({ ...durable, saved_evidence: undefined }), /incompatible saved-data status/);
assert.throws(() => parseContextDataSummary({ ...durable, cleared_saved: undefined }), /incompatible context history/);
const ready = parseContextAssistanceStatus(JSON.parse(readFileSync(new URL("../../../docs/guard/cigar-integration/evidence/intent-state-verification.json", import.meta.url), "utf8")).native_test.ready_observation);
const privateStatus = { ...ready, diagnostic: "/private/diagnostic-must-not-export", restriction: "private organization",
  preferences: { ...ready.preferences, runtime_id: "private-runtime-reference" },
  runtime: { ...ready.runtime!, private_token: "private-token-must-not-export", interpreter: { ...ready.runtime!.interpreter, executable: "/private/python-must-not-export" } } };
const exported = JSON.stringify(contextDiagnostics(privateStatus, { ...summary, query: "private-query-must-not-export", workspace: "/private/workspace-must-not-export" } as typeof summary));
for (const privateValue of ["private-runtime-reference", "private-token-must-not-export", "/private/", "private organization", "private-query-must-not-export"]) assert.ok(!exported.includes(privateValue));
assert.match(exported, /redacted_diagnostic/);
assert.match(exported, /history_encoded_bytes/);

const originalFetch = globalThis.fetch;
const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
const storage = { getItem: () => null, setItem: () => {} };
Object.defineProperty(globalThis, "window", { configurable: true, value: { location: new URL("http://127.0.0.1:4781/evidence"), sessionStorage: storage, localStorage: storage } });
let requests = 0;
globalThis.fetch = async () => { requests += 1; throw new Error("history must load explicitly"); };
try {
  const markup = renderToStaticMarkup(<ContextHistoryPanel />);
  assert.match(markup, /Load prepared context history/);
  assert.match(markup, /Preparation does not confirm delivery, approval, or execution/);
  assert.equal(requests, 0);
  const repair = renderToStaticMarkup(<ContextDataRepairPanel savedEnabled disabled={false} onStopped={() => {}} onBusyChange={() => {}} />);
  assert.match(repair, /Context data and repair/);
  assert.match(repair, /Turn off context assistance/);
  assert.match(repair, /Existing saved evidence can still be inspected and removed/);
  assert.match(repair, /Clear all context data/);
  assert.doesNotMatch(repair, /<button[^>]*>Clear evidence/);
} finally {
  globalThis.fetch = originalFetch;
  if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
  else Reflect.deleteProperty(globalThis, "window");
}
console.log("Actual native historical projections, currentness refusal, data bounds, lazy disclosure and diagnostic redaction passed.");
