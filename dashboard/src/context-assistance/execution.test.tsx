import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { isContextExecutionObservation } from "./execution-observation";
import { ContextExecutionPanel } from "./execution-panel";
import { parseContextAssistanceStatus } from "./status";

const receipt = JSON.parse(readFileSync(new URL("../../../docs/guard/cigar-integration/evidence/intent-state-verification.json", import.meta.url), "utf8"));
const ready = parseContextAssistanceStatus(receipt.native_test.ready_observation);
// These new fields are projection fixtures. Native/SDK and executor proof is
// established by the separate actual candidate tests, never by this renderer.
const observation = {
  schema: "guard-cigar-native-execution-observation.v1", data_role: true,
  effect_id: `execution:${"a".repeat(64)}`, snapshot_id: "b".repeat(64), scope_id: `scope:${"c".repeat(64)}`,
  execution_reference: "d".repeat(64), phase: "completed", source_qualification: "captured_native_facts_only",
  SDK_checked_at_ms: 1792800000000, native_barrier_checked_at_ms: 1792800000100,
  context_eligible_at_last_check: true, association_applied: true, native_dispatch_acknowledged: true,
  reason: null, approval_grant: false, send_boundary_atomicity: false,
};
const current = {
  ...ready, preferences: { ...ready.preferences, features: { ...ready.preferences.features, execution_context: true } },
  effective_preferences: { ...ready.effective_preferences, features: { ...ready.effective_preferences.features, execution_context: true } },
  capabilities: { shared_agents: true, private_persistence: true, execution_context: true },
  runtime: { ...ready.runtime, execution_handoff_verified: true }, execution_ready: true,
  execution_observations: [observation],
};
assert.ok(isContextExecutionObservation(observation));
const status = parseContextAssistanceStatus(current);
const html = renderToStaticMarkup(createElement(ContextExecutionPanel, { status }));
assert.match(html, /Native execution record completed/);
assert.match(html, /Checked context was associated at native dispatch/);
assert.match(html, /Pi and Oh My Pi/);
assert.match(html, /Selected files and shared notes remain separate review context/);
assert.equal(renderToStaticMarkup(createElement(ContextExecutionPanel, { status: ready })), "");
for (const malformed of [
  { ...observation, approval_grant: true }, { ...observation, send_boundary_atomicity: true },
  { ...observation, ticket: "must-never-appear" }, { ...observation, effect_id: "caller-provided" },
  { ...observation, native_dispatch_acknowledged: false }, { ...observation, native_barrier_checked_at_ms: null },
  { ...observation, phase: "not_dispatched" }, { ...observation, reason: "unbounded free text" },
]) assert.equal(isContextExecutionObservation(malformed), false);
for (const malformed of [
  { ...current, runtime: { ...current.runtime, execution_handoff_verified: false } },
  { ...current, runtime: { ...current.runtime, execution_handoff_verified: "true" } },
  { ...current, capabilities: { ...current.capabilities, execution_context: false } },
  { ...current, execution_ready: "true" },
  { ...current, effective_preferences: { ...current.effective_preferences, features: { ...current.effective_preferences.features, execution_context: false } } },
  { ...current, execution_observations: Array(33).fill(observation) },
  { ...current, execution_observations: [{ ...observation, command: "private command" }] },
]) assert.throws(() => parseContextAssistanceStatus(malformed));
const uncertain = parseContextAssistanceStatus({ ...current, execution_observations: [{
  ...observation, phase: "outcome_unknown", association_applied: false,
  native_dispatch_acknowledged: false, native_barrier_checked_at_ms: null,
}] });
assert.match(renderToStaticMarkup(createElement(ContextExecutionPanel, { status: uncertain })), /Consult Guard&#x27;s native execution record before retrying/);
console.log("Execution readiness, private observation schema and native outcome rendering checks passed.");
