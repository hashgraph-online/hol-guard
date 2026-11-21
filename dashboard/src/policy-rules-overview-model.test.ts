import assert from "node:assert/strict";
import type { GuardPolicyDecision } from "./guard-types";
import {
  countPolicyRules,
  filterPoliciesByAction,
  isBulkRemovablePolicy,
  policySelectionKey,
  prunePolicySelection,
  resolveRulesResultSummary,
  togglePolicySelection,
} from "./policy-rules-overview-model";

assert.equal(isBulkRemovablePolicy(policy({ scope: "workspace" })), true);
assert.equal(isBulkRemovablePolicy(policy({ scope: "global" })), false);
assert.equal(isBulkRemovablePolicy(policy({ scope: "workspace", source: "cloud-sync" })), false);

function policy(overrides: Partial<GuardPolicyDecision>): GuardPolicyDecision {
  return {
    harness: "claude-code",
    scope: "workspace",
    action: "allow",
    source: "local",
    artifact_id: null,
    publisher: null,
    workspace: null,
    reason: null,
    updated_at: "2026-10-01T00:00:00Z",
    ...overrides,
  };
}

const rules = [
  policy({ action: "allow", source: "local", artifact_id: "a" }),
  policy({ action: "block", source: "local", artifact_id: "b" }),
  policy({ action: "allow", source: "cloud-sync", artifact_id: "c" }),
  policy({ action: "ask", source: "local", artifact_id: "d" }),
];

const counts = countPolicyRules(rules);
assert.deepEqual(counts, { total: 4, local: 3, cloud: 1, allow: 2, block: 1, other: 1 });

assert.equal(filterPoliciesByAction(rules, "all").length, 4);
assert.equal(filterPoliciesByAction(rules, "allow").length, 2);
assert.equal(filterPoliciesByAction(rules, "block").length, 1);

const key = policySelectionKey(rules[0]);
assert.equal(key, policySelectionKey({ ...rules[0] }));
assert.notEqual(key, policySelectionKey(rules[1]));

// Rules that share harness/scope/timestamp but differ in workspace stay distinct.
const twinA = policy({ artifact_id: "same", workspace: "/work/a" });
const twinB = policy({ artifact_id: "same", workspace: "/work/b" });
assert.notEqual(policySelectionKey(twinA), policySelectionKey(twinB));
assert.equal(policySelectionKey(policy({ decision_id: 7, workspace: "/work/a" })), "decision:7");

let selected = togglePolicySelection(new Set<string>(), key);
assert.equal(selected.has(key), true);
selected = togglePolicySelection(selected, key);
assert.equal(selected.has(key), false);

const pruned = prunePolicySelection(new Set([key, "stale-key"]), [rules[0]]);
assert.deepEqual([...pruned], [key]);

assert.equal(
  resolveRulesResultSummary({ visible: 4, total: 4, searchQuery: "", actionFilter: "all", appFilter: "", familyFilter: "" }),
  null,
);
assert.match(
  resolveRulesResultSummary({ visible: 0, total: 4, searchQuery: "git", actionFilter: "all", appFilter: "", familyFilter: "" }) ?? "",
  /No rules match/,
);
assert.match(
  resolveRulesResultSummary({ visible: 2, total: 4, searchQuery: "", actionFilter: "allow", appFilter: "", familyFilter: "" }) ?? "",
  /Showing 2 of 4/,
);

console.log("policy-rules-overview-model.test.ts: all assertions passed");
