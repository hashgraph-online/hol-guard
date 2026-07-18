import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { GuardAction, GuardReceipt } from "./guard-types";
import { GUARD_ACTIONS } from "./guard-types";
import { buildDailyStory, buildRecentProtectionCopy } from "./home-dashboard";
import { DecisionBadge } from "./evidence/decision-badge";
import { computeMetrics } from "./evidence/evidence-metrics";
import { filterByDecision } from "./evidence/evidence-filters";
import { plainEnglishDescription } from "./evidence/plain-english";
import { nextSafeStep } from "./evidence/evidence-action-detail";

const NOW = new Date();

function receipt(action: GuardAction): GuardReceipt {
  return {
    receipt_id: `receipt-${action}`,
    harness: "codex",
    artifact_id: `artifact-${action}`,
    artifact_hash: `hash-${action}`,
    policy_decision: action,
    capabilities_summary: "",
    changed_capabilities: [],
    provenance_summary: "",
    user_override: null,
    artifact_name: "tool",
    artifact_type: "tool_action_request",
    source_scope: null,
    timestamp: NOW.toISOString(),
  };
}

const receipts = GUARD_ACTIONS.map(receipt);
const metrics = computeMetrics(receipts, NOW);
assert.deepEqual(
  { total: metrics.total, allowed: metrics.allowed, reviewed: metrics.reviewed, blocked: metrics.blocked },
  { total: 6, allowed: 2, reviewed: 3, blocked: 1 },
  "analytics uses the same six-action disposition contract",
);

assert.deepEqual(
  filterByDecision(receipts, "allow").map((item) => item.policy_decision),
  ["allow", "warn"],
  "the Allowed evidence filter includes warning launches",
);
assert.deepEqual(
  filterByDecision(receipts, "ask").map((item) => item.policy_decision),
  ["review", "require-reapproval", "sandbox-required"],
  "the legacy Review filter includes all three review dispositions",
);
assert.deepEqual(
  filterByDecision(receipts, "block").map((item) => item.policy_decision),
  ["block"],
  "the Stopped filter includes only authoritative blocks",
);

const expectedLabels: Record<GuardAction, string> = {
  allow: "Allowed",
  warn: "Allowed with warning",
  review: "Needs review",
  "require-reapproval": "Needs fresh approval",
  "sandbox-required": "Sandbox required",
  block: "Stopped",
};

for (const action of GUARD_ACTIONS) {
  const markup = renderToStaticMarkup(createElement(DecisionBadge, { decision: action }));
  assert.ok(markup.includes(expectedLabels[action]), `${action}: evidence badge uses the centralized label`);
}

const descriptions = Object.fromEntries(
  receipts.map((item) => [item.policy_decision, plainEnglishDescription(item)]),
) as Record<GuardAction, string>;
assert.ok(descriptions.allow.includes("Guard allowed it automatically."), "allow copy remains an allowed launch");
assert.ok(descriptions.warn.includes("with a warning"), "warn copy preserves its warning");
assert.ok(descriptions.review.includes("paused it for review"), "review copy does not claim the action was blocked");
assert.ok(descriptions["require-reapproval"].includes("paused it for fresh approval"), "reapproval copy requires a fresh decision");
assert.ok(descriptions["sandbox-required"].includes("sandbox requirements are met"), "sandbox copy preserves enforcement");
assert.ok(descriptions.block.includes("blocked it"), "block copy remains blocked");

const blockStep = nextSafeStep(receipt("block"));
assert.ok(blockStep?.includes("cannot be approved"), "blocked receipts do not advertise queue approval");
const sandboxStep = nextSafeStep(receipt("sandbox-required"));
assert.ok(sandboxStep?.includes("approved sandbox"), "sandbox receipts preserve the required execution path");
assert.ok(!sandboxStep?.includes("review queue"), "sandbox receipts do not collapse to ordinary review");

assert.equal(buildRecentProtectionCopy(receipt("warn")), "Codex allowed tool with a warning");
assert.equal(buildRecentProtectionCopy(receipt("review")), "Codex paused tool for review");
assert.equal(buildRecentProtectionCopy(receipt("sandbox-required")), "Codex paused tool until sandbox requirements are met");

const story = buildDailyStory(receipts, 0);
assert.ok(story?.body.includes("allowed 2 actions"), "Home story counts allow and warn as allowed");
assert.ok(story?.body.includes("blocked 1"), "Home story counts the block disposition");
assert.ok(story?.body.includes("sent 3 for review"), "Home story reports all review dispositions");

console.log("authoritative-action-surfaces.test.tsx: all tests passed");
