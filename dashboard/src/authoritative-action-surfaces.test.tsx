import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { GuardAction, GuardReceipt } from "./guard-types";
import { GUARD_ACTIONS } from "./guard-types";
import { buildDailyStory, buildRecentProtectionCopy } from "./home-dashboard";
import { DecisionBadge } from "./evidence/decision-badge";
import { APPROVAL_RETRY_BLOCKED_OVERRIDE } from "./evidence/approval-outcome";
import { computeMetrics } from "./evidence/evidence-metrics";
import { filterByDecision } from "./evidence/evidence-filters";
import { plainEnglishDescription } from "./evidence/plain-english";
import { EvidenceActionDetail, nextSafeStep } from "./evidence/evidence-action-detail";
import { pastDecisionVerb } from "./review-states";
import { GUARD_REVIEW_INTENT_COPY, guardActionPresentation } from "./guard-action";

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

assert.deepEqual(
  Object.fromEntries(GUARD_ACTIONS.map((action) => [action, pastDecisionVerb(action)])),
  {
    allow: "allowed",
    warn: "allowed with a warning",
    review: "sent for review",
    "require-reapproval": "required fresh approval for",
    "sandbox-required": "required sandboxing for",
    block: "blocked",
  },
  "review history copy preserves every authoritative action",
);

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

// #3844: a one-time approval the agent's retry could not reuse is recorded as an
// allow decision, but the action never ran, so no surface may call it allowed.
const stoppedApproval: GuardReceipt = { ...receipt("allow"), user_override: APPROVAL_RETRY_BLOCKED_OVERRIDE };
const stoppedBadge = renderToStaticMarkup(
  createElement(DecisionBadge, { decision: "allow", userOverride: APPROVAL_RETRY_BLOCKED_OVERRIDE }),
);
assert.ok(stoppedBadge.includes("Approved, still stopped"), "the badge says the approved action stayed stopped");
assert.ok(!stoppedBadge.includes(expectedLabels.allow), "the badge does not call it allowed");
const stoppedDescription = plainEnglishDescription(stoppedApproval);
assert.ok(stoppedDescription.startsWith("Codex tried to"), "the description does not say the action ran");
assert.ok(stoppedDescription.includes("stayed stopped"), "the description names the outcome");
assert.ok(!stoppedDescription.includes("allowed it"), "the description does not claim the action was allowed");
assert.ok(nextSafeStep(stoppedApproval)?.includes("Always allow exact action"), "the next step names what can let it run");
assert.equal(buildRecentProtectionCopy(stoppedApproval), "Codex stayed stopped on tool after a one-time approval");
const stoppedDetail = renderToStaticMarkup(
  createElement(EvidenceActionDetail, { receipt: stoppedApproval, onClose: () => undefined }),
);
const stoppedTimeline = stoppedDetail.slice(stoppedDetail.indexOf('aria-label="Evidence timeline"'));
assert.ok(stoppedTimeline.includes("Approved, still stopped"), "the detail timeline says the action stayed stopped");
assert.ok(!stoppedTimeline.includes(`>${expectedLabels.allow}<`), "the detail timeline does not call it allowed");
assert.ok(stoppedDetail.includes("Next safe step"), "the detail panel shows the next step for a stopped approval");
assert.ok(
  plainEnglishDescription({ ...receipt("allow"), user_override: "approval-approved" }).includes("You reviewed and allowed it."),
  "an approval that let the action run keeps the reviewed-and-allowed copy",
);

for (const action of GUARD_ACTIONS) {
  assert.notEqual(
    GUARD_REVIEW_INTENT_COPY.setup.label,
    guardActionPresentation(action).label,
    `${action}: the Needs setup label never reads as an enforcement outcome`,
  );
}
for (const copy of Object.values(GUARD_REVIEW_INTENT_COPY)) {
  assert.ok(!/\ballow(ed)?\b/i.test(`${copy.label} ${copy.action} ${copy.scope}`), "review intent copy never claims an allow");
}

console.log("authoritative-action-surfaces.test.tsx: all tests passed");
