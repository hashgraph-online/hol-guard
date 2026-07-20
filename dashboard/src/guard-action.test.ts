import assert from "node:assert/strict";
import { GUARD_ACTIONS } from "./guard-types";
import {
  guardActionActivityCopy,
  guardActionDisposition,
  guardActionPresentation,
  guardDecisionV2Action,
  isActionBearingKey,
  isAllowedGuardAction,
  isBlockedGuardAction,
  isRecognizedGuardActionInput,
  mostRestrictiveGuardAction,
  normalizeGuardAction,
} from "./guard-action";

const expected = {
  allow: ["allowed", "Allowed", "allowed", true],
  warn: ["allowed", "Allowed with warning", "allowed with a warning", true],
  review: ["reviewed", "Needs review", "paused for review", false],
  "require-reapproval": ["reviewed", "Needs fresh approval", "paused for fresh approval", false],
  "sandbox-required": ["reviewed", "Sandbox required", "paused until sandbox requirements are met", false],
  block: ["blocked", "Stopped", "blocked", false],
} as const;

assert.deepEqual(Object.keys(expected), [...GUARD_ACTIONS], "all six Guard actions have a presentation contract");

for (const action of GUARD_ACTIONS) {
  const presentation = guardActionPresentation(action);
  const [disposition, label, copy, allowsLaunch] = expected[action];
  assert.equal(presentation.action, action, `${action}: exact authoritative action is preserved`);
  assert.equal(presentation.disposition, disposition, `${action}: disposition`);
  assert.equal(presentation.label, label, `${action}: label`);
  assert.equal(presentation.copy, copy, `${action}: copy`);
  assert.equal(presentation.allowsLaunch, allowsLaunch, `${action}: launch semantics`);
}

assert.equal(normalizeGuardAction("ask"), "review", "legacy product-level ask remains compatible");
assert.equal(isRecognizedGuardActionInput("ask"), true, "legacy ask is a recognized compatibility alias");
assert.equal(guardActionDisposition("ask"), "reviewed", "legacy ask is counted as reviewed");
assert.equal(normalizeGuardAction("future-action"), "review", "unknown actions fail closed to review");
assert.equal(guardActionPresentation("future-action").label, "Needs review", "unknown actions are never labeled allowed");
assert.equal(isAllowedGuardAction("warn"), true, "warn allows launch and counts as allowed");
assert.equal(isAllowedGuardAction("sandbox-required"), false, "sandbox-required is not counted as allowed");
assert.equal(isBlockedGuardAction("block"), true, "block is the blocked disposition");
assert.equal(isBlockedGuardAction("review"), false, "review remains distinct from a policy block");
assert.equal(mostRestrictiveGuardAction("allow", "sandbox-required", "warn"), "sandbox-required");
assert.equal(isActionBearingKey("finalAction"), true, "camel-case hidden action aliases are detected");
assert.equal(isActionBearingKey("redaction_level"), false, "redaction metadata is not an action alias");
assert.deepEqual(
  GUARD_ACTIONS.map((action) => guardDecisionV2Action(action)),
  ["allow", "warn", "ask", "ask", "ask", "block"],
  "all exact actions map deterministically to Decision V2",
);
assert.equal(
  guardActionActivityCopy("sandbox-required", "Codex", "a local action"),
  "Codex paused a local action until sandbox requirements are met",
  "activity copy remains grammatical for sandbox enforcement",
);

console.log("guard-action.test.ts: all tests passed");
