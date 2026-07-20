import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  normalizeProtectionHealth,
  PROTECTION_CHECK_IDS,
  protectionHeadlineFor,
  protectionHealthFor,
} from "./protection-health";
import type { GuardProtectionCheck, GuardRuntimeSnapshot } from "./guard-types";

function checks(status: GuardProtectionCheck["status"] = "pass"): GuardProtectionCheck[] {
  return PROTECTION_CHECK_IDS.map((checkId) => ({
    check_id: checkId,
    status,
    reason_code: `${checkId}_verified`,
  }));
}

function payload(checkValues: GuardProtectionCheck[]) {
  return {
    schema_version: "guard.protection-health.v1",
    state: "degraded",
    label: "Untrusted server label",
    detail: "Untrusted server detail",
    evidence_gap: true,
    reason_codes: ["untrusted"],
    checks: checkValues,
    apps: [],
  };
}

const protectedHealth = normalizeProtectionHealth(payload(checks()));
assert.equal(protectedHealth.state, "protected");
assert.equal(protectedHealth.label, "Protected");
assert.equal(protectedHealth.evidence_gap, false);

const decisionGap = checks();
decisionGap[PROTECTION_CHECK_IDS.indexOf("decision_stream")] = {
  check_id: "decision_stream",
  status: "unknown",
  reason_code: "decision_stream_gap",
};
assert.equal(normalizeProtectionHealth(payload(decisionGap)).state, "partial");

const decisionFailure = checks();
decisionFailure[PROTECTION_CHECK_IDS.indexOf("decision_stream")] = {
  check_id: "decision_stream",
  status: "fail",
  reason_code: "decision_stream_failed",
};
assert.equal(normalizeProtectionHealth(payload(decisionFailure)).state, "degraded");

const malformed = normalizeProtectionHealth({
  ...payload(checks().slice(0, -1)),
  local_path: "/private/workspace",
});
assert.equal(malformed.state, "degraded");
assert.equal(JSON.stringify(malformed).includes("/private/workspace"), false);

const duplicateChecks = checks();
duplicateChecks[0] = duplicateChecks[1];
assert.equal(normalizeProtectionHealth(payload(duplicateChecks)).state, "degraded");

const oversizedApps = Array.from({ length: 101 }, (_, index) => ({
  harness: `app-${index}`,
  ...payload(checks()),
}));
assert.equal(normalizeProtectionHealth({ ...payload(checks()), apps: oversizedApps }).apps.length, 0);

const duplicateApps = [
  { harness: "codex", ...payload(checks()) },
  { harness: "codex", ...payload(decisionFailure) },
];
const duplicateAppHealth = normalizeProtectionHealth({ ...payload(checks()), apps: duplicateApps });
assert.equal(duplicateAppHealth.state, "degraded");
assert.equal(duplicateAppHealth.apps.length, 0);

const scoped = normalizeProtectionHealth({
  ...payload(checks()),
  apps: [{ harness: "codex", ...payload(checks()) }],
});
const snapshot = { protection_health: scoped };
assert.equal(protectionHealthFor(snapshot, "codex").state, "protected");
assert.equal(protectionHealthFor(snapshot, "unknown").state, "degraded");

const degradedHealth = normalizeProtectionHealth(payload(decisionFailure));
const contradictorySnapshot: Pick<GuardRuntimeSnapshot, "protection_health"> = {
  protection_health: {
    ...degradedHealth,
    state: "protected",
    label: "Protected",
  },
};
assert.equal(protectionHealthFor(contradictorySnapshot).state, "degraded");
assert.equal(protectionHealthFor(contradictorySnapshot).label, "Degraded");

assert.deepEqual(
  protectionHeadlineFor({ health: degradedHealth, runtimeActive: true, pendingCount: 0 }),
  {
    headline_state: "degraded",
    headline_label: "Degraded",
    headline_detail: "One or more required protection checks failed or remain unproven.",
  },
);
assert.equal(
  protectionHeadlineFor({ health: protectedHealth, runtimeActive: true, pendingCount: 1 }).headline_state,
  "blocked",
);
assert.equal(
  protectionHeadlineFor({ health: protectedHealth, runtimeActive: false, pendingCount: 0 }).headline_state,
  "setup",
);

const appDetailSource = readFileSync(new URL("./apps/app-detail-workspace.tsx", import.meta.url), "utf8");
const fleetSource = readFileSync(new URL("./fleet-workspace.tsx", import.meta.url), "utf8");
const reviewStatesSource = readFileSync(new URL("./review-states.tsx", import.meta.url), "utf8");
assert.match(appDetailSource, /Install state" value=\{active \? "Installed"/);
assert.match(appDetailSource, /protectionHealthFor\(runtime, harness\)/);
assert.match(fleetSource, /resolveAppStatus\(install, appProtection\.state/);
assert.match(reviewStatesSource, /protectedAppsCount = protectionHealth\.apps\.filter/);
