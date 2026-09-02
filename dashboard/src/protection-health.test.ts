import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  normalizeProtectionHealth,
  PROTECTION_CHECK_IDS,
  PROTECTION_PROVING_GRACE_MS,
  protectionHeadlineFor,
  protectionHealthFor,
  protectionPresentationState,
  remainingProtectionRepairMessage,
  remainingProtectionRepairParts,
  unavailableProtectionHealth,
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

assert.equal(protectionPresentationState(unavailableProtectionHealth()), "checking");
assert.equal(protectionPresentationState(normalizeProtectionHealth(payload(decisionFailure))), "degraded");
assert.equal(protectionPresentationState(protectedHealth), "protected");
assert.equal(
  protectionPresentationState(normalizeProtectionHealth(payload(decisionGap))),
  "partial",
);

const unprovenCore = checks();
unprovenCore[PROTECTION_CHECK_IDS.indexOf("harness_hooks")] = {
  check_id: "harness_hooks",
  status: "unknown",
  reason_code: "hook_verification_unavailable",
};
const unprovenCoreHealth = normalizeProtectionHealth(payload(unprovenCore));
assert.equal(unprovenCoreHealth.state, "degraded");
assert.equal(protectionPresentationState(unprovenCoreHealth), "checking");

const startupMixed = checks();
for (const checkId of ["harness_hooks", "rule_packs", "tamper_checks"] as const) {
  startupMixed[PROTECTION_CHECK_IDS.indexOf(checkId)] = {
    check_id: checkId,
    status: "unknown",
    reason_code: `${checkId}_unavailable`,
  };
}
const startupMixedHealth = normalizeProtectionHealth(payload(startupMixed));
assert.equal(startupMixedHealth.state, "degraded");
assert.equal(protectionPresentationState(startupMixedHealth), "checking");
assert.equal(protectionPresentationState(protectedHealth), "protected");

const failWhileProving = checks();
failWhileProving[PROTECTION_CHECK_IDS.indexOf("harness_hooks")] = {
  check_id: "harness_hooks",
  status: "fail",
  reason_code: "hooks_verification_failed",
};
failWhileProving[PROTECTION_CHECK_IDS.indexOf("tamper_checks")] = {
  check_id: "tamper_checks",
  status: "unknown",
  reason_code: "tamper_proof_unavailable",
};
assert.equal(
  protectionPresentationState(normalizeProtectionHealth(payload(failWhileProving))),
  "degraded",
);

const settledAttestation = checks();
settledAttestation[PROTECTION_CHECK_IDS.indexOf("harness_hooks")] = {
  check_id: "harness_hooks",
  status: "unknown",
  reason_code: "hook_attestation_unavailable",
};
const settledAttestationHealth = normalizeProtectionHealth(payload(settledAttestation));
assert.equal(
  protectionPresentationState(settledAttestationHealth, { unprovenElapsedMs: 0 }),
  "checking",
);
assert.equal(
  protectionPresentationState(settledAttestationHealth, {
    unprovenElapsedMs: PROTECTION_PROVING_GRACE_MS,
  }),
  "degraded",
);

const appSource = readFileSync(new URL("./app.tsx", import.meta.url), "utf8");
const healthSource = readFileSync(new URL("./protection-health.ts", import.meta.url), "utf8");
const appDetailSource = readFileSync(new URL("./apps/app-detail-workspace.tsx", import.meta.url), "utf8");
const fleetSource = readFileSync(new URL("./fleet-workspace.tsx", import.meta.url), "utf8");
const reviewStatesSource = readFileSync(new URL("./review-states.tsx", import.meta.url), "utf8");
const homeSource = readFileSync(new URL("./home-dashboard.tsx", import.meta.url), "utf8");
assert.match(appSource, /const handleRepairProtection = useCallback/);
assert.match(appSource, /onRepairProtection=\{handleRepairProtection\}/);
assert.match(appSource, /remainingProtectionRepairMessage\(remainingHealth, harnessDisplayName\)/);
assert.match(healthSource, /Command evidence still needs repair/);
assert.match(healthSource, /Connect an AI app to start local protection/);
assert.doesNotMatch(appSource, /app\.checks\.some\(\(check\) => check\.status === "fail"\)/);

const evidenceOnlyHealth = normalizeProtectionHealth({
  ...payload(decisionFailure),
  apps: [
    {
      harness: "grok",
      state: "degraded",
      label: "Degraded",
      detail: "Shared evidence failed.",
      evidence_gap: false,
      reason_codes: ["hooks_verified"],
      checks: checks().map((check) => (
        check.check_id === "decision_stream"
          ? { check_id: "decision_stream", status: "fail", reason_code: "decision_stream_failed" }
          : check
      )),
    },
  ],
});
assert.deepEqual(remainingProtectionRepairParts(evidenceOnlyHealth), {
  failedHookHarnesses: [],
  evidenceFailed: true,
  needsConnectedApp: false,
});

const evidenceUnknown = checks();
evidenceUnknown[PROTECTION_CHECK_IDS.indexOf("decision_stream")] = {
  check_id: "decision_stream",
  status: "unknown",
  reason_code: "decision_stream_gap",
};
assert.equal(
  remainingProtectionRepairParts(normalizeProtectionHealth(payload(evidenceUnknown))).evidenceFailed,
  true,
);

const hookFailureChecks = checks();
hookFailureChecks[PROTECTION_CHECK_IDS.indexOf("harness_hooks")] = {
  check_id: "harness_hooks",
  status: "fail",
  reason_code: "hook_verification_failed",
};
const hookFailureHealth = normalizeProtectionHealth({
  ...payload(hookFailureChecks),
  apps: [
    {
      harness: "grok",
      state: "degraded",
      label: "Degraded",
      detail: "Hooks failed.",
      evidence_gap: false,
      reason_codes: ["hook_verification_failed"],
      checks: hookFailureChecks,
    },
  ],
});
assert.deepEqual(remainingProtectionRepairParts(hookFailureHealth), {
  failedHookHarnesses: ["grok"],
  evidenceFailed: false,
  needsConnectedApp: false,
});
const noManagedChecks = checks();
noManagedChecks[PROTECTION_CHECK_IDS.indexOf("harness_hooks")] = {
  check_id: "harness_hooks",
  status: "fail",
  reason_code: "no_managed_harness",
};
assert.deepEqual(remainingProtectionRepairParts(normalizeProtectionHealth(payload(noManagedChecks))), {
  failedHookHarnesses: [],
  evidenceFailed: false,
  needsConnectedApp: true,
});
assert.match(
  remainingProtectionRepairMessage(normalizeProtectionHealth(payload(noManagedChecks)), (harness) => harness).message,
  /Connect an AI app to start local protection/,
);
assert.match(appDetailSource, /Install state" value=\{active \? "Installed"/);
assert.match(appDetailSource, /protectionHealthFor\(runtime, harness\)/);
assert.match(appDetailSource, /useProtectionPresentationState\(appProtection\)/);
assert.match(fleetSource, /useProtectionPresentationState\(protectionHealth\)/);
assert.match(fleetSource, /resolveAppStatus\(install, appProtection,/);
assert.match(fleetSource, /hookCheck\?\.status === "fail"/);
assert.match(fleetSource, /connectHarness=\{defaultConnectHarness\(repairHarness, visibleHarnesses\)\}/);
assert.match(reviewStatesSource, /useProtectionPresentationState\(protectionHealth\)/);
assert.match(reviewStatesSource, /protectedAppsCount = protectionHealth\.apps\.filter/);
assert.match(reviewStatesSource, /if \(runtime === null\)/);
assert.match(reviewStatesSource, /guard-skeleton/);
assert.match(homeSource, /snapshot\?\.pending_count/);
assert.match(homeSource, /resolveHomeQueuedCount/);
assert.match(homeSource, /useProtectionPresentationState/);
assert.doesNotMatch(homeSource, /protectionHealthFor\(snapshot\)\.state : "degraded"/);
