import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  GuardProtectionRepairError,
} from "./guard-api";
import type { GuardProtectionCheck } from "./guard-types";
import {
  nextProtectionRepairOutcome,
  protectionGapSignature,
  protectionRepairFinishMessage,
  RECHECK_UNAVAILABLE_SIGNATURE,
  repairOutcomeIsStalled,
  resetRepairOutcomeTracker,
} from "./protection-repair-flow";
import {
  normalizeProtectionHealth,
  PROTECTION_CHECK_IDS,
  remainingProtectionRepairMessage,
} from "./protection-health";
import { protectionReasonText } from "./protection-reason-copy";

function checks(status: GuardProtectionCheck["status"] = "pass"): GuardProtectionCheck[] {
  return PROTECTION_CHECK_IDS.map((checkId) => ({
    check_id: checkId,
    status,
    reason_code: `${checkId}_verified`,
  }));
}

function healthWith(checkValues: GuardProtectionCheck[]) {
  return normalizeProtectionHealth({
    schema_version: "guard.protection-health.v1",
    state: "degraded",
    label: "Degraded",
    detail: "Degraded",
    evidence_gap: false,
    reason_codes: [],
    checks: checkValues,
    apps: [],
  });
}

// Gap signatures only cover repairable (non-pass, non-unsupported) checks.
const signed = checks();
signed[PROTECTION_CHECK_IDS.indexOf("decision_stream")] = {
  check_id: "decision_stream",
  status: "unknown",
  reason_code: "native_evaluation_unavailable",
};
signed[PROTECTION_CHECK_IDS.indexOf("sandbox")] = {
  check_id: "sandbox",
  status: "fail",
  reason_code: "unsupported_platform",
};
assert.equal(
  protectionGapSignature(signed),
  "decision_stream:unknown:native_evaluation_unavailable",
  "unsupported platform gaps are excluded from the repair signature",
);

const multiGap = checks();
multiGap[PROTECTION_CHECK_IDS.indexOf("sandbox")] = {
  check_id: "sandbox",
  status: "fail",
  reason_code: "containment_probe_stale",
};
multiGap[PROTECTION_CHECK_IDS.indexOf("daemon")] = {
  check_id: "daemon",
  status: "unknown",
  reason_code: "daemon_registration_missing",
};
assert.equal(
  protectionGapSignature(multiGap),
  "daemon:unknown:daemon_registration_missing|sandbox:fail:containment_probe_stale",
  "signatures are deterministic across gap order",
);

// Two identical incomplete outcomes stall the repair loop; a changed signature resets it.
let tracker = nextProtectionRepairOutcome(null, "a:fail:x");
assert.equal(repairOutcomeIsStalled(tracker, "a:fail:x"), false);
tracker = nextProtectionRepairOutcome(tracker, "a:fail:x");
assert.deepEqual(tracker, {
  signature: "a:fail:x",
  count: 2,
  healthSignature: "a:fail:x",
});
assert.equal(repairOutcomeIsStalled(tracker, "a:fail:x"), true);
tracker = nextProtectionRepairOutcome(tracker, "b:fail:y");
assert.deepEqual(tracker, {
  signature: "b:fail:y",
  count: 1,
  healthSignature: "b:fail:y",
});
assert.equal(repairOutcomeIsStalled(tracker, "b:fail:y"), false);
assert.equal(
  resetRepairOutcomeTracker(
    { signature: "a:fail:x", count: 5, healthSignature: "a:fail:x" },
    "a:fail:x",
  )?.count,
  5,
);
assert.equal(
  resetRepairOutcomeTracker(
    { signature: "a:fail:x", count: 5, healthSignature: "a:fail:x" },
    "c:fail:z",
  ),
  null,
);

// Two consecutive failed rechecks stall while health is unchanged; once health
// changes (for example after a runtime restart) the tracker resets so repair
// can run again.
const healthAtOutcome = "daemon:unknown:daemon_registration_missing";
let recheckTracker = nextProtectionRepairOutcome(
  null,
  RECHECK_UNAVAILABLE_SIGNATURE,
  healthAtOutcome,
);
assert.equal(repairOutcomeIsStalled(recheckTracker, healthAtOutcome), false);
recheckTracker = nextProtectionRepairOutcome(
  recheckTracker,
  RECHECK_UNAVAILABLE_SIGNATURE,
  healthAtOutcome,
);
assert.deepEqual(recheckTracker, {
  signature: RECHECK_UNAVAILABLE_SIGNATURE,
  count: 2,
  healthSignature: healthAtOutcome,
});
assert.equal(
  repairOutcomeIsStalled(recheckTracker, healthAtOutcome),
  true,
  "unchanged health keeps the recheck stall",
);
assert.equal(
  resetRepairOutcomeTracker(recheckTracker, healthAtOutcome),
  recheckTracker,
  "unchanged health keeps the recheck tracker",
);
const changedHealth = "decision_stream:fail:decision_stream_degraded";
assert.equal(resetRepairOutcomeTracker(recheckTracker, changedHealth), null);
assert.equal(
  repairOutcomeIsStalled(recheckTracker, changedHealth),
  false,
  "changed health is not stalled even before the reset effect runs",
);

// Repair errors expose per-check reason codes parsed from the daemon payload.
const reasonedError = new GuardProtectionRepairError(409, {
  error: "protection_repair_incomplete",
  repair_scope: "local_integrity",
  message: "Repair paused.",
  pending_check_ids: ["decision_stream"],
  check_reasons: {
    decision_stream: "native_evaluation_unavailable",
    daemon: "daemon_registration_missing",
    "unsafe key!": "daemon_registration_missing",
    oversized: "x".repeat(97),
    malformed: "Not a reason code",
    numeric: 7,
  },
});
assert.deepEqual(reasonedError.checkReasons, {
  decision_stream: "native_evaluation_unavailable",
  daemon: "daemon_registration_missing",
});
assert.deepEqual(reasonedError.pendingCheckIds, ["decision_stream"]);

// Reason copy covers the reason codes repair and runtime health can emit.
assert.equal(
  protectionReasonText("native_evaluation_unavailable"),
  "Guard could not run the native policy engine to prove command evidence.",
);
assert.equal(
  protectionReasonText("daemon_registration_missing"),
  "Guard is re-registering the running local runtime. This clears on the next check.",
);
for (const code of [
  "daemon_runtime_unavailable",
  "daemon_heartbeat_stale",
  "daemon_heartbeat_unavailable",
  "daemon_runtime_drift",
  "daemon_registration_unavailable",
  "daemon_registration_foreign",
  "containment_health_invalid",
  "containment_health_unavailable",
  "containment_probe_stale",
  "containment_probe_failed",
  "policy_digest_mismatch",
  "unsupported_platform",
  "decision_stream_degraded",
  "decision_stream_health_unavailable",
  "no_managed_harness",
  "hook_verification_failed",
  "one_or_more_hooks_inactive",
  "hook_attestation_unavailable",
  "hook_repair_failed",
  "hook_repair_unknown",
  "rule_pack_runtime_proof_unavailable",
  "rule_packs_disabled",
  "tamper_checks_failed",
  "tamper_proof_unavailable",
  "local_integrity_unproven",
  "proof_unavailable",
]) {
  assert.equal(typeof protectionReasonText(code), "string", `reason copy exists for ${code}`);
}
assert.equal(protectionReasonText("unlisted_reason_code"), null);

// Remaining-gap messaging is reason aware.
const registrationMissing = checks();
registrationMissing[PROTECTION_CHECK_IDS.indexOf("daemon")] = {
  check_id: "daemon",
  status: "unknown",
  reason_code: "daemon_registration_missing",
};
assert.match(
  remainingProtectionRepairMessage(healthWith(registrationMissing), (harness) => harness).message,
  /The local runtime is re-registering; check again in a moment\./,
);

const nativeUnavailable = checks();
nativeUnavailable[PROTECTION_CHECK_IDS.indexOf("decision_stream")] = {
  check_id: "decision_stream",
  status: "unknown",
  reason_code: "native_evaluation_unavailable",
};
const nativeMessage = remainingProtectionRepairMessage(
  healthWith(nativeUnavailable),
  (harness) => harness,
).message;
assert.match(nativeMessage, /Guard could not run the native policy engine to prove command evidence\./);
assert.doesNotMatch(nativeMessage, /Run a protected command/);

const evidenceDegraded = checks();
evidenceDegraded[PROTECTION_CHECK_IDS.indexOf("decision_stream")] = {
  check_id: "decision_stream",
  status: "fail",
  reason_code: "decision_stream_degraded",
};
const degradedMessage = remainingProtectionRepairMessage(
  healthWith(evidenceDegraded),
  (harness) => harness,
).message;
assert.match(degradedMessage, /Guard could not restore command evidence persistence\./);
assert.doesNotMatch(
  degradedMessage,
  /Run a protected command/,
  "repair copy never instructs the user to run a protected command",
);

const mixedFailure = checks();
mixedFailure[PROTECTION_CHECK_IDS.indexOf("decision_stream")] = {
  check_id: "decision_stream",
  status: "fail",
  reason_code: "decision_stream_degraded",
};
mixedFailure[PROTECTION_CHECK_IDS.indexOf("harness_hooks")] = {
  check_id: "harness_hooks",
  status: "fail",
  reason_code: "hook_verification_failed",
};
const mixedMessage = remainingProtectionRepairMessage(
  healthWith(mixedFailure),
  (harness) => harness,
).message;
assert.doesNotMatch(mixedMessage, /Run a protected command/);
assert.match(mixedMessage, /Guard could not restore command evidence persistence\./);

// A successful recheck after a repair that reported reasons is qualified, not
// claimed as a clean pass.
assert.equal(
  protectionRepairFinishMessage({
    decision_stream: "native_evaluation_unavailable",
    daemon: "daemon_registration_missing",
  }),
  "Protection checks pass, but Guard could not finish: " +
    "Guard is re-registering the running local runtime. This clears on the next check. " +
    "Guard could not run the native policy engine to prove command evidence.",
);
assert.equal(
  protectionRepairFinishMessage({ decision_stream: "unlisted_reason_code" }),
  "Protection checks pass, but Guard could not finish: Reason code: unlisted_reason_code",
);

const flowSource = readFileSync(new URL("./protection-repair-flow.ts", import.meta.url), "utf8");
assert.match(flowSource, /protectionRepairFinishMessage\(repairCheckReasons\)/);

// The recovery surface renders stable reason copy and the stalled restart step.
const recoverySource = readFileSync(new URL("./fleet-protection-recovery.tsx", import.meta.url), "utf8");
const recoveryPartsSource = readFileSync(
  new URL("./fleet-protection-recovery-parts.tsx", import.meta.url),
  "utf8",
);
const recoveryCopySource = readFileSync(
  new URL("./fleet-protection-recovery-copy.ts", import.meta.url),
  "utf8",
);
assert.match(recoveryPartsSource, /protectionReasonText\(check\.reason_code\)/);
assert.match(recoveryPartsSource, /Reason code: \{check\.reason_code\}/);
assert.match(recoverySource, /repairOutcomeIsStalled\(repairOutcomeTracker, currentGapSignature\)/);
assert.match(
  recoverySource,
  /nextProtectionRepairOutcome\(tracker, outcomeSignature, outcomeHealthSignature\)/,
);
assert.match(recoveryPartsSource, /STALLED_REPAIR_SUMMARY/);
assert.match(recoveryPartsSource, /STALLED_RECHECK_SUMMARY/);
assert.match(recoverySource, /RECHECK_UNAVAILABLE_SIGNATURE/);
assert.match(recoverySource, /actionForCheck\(check, props\.repairHarness\)\.label/);
assert.match(recoveryPartsSource, /\{RUNTIME_STOP_COMMAND\}/);
assert.match(recoveryPartsSource, /\{RUNTIME_START_COMMAND\}/);
assert.match(recoveryCopySource, /Repair stopped after two attempts ended the same way\./);
assert.match(recoveryCopySource, /Repair stopped after two attempts could not recheck protection\./);
assert.match(recoveryCopySource, /hol-guard daemon stop/);
assert.match(recoveryCopySource, /hol-guard bootstrap/);
assert.doesNotMatch(recoveryCopySource, /`hol-guard/, "restart copy must not embed literal backticks");
