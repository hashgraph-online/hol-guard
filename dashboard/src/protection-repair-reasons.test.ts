import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { GuardProtectionRepairError } from "./guard-api";
import { checkReasonMapValue, REASON_CODE_ID } from "./protection-repair-reasons";

const reasonedRepairError = new GuardProtectionRepairError(409, {
  error: "protection_repair_incomplete",
  repair_scope: "local_integrity",
  message: "Repair paused.",
  pending_check_ids: ["decision_stream"],
  check_reasons: {
    decision_stream: "native_evaluation_unavailable",
    injected: "not a reason!!",
    "not a check!!": "daemon_registration_missing",
  },
});
assert.deepEqual(reasonedRepairError.checkReasons, {
  decision_stream: "native_evaluation_unavailable",
});

const localIntegrityRepairError = new GuardProtectionRepairError(409, {
  error: "local_integrity_repair_incomplete",
  repair_scope: "local_integrity",
  message: "Guard could not establish a local integrity proof.",
  failed_check_ids: ["harness_hooks"],
  failed_harnesses: ["codex"],
  pending_check_ids: ["sandbox"],
});
assert.deepEqual(
  localIntegrityRepairError.checkReasons,
  {},
  "protection repair errors without check_reasons parse to an empty map",
);

assert.ok(REASON_CODE_ID.test("daemon_registration_missing"));
assert.ok(!REASON_CODE_ID.test("not a check!!"));
assert.ok(!REASON_CODE_ID.test("Missing capitals"));
assert.deepEqual(checkReasonMapValue({ daemon: "daemon_registration_missing" }), {
  daemon: "daemon_registration_missing",
});
assert.deepEqual(checkReasonMapValue("not-a-map"), {});
assert.deepEqual(
  checkReasonMapValue({
    "ok.check_id": "daemon_registration_missing",
    oversized_reason: "x".repeat(97),
    ["x".repeat(97)]: "daemon_registration_missing",
    bad_value: 7,
  }),
  { "ok.check_id": "daemon_registration_missing" },
  "oversized or malformed entries are dropped",
);

const guardApiSource = readFileSync(new URL("./guard-api.ts", import.meta.url), "utf8");
assert.ok(
  guardApiSource.includes('from "./protection-repair-reasons"'),
  "guard-api delegates check_reasons parsing to protection-repair-reasons",
);
