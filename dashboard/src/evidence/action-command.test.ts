import assert from "node:assert/strict";
import type { GuardReceipt } from "../guard-types";
import { resolveActionCommand, resolveActionTitle } from "./plain-english";

const receipt: GuardReceipt = {
  receipt_id: "example", harness: "bun", artifact_id: "example", artifact_hash: "example",
  policy_decision: "allow", capabilities_summary: "bun custom", changed_capabilities: [],
  provenance_summary: "bun test example.test.ts", artifact_name: "bun", user_override: null,
  source_scope: null, timestamp: "2026-09-10T12:00:00Z",
};
assert.equal(resolveActionCommand(receipt), "bun test example.test.ts");
assert.equal(resolveActionTitle(receipt), "bun test example.test.ts");
assert.equal(resolveActionCommand({ ...receipt, provenance_summary: "hook event for bun" }), null);
assert.equal(resolveActionCommand({ ...receipt, decision_contract_error: "invalid" }), null);
assert.equal(resolveActionCommand({ ...receipt, provenance_summary: "Command details are redacted" }), null);
