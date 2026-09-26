import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { normalizeApprovalRequest } from "./guard-api";

const envelope = JSON.parse(readFileSync(
  new URL("../../tests/fixtures/native-review-action-envelope.json", import.meta.url), "utf8",
));
const request = normalizeApprovalRequest({
  request_id: "native-review-fixture", harness: "omp",
  artifact_id: "omp:tool:eval", artifact_name: "eval", artifact_type: "tool_call",
  artifact_hash: "fixture-hash", publisher: null, policy_action: "review",
  recommended_scope: "artifact", changed_fields: ["native_pre_tool"],
  source_scope: "harness", config_path: "fixture", launch_target: "tool:eval",
  transport: "stdio", review_command: "fixture", approval_url: null,
  status: "pending", resolution_action: null, resolution_scope: null, reason: null,
  created_at: "2026-04-11T12:00:00Z", resolved_at: null,
  action_envelope_json: envelope, decision_v2_json: null,
});
assert.equal(request.decision_contract_error, undefined);
assert.equal(request.action_envelope_json?.tool_name, "eval");
console.log("Native review dashboard contract passed");
