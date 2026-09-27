import assert from "node:assert/strict";

import { requestResolutionBlockReason } from "./approval-center-utils";
import { normalizeApprovalRequest, parseActionEnvelope } from "./guard-api";
import type { GuardApprovalRequest, GuardDecisionV2 } from "./guard-types";

const historicalNativeReviewEnvelope = {
  schema_version: 1,
  action_id: "native-review",
  harness: "cursor",
  event_name: "PreToolUse",
  action_type: "shell_command" as const,
  workspace: null,
  workspace_hash: null,
  tool_name: "Shell",
  command: "printf fixture",
  prompt_excerpt: null,
  prompt_text: null,
  target_paths: [],
  network_hosts: [],
  mcp_server: null,
  mcp_tool: null,
  package_manager: null,
  package_name: null,
  pre_execution_result: "review" as const,
};

const decision: GuardDecisionV2 = {
  guard_action: "review",
  action: "ask",
  reason: "Review required before this action can run.",
  user_title: "Needs review",
  user_body: "HOL Guard paused this action for review.",
  harness_message: "HOL Guard paused this action for review.",
  dashboard_primary_detail: "printf fixture",
  approval_scopes: ["artifact", "workspace", "publisher", "harness"],
  retry_instruction: "Retry the action after approval.",
  signals: [],
  confidence: "likely",
};

const request: GuardApprovalRequest = {
  request_id: "native-review",
  harness: "cursor",
  artifact_id: "cursor:native-pretool:Shell",
  artifact_name: "Shell",
  artifact_type: "tool_call",
  artifact_hash: "fixture-hash",
  publisher: null,
  policy_action: "review",
  recommended_scope: "artifact",
  changed_fields: ["native_pre_tool"],
  source_scope: "project",
  config_path: "fixture",
  launch_target: "printf fixture",
  transport: "stdio",
  review_command: "hol-guard approvals approve native-review",
  approval_url: null,
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: "2026-09-26T22:10:36Z",
  resolved_at: null,
  action_envelope_json: null,
};

const parsed = parseActionEnvelope(historicalNativeReviewEnvelope);
assert(parsed !== null, "historical native reviews omit presentation fields without losing their action");
assert.equal(parsed?.script_name, null);
assert.deepEqual(parsed?.raw_payload_redacted, {});
assert.equal(parsed?.pre_execution_result, "review");

assert.equal(parseActionEnvelope({ ...historicalNativeReviewEnvelope, script_name: 1 }), null);
assert.equal(parseActionEnvelope({ ...historicalNativeReviewEnvelope, raw_payload_redacted: null }), null);
assert.equal(parseActionEnvelope({ ...historicalNativeReviewEnvelope, raw_payload_redacted: ["not-a-record"] }), null);
assert.equal(parseActionEnvelope({ ...historicalNativeReviewEnvelope, final_action: "allow" }), null);

const approvable = normalizeApprovalRequest({
  ...request,
  action_envelope_json: historicalNativeReviewEnvelope,
  decision_v2_json: decision,
});
assert.equal(approvable.decision_contract_error, undefined);
assert.equal(approvable.policy_action, "review");
assert.equal(approvable.action_envelope_json?.pre_execution_result, "review");
assert.equal(approvable.decision_v2_json?.action, "ask");
assert.equal(requestResolutionBlockReason(approvable), null);

const contradictory = normalizeApprovalRequest({
  ...request,
  action_envelope_json: { ...historicalNativeReviewEnvelope, pre_execution_result: "block" },
  decision_v2_json: decision,
});
assert.equal(contradictory.decision_contract_error, "authoritative_decision_inconsistent");
assert.equal(contradictory.action_envelope_json, null);
assert.match(requestResolutionBlockReason(contradictory) ?? "", /inconsistent stored decision data/);

console.log("historical native review envelope contract passed");
