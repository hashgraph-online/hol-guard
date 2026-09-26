import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { normalizeApprovalRequest } from "./guard-api";
import { resolveActionEnvelopeDetailText } from "./approval-center-utils";

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
assert.equal(request.action_envelope_json?.action_type, "config_change");
assert.ok(request.action_envelope_json);
assert.match(resolveActionEnvelopeDetailText(request.action_envelope_json) ?? "", /1 \+ 1/);
const canonicalCases = [
  { action_type: "shell_command", command: "printf guard", expected: "printf guard" },
  { action_type: "file_read", target_paths: ["src/example.py"], expected: "src/example.py" },
  { action_type: "file_write", target_paths: ["src/output.py"], expected: "src/output.py" },
  { action_type: "network_request", network_hosts: ["example.test"], expected: "example.test" },
  { action_type: "package_script", package_manager: "npm", package_name: "fixture-package", expected: "npm install fixture-package" },
] as const;
for (const { expected, ...details } of canonicalCases) {
  const candidate = { ...envelope, ...details };
  assert.equal(resolveActionEnvelopeDetailText(candidate), expected);
  assert.equal(candidate.action_type, details.action_type);
}
for (const action_type of ["shell_command", "file_read", "file_write", "network_request"]) {
  const candidate = { ...envelope, action_type };
  assert.match(resolveActionEnvelopeDetailText(candidate) ?? "", /1 \+ 1/);
  assert.equal(candidate.action_type, action_type);
}
for (const command of [null, "", "   "]) {
  for (const event_name of ["PreToolUse", "tool_call"]) {
    assert.equal(resolveActionEnvelopeDetailText({
      ...envelope, event_name, action_type: "shell_command", command, raw_payload_redacted: {},
    }), null);
  }
}
console.log("Native review dashboard contract passed");
