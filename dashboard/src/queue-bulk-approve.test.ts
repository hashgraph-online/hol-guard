import type { GuardActionEnvelope, GuardApprovalRequest } from "./guard-types";
import {
  buildBulkApproveConsequenceCopy,
  summarizeBulkApproveSelection,
} from "./approval-center-utils";
import { buildBulkGateCredentials } from "./queue-bulk-approve-flow";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const fileReadEnvelope: GuardActionEnvelope = {
  schema_version: 1,
  action_id: "act-read",
  harness: "cursor",
  event_name: "tool_call",
  action_type: "file_read",
  command: null,
  workspace: null,
  workspace_hash: null,
  tool_name: null,
  prompt_excerpt: null,
  target_paths: ["src/index.ts"],
  network_hosts: [],
  mcp_server: null,
  mcp_tool: null,
  package_manager: null,
  package_name: null,
  script_name: null,
  raw_payload_redacted: {},
};

const BASE_REQUEST: GuardApprovalRequest = {
  request_id: "req-1",
  harness: "cursor",
  artifact_id: "cursor:project:read",
  artifact_name: "file read",
  artifact_type: "command",
  artifact_hash: "sha256-001",
  publisher: null,
  policy_action: "require-reapproval",
  recommended_scope: "artifact",
  changed_fields: ["first_seen"],
  source_scope: "project",
  config_path: "/tmp/.cursor/config.toml",
  transport: "stdio",
  review_command: "hol-guard approvals approve req-1",
  approval_url: "http://127.0.0.1:5475/requests/req-1",
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: "2026-04-01T10:00:00Z",
  resolved_at: null,
  action_envelope_json: fileReadEnvelope,
};

const secondRequest: GuardApprovalRequest = {
  ...BASE_REQUEST,
  request_id: "req-2",
  action_envelope_json: { ...fileReadEnvelope, target_paths: ["README.md"] },
};

const summary = summarizeBulkApproveSelection([
  { primary: BASE_REQUEST, duplicateCount: 0 },
  { primary: secondRequest, duplicateCount: 1 },
]);

assert(summary.length === 2, "T-BULK-01: summarizeBulkApproveSelection returns one line per group");
assert(summary[0].path === "src/index.ts", "T-BULK-02: summarizeBulkApproveSelection includes file path");
assert(summary[1].duplicateCount === 1, "T-BULK-03: summarizeBulkApproveSelection preserves duplicate count");

assert(
  buildBulkApproveConsequenceCopy(2).includes("2 read-only file accesses"),
  "T-BULK-04: buildBulkApproveConsequenceCopy pluralizes selected action count"
);

assert(
  buildBulkApproveConsequenceCopy(1).includes("one read-only file access"),
  "T-BULK-05: buildBulkApproveConsequenceCopy handles single selection"
);

const gateCredentials = buildBulkGateCredentials(true, "secret", "123456", true);
assert(gateCredentials?.approval_password === "secret", "T-BULK-06: buildBulkGateCredentials includes password when gate fields are shown");
assert(gateCredentials?.approval_gate_use_cooldown === true, "T-BULK-07: buildBulkGateCredentials includes cooldown preference");

assert(buildBulkGateCredentials(false, "secret", "", false) === undefined, "T-BULK-08: buildBulkGateCredentials omits credentials when gate fields are hidden");

console.log("queue-bulk-approve.test.ts: all tests passed");
