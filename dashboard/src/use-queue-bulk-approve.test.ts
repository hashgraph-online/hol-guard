import type { GuardActionEnvelope, GuardApprovalRequest } from "./guard-types";
import { groupDuplicates } from "./queue-state";
import { isBulkSelectableRequest, resolveBulkSelectionGroupId } from "./use-queue-bulk-approve";

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

const plainRead: GuardApprovalRequest = {
  request_id: "req-plain",
  harness: "cursor",
  artifact_id: "cursor:project:plain",
  artifact_name: "file read",
  artifact_type: "command",
  artifact_hash: "hash-plain",
  publisher: null,
  policy_action: "require-reapproval",
  recommended_scope: "artifact",
  changed_fields: ["first_seen"],
  source_scope: "project",
  config_path: "/repo/.cursor/config.toml",
  transport: "stdio",
  review_command: "hol-guard approvals approve req-plain",
  approval_url: "http://127.0.0.1:5474/requests/req-plain",
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: "2026-06-16T00:00:00Z",
  resolved_at: null,
  action_envelope_json: fileReadEnvelope,
};

const secondRead: GuardApprovalRequest = {
  ...plainRead,
  request_id: "req-plain-2",
  action_envelope_json: { ...fileReadEnvelope, target_paths: ["README.md"] },
};

const shellItem: GuardApprovalRequest = {
  ...plainRead,
  request_id: "req-shell",
  action_envelope_json: { ...fileReadEnvelope, action_type: "shell", command: "npm test" },
};

const groups = groupDuplicates([plainRead, secondRead, shellItem]);

assert(
  isBulkSelectableRequest(plainRead, groups) === true,
  "T-BULK-HOOK-01: plain file read is bulk selectable",
);
assert(
  isBulkSelectableRequest(shellItem, groups) === false,
  "T-BULK-HOOK-02: shell command is not bulk selectable",
);
assert(
  resolveBulkSelectionGroupId(plainRead, groups) === "req-plain",
  "T-BULK-HOOK-03: resolveBulkSelectionGroupId returns primary id",
);

console.log("use-queue-bulk-approve.test.ts: all tests passed");
