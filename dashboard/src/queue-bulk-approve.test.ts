import type { GuardActionEnvelope, GuardApprovalRequest } from "./guard-types";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { isBulkApprovableGroup, isReadOnlyQueueGroup, type QueueGroup } from "./queue-state";
import {
  buildBulkApproveConsequenceCopy,
  summarizeBulkApproveSelection,
} from "./approval-center-utils";
import type { GuardApprovalGatePublicConfig } from "./guard-types";
import {
  buildBulkGateCredentials,
  isBulkApproveGateReady,
  validateBulkApproveCredentials,
  QueueBulkGatePrompt,
  QueueBulkStickyBar,
} from "./queue-bulk-approve-flow";

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

const issueWriteGroup: QueueGroup = {
  primary: {
    ...BASE_REQUEST,
    harness: "opencode",
    artifact_name: "gitea:issue_write",
    artifact_type: "mcp",
    action_envelope_json: {
      ...fileReadEnvelope,
      action_type: "mcp_tool",
      tool_name: "issue_write",
      mcp_tool: "issue_write",
      target_paths: [],
    },
  },
  duplicateCount: 0,
  duplicateIds: [],
};
assert(isBulkApprovableGroup(issueWriteGroup), "issue_write retains existing one-shot bulk eligibility");
assert(!isReadOnlyQueueGroup(issueWriteGroup), "issue_write is not a file read");
for (const count of [1, 2]) {
  const prompt = renderToStaticMarkup(createElement(QueueBulkGatePrompt, {
    visible: true, eligibleActionCount: count, settingsHref: "/settings",
  }));
  const bar = renderToStaticMarkup(createElement(QueueBulkStickyBar, {
    visible: true, selectedGroupCount: 1, selectedActionCount: count,
    riskTier: "elevated", riskTone: "amber", gateReady: false,
    onStartReview: () => {}, onClearSelection: () => {},
  }));
  assert(prompt.includes(`Approve ${count} action${count === 1 ? "" : "s"} at once`),
    "non-read bulk eligibility renders an accurate action count");
  assert(!/\breads?\b|read-only/.test(prompt + bar), "non-read approval is never advertised as a read");
  assert(prompt.includes("Enable Ask for proof with a configured approval password"),
    "gate copy explains both enabling proof and configuring a password");
  assert(prompt.includes("never remembers future actions"), "one-shot semantics remain visible");
}

const summary = summarizeBulkApproveSelection([
  { primary: BASE_REQUEST, duplicateCount: 0 },
  { primary: secondRequest, duplicateCount: 1 },
]);

assert(summary.length === 2, "T-BULK-01: summarizeBulkApproveSelection returns one line per group");
assert(summary[0].path === "src/index.ts", "T-BULK-02: summarizeBulkApproveSelection includes file path");
assert(summary[1].duplicateCount === 1, "T-BULK-03: summarizeBulkApproveSelection preserves duplicate count");

assert(
  buildBulkApproveConsequenceCopy(2).toLowerCase().includes("mass approval"),
  "T-BULK-04: buildBulkApproveConsequenceCopy warns about mass approval"
);

assert(
  buildBulkApproveConsequenceCopy(1).includes("approve this action once"),
  "T-BULK-05: buildBulkApproveConsequenceCopy handles single selection with approve-once copy"
);

const readyGate: GuardApprovalGatePublicConfig = {
  enabled: true,
  configured: true,
  cooldown_seconds: 900,
  cooldown_active: false,
  cooldown_expires_at: null,
  locked_until: null,
  fail_closed: false,
  strict_all_decisions: false,
  totp_enabled: false,
  totp_pending: false,
};

assert(isBulkApproveGateReady(readyGate) === true, "T-BULK-06: gate ready when enabled and configured");
assert(isBulkApproveGateReady({ ...readyGate, configured: false }) === false, "T-BULK-07: gate not ready without password");
assert(
  validateBulkApproveCredentials(readyGate, { password: "", totpCode: "" }) !== null,
  "T-BULK-08: validateBulkApproveCredentials rejects empty password",
);

const gateCredentials = buildBulkGateCredentials(readyGate, "secret", "123456");
assert(gateCredentials?.approval_password === "secret", "T-BULK-09: buildBulkGateCredentials includes password when gate is ready");
assert(gateCredentials?.approval_gate_use_cooldown === false, "T-BULK-10: buildBulkGateCredentials never enables cooldown for bulk");
const totpGate = { ...readyGate, totp_enabled: true };
assert(
  validateBulkApproveCredentials(totpGate, { password: "", totpCode: "123456" }) === null,
  "T-BULK-11: validateBulkApproveCredentials accepts totp without password when MFA is enabled",
);
assert(
  validateBulkApproveCredentials(totpGate, { password: "secret", totpCode: "123456" }) === null,
  "T-BULK-12: validateBulkApproveCredentials ignores password when MFA is enabled",
);
const totpCredentials = buildBulkGateCredentials(totpGate, "secret", "123456");
assert(totpCredentials?.approval_totp_code === "123456", "T-BULK-13: buildBulkGateCredentials includes totp when MFA is enabled");
assert(!("approval_password" in (totpCredentials ?? {})), "T-BULK-14: buildBulkGateCredentials omits password when MFA is enabled");

assert(buildBulkGateCredentials(null, "secret", "") === undefined, "T-BULK-15: buildBulkGateCredentials omits credentials when gate is not ready");

console.log("queue-bulk-approve.test.ts: all tests passed");
