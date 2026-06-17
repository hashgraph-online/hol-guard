import type { GuardActionEnvelope, GuardApprovalRequest } from "./guard-types";
import {
  countDuplicateActionsInGroups,
  countSensitiveFileReadGroups,
  groupDuplicates,
  isReadOnlyQueueGroup,
  summarizeSensitiveFileReadGroups,
  bulkApproveActionCount,
  type QueueGroup,
} from "./queue-state";
import {
  isBulkSelectableRequest,
  resolveBulkSelectionGroupId,
} from "./use-queue-bulk-approve";
import { isBulkApproveGateReady } from "./queue-bulk-approve-flow";
import {
  buildBulkRiskDisclosure,
  resolveBulkRiskTier,
  type BulkSelectionStats,
} from "./queue-bulk-risk-disclosure";

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

const sensitiveRead: GuardApprovalRequest = {
  ...plainRead,
  request_id: "req-secret",
  artifact_name: "secret file read",
  risk_summary: "Reads a credential file containing secrets",
  action_envelope_json: { ...fileReadEnvelope, target_paths: [".env"] },
};

const shellItem: GuardApprovalRequest = {
  ...plainRead,
  request_id: "req-shell",
  action_envelope_json: { ...fileReadEnvelope, action_type: "shell_command", command: "npm test" },
};

const groups = groupDuplicates([plainRead, secondRead, shellItem]);

// T-BULK-HOOK-01: plain file read is bulk selectable
assert(
  isBulkSelectableRequest(plainRead, groups) === true,
  "T-BULK-HOOK-01: plain file read is bulk selectable",
);
// T-BULK-HOOK-02: shell command is not bulk selectable
assert(
  isBulkSelectableRequest(shellItem, groups) === false,
  "T-BULK-HOOK-02: shell command is not bulk selectable",
);
// T-BULK-HOOK-03: resolveBulkSelectionGroupId returns primary id
assert(
  resolveBulkSelectionGroupId(plainRead, groups) === "req-plain",
  "T-BULK-HOOK-03: resolveBulkSelectionGroupId returns primary id",
);

// T-BULK-HOOK-04: ambient selection eligibility — isReadOnlyQueueGroup covers single eligible group
assert(
  isReadOnlyQueueGroup({ primary: plainRead, duplicateCount: 0, duplicateIds: [] }) === true,
  "T-BULK-HOOK-04: isReadOnlyQueueGroup true for a single plain read",
);

// T-BULK-HOOK-05: duplicate actions counted across groups
const dupGroups: QueueGroup[] = [
  { primary: plainRead, duplicateCount: 2, duplicateIds: ["a", "b"] },
  { primary: secondRead, duplicateCount: 0, duplicateIds: [] },
];
assert(
  countDuplicateActionsInGroups(dupGroups) === 2,
  "T-BULK-HOOK-05: countDuplicateActionsInGroups sums duplicate counts",
);

// T-BULK-HOOK-06: sensitive groups detected + summarized
const mixedGroups = groupDuplicates([plainRead, sensitiveRead, shellItem]);
const sensitiveCount = countSensitiveFileReadGroups(mixedGroups);
assert(sensitiveCount >= 1, "T-BULK-HOOK-06a: sensitive reads counted in groups");
const sensitiveSummary = summarizeSensitiveFileReadGroups(mixedGroups);
assert(sensitiveSummary.count >= 1, "T-BULK-HOOK-06b: summarizeSensitiveFileReadGroups counts sensitive");
assert(
  sensitiveSummary.samplePaths.length <= 3,
  "T-BULK-HOOK-06c: sample paths capped at 3",
);

// T-BULK-HOOK-07: a selection with sensitive items in queue escalates risk to high
const statsWithSensitive: BulkSelectionStats = {
  actionCount: 2,
  groupCount: 2,
  duplicateActionCount: 0,
  sensitiveCount: 1,
  sensitiveSamplePaths: [".env"],
};
assert(
  resolveBulkRiskTier(statsWithSensitive) === "high",
  "T-BULK-HOOK-07a: sensitive-in-queue forces high tier even at low selection",
);
const disclosureWithSensitive = buildBulkRiskDisclosure(statsWithSensitive);
assert(
  disclosureWithSensitive.requiresTypedConfirm === true,
  "T-BULK-HOOK-07b: sensitive selection requires typed confirm",
);
assert(
  disclosureWithSensitive.bullets.some((b) => b.includes(".env")),
  "T-BULK-HOOK-07c: sensitive sample path included in disclosure bullets",
);

// T-BULK-HOOK-08: a high-tier selection (>=10 reads) requires typed confirm
const highStats: BulkSelectionStats = {
  actionCount: 12,
  groupCount: 10,
  duplicateActionCount: 2,
  sensitiveCount: 0,
  sensitiveSamplePaths: [],
};
const highDisclosure = buildBulkRiskDisclosure(highStats);
assert(highDisclosure.tier === "high", "T-BULK-HOOK-08a: 12 reads is high tier");
assert(highDisclosure.requiresTypedConfirm === true, "T-BULK-HOOK-08b: high tier requires typed confirm");
assert(
  highDisclosure.confirmPhrase === "approve 12 reads",
  "T-BULK-HOOK-08c: high confirm phrase matches selection count",
);
assert(
  highDisclosure.bullets.some((b) => b.includes("duplicate retr") && b.includes("included")),
  "T-BULK-HOOK-08d: duplicate retries surfaced in high disclosure",
);

// T-BULK-HOOK-09: discovery path — when the gate is not configured, ambient
// selection is suppressed, so a discovery prompt must remain reachable.
// This guards against the regression where eligible reads exist but the user
// has no approval gate configured (gatePromptVisible requires !bulkGateReady).
assert(
  isBulkApproveGateReady(null) === false,
  "T-BULK-HOOK-09a: gate not ready when no config is supplied",
);
assert(
  isBulkApproveGateReady({ enabled: true, configured: false, cooldown_seconds: 0, cooldown_active: false, cooldown_expires_at: null, locked_until: null, fail_closed: false, strict_all_decisions: false, totp_enabled: false, totp_pending: false }) === false,
  "T-BULK-HOOK-09b: gate not ready when configured is false",
);
// The discovery banner surfaces the eligible action count, which must be > 0
// whenever eligible groups exist.
const eligibleActionCount = bulkApproveActionCount([
  { primary: plainRead, duplicateCount: 0, duplicateIds: [] },
  { primary: secondRead, duplicateCount: 1, duplicateIds: ["dup"] },
]);
assert(
  eligibleActionCount === 3,
  "T-BULK-HOOK-09c: eligible action count drives the discovery banner copy",
);

console.log("use-queue-bulk-approve.test.ts: all tests passed");
