import type { GuardApprovalRequest, GuardReceipt } from "./guard-types";
import {
  isReadOnlyQueueGroup,
  isSensitiveFileReadItem,
  countSensitiveFileReadGroups,
  groupDuplicates,
  type QueueGroup,
} from "./queue-state";
import { resolveFileReadPath } from "./approval-center-utils";
import { exportReceiptsAsCsv } from "./history-export";
import { resolveSecurityLevelDescription, resolveSecurityLevelCardDescription } from "./settings-workspace";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`FAIL: ${message}`);
}

const BASE_REQUEST: GuardApprovalRequest = {
  request_id: "req-1",
  harness: "codex",
  artifact_id: "codex:project:bash",
  artifact_name: "bash",
  artifact_type: "command",
  artifact_hash: "sha256-001",
  publisher: null,
  policy_action: "require-reapproval",
  recommended_scope: "artifact",
  changed_fields: ["first_seen"],
  source_scope: "project",
  config_path: "/Users/test/.codex/config.toml",
  transport: "stdio",
  review_command: "hol-guard approvals approve req-1",
  approval_url: "http://127.0.0.1:4455/approvals/req-1",
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: "2026-04-01T10:00:00Z",
  resolved_at: null,
  action_envelope_json: null,
};

function makeItem(overrides: Partial<GuardApprovalRequest>): GuardApprovalRequest {
  return { ...BASE_REQUEST, ...overrides };
}

function makeGroup(item: GuardApprovalRequest, duplicates: string[] = []): QueueGroup {
  return { primary: item, duplicateCount: duplicates.length, duplicateIds: duplicates };
}

const plainFileReadItem = makeItem({
  artifact_type: "file_read_request",
  action_envelope_json: {
    schema_version: 1,
    action_id: "a1",
    harness: "codex",
    event_name: "file_read",
    action_type: "file_read",
    workspace: null,
    workspace_hash: null,
    tool_name: null,
    command: null,
    prompt_excerpt: null,
    target_paths: ["/Users/test/project/src/main.ts"],
    network_hosts: [],
    mcp_server: null,
    mcp_tool: null,
    package_manager: null,
    package_name: null,
    script_name: null,
    raw_payload_redacted: {},
  },
});

const secretFileReadItem = makeItem({
  artifact_type: "file_read_request",
  risk_headline: "secret file access",
  risk_summary: "reads .env file containing credentials",
  decision_v2_json: {
    guard_action: "require-reapproval",
    action: "ask",
    reason: "secret read",
    user_title: "Secret file access",
    user_body: "reads .env",
    harness_message: "secret",
    dashboard_primary_detail: "reads .env containing credential",
    approval_scopes: [],
    retry_instruction: null,
    signals: [
      {
        signal_id: "sec-001",
        category: "secret",
        severity: "high",
        confidence: "strong",
        detector: "secret.read",
        title: "Secret file read",
        plain_reason: "reads .env file",
        technical_detail: null,
        evidence_ref: null,
        redaction_level: "none",
        false_positive_hint: null,
        advisory_id: null,
      },
    ],
    confidence: "strong",
  },
  action_envelope_json: {
    schema_version: 1,
    action_id: "a2",
    harness: "codex",
    event_name: "file_read",
    action_type: "file_read",
    workspace: null,
    workspace_hash: null,
    tool_name: null,
    command: null,
    prompt_excerpt: null,
    target_paths: ["/Users/test/project/.env"],
    network_hosts: [],
    mcp_server: null,
    mcp_tool: null,
    package_manager: null,
    package_name: null,
    script_name: null,
    raw_payload_redacted: {},
  },
});

const blockedFileReadItem = makeItem({
  artifact_type: "file_read_request",
  policy_action: "block",
  action_envelope_json: {
    schema_version: 1,
    action_id: "a3",
    harness: "codex",
    event_name: "file_read",
    action_type: "file_read",
    workspace: null,
    workspace_hash: null,
    tool_name: null,
    command: null,
    prompt_excerpt: null,
    target_paths: ["/etc/passwd"],
    network_hosts: [],
    mcp_server: null,
    mcp_tool: null,
    package_manager: null,
    package_name: null,
    script_name: null,
    raw_payload_redacted: {},
  },
});

const shellItem = makeItem({
  artifact_type: "command",
  action_envelope_json: {
    schema_version: 1,
    action_id: "a4",
    harness: "codex",
    event_name: "shell_command",
    action_type: "shell_command",
    workspace: null,
    workspace_hash: null,
    tool_name: null,
    command: "ls -la",
    prompt_excerpt: null,
    target_paths: [],
    network_hosts: [],
    mcp_server: null,
    mcp_tool: null,
    package_manager: null,
    package_name: null,
    script_name: null,
    raw_payload_redacted: {},
  },
});

assert(
  isSensitiveFileReadItem(plainFileReadItem) === false,
  "SF-01: plain file read is not sensitive"
);

assert(
  isSensitiveFileReadItem(secretFileReadItem) === true,
  "SF-02: secret file read is sensitive"
);

assert(
  isSensitiveFileReadItem(shellItem) === false,
  "SF-03: shell command is not a sensitive file read"
);

assert(
  isReadOnlyQueueGroup(makeGroup(plainFileReadItem)) === true,
  "SF-04: plain file read group is bulk-approvable"
);

assert(
  isReadOnlyQueueGroup(makeGroup(secretFileReadItem)) === false,
  "SF-05: secret file read group is NOT bulk-approvable"
);

assert(
  isReadOnlyQueueGroup(makeGroup(blockedFileReadItem)) === false,
  "SF-06: blocked file read is not bulk-approvable"
);

assert(
  isReadOnlyQueueGroup(makeGroup(shellItem)) === false,
  "SF-07: shell command is not bulk-approvable"
);

const mixedGroups = [
  makeGroup(plainFileReadItem),
  makeGroup(secretFileReadItem),
  makeGroup(shellItem),
  makeGroup(blockedFileReadItem),
];

assert(
  countSensitiveFileReadGroups(mixedGroups) === 1,
  "SF-08: counts exactly one sensitive file read group"
);

assert(
  countSensitiveFileReadGroups([makeGroup(shellItem), makeGroup(plainFileReadItem)]) === 0,
  "SF-09: no sensitive reads in shell+plain set"
);

assert(
  countSensitiveFileReadGroups([makeGroup(secretFileReadItem), makeGroup(secretFileReadItem)]) === 2,
  "SF-10: counts each sensitive group separately"
);

const plainPath = resolveFileReadPath(plainFileReadItem);
assert(plainPath === "/Users/test/project/src/main.ts", "SF-11: resolves path from target_paths");

const secretPath = resolveFileReadPath(secretFileReadItem);
assert(secretPath === "/Users/test/project/.env", "SF-12: resolves secret file path");

const shellPath = resolveFileReadPath(shellItem);
assert(shellPath === null, "SF-13: shell command has no file read path");

const noPathItem = makeItem({
  artifact_type: "file_read_request",
  action_envelope_json: null,
  launch_target: "/fallback/path.txt",
});
const fallbackPath = resolveFileReadPath(noPathItem);
assert(fallbackPath === "/fallback/path.txt", "SF-14: falls back to launch_target");

function makeReceipt(id: string, overrides: Partial<GuardReceipt> = {}): GuardReceipt {
  return {
    receipt_id: id,
    harness: "codex",
    artifact_id: `artifact-${id}`,
    artifact_hash: `hash-${id}`,
    policy_decision: "allow",
    capabilities_summary: "Summary",
    changed_capabilities: [],
    provenance_summary: "Provenance",
    user_override: null,
    artifact_name: `Tool ${id}`,
    source_scope: null,
    timestamp: new Date("2024-06-15T10:00:00.000Z").toISOString(),
    ...overrides,
  };
}

const formulaReceipts = [
  makeReceipt("f1", { artifact_name: "=HYPERLINK(\"http://evil.com\")" }),
  makeReceipt("f2", { artifact_name: "+1 malicious" }),
  makeReceipt("f3", { artifact_name: "-1 malicious" }),
  makeReceipt("f4", { artifact_name: "@SUM(A1:A10)" }),
  makeReceipt("f5", { artifact_name: "safe name" }),
  makeReceipt("f6", { artifact_name: "normal,with,commas" }),
];

const formulaCsv = exportReceiptsAsCsv(formulaReceipts);
const formulaText = await formulaCsv.blob.text();

assert(
  formulaText.includes("'=HYPERLINK"),
  "SF-15: =formula cell is sanitized with single-quote prefix in CSV"
);
assert(
  formulaText.includes("'+1 malicious"),
  "SF-16: +formula cell is prefixed with single-quote in CSV"
);
assert(
  formulaText.includes("'-1 malicious"),
  "SF-17: -formula cell is prefixed with single-quote in CSV"
);
assert(
  formulaText.includes("'@SUM"),
  "SF-18: @formula cell is prefixed with single-quote in CSV"
);
assert(
  formulaText.includes("safe name"),
  "SF-19: safe cell is written unmodified"
);
assert(
  formulaText.includes('"normal,with,commas"'),
  "SF-20: cell with commas is quoted"
);

const relaxedDesc = resolveSecurityLevelCardDescription("relaxed");
assert(
  !relaxedDesc.toLowerCase().includes("ask before"),
  "SF-21: relaxed description does not say 'ask before' (would mislead about warn behavior)"
);
assert(
  relaxedDesc.toLowerCase().includes("warn"),
  "SF-22: relaxed card description mentions warn behavior"
);

const groupsAll = groupDuplicates([plainFileReadItem, secretFileReadItem, shellItem]);
const bulkEligible = groupsAll.filter((g) => isReadOnlyQueueGroup(g));
assert(
  bulkEligible.length === 1,
  "SF-23: only plain file read is eligible for bulk approval (not secret, not shell)"
);
assert(
  bulkEligible[0].primary.request_id === plainFileReadItem.request_id,
  "SF-24: correct item is bulk-eligible"
);

console.log("security-fixes.test.ts: all tests passed");
