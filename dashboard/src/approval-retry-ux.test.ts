import { normalizeApprovalRequest } from "./guard-api";
import {
  buildRetryAfterApprovalCopy,
  receiptDescribesRequest,
  retryCannotReuseApproval,
  summarizeBulkApproveSelection,
} from "./approval-center-utils";
import { bulkApprovalRiskTier, groupDuplicates } from "./queue-state";
import { resolvedStateForItem } from "./review-decision-card";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function nativeBashRequest(requestId: string, command: string, restrictions: string[]) {
  return normalizeApprovalRequest({
    request_id: requestId,
    harness: "omp",
    artifact_id: "omp:native-pretool:bash",
    artifact_name: "bash",
    artifact_type: "tool_call",
    artifact_hash: requestId,
    policy_action: "review",
    recommended_scope: "artifact",
    changed_fields: ["native_pre_tool"],
    source_scope: "project",
    config_path: "/workspace",
    workspace: "/workspace",
    launch_target: command,
    raw_command_text: command,
    risk_summary: "HOL Guard requires review because the Rust authority could not prove this command explicitly benign.",
    created_at: "2026-10-09T16:00:00+00:00",
    last_seen_at: "2026-10-09T16:00:00+00:00",
    status: "pending",
    dedupe_count: 1,
    scope_contract_version: "guard.approval-scopes.v7",
    scope_contract_digest: "a".repeat(64),
    allowed_scopes: ["artifact"],
    allowed_scopes_by_action: { allow: ["artifact"], block: ["artifact"] },
    recommended_scope_by_action: { allow: "artifact", block: "artifact" },
    scope_restrictions: restrictions,
    task_capability_eligibility: { eligible: false, reason_codes: ["task_capability_not_enabled"] },
    exact_action_persistence_eligible: false,
  } as never);
}

const pythonChain = "python3 joker.py && python3 joker.py -n 2 && python3 joker.py --all | head -6";
const gitChain = 'git checkout -b feature/x && git add f.py && git commit -m "m"';
const unbound = nativeBashRequest("11111111111111111111111111111111", pythonChain, [
  "reusable_allow_is_action_bound",
  "retry_cannot_reuse_approval",
  "task_capability_not_enabled",
]);
const bound = nativeBashRequest("22222222222222222222222222222222", "cat notes.txt", [
  "reusable_allow_is_action_bound",
  "task_capability_not_enabled",
]);
const otherGit = nativeBashRequest("33333333333333333333333333333333", gitChain, ["retry_cannot_reuse_approval"]);

// #3838: approval copy never promises a retry the daemon cannot match.
assert(retryCannotReuseApproval(unbound), "unbound native review is flagged as not reusable");
assert(!retryCannotReuseApproval(bound), "bound native review is not flagged");
const unboundCopy = buildRetryAfterApprovalCopy(unbound, "allow");
assert(!unboundCopy.includes("within 15 minutes"), "unbound approval copy drops the retry window");
assert(unboundCopy.includes("may be blocked again"), "unbound approval copy says the retry may be blocked");
assert(
  buildRetryAfterApprovalCopy(bound, "allow").includes("retry within 15 minutes"),
  "bound approval copy keeps the retry instruction",
);

// #3835: a decision made on one request never applies to the request shown after it.
const decided = { requestId: unbound.request_id, action: "allow" as const, persistedExactAction: false };
assert(resolvedStateForItem(decided, unbound) === decided, "decision applies to its own request");
assert(resolvedStateForItem(decided, otherGit) === null, "decision does not leak onto the next request");
assert(resolvedStateForItem(decided, null) === null, "decision is hidden while no request is shown");

// #3836: a receipt for another command on the same native tool is not "a similar action".
assert(
  !receiptDescribesRequest(otherGit, { artifact_hash: unbound.artifact_hash }),
  "receipt for a different bash command does not describe this request",
);
assert(
  receiptDescribesRequest(unbound, { artifact_hash: unbound.artifact_hash }),
  "receipt for the same action hash describes this request",
);
assert(
  receiptDescribesRequest({ ...unbound, artifact_id: "omp:mcp:server" }, { artifact_hash: "other" }),
  "non-native artifacts keep the existing artifact-level receipt",
);

// #3840: uncategorized commands are not counted as file reads, and the dialog can show the command.
const [pythonGroup] = groupDuplicates([unbound]);
assert(bulkApprovalRiskTier(pythonGroup) === "elevated", "uncategorized shell command is elevated, not low");
const [line] = summarizeBulkApproveSelection([pythonGroup]);
assert(line.command === pythonChain, "bulk approval line carries the command text");

console.log("approval-retry-ux tests passed");
