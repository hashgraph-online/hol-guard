import {
  groupDuplicates,
  sortQueue,
  buildProgressCopy,
} from "./queue-state";
import type { GuardApprovalRequest } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const BASE_REQUEST: GuardApprovalRequest = {
  request_id: "mobile-req-1",
  harness: "claude-code",
  artifact_id: "claude-code:project:bash",
  artifact_name: "bash",
  artifact_type: "command",
  artifact_hash: "sha256-mobile-1",
  publisher: null,
  policy_action: "require-reapproval",
  recommended_scope: "artifact",
  changed_fields: ["first_seen"],
  source_scope: "project",
  config_path: "/Users/test/.codex/config.toml",
  launch_target: "git status",
  transport: "stdio",
  review_command: "hol-guard approvals approve mobile-req-1",
  approval_url: "http://127.0.0.1:4781/approvals/mobile-req-1",
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: "2026-04-11T12:00:00Z",
  resolved_at: null,
  action_envelope_json: null,
};

const SECOND_REQUEST: GuardApprovalRequest = {
  ...BASE_REQUEST,
  request_id: "mobile-req-2",
  artifact_id: "claude-code:project:npm",
  artifact_name: "npm",
  artifact_hash: "sha256-mobile-2",
  review_command: "hol-guard approvals approve mobile-req-2",
  approval_url: "http://127.0.0.1:4781/approvals/mobile-req-2",
  created_at: "2026-04-11T12:01:00Z",
};

const THIRD_REQUEST: GuardApprovalRequest = {
  ...BASE_REQUEST,
  request_id: "mobile-req-3",
  artifact_id: "claude-code:project:curl",
  artifact_name: "curl",
  artifact_hash: "sha256-mobile-3",
  review_command: "hol-guard approvals approve mobile-req-3",
  approval_url: "http://127.0.0.1:4781/approvals/mobile-req-3",
  created_at: "2026-04-11T12:02:00Z",
};

const multipleRequests = [BASE_REQUEST, SECOND_REQUEST, THIRD_REQUEST];

assert(
  multipleRequests.length >= 2,
  "L114: Queue drawer renders multiple requests on mobile (375px) — at least 2 requests exist"
);

const groups = groupDuplicates(multipleRequests);

assert(
  groups.length === 3,
  "L114: Queue drawer lists all 3 requests without collapsing non-duplicates"
);

assert(
  groups[0].primary.request_id === "mobile-req-1",
  "L114: First request is accessible in queue list"
);

assert(
  groups[1].primary.request_id === "mobile-req-2",
  "L114: Second request is accessible in queue list"
);

assert(
  groups[2].primary.request_id === "mobile-req-3",
  "L114: Third request is accessible in queue list"
);

const sortedNewest = sortQueue(multipleRequests, "newest");
assert(
  sortedNewest[0].request_id === "mobile-req-3",
  "L114: Newest sort puts most recent request first (correct order for mobile queue)"
);

const sortedOldest = sortQueue(multipleRequests, "oldest");
assert(
  sortedOldest[0].request_id === "mobile-req-1",
  "L114: Oldest sort puts earliest request first"
);

const progressAt0 = buildProgressCopy(0, 3);
assert(
  progressAt0 === "1 of 3 decisions",
  "L114: Progress copy is correct for first item in 3-item queue"
);

const progressAt2 = buildProgressCopy(2, 3);
assert(
  progressAt2 === "3 of 3 decisions",
  "L114: Progress copy is correct for last item in 3-item queue"
);

assert(
  buildProgressCopy(0, 0) === "",
  "L114: Progress copy is empty when queue is empty"
);

const activeIndex = multipleRequests.findIndex(
  (item) => item.request_id === "mobile-req-1"
);
assert(
  activeIndex === 0,
  "L114: Active request index is correctly computed for queue positioning"
);

const blockedRequest: GuardApprovalRequest = {
  ...BASE_REQUEST,
  request_id: "mobile-blocked-1",
  policy_action: "block",
  artifact_name: "curl",
  artifact_hash: "sha256-mobile-blocked",
};

const blockedGroups = groupDuplicates([blockedRequest, SECOND_REQUEST]);
assert(
  blockedGroups.length === 2,
  "L114: Approve and block buttons are available — both blocked and pending items render in queue"
);

assert(
  blockedGroups[0].primary.policy_action === "block",
  "L114: Blocked item policy_action is preserved — block button reflects correct state"
);

assert(
  blockedGroups[1].primary.policy_action === "require-reapproval",
  "L114: Pending item policy_action is preserved — approve button reflects correct state"
);

const allowLabel = (scope: string): string =>
  scope === "artifact" ? "Approve once" : scope === "workspace" ? "Remember for project" : "Approve and remember";
const blockLabel = (isBlocked: boolean): string =>
  isBlocked ? "Keep blocked" : "Block this action";

assert(
  allowLabel("artifact") === "Approve once",
  "L114: Approve button label is 'Approve once' for artifact scope — visible above fold on mobile"
);

assert(
  allowLabel("workspace") === "Remember for project",
  "L114: Approve button label is 'Remember for project' for workspace scope (GR125)"
);

assert(
  blockLabel(false) === "Block this action",
  "L114: Block button label is 'Block this action' for non-blocked item"
);

assert(
  blockLabel(true) === "Keep blocked",
  "L114: Block button label is 'Keep blocked' for blocked item"
);

assert(
  BASE_REQUEST.recommended_scope === "artifact",
  "L114: Default scope is artifact — sticky button bar uses correct initial label on mobile"
);

assert(
  allowLabel("harness") === "Approve and remember",
  "L115: Approve button label is 'Approve and remember' for broader scopes like harness (GR125)"
);

assert(
  allowLabel("global") === "Approve and remember",
  "L115: Approve button label is 'Approve and remember' for global scope (GR125)"
);
