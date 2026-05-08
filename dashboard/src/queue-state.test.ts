import type { GuardActionEnvelope, GuardApprovalRequest, GuardQueueResolutionResult } from "./guard-types";
import {
  buildProgressCopy,
  selectNextAfterResolution,
  groupDuplicates,
  sortQueue,
  searchQueue,
  resolveStaleRequestRecovery,
  buildHomePrimaryState,
} from "./queue-state";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
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

assert(
  buildProgressCopy(0, 5) === "1 of 5 decisions",
  "T-QS-01: buildProgressCopy returns '1 of 5 decisions' for first item in five"
);

assert(
  buildProgressCopy(2, 5) === "3 of 5 decisions",
  "T-QS-02: buildProgressCopy returns correct index for third item in five"
);

assert(
  buildProgressCopy(0, 1) === "1 of 1 decisions",
  "T-QS-03: buildProgressCopy handles single item queue"
);

assert(
  buildProgressCopy(0, 0) === "",
  "T-QS-04: buildProgressCopy returns empty string when total is zero"
);

const req2: GuardApprovalRequest = { ...BASE_REQUEST, request_id: "req-2", created_at: "2026-04-01T10:01:00Z" };
const req3: GuardApprovalRequest = { ...BASE_REQUEST, request_id: "req-3", created_at: "2026-04-01T10:02:00Z" };

const resultWithNext: GuardQueueResolutionResult = {
  resolved: true,
  item: BASE_REQUEST,
  resolved_request: BASE_REQUEST,
  remaining_pending_count: 2,
  next_selectable_request_id: "req-2",
  remaining_pending_summaries: [req2, req3],
  resolved_duplicate_ids: [],
  resolution_summary: "Decision saved.",
  retry_hint: null,
  copy: null,
};

assert(
  selectNextAfterResolution(resultWithNext, [BASE_REQUEST, req2, req3]) === "req-2",
  "T-QS-05: selectNextAfterResolution returns next_selectable_request_id when present"
);

const resultNoNext: GuardQueueResolutionResult = {
  ...resultWithNext,
  next_selectable_request_id: null,
  remaining_pending_summaries: [req3],
};

assert(
  selectNextAfterResolution(resultNoNext, [BASE_REQUEST, req2, req3]) === "req-3",
  "T-QS-06: selectNextAfterResolution falls back to first remaining_pending_summary"
);

const resultFallback: GuardQueueResolutionResult = {
  ...resultWithNext,
  next_selectable_request_id: null,
  remaining_pending_summaries: [],
  resolved_duplicate_ids: ["req-1"],
};

assert(
  selectNextAfterResolution(resultFallback, [req2, req3]) === "req-2",
  "T-QS-07: selectNextAfterResolution falls back to current items excluding resolved ids"
);

const resultEmpty: GuardQueueResolutionResult = {
  ...resultWithNext,
  next_selectable_request_id: null,
  remaining_pending_summaries: [],
  resolved_duplicate_ids: ["req-1"],
  resolved_request: BASE_REQUEST,
};

assert(
  selectNextAfterResolution(resultEmpty, [BASE_REQUEST]) === null,
  "T-QS-08: selectNextAfterResolution returns null when no items remain after resolution"
);

const reqA1: GuardApprovalRequest = { ...BASE_REQUEST, request_id: "req-a1", queue_group_id: "grp-a" };
const reqA2: GuardApprovalRequest = { ...BASE_REQUEST, request_id: "req-a2", queue_group_id: "grp-a" };
const reqB: GuardApprovalRequest = { ...BASE_REQUEST, request_id: "req-b" };

const groups = groupDuplicates([reqA1, reqA2, reqB]);

assert(groups.length === 2, "T-QS-09: groupDuplicates collapses items with same queue_group_id into one group");

assert(
  groups[0].primary.request_id === "req-a1",
  "T-QS-10: groupDuplicates uses the first encountered item as primary"
);

assert(groups[0].duplicateCount === 1, "T-QS-11: groupDuplicates counts collapsed duplicates correctly");

assert(
  groups[0].duplicateIds[0] === "req-a2",
  "T-QS-12: groupDuplicates captures duplicate request IDs"
);

assert(groups[1].duplicateCount === 0, "T-QS-13: groupDuplicates reports zero duplicates for ungrouped items");

const oldItem: GuardApprovalRequest = { ...BASE_REQUEST, request_id: "req-old", created_at: "2026-01-01T10:00:00Z" };
const midItem: GuardApprovalRequest = { ...BASE_REQUEST, request_id: "req-mid", created_at: "2026-02-01T10:00:00Z" };
const recentItem: GuardApprovalRequest = { ...BASE_REQUEST, request_id: "req-recent", created_at: "2026-03-01T10:00:00Z" };

const newestFirst = sortQueue([oldItem, recentItem, midItem], "newest");

assert(newestFirst[0].request_id === "req-recent", "T-QS-14: sortQueue puts newest item first when direction is newest");
assert(newestFirst[2].request_id === "req-old", "T-QS-15: sortQueue puts oldest item last when direction is newest");

const oldestFirst = sortQueue([oldItem, recentItem, midItem], "oldest");

assert(oldestFirst[0].request_id === "req-old", "T-QS-16: sortQueue puts oldest item first when direction is oldest");
assert(oldestFirst[2].request_id === "req-recent", "T-QS-17: sortQueue puts newest item last when direction is oldest");

const recentlySeenOldItem: GuardApprovalRequest = {
  ...oldItem,
  request_id: "req-recently-seen",
  last_seen_at: "2026-04-01T10:00:00Z",
};
const olderSeenNewItem: GuardApprovalRequest = {
  ...recentItem,
  request_id: "req-older-seen",
  last_seen_at: "2026-03-01T10:00:00Z",
};
const lastSeenFirst = sortQueue([olderSeenNewItem, recentlySeenOldItem], "newest");
assert(
  lastSeenFirst[0].request_id === "req-recently-seen",
  "T-QS-18: sortQueue prefers last_seen_at over created_at for newest queue order"
);

const shellEnvelope: GuardActionEnvelope = {
  schema_version: 1,
  action_id: "act-shell",
  harness: "codex",
  event_name: "tool_call",
  action_type: "shell_command",
  command: "git diff HEAD~1 -- src/",
  workspace: null,
  workspace_hash: null,
  tool_name: null,
  prompt_excerpt: null,
  target_paths: [],
  network_hosts: [],
  mcp_server: null,
  mcp_tool: null,
  package_manager: null,
  package_name: null,
  script_name: null,
  raw_payload_redacted: {},
};

const shellItem: GuardApprovalRequest = {
  ...BASE_REQUEST,
  request_id: "req-shell",
  action_envelope_json: shellEnvelope,
};

const searchResults = searchQueue([BASE_REQUEST, shellItem], "git diff");

assert(searchResults.length === 1, "T-QS-19: searchQueue filters items by command text");
assert(searchResults[0].request_id === "req-shell", "T-QS-20: searchQueue returns matching item for command search");

const emptyResults = searchQueue([BASE_REQUEST, shellItem], "nonexistent-xyz");
assert(emptyResults.length === 0, "T-QS-21: searchQueue returns empty array when no items match");

const allResults = searchQueue([BASE_REQUEST, shellItem], "");
assert(allResults.length === 2, "T-QS-22: searchQueue returns all items when search term is empty");

const mcpEnvelope: GuardActionEnvelope = {
  ...shellEnvelope,
  action_type: "mcp_tool",
  command: null,
  mcp_server: "my-filesystem-server",
  mcp_tool: "read_file",
};

const mcpItem: GuardApprovalRequest = {
  ...BASE_REQUEST,
  request_id: "req-mcp",
  action_envelope_json: mcpEnvelope,
};

const mcpResults = searchQueue([BASE_REQUEST, shellItem, mcpItem], "filesystem");
assert(mcpResults.length === 1, "T-QS-23: searchQueue matches MCP server name");
assert(mcpResults[0].request_id === "req-mcp", "T-QS-24: searchQueue returns correct item for MCP server search");

assert(
  resolveStaleRequestRecovery("req-1", [BASE_REQUEST, req2]) === "req-1",
  "T-QS-25: resolveStaleRequestRecovery returns active ID when request is still in queue"
);

assert(
  resolveStaleRequestRecovery("req-gone", [req2, req3]) === "req-2",
  "T-QS-26: resolveStaleRequestRecovery falls back to first queue item when active request is stale"
);

assert(
  resolveStaleRequestRecovery("req-gone", []) === null,
  "T-QS-27: resolveStaleRequestRecovery returns null when queue is empty and request is stale"
);

assert(
  resolveStaleRequestRecovery(null, [BASE_REQUEST]) === null,
  "T-QS-28: resolveStaleRequestRecovery returns null when activeRequestId is null"
);

const needsDecision = buildHomePrimaryState(3, 2);
assert(
  needsDecision.status === "needs_decision",
  "T-QS-29: buildHomePrimaryState returns needs_decision status when pending count is greater than zero"
);
assert(
  needsDecision.copy.includes("3 actions"),
  "T-QS-30: buildHomePrimaryState includes action count in copy when pending"
);
assert(
  needsDecision.ctaLabel === "Review blocked action",
  "T-QS-31: buildHomePrimaryState CTA is 'Review blocked action' when pending"
);

const setupNeeded = buildHomePrimaryState(0, 0);
assert(
  setupNeeded.status === "setup_needed",
  "T-QS-32: buildHomePrimaryState returns setup_needed when no watched apps and no pending"
);
assert(
  setupNeeded.ctaLabel === "Connect an app",
  "T-QS-33: buildHomePrimaryState CTA is 'Connect an app' when no watched apps"
);

const protectedState = buildHomePrimaryState(0, 2);
assert(
  protectedState.status === "protected",
  "T-QS-34: buildHomePrimaryState returns protected status when guarded with apps present"
);
assert(
  protectedState.copy.includes("watching"),
  "T-QS-35: buildHomePrimaryState copy mentions watching when protected"
);

const singlePending = buildHomePrimaryState(1, 1);
assert(
  singlePending.copy.includes("1 action paused"),
  "T-QS-36: buildHomePrimaryState uses singular 'action' when exactly one pending"
);
