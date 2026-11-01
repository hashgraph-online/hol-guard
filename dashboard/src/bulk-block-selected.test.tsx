import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { blockRequestsOnce, bulkBlockFailureMessage, bulkBlockSummary } from "./bulk-block-requests";
import type { GuardApprovalRequest, GuardApprovalResolutionInput, GuardQueueResolutionResult } from "./guard-types";
import { QueueBulkStickyBar } from "./queue-bulk-approve-flow";
import type { QueueGroup } from "./queue-state";
import {
  bulkBlockGroups,
  isBulkBlockableGroup,
  type QueueBulkStickyBarProps,
} from "./use-queue-bulk-approve";

const pending: GuardApprovalRequest = {
  request_id: "req-stale",
  harness: "omp",
  artifact_id: "omp:tool:bash",
  artifact_name: "bash",
  artifact_type: "tool_call",
  artifact_hash: "hash-stale",
  publisher: null,
  policy_action: "review",
  recommended_scope: "artifact",
  changed_fields: ["first_seen"],
  source_scope: "project",
  config_path: "/home/alice/.omp/agent/settings.json",
  transport: "stdio",
  review_command: "hol-guard approvals deny req-stale",
  approval_url: "http://127.0.0.1:5474/requests/req-stale",
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: "2026-10-13T00:00:00Z",
  resolved_at: null,
};

function group(primary: GuardApprovalRequest, duplicateIds: string[] = []): QueueGroup {
  return { primary, duplicateCount: duplicateIds.length, duplicateIds };
}

// Any pending request can be refused; a resolved one cannot. Queue pages
// leave `status` out, and those requests are pending.
assert.equal(isBulkBlockableGroup(group(pending)), true);
const { status: _omitted, ...fromQueuePage } = pending;
assert.equal(isBulkBlockableGroup(group(fromQueuePage as GuardApprovalRequest)), true);
assert.equal(isBulkBlockableGroup(group({ ...pending, status: "resolved" })), false);
// Requests a single review cannot block are not selectable for bulk either.
assert.equal(isBulkBlockableGroup(group({ ...pending, policy_action: "block" })), false);
assert.equal(isBulkBlockableGroup(group({ ...pending, policy_action: "sandbox-required" })), false);
assert.equal(isBulkBlockableGroup(group({ ...pending, native_business_review_display_only: true } as GuardApprovalRequest)), false);

// Only selected, pending groups are blocked.
const second = { ...pending, request_id: "req-second" };
const groups = [group(pending, ["req-dup"]), group(second), group({ ...pending, request_id: "req-done", status: "resolved" })];
assert.deepEqual(
  bulkBlockGroups(groups, new Set(["req-stale", "req-done"])).map((selected) => selected.primary.request_id),
  ["req-stale"],
);

function settled(...ids: string[]): GuardQueueResolutionResult {
  return {
    resolved: true,
    item: null,
    resolved_request: null,
    remaining_pending_count: 0,
    next_selectable_request_id: null,
    remaining_pending_summaries: [],
    resolved_duplicate_ids: ids,
    resolution_summary: "Decision saved.",
    retry_hint: null,
    copy: null,
    codexResume: null,
  } as GuardQueueResolutionResult;
}

// Each request is blocked just this once at artifact scope and never
// remembered. A duplicate the server settles is counted; one it leaves
// pending is blocked on its own, so totals match the confirmed count.
const looseDuplicate = { ...pending, request_id: "req-loose" };
const queued = new Map([looseDuplicate].map((item) => [item.request_id, item]));
const sent: GuardApprovalResolutionInput[] = [];
const outcome = await blockRequestsOnce(
  [group(pending, ["req-dup", "req-loose"]), group(second)],
  (id) => queued.get(id),
  async (input) => {
    sent.push(input);
    if (input.requestId === "req-second") throw new Error("This request was already resolved.");
    return settled(...(input.requestId === "req-stale" ? ["req-dup"] : []));
  },
);
assert.deepEqual(outcome, { blocked: 3, failed: 1, reasons: ["This request was already resolved."], failedIds: ["req-second"] });
assert.deepEqual(
  sent.map((input) => [input.requestId, input.action, input.scope, input.persist_policy]),
  [
    ["req-stale", "block", "artifact", undefined],
    ["req-loose", "block", "artifact", undefined],
    ["req-second", "block", "artifact", undefined],
  ],
);

// A loose duplicate's own block can settle the rest of the group.
const looseB = { ...pending, request_id: "req-loose-b" };
const looseQueue = new Map([looseDuplicate, looseB].map((item) => [item.request_id, item]));
const looseSent: string[] = [];
const looseOutcome = await blockRequestsOnce(
  [group(pending, ["req-loose", "req-loose-b"])],
  (id) => looseQueue.get(id),
  async (input) => {
    looseSent.push(input.requestId);
    return settled(...(input.requestId === "req-loose" ? ["req-loose-b"] : []));
  },
);
assert.deepEqual(looseOutcome, { blocked: 3, failed: 0, reasons: [], failedIds: [] });
assert.deepEqual(looseSent, ["req-stale", "req-loose"]);

// A request resolved elsewhere still lets its pending duplicates be blocked.
const orphanSent: string[] = [];
const orphanOutcome = await blockRequestsOnce(
  [group(pending, ["req-loose"])],
  (id) => looseQueue.get(id),
  async (input) => {
    orphanSent.push(input.requestId);
    if (input.requestId === "req-stale") throw new Error("This request was already resolved.");
    return settled();
  },
);
assert.deepEqual(orphanOutcome, { blocked: 1, failed: 1, reasons: ["This request was already resolved."], failedIds: ["req-stale"] });
assert.deepEqual(orphanSent, ["req-stale", "req-loose"]);

// A request whose block cannot be one-time is reported, never blocked wider.
const projectOnly = {
  ...pending,
  request_id: "req-project",
  workspace: "/home/alice/notes",
  scope_contract_version: "1",
  scope_contract_digest: "digest-project",
  allowed_scopes_by_action: { allow: ["artifact"], block: ["workspace"] },
  recommended_scope_by_action: { allow: "artifact", block: "workspace" },
} as GuardApprovalRequest;
const wider: GuardApprovalResolutionInput[] = [];
const refused = await blockRequestsOnce([group(projectOnly)], () => undefined, async (input) => {
  wider.push(input);
  return settled();
});
assert.equal(wider.length, 0);
assert.equal(refused.failed, 1);
assert.match(refused.reasons[0] ?? "", /could not be blocked just this once/);

// A block that settles a request which failed earlier in its group does not
// leave that request reported as failed, and its reason is no longer shown.
const lateSent: string[] = [];
const lateOutcome = await blockRequestsOnce(
  [group(pending, ["req-loose"])],
  (id) => looseQueue.get(id),
  async (input) => {
    lateSent.push(input.requestId);
    if (input.requestId === "req-stale") throw new Error("Guard could not be reached.");
    return settled("req-stale");
  },
);
assert.deepEqual(lateOutcome, { blocked: 2, failed: 0, reasons: [], failedIds: [] });
assert.deepEqual(lateSent, ["req-stale", "req-loose"]);

// A failed duplicate settled by a later duplicate is reconciled too, while a
// request that stays failed keeps its own reason and stays selected.
const lateDuplicate = { ...pending, request_id: "req-late-dup" };
const stayQueue = new Map([looseDuplicate, lateDuplicate].map((item) => [item.request_id, item]));
const stayOutcome = await blockRequestsOnce(
  [group(pending, ["req-loose", "req-late-dup"])],
  (id) => stayQueue.get(id),
  async (input) => {
    if (input.requestId === "req-stale") throw new Error("This request was already resolved.");
    if (input.requestId === "req-loose") throw new Error("Guard could not be reached.");
    return settled("req-loose");
  },
);
assert.deepEqual(stayOutcome, {
  blocked: 2,
  failed: 1,
  reasons: ["This request was already resolved."],
  failedIds: ["req-stale"],
});

assert.equal(bulkBlockSummary({ blocked: 2, failed: 0, reasons: [], failedIds: [] }), "2 requests blocked.");
assert.equal(
  bulkBlockFailureMessage({ blocked: 1, failed: 1, reasons: ["This request was already resolved."], failedIds: ["req-second"] }),
  "1 blocked, 1 failed. Open the failed requests to block them one at a time. This request was already resolved.",
);
assert.match(bulkBlockFailureMessage({ blocked: 0, failed: 3, reasons: [], failedIds: [] }), /could not block the selected requests/);

const noop = () => undefined;
const bar: QueueBulkStickyBarProps = {
  visible: true,
  selectedGroupCount: 0,
  selectedActionCount: 0,
  selectedRequestCount: 3,
  canApprove: false,
  riskTier: "low",
  riskTone: "green",
  gateReady: false,
  blockAvailable: true,
  blockStep: "idle",
  blockError: null,
  onStartReview: noop,
  onRequestBlock: noop,
  onConfirmBlock: noop,
  onCancelBlock: noop,
  onClearSelection: noop,
};

// A selection of requests that can only be blocked offers no approval.
const blockOnly = renderToStaticMarkup(createElement(QueueBulkStickyBar, bar));
assert.match(blockOnly, />3<\/span> requests selected</);
assert.match(blockOnly, /Block selected/);
assert.doesNotMatch(blockOnly, /Review &amp; approve/);
assert.doesNotMatch(blockOnly, /Low risk/);

// Confirming names the count and that the block is just this once.
const confirming = renderToStaticMarkup(createElement(QueueBulkStickyBar, { ...bar, blockStep: "confirming" }));
assert.match(confirming, /Block 3 requests just this once\? Any agent still waiting is told no\./);
assert.match(confirming, />Block 3</);
assert.doesNotMatch(confirming, /Block selected/);

const blocking = renderToStaticMarkup(createElement(QueueBulkStickyBar, { ...bar, blockStep: "blocking" }));
assert.match(blocking, /Blocking…/);
assert.match(blocking, /disabled=""/);

// A mixed selection says how many of the selected requests can be approved.
const mixed = renderToStaticMarkup(createElement(QueueBulkStickyBar, {
  ...bar,
  canApprove: true,
  gateReady: true,
  selectedGroupCount: 1,
  selectedActionCount: 1,
}));
assert.match(mixed, /3<\/span> requests selected · 1 can be approved at once/);
assert.match(mixed, /Review &amp; approve/);
assert.match(mixed, /Block selected/);

const failed = renderToStaticMarkup(createElement(QueueBulkStickyBar, { ...bar, blockError: "1 blocked, 1 failed." }));
assert.match(failed, /role="alert"[^>]*>1 blocked, 1 failed\.</);

// With nothing left selected the bar is hidden, but a partial block's outcome
// is still shown; without one, nothing is rendered.
const hiddenFailure = renderToStaticMarkup(createElement(QueueBulkStickyBar, {
  ...bar,
  visible: false,
  blockError: "1 blocked, 1 failed.",
}));
assert.match(hiddenFailure, /role="alert"[^>]*>1 blocked, 1 failed\.</);
assert.doesNotMatch(hiddenFailure, /Block selected/);
assert.equal(renderToStaticMarkup(createElement(QueueBulkStickyBar, { ...bar, visible: false })), "");

console.log("bulk-block-selected.test.tsx: all tests passed");
