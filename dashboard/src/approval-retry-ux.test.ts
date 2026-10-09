import { normalizeApprovalRequest } from "./guard-api";
import { buildBulkApproveConsequenceCopy, buildRetryAfterApprovalCopy, summarizeBulkApproveSelection } from "./approval-center-utils";
import {
  bulkApproveConsequenceCopyForSelection,
  countRetryBlockedActions,
  receiptDescribesRequest,
  retryCannotReuseApproval,
  retryCannotReuseApprovalHint,
} from "./approval-retry-guidance";
import { GuardRequestResolutionError } from "./guard-api";
import { bulkApprovalRiskTier, groupDuplicates } from "./queue-state";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { approvalGateRefreshNeeded, resolvedStateForItem } from "./review-decision-state";
import { ReviewScopeControls } from "./review-scope-controls";
import { buildBulkRiskDisclosure } from "./queue-bulk-risk-disclosure";

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
assert(unboundCopy.includes("will still be blocked"), "unbound approval copy says the agent stays blocked");
assert(unboundCopy.includes("Allow in Extensions"), "unbound approval copy points to the extension pattern");
assert(
  buildRetryAfterApprovalCopy(bound, "allow").includes("retry within 5 minutes"),
  "bound native approval copy uses the native 5-minute retry window",
);

// #3838: where "Always allow exact action" is offered, point to it instead of extension patterns.
const alwaysEligible = { ...unbound, exact_action_persistence_eligible: true };
assert(
  buildRetryAfterApprovalCopy(alwaysEligible, "allow").includes("Always allow exact action"),
  "eligible approval copy points to Always allow exact action",
);
assert(
  retryCannotReuseApprovalHint(alwaysEligible, "Oh My Pi").includes("Always allow exact action"),
  "eligible pre-approval hint points to Always allow exact action",
);
assert(
  retryCannotReuseApprovalHint(unbound, "Oh My Pi").includes("Allow in Extensions"),
  "ineligible pre-approval hint points to extension patterns",
);

// #3855: a missing-code error refreshes the stale gate snapshot, like a lock does.
assert(
  approvalGateRefreshNeeded(new GuardRequestResolutionError(403, { error: "approval_gate_totp_required" }, "x")),
  "missing TOTP code refreshes the gate",
);
assert(
  approvalGateRefreshNeeded(new GuardRequestResolutionError(423, { error: "approval_gate_locked" }, "x")),
  "locked gate still refreshes",
);
assert(
  !approvalGateRefreshNeeded(new GuardRequestResolutionError(409, { error: "already_resolved" }, "x")),
  "unrelated errors do not refresh the gate",
);
assert(!approvalGateRefreshNeeded(new Error("network")), "non-resolution errors do not refresh the gate");

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

// Review feedback: the same command text matches a prior receipt even with a fresh per-request hash.
const inProject = (item: typeof unbound, workspaceHash: string) =>
  ({ ...item, action_envelope_json: { ...(item.action_envelope_json ?? {}), workspace_hash: workspaceHash } }) as never;
const projectReceipt = (workspaceHash: string) => ({
  artifact_hash: "fresh-hash",
  raw_command_text: pythonChain,
  action_envelope_json: { workspace_hash: workspaceHash },
});
assert(
  receiptDescribesRequest(inProject(unbound, "ws-a"), projectReceipt("ws-a")),
  "repeat of the same command in the same project keeps its Last time receipt",
);
assert(
  !receiptDescribesRequest(inProject(unbound, "ws-a"), projectReceipt("ws-b")),
  "the same command text in another project does not show its receipt",
);
assert(
  !receiptDescribesRequest(unbound, { artifact_hash: "fresh-hash", raw_command_text: pythonChain }),
  "a receipt without a comparable project stays hidden",
);
assert(
  !receiptDescribesRequest(otherGit, { artifact_hash: "fresh-hash", raw_command_text: pythonChain }),
  "a different command's receipt still does not describe this request",
);
const boundReview = { ...unbound, artifact_hash: "native-review-v4:" + "b".repeat(64) + ":deny:review:review:native_command_review_required" };
assert(
  !receiptDescribesRequest(boundReview, { artifact_hash: "native-review-v4:" + "c".repeat(64), raw_command_text: pythonChain }),
  "a bound review with a different action identity ignores a same-text receipt",
);

// Review feedback: "This time" never promises a retry when the agent stays blocked.
const scopeControls = (oneTimeRetryBlocked: boolean) =>
  renderToStaticMarkup(
    createElement(ReviewScopeControls, {
      commonScopeOptions: [],
      broaderScopeOptions: [],
      advancedScopeOptions: [],
      blockScopeOptions: [],
      hasAllowScope: true,
      taskCapabilityCopy: null,
      exactActionPersistenceEligible: true,
      rememberExactAction: false,
      oneTimeRetryBlocked,
      allowScope: "artifact",
      blockScope: "artifact",
      onAllowScopeChange: () => undefined,
      onBlockScopeChange: () => undefined,
      onRememberExactActionChange: () => undefined,
    }),
  );
assert(
  scopeControls(true).includes("the agent stays blocked") && !scopeControls(true).includes("Retry within 15 minutes"),
  "restricted requests describe This time without a retry promise",
);
assert(scopeControls(false).includes("Retry within 15 minutes"), "reusable requests keep the default retry window");

// Review feedback: bulk approval warns when selected commands stay blocked for the agent.
const bulkStats = {
  actionCount: 2,
  groupCount: 2,
  duplicateActionCount: 0,
  highActionCount: 0,
  elevatedActionCount: 2,
  lowActionCount: 0,
  sensitiveCount: 0,
  sensitiveSamplePaths: [],
};
assert(
  buildBulkRiskDisclosure({ ...bulkStats, retryBlockedActionCount: 2 }).bullets.some((bullet) =>
    bullet.includes("will still be blocked on after approval"),
  ),
  "bulk disclosure warns about commands the agent stays blocked on",
);
assert(
  !buildBulkRiskDisclosure(bulkStats).bullets.some((bullet) => bullet.includes("still be blocked")),
  "bulk disclosure stays unchanged without restricted commands",
);
const restrictedDisclosure = buildBulkRiskDisclosure({ ...bulkStats, retryBlockedActionCount: 1 });
assert(
  !restrictedDisclosure.body.includes("runs once") && !restrictedDisclosure.bullets.some((b) => b.includes("runs once")),
  "bulk disclosure never says restricted commands run once",
);
assert(
  buildBulkRiskDisclosure(bulkStats).bullets[0].includes("Each runs once"),
  "unrestricted bulk disclosure keeps the run-once wording",
);

// Review feedback: count retry-blocked members individually, not by the group's primary.
const reusableTwin = { ...bound, request_id: "44444444444444444444444444444444" };
const blockedTwin = { ...unbound, request_id: "55555555555555555555555555555555" };
assert(
  countRetryBlockedActions([{ primary: bound, duplicateCount: 1, duplicateIds: [blockedTwin.request_id] }], [bound, blockedTwin]) === 1,
  "a blocked duplicate behind a reusable primary is counted",
);
assert(
  countRetryBlockedActions([{ primary: unbound, duplicateCount: 1, duplicateIds: [reusableTwin.request_id] }], [unbound, reusableTwin]) === 1,
  "a reusable duplicate behind a blocked primary is not counted",
);
assert(
  countRetryBlockedActions([{ primary: unbound, duplicateCount: 2, duplicateIds: [blockedTwin.request_id] }], [unbound, blockedTwin]) === 3,
  "a fully blocked group counts every action, matching the bulk action count",
);

// Review feedback: the bulk confirmation never promises a retry for commands that stay blocked.
const restrictedConsequence = bulkApproveConsequenceCopyForSelection(3, 2, buildBulkApproveConsequenceCopy);
assert(
  !restrictedConsequence.includes("retry") && restrictedConsequence.includes("still be blocked"),
  "restricted bulk confirmation drops the retry promise",
);
assert(
  bulkApproveConsequenceCopyForSelection(3, 0, buildBulkApproveConsequenceCopy) === buildBulkApproveConsequenceCopy(3),
  "unrestricted bulk confirmation keeps the existing copy",
);

// Review feedback: the bulk preview falls back to the action-envelope command.
const envelopeOnly = { ...unbound, raw_command_text: null, action_envelope_json: { ...(unbound.action_envelope_json ?? {}), command: "make test" } } as never;
const [envelopeGroup] = groupDuplicates([envelopeOnly]);
const [envelopeLine] = summarizeBulkApproveSelection([envelopeGroup]);
assert(envelopeLine.command === "make test", "bulk preview uses the action-envelope command when raw text is empty");

// #3840: uncategorized commands are not counted as file reads, and the dialog can show the command.
const [pythonGroup] = groupDuplicates([unbound]);
assert(bulkApprovalRiskTier(pythonGroup) === "elevated", "uncategorized shell command is elevated, not low");
const [line] = summarizeBulkApproveSelection([pythonGroup]);
assert(line.command === pythonChain, "bulk approval line carries the command text");

console.log("approval-retry-ux tests passed");
