// Native reviews may lack a retry binding or a supported script execution route.
// The daemon reports the restriction; a specific script refusal takes precedence
// over stale persistence eligibility and legacy retry advice.
import { onceOnlyReasonCopy } from "./approval-scopes";
import type { GuardApprovalRequest } from "./guard-types";
import type { QueueGroup } from "./queue-state";

/** True when the daemon reports that a retry of this native command can never reuse its approval. */
export function retryCannotReuseApproval(item: GuardApprovalRequest): boolean {
  return item.once_only_reason === "script_execution_binding_unavailable" ||
    item.scope_restrictions?.includes("retry_cannot_reuse_approval") === true;
}

/** Native one-time approvals are honoured for 5 minutes (store_native_review_approvals.py); others for 15. */
export function oneTimeRetryWindowMinutes(item: GuardApprovalRequest): number {
  return item.artifact_id.includes(":native-pretool:") ? 5 : 15;
}

/** Labels of the Extensions permissions Guard verified would let this command run, or null when none would. */
function allowPermissionLabels(item: GuardApprovalRequest): string | null {
  const recommendation = item.extension_recommendation;
  if (recommendation?.status !== "available") return null;
  const labels = recommendation.permissions.map((permission) => permission.label).filter((label) => label.length > 0);
  if (labels.length === 0) return null;
  return labels.length === 1 ? labels[0] : `${labels.slice(0, -1).join(", ")} and ${labels[labels.length - 1]}`;
}

/** What lets the agent run a command whose request predates retry bindings. Never "run it yourself". */
function legacyRequestNextStep(item: GuardApprovalRequest, harness: string): string {
  if (item.exact_action_persistence_eligible === true) {
    return `Choose "Always allow exact action" to let ${harness} run this exact command.`;
  }
  const labels = allowPermissionLabels(item);
  const retry = `Ask ${harness} to run the command again; the new request offers Allow once and Always allow.`;
  return labels === null ? retry : `${retry} To let ${harness} run commands like this, set ${labels} to Allow in Extensions.`;
}

/** Explain unavailable delivery before approval, preserving legacy recovery where applicable. */
export function retryCannotReuseApprovalHint(item: GuardApprovalRequest, harness: string): string {
  if (item.once_only_reason === "script_execution_binding_unavailable") {
    return onceOnlyReasonCopy(item.once_only_reason);
  }
  return `An older version of Guard recorded this request, so Run once cannot reach ${harness}'s retry. ${legacyRequestNextStep(item, harness)}`;
}

/** Post-decision copy must not promise a retry through an unsupported execution route. */
export function retryBlockedApprovalCopy(item: GuardApprovalRequest, harness: string): string {
  if (item.once_only_reason === "script_execution_binding_unavailable") {
    return `Decision recorded. ${onceOnlyReasonCopy(item.once_only_reason)}`;
  }
  return `Decision recorded. ${legacyRequestNextStep(item, harness)}`;
}

/**
 * Receipts are looked up by harness and artifact id. For native tool calls that id names
 * the tool (for example `omp:native-pretool:bash`), so only a receipt for the same action
 * hash or the same command text describes this request.
 */
export function receiptDescribesRequest(
  item: GuardApprovalRequest,
  receipt: {
    artifact_hash: string;
    raw_command_text?: string | null;
    action_envelope_json?: { workspace_hash?: string | null } | null;
  },
): boolean {
  if (!item.artifact_id.includes(":native-pretool:")) return true;
  if (receipt.artifact_hash === item.artifact_hash) return true;
  // A bound review's hash is its action identity: a different hash is a different action.
  if (item.artifact_hash.startsWith("native-review-v4:")) return false;
  // Unbound reviews get a fresh hash per request, so a repeat of the same command in the same
  // project matches by its text. Without a comparable project the receipt stays hidden.
  const receiptWorkspace = receipt.action_envelope_json?.workspace_hash;
  if (!receiptWorkspace || receiptWorkspace !== item.action_envelope_json?.workspace_hash) return false;
  const receiptCommand = receipt.raw_command_text?.trim();
  return Boolean(receiptCommand) && receiptCommand === item.raw_command_text?.trim();
}

/** The command a bulk line approves: the raw command text, else the action-envelope command. */
export function bulkLineCommand(item: GuardApprovalRequest): string | null {
  return item.raw_command_text?.trim() || item.action_envelope_json?.command?.trim() || null;
}

/**
 * Count selected actions the agent stays blocked on after approval. Group members can come
 * from different sources with different restrictions, so check every member, not just the
 * primary. A fully blocked group counts all of its actions, matching the bulk action count.
 */
export function countRetryBlockedActions(groups: QueueGroup[], items: GuardApprovalRequest[]): number {
  const byId = new Map(items.map((item) => [item.request_id, item]));
  let total = 0;
  for (const group of groups) {
    const members = [group.primary, ...group.duplicateIds.map((id) => byId.get(id)).filter((item) => item !== undefined)];
    const blocked = members.filter((member) => retryCannotReuseApproval(member)).length;
    total += blocked === members.length ? 1 + group.duplicateCount : blocked;
  }
  return total;
}

/** Bulk confirmation copy that never promises a retry for commands the agent stays blocked on. */
export function bulkApproveConsequenceCopyForSelection(
  actionCount: number,
  retryBlockedActionCount: number,
  defaultCopy: (count: number) => string,
): string {
  if (retryBlockedActionCount <= 0) return defaultCopy(actionCount);
  return `Run once is unavailable for ${retryBlockedActionCount} of these ${actionCount} actions. Open those requests to inspect their execution limitations before approving the remaining actions.`;
}
