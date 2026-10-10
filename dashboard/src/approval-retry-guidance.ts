// Guidance for native reviews whose one-time approval never lets the agent's next call through.
// The daemon marks them with the `retry_cannot_reuse_approval` scope restriction.
import type { GuardApprovalRequest } from "./guard-types";
import type { QueueGroup } from "./queue-state";

/** True when the daemon reports that a retry of this native command can never reuse its approval. */
export function retryCannotReuseApproval(item: GuardApprovalRequest): boolean {
  return item.scope_restrictions?.includes("retry_cannot_reuse_approval") === true;
}

/** Native one-time approvals are honoured for 5 minutes (store_native_review_approvals.py); others for 15. */
export function oneTimeRetryWindowMinutes(item: GuardApprovalRequest): number {
  return item.artifact_id.includes(":native-pretool:") ? 5 : 15;
}

/** Explain, before approval, what actually lets the agent run a command whose one-time approval cannot. */
export function retryCannotReuseApprovalHint(item: GuardApprovalRequest, harness: string): string {
  const base = `Approving just this once records your decision but does not let ${harness} run this command; it will be blocked again.`;
  return item.exact_action_persistence_eligible === true
    ? `${base} To let ${harness} run this exact command, choose "Always allow exact action".`
    : `${base} To let ${harness} run commands like this, set the matching command pattern to Allow in Extensions, or copy the command and run it yourself.`;
}

/** Post-approval copy for a one-time approval that leaves the agent blocked. */
export function retryBlockedApprovalCopy(item: GuardApprovalRequest, harness: string): string {
  return item.exact_action_persistence_eligible === true
    ? `Decision recorded. ${harness} will still be blocked on this command. To let it run this exact command, approve it with "Always allow exact action", or run it yourself.`
    : `Decision recorded. ${harness} will still be blocked on this command. To let it run commands like this, set the matching command pattern to Allow in Extensions, or run the command yourself.`;
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
  const blocked = `${retryBlockedActionCount} of them ${retryBlockedActionCount === 1 ? "is a command" : "are commands"} the agent will still be blocked on.`;
  return `Guard will record your decision for ${actionCount} ${actionCount === 1 ? "action" : "actions"} once and won't remember it. ${blocked} Mass approval skips opening each request, so an unexpected action is harder to catch.`;
}
