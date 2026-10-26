import { buildDecisionPayload } from "./approval-scopes";
import type { GuardApprovalRequest, GuardApprovalResolutionInput, GuardQueueResolutionResult } from "./guard-types";
import type { QueueGroup } from "./queue-state";

/** Requests, counting each group's duplicates, so totals match what was confirmed. */
export type BulkBlockOutcome = { blocked: number; failed: number; reasons: string[]; failedIds: string[] };

/** A partial bulk block; `failedIds` are the requests to keep selected for a retry. */
export class BulkBlockError extends Error {
  readonly failedIds: readonly string[];

  constructor(message: string, failedIds: readonly string[]) {
    super(message);
    this.name = "BulkBlockError";
    this.failedIds = failedIds;
  }
}

const MAX_REASONS = 3;

/**
 * Refuse each selected request just this once, the same way "Keep blocked"
 * does, one at a time. Guard keeps a one-time block for 15 minutes so the
 * agent's identical retry is refused too, and saves no lasting rule.
 *
 * The server settles the duplicates it can match with the request it
 * resolves and reports them; any other request in the group is blocked on
 * its own. A request that cannot be blocked just this once is reported, never
 * blocked under a wider remembered scope.
 */
export async function blockRequestsOnce(
  groups: readonly QueueGroup[],
  lookup: (requestId: string) => GuardApprovalRequest | undefined,
  resolve: (input: GuardApprovalResolutionInput) => Promise<GuardQueueResolutionResult>,
): Promise<BulkBlockOutcome> {
  let blocked = 0;
  // Request id to why it could not be blocked, in the order each failed.
  const failures = new Map<string, string>();
  const fail = (requestId: string, error: unknown) => {
    failures.set(requestId, error instanceof Error ? error.message : String(error));
  };
  const blockOnce = async (item: GuardApprovalRequest) => {
    const payload = buildDecisionPayload({ item, action: "block", scope: "artifact", reason: "blocked in bulk review" });
    if (payload.scope !== "artifact") {
      throw new Error("A request could not be blocked just this once. Open it to choose how to block it.");
    }
    return resolve(payload);
  };
  for (const group of groups) {
    // Every request the server reports settled, whichever block settled it.
    const settled = new Set<string>();
    try {
      const result = await blockOnce(group.primary);
      for (const id of result.resolved_duplicate_ids) settled.add(id);
      blocked += 1;
    } catch (error) {
      // A request resolved elsewhere can leave its duplicates pending.
      fail(group.primary.request_id, error);
    }
    for (const duplicateId of group.duplicateIds) {
      if (settled.has(duplicateId)) {
        blocked += 1;
        continue;
      }
      const duplicate = lookup(duplicateId);
      try {
        if (duplicate === undefined) throw new Error("A selected request is no longer in the queue.");
        const result = await blockOnce(duplicate);
        for (const id of result.resolved_duplicate_ids) settled.add(id);
        blocked += 1;
      } catch (error) {
        fail(duplicateId, error);
      }
    }
    // A later block can settle a request that failed earlier in the group,
    // such as a primary the server still held pending. It is blocked, not failed.
    for (const id of settled) {
      if (failures.delete(id)) blocked += 1;
    }
  }
  const reasons: string[] = [];
  for (const reason of failures.values()) {
    if (reasons.length < MAX_REASONS && !reasons.includes(reason)) reasons.push(reason);
  }
  return { blocked, failed: failures.size, reasons, failedIds: [...failures.keys()] };
}

export function bulkBlockSummary(outcome: BulkBlockOutcome): string {
  const unit = outcome.blocked === 1 ? "request" : "requests";
  return `${outcome.blocked} ${unit} blocked.`;
}

export function bulkBlockFailureMessage(outcome: BulkBlockOutcome): string {
  const reason = outcome.reasons.length > 0 ? ` ${outcome.reasons.join(" ")}` : "";
  if (outcome.blocked === 0) {
    return `Guard could not block the selected requests. Open them to block them one at a time.${reason}`;
  }
  return `${outcome.blocked} blocked, ${outcome.failed} failed. Open the failed requests to block them one at a time.${reason}`;
}
