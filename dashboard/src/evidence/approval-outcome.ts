// A one-time approval of a native review with no retry binding records the user's decision,
// but the agent's retry cannot reuse it, so the action stays stopped.
import type { GuardReceipt } from "../guard-types";

/** The receipt override the daemon writes for that case (memory_decision_outbox.py). */
export const APPROVAL_RETRY_BLOCKED_OVERRIDE = "approval-approved-retry-blocked";

/** The badge and timeline label for that outcome. */
export const APPROVAL_LEFT_STOPPED_LABEL = "Approved, still stopped";

/** True when the user approved this action once but it stayed stopped. */
export function approvalLeftActionStopped(receipt: Pick<GuardReceipt, "user_override">): boolean {
  return receipt.user_override === APPROVAL_RETRY_BLOCKED_OVERRIDE;
}
