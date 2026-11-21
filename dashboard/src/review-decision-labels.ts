import { buildRetryAfterApprovalCopy } from "./approval-center-utils";
import { retryCannotReuseApproval } from "./approval-retry-guidance";
import { willPersistExactAction } from "./approval-scopes";
import type { DecisionScope, GuardApprovalRequest } from "./guard-types";
import { allowButtonLabel, blockButtonLabel } from "./review-scope-controls";

/** What the Allow and Block buttons say, and whether each saves the exact action. */
export function decisionButtonLabels(input: {
  item: GuardApprovalRequest;
  allowScope: DecisionScope;
  blockScope: DecisionScope;
  rememberExactAction: boolean;
  watchOnlyObservation: boolean;
  /** The review uses the two-card MCP choice. */
  simpleMcp: boolean;
}): { persistExactAllow: boolean; persistExactBlock: boolean; allowLabel: string; blockLabel: string } {
  const { item, allowScope, blockScope, watchOnlyObservation } = input;
  const versionBoundScript = item.artifact_type === "native_bash_request";
  const persistExactAllow = willPersistExactAction(item, "allow", allowScope, input.rememberExactAction);
  const persistExactBlock = willPersistExactAction(item, "block", blockScope, watchOnlyObservation);
  let allowLabel = allowButtonLabel(allowScope, versionBoundScript, persistExactAllow);
  if (watchOnlyObservation) {
    allowLabel = "Keep allowing";
  } else if (input.simpleMcp && allowScope === "artifact") {
    allowLabel = persistExactAllow ? "Always allow this call" : "Allow once";
  } else if (persistExactAllow && !versionBoundScript) {
    allowLabel = "Approve and remember";
  } else if (retryCannotReuseApproval(item)) {
    allowLabel = "Choose an available approval duration";
  }
  const blockLabel = watchOnlyObservation || persistExactBlock ? "Stop this next time" : blockButtonLabel(blockScope);
  return { persistExactAllow, persistExactBlock, allowLabel, blockLabel };
}

/** The line shown after a decision is saved. */
export function resolvedActionCopy(
  item: GuardApprovalRequest | null,
  action: "allow" | "block",
  persistedExactAction: boolean,
): string {
  if (item !== null) return buildRetryAfterApprovalCopy(item, action, persistedExactAction);
  if (action === "allow") return "Approved: action can proceed";
  return "Blocked: action stopped";
}
