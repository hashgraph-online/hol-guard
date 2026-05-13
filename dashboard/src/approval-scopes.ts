import type { DecisionScope, GuardApprovalRequest } from "./guard-types";

export type ApprovalScopeChoice = {
  value: DecisionScope;
  label: string;
  description: string;
};

export const DEFAULT_SCOPE_CHOICES: ApprovalScopeChoice[] = [
  {
    value: "artifact",
    label: "Approve once",
    description:
      "Allow only this exact action this time. Guard will ask again for anything different. Nothing is saved.",
  },
  {
    value: "workspace",
    label: "Remember for project",
    description:
      "Save this decision for the current project. Future matching actions skip review here without asking again.",
  },
  {
    value: "publisher",
    label: "This source",
    description:
      "Save this decision for all actions from the same source. Matching actions skip review in any project.",
  },
  {
    value: "harness",
    label: "This app",
    description:
      "Save this decision for this AI app everywhere. Matching actions from this app skip review in all your projects.",
  },
  {
    value: "global",
    label: "Everywhere",
    description:
      "Save this decision across all your projects on this machine. All matching actions skip review. Use only if you fully trust this.",
  },
];

export function requestSupportsScope(item: GuardApprovalRequest, scope: DecisionScope): boolean {
  if (scope === "workspace") {
    return typeof item.workspace === "string" && item.workspace.trim().length > 0;
  }
  if (scope === "publisher") {
    return typeof item.publisher === "string" && item.publisher.trim().length > 0;
  }
  return true;
}

export function filterScopeChoicesForRequest<T extends { value: DecisionScope }>(
  item: GuardApprovalRequest,
  choices: readonly T[],
): T[] {
  return choices.filter((choice) => requestSupportsScope(item, choice.value));
}

export function scopeChoicesForRequest(item: GuardApprovalRequest): ApprovalScopeChoice[] {
  return filterScopeChoicesForRequest(item, DEFAULT_SCOPE_CHOICES);
}

export const ADVANCED_SCOPE_VALUES = new Set<DecisionScope>(["global"]);

export function isAdvancedScope(scope: DecisionScope): boolean {
  return ADVANCED_SCOPE_VALUES.has(scope);
}

export function advancedScopeChoicesForRequest(item: GuardApprovalRequest): ApprovalScopeChoice[] {
  return filterScopeChoicesForRequest(item, DEFAULT_SCOPE_CHOICES).filter((choice) =>
    ADVANCED_SCOPE_VALUES.has(choice.value)
  );
}

export function standardScopeChoicesForRequest(item: GuardApprovalRequest): ApprovalScopeChoice[] {
  return filterScopeChoicesForRequest(item, DEFAULT_SCOPE_CHOICES).filter((choice) =>
    !ADVANCED_SCOPE_VALUES.has(choice.value)
  );
}

export function normalizeDecisionScope(item: GuardApprovalRequest, scope: DecisionScope): DecisionScope {
  if (requestSupportsScope(item, scope)) {
    return scope;
  }
  if (requestSupportsScope(item, item.recommended_scope)) {
    return item.recommended_scope;
  }
  return "artifact";
}

export function buildDecisionPayload(input: {
  item: GuardApprovalRequest;
  action: "allow" | "block";
  scope: DecisionScope;
  reason: string;
}): {
  requestId: string;
  action: "allow" | "block";
  scope: DecisionScope;
  workspace?: string;
  reason: string;
} {
  const normalizedScope = normalizeDecisionScope(input.item, input.scope);
  const workspace =
    normalizedScope === "workspace" && typeof input.item.workspace === "string"
      ? input.item.workspace
      : undefined;
  return {
    requestId: input.item.request_id,
    action: input.action,
    scope: normalizedScope,
    workspace,
    reason: input.reason,
  };
}
