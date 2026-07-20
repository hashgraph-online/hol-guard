import type {
  ApprovalResolutionAction,
  DecisionScope,
  GuardApprovalRequest,
} from "./guard-types";

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

export const BLOCK_SCOPE_CHOICES: ApprovalScopeChoice[] = [
  {
    value: "artifact",
    label: "Block this action",
    description: "Block only this exact action. Other actions still follow their current Guard policy.",
  },
  {
    value: "workspace",
    label: "Block in project",
    description: "Block matching actions in the current project.",
  },
  {
    value: "publisher",
    label: "Block this source",
    description: "Block matching actions from this source.",
  },
  {
    value: "harness",
    label: "Block in this app",
    description: "Block matching actions from this AI app.",
  },
  {
    value: "global",
    label: "Block everywhere",
    description: "Block matching actions across every project and AI app on this machine.",
  },
];

function hasScopeContractMetadata(item: GuardApprovalRequest): boolean {
  return (
    item.scope_contract_version !== undefined ||
    item.scope_contract_digest !== undefined ||
    item.allowed_scopes_by_action !== undefined ||
    item.recommended_scope_by_action !== undefined ||
    item.scope_restrictions !== undefined ||
    item.task_capability_eligibility !== undefined
  );
}

function hasCompleteScopeContractBinding(item: GuardApprovalRequest): boolean {
  return (
    typeof item.scope_contract_version === "string" &&
    item.scope_contract_version.length > 0 &&
    typeof item.scope_contract_digest === "string" &&
    item.scope_contract_digest.length > 0
  );
}

function declaredScopesForAction(
  item: GuardApprovalRequest,
  action: ApprovalResolutionAction,
): DecisionScope[] | null {
  if (hasScopeContractMetadata(item) && !hasCompleteScopeContractBinding(item)) {
    return [];
  }
  const actionScopes = item.allowed_scopes_by_action?.[action];
  if (Array.isArray(actionScopes)) {
    return actionScopes;
  }
  if (action === "allow" && Array.isArray(item.allowed_scopes)) {
    return item.allowed_scopes;
  }
  return null;
}

export function requestSupportsScope(
  item: GuardApprovalRequest,
  action: ApprovalResolutionAction,
  scope: DecisionScope,
): boolean {
  const declaredScopes = declaredScopesForAction(item, action);
  if (declaredScopes !== null) {
    return declaredScopes.includes(scope);
  }
  return scope === "artifact";
}

export function filterScopeChoicesForRequest<T extends { value: DecisionScope }>(
  item: GuardApprovalRequest,
  action: ApprovalResolutionAction,
  choices: readonly T[],
): T[] {
  return choices.filter((choice) => requestSupportsScope(item, action, choice.value));
}

export function scopeChoicesForRequest(
  item: GuardApprovalRequest,
  action: ApprovalResolutionAction = "allow",
): ApprovalScopeChoice[] {
  return filterScopeChoicesForRequest(
    item,
    action,
    action === "allow" ? DEFAULT_SCOPE_CHOICES : BLOCK_SCOPE_CHOICES,
  );
}

export const ADVANCED_SCOPE_VALUES = new Set<DecisionScope>(["global"]);

export function isAdvancedScope(scope: DecisionScope): boolean {
  return ADVANCED_SCOPE_VALUES.has(scope);
}

export function advancedScopeChoicesForRequest(
  item: GuardApprovalRequest,
  action: ApprovalResolutionAction = "allow",
): ApprovalScopeChoice[] {
  return scopeChoicesForRequest(item, action).filter((choice) =>
    ADVANCED_SCOPE_VALUES.has(choice.value)
  );
}

export function standardScopeChoicesForRequest(
  item: GuardApprovalRequest,
  action: ApprovalResolutionAction = "allow",
): ApprovalScopeChoice[] {
  return scopeChoicesForRequest(item, action).filter((choice) =>
    !ADVANCED_SCOPE_VALUES.has(choice.value)
  );
}

export function recommendedScopeForAction(
  item: GuardApprovalRequest,
  action: ApprovalResolutionAction,
): DecisionScope | null {
  const actionRecommendation = item.recommended_scope_by_action?.[action] ?? null;
  if (actionRecommendation !== null && requestSupportsScope(item, action, actionRecommendation)) {
    return actionRecommendation;
  }
  if (
    action === "allow" &&
    item.recommended_scope !== null &&
    requestSupportsScope(item, action, item.recommended_scope)
  ) {
    return item.recommended_scope;
  }
  return scopeChoicesForRequest(item, action)[0]?.value ?? null;
}

export function normalizeDecisionScope(
  item: GuardApprovalRequest,
  action: ApprovalResolutionAction,
  scope: DecisionScope,
): DecisionScope | null {
  if (requestSupportsScope(item, action, scope)) {
    return scope;
  }
  return recommendedScopeForAction(item, action);
}

export function taskCapabilityExplanation(item: GuardApprovalRequest): string | null {
  const eligibility = item.task_capability_eligibility;
  if (eligibility === undefined) {
    return null;
  }
  if (eligibility.eligible) {
    return "Task access can cover only the approved operations and expires automatically.";
  }
  if (
    eligibility.reason_codes.includes("current_action_not_overridable") ||
    item.scope_restrictions?.includes("current_action_not_overridable") === true
  ) {
    return "Task access cannot override this blocked or protected Guard action.";
  }
  if (eligibility.reason_codes.includes("task_capability_not_enabled")) {
    return "Task access is not available for this action. Guard will ask again after this one-time approval.";
  }
  return "Task access is unavailable because this request does not include complete reusable proof.";
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
  scope_contract_version?: string;
  scope_contract_digest?: string;
} {
  const contractVersion = input.item.scope_contract_version;
  const contractDigest = input.item.scope_contract_digest;
  const hasCompleteBinding =
    typeof contractVersion === "string" &&
    contractVersion.length > 0 &&
    typeof contractDigest === "string" &&
    contractDigest.length > 0;
  if (hasScopeContractMetadata(input.item) && !hasCompleteBinding) {
    throw new Error("The approval scope contract is incomplete. Refresh this request before deciding.");
  }
  const normalizedScope = normalizeDecisionScope(input.item, input.action, input.scope);
  if (normalizedScope === null) {
    throw new Error(`No eligible ${input.action} scope is available for this request.`);
  }
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
    ...(hasCompleteBinding
      ? {
          scope_contract_version: contractVersion,
          scope_contract_digest: contractDigest,
        }
      : {}),
  };
}
