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

export function approvalDecisionSubjectKey(item: GuardApprovalRequest): string {
  return JSON.stringify([
    item.request_id,
    item.harness,
    item.artifact_id ?? null,
    item.artifact_type ?? null,
    item.artifact_hash ?? null,
    item.action_identity ?? null,
    item.raw_command_text ?? null,
    item.workspace ?? null,
  ]);
}

export function approvalDecisionContractKey(item: GuardApprovalRequest): string {
  return JSON.stringify([
    approvalDecisionSubjectKey(item),
    item.scope_contract_version ?? "legacy",
    item.scope_contract_digest ?? "legacy",
  ]);
}

export const DEFAULT_SCOPE_CHOICES: ApprovalScopeChoice[] = [
  {
    value: "artifact",
    label: "Allow just this once",
    description:
      "Allow only this exact action this time. Guard will ask again for anything different. Nothing is saved.",
  },
  {
    value: "workspace",
    label: "Allow and remember for this project",
    description:
      "Save this exact action for the current project. Matching actions skip review here until the action changes.",
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

const ONCE_ONLY_REASON_COPY: Record<string, string> = {
  no_command_identity:
    "Always allow is unavailable: this tool call has no stable command or file to remember. You can allow it once.",
  mutable_launcher:
    "Always allow is unavailable: this program can run other code or config, so Guard cannot prove what it will do next time. You can allow it once.",
  compound_command:
    "Always allow is unavailable: this command chains steps that Guard cannot verify one by one. You can allow it once.",
  guard_control: "Changes to Guard itself are always reviewed. You can allow this one time.",
  package_action: "Package installs and updates are always reviewed. You can allow this one time.",
  non_overridable: "Guard policy does not let this action be remembered. You can allow it once.",
  unproven_launch:
    "Always allow is unavailable: Guard could not verify exactly what this command launches. You can allow it once.",
  sensitive_path:
    "Always allow is unavailable for files that may hold secrets. You can allow it once.",
  broad_scope:
    "Always allow is unavailable: this search covers too much. Narrow it to a project folder to remember it.",
  destructive_command:
    "Always allow is unavailable for commands that delete, move or send data. You can allow it once.",
  provider_unverified:
    "Always allow is unavailable until the provider account is verified. You can allow it once.",
};
const EXTENSION_ROUTE_BLOCKED_REASONS = new Set([
  "guard_control",
  "package_action",
  "non_overridable",
  "provider_unverified",
  "sensitive_path",
  "destructive_command",
]);
const GENERIC_ONCE_ONLY_COPY = "Always allow is not available for this action. You can allow it once.";

export function onceOnlyReasonCopy(reason: string | null | undefined): string {
  return (typeof reason === "string" ? ONCE_ONLY_REASON_COPY[reason] : undefined) ?? GENERIC_ONCE_ONLY_COPY;
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
  if (item.exact_action_persistence_eligible === true) {
    return null;
  }
  if (eligibility.reason_codes.includes("task_capability_not_enabled")) {
    // Task access only applies to GitHub workflow requests. For everything else
    // the useful question is why "Always allow" is missing.
    const reason = item.once_only_reason;
    if (item.extension_recommendation && !EXTENSION_ROUTE_BLOCKED_REASONS.has(reason ?? "")) {
      // The extension permission card offers a persistent route; do not say Always is unavailable.
      return null;
    }
    return onceOnlyReasonCopy(reason);
  }
  return "Task access is unavailable because this request does not include complete reusable proof.";
}

export function buildDecisionPayload(input: {
  item: GuardApprovalRequest;
  action: "allow" | "block";
  scope: DecisionScope;
  reason: string;
  persistExactAction?: boolean;
}): {
  requestId: string;
  action: "allow" | "block";
  scope: DecisionScope;
  workspace?: string;
  reason: string;
  scope_contract_version?: string;
  scope_contract_digest?: string;
  persist_policy?: boolean;
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
  const persistExactAction = willPersistExactAction(
    input.item,
    input.action,
    normalizedScope,
    input.persistExactAction === true,
  );
  return {
    requestId: input.item.request_id,
    action: input.action,
    scope: normalizedScope,
    workspace,
    reason: input.reason,
    ...(persistExactAction ? { persist_policy: true } : {}),
    ...(hasCompleteBinding
      ? {
          scope_contract_version: contractVersion,
          scope_contract_digest: contractDigest,
        }
      : {}),
  };
}

export function willPersistExactAction(
  item: GuardApprovalRequest,
  action: "allow" | "block",
  scope: DecisionScope,
  requested: boolean,
): boolean {
  return (
    requested &&
    normalizeDecisionScope(item, action, scope) === "artifact" &&
    item.exact_action_persistence_eligible === true
  );
}
