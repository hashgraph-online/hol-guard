import type {
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardPolicyDecision,
  GuardReceipt
} from "./guard-types";

export function humanizeList(values: string[]): string {
  if (values.length === 0) {
    return "nothing tracked yet";
  }
  if (values.length === 1) {
    return values[0];
  }
  if (values.length === 2) {
    return `${values[0]} and ${values[1]}`;
  }
  return `${values.slice(0, -1).join(", ")}, and ${values.at(-1)}`;
}

export function buildPauseLine(item: GuardApprovalRequest): string {
  return `${item.artifact_name} changed in ${humanizeList(item.changed_fields)}, so Guard paused the ${item.harness} launch before the tool could run.`;
}

export function buildRecommendation(item: GuardApprovalRequest): string {
  if (item.policy_action === "block") {
    return "Block this launch until you understand the drift.";
  }
  if (item.policy_action === "require-reapproval") {
    return "Review the drift and approve the narrowest rule that gets you moving again.";
  }
  return "Review the drift and decide how broadly Guard should trust it.";
}

export function scopeLabel(scope: string): string {
  switch (scope) {
    case "artifact":
      return "This version only";
    case "workspace":
      return "This workspace";
    case "publisher":
      return "This publisher in this harness";
    case "harness":
      return "This harness";
    case "global":
      return "Everywhere";
    default:
      return scope;
  }
}

export function profileItems(
  item: GuardApprovalRequest,
  diff: GuardArtifactDiff | null,
  receipt: GuardReceipt | null,
  policy: GuardPolicyDecision[]
): {
  identity: Array<[string, string]>;
  drift: Array<[string, string]>;
  trust: Array<[string, string]>;
  memory: Array<[string, string]>;
} {
  return {
    identity: [
      ["Artifact", item.artifact_name],
      ["Harness", item.harness],
      ["Publisher", item.publisher ?? "Not reported"],
      ["Source", item.source_scope],
      ["Config path", item.config_path]
    ],
    drift: [
      ["Changed fields", humanizeList(item.changed_fields)],
      ["Previous hash", diff?.previous_hash ?? "First time seen"],
      ["Current hash", diff?.current_hash ?? item.artifact_hash],
      ["Review command", item.review_command]
    ],
    trust: [
      ["Last decision", receipt?.policy_decision ?? "No earlier receipt"],
      ["Capabilities", receipt?.capabilities_summary ?? "No earlier capability snapshot"],
      ["Provenance", receipt?.provenance_summary ?? "No earlier provenance snapshot"],
      ["Changed capabilities", receipt?.changed_capabilities.length ? humanizeList(receipt.changed_capabilities) : "No capability diff saved"]
    ],
    memory: [
      ["Guard recommends", scopeLabel(item.recommended_scope)],
      ["Current rule count", `${policy.length}`],
      ["Current action", item.policy_action],
      [
        "Top saved rule",
        policy[0] ? `${scopeLabel(policy[0].scope)} · ${policy[0].action}` : "No saved rule for this harness yet"
      ]
    ]
  };
}
