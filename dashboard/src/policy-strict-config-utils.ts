import type { GuardSettings } from "./guard-types";

export const STRICT_POLICY_LAYER_OPTIONS = [
  { value: "none", label: "No match" },
  { value: "allow", label: "Allow" },
  { value: "block", label: "Block" },
] as const;

export const STRICT_CONFIG_ACTION_OPTIONS = [
  { value: "allow", label: "Allow without asking" },
  { value: "warn", label: "Warn only" },
  { value: "review", label: "Ask me first" },
  { value: "require-reapproval", label: "Ask every time" },
  { value: "sandbox-required", label: "Run in sandbox" },
  { value: "block", label: "Block" },
] as const;

export const STRICT_POLICY_EVALUATION_ORDER = [
  "Local remembered rule",
  "Guard Cloud policy",
  "Cloud exception",
  "Strict fallback",
  "Ask or block",
] as const;

export type StrictPolicySimulationInput = {
  rememberedRuleAction: "allow" | "block" | "none";
  cloudPolicyAction: "allow" | "block" | "none";
  cloudExceptionActive: boolean;
  fallbackAction: string;
};

export type StrictPolicySimulationResult = {
  outcome: string;
  winningStep: (typeof STRICT_POLICY_EVALUATION_ORDER)[number];
  path: string[];
};

export function fingerprintLocalPolicySettings(settings: GuardSettings): string {
  const payload = JSON.stringify({
    mode: settings.mode,
    security_level: settings.security_level,
    default_action: settings.default_action,
    changed_hash_action: settings.changed_hash_action,
    new_network_domain_action: settings.new_network_domain_action,
    subprocess_action: settings.subprocess_action,
    destructive_shell: settings.risk_actions?.destructive_shell ?? null,
  });
  let hash = 5381;
  for (let index = 0; index < payload.length; index += 1) {
    hash = ((hash << 5) + hash) ^ payload.charCodeAt(index);
  }
  return `local-${(hash >>> 0).toString(16).padStart(8, "0")}`;
}

export function resolveStrictFileWriteAction(settings: GuardSettings): string {
  return settings.risk_actions?.destructive_shell ?? settings.default_action;
}

export function simulateStrictPolicyOutcome(input: StrictPolicySimulationInput): StrictPolicySimulationResult {
  const path: string[] = [];
  if (input.rememberedRuleAction !== "none") {
    path.push(`Local remembered rule → ${input.rememberedRuleAction}`);
    return {
      outcome: input.rememberedRuleAction,
      winningStep: "Local remembered rule",
      path,
    };
  }
  path.push("Local remembered rule → none");
  if (input.cloudPolicyAction !== "none") {
    path.push(`Guard Cloud policy → ${input.cloudPolicyAction}`);
    return {
      outcome: input.cloudPolicyAction,
      winningStep: "Guard Cloud policy",
      path,
    };
  }
  path.push("Guard Cloud policy → none");
  if (input.cloudExceptionActive) {
    path.push("Cloud exception → allow");
    return {
      outcome: "allow",
      winningStep: "Cloud exception",
      path,
    };
  }
  path.push("Cloud exception → none");
  path.push(`Strict fallback → ${input.fallbackAction}`);
  if (input.fallbackAction === "allow" || input.fallbackAction === "warn") {
    return {
      outcome: input.fallbackAction,
      winningStep: "Strict fallback",
      path,
    };
  }
  path.push("Ask or block → review/block");
  return {
    outcome: input.fallbackAction === "block" ? "block" : "review",
    winningStep: "Ask or block",
    path,
  };
}
