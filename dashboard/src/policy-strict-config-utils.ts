import type { GuardSettings } from "./guard-types";
import { policyActionLabel } from "./approval-center-utils";

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

export const STRICT_POLICY_DEFAULTS = {
  default_action: "block",
  changed_hash_action: "review",
  new_network_domain_action: "review",
  subprocess_action: "review",
  destructive_shell: "block",
} as const;

export type StrictScenarioId = "first-time" | "remembered-allow" | "cloud-exception";

export function resolveStrictScenarioOutcome(
  scenarioId: StrictScenarioId,
  settings: GuardSettings,
): { outcome: string; reasoning: string } {
  if (scenarioId === "remembered-allow") {
    return {
      outcome: "allow",
      reasoning: "Because a remembered allow rule matches before Cloud policy.",
    };
  }
  if (scenarioId === "cloud-exception") {
    return {
      outcome: "allow",
      reasoning: "Because an active Cloud exception overrides team policy.",
    };
  }
  const outcome = settings.new_network_domain_action;
  return {
    outcome,
    reasoning: `Because New network domain action is set to ${policyActionLabel(outcome)}.`,
  };
}

export function resolveStrictScenarioSimulation(
  settings: GuardSettings,
  scenarioId: StrictScenarioId,
): StrictPolicySimulationResult {
  const fallbackAction = settings.new_network_domain_action;

  if (scenarioId === "remembered-allow") {
    return simulateStrictPolicyOutcome({
      rememberedRuleAction: "allow",
      cloudPolicyAction: "none",
      cloudExceptionActive: false,
      fallbackAction,
    });
  }

  if (scenarioId === "cloud-exception") {
    return simulateStrictPolicyOutcome({
      rememberedRuleAction: "none",
      cloudPolicyAction: "none",
      cloudExceptionActive: true,
      fallbackAction,
    });
  }

  return simulateStrictPolicyOutcome({
    rememberedRuleAction: "none",
    cloudPolicyAction: "none",
    cloudExceptionActive: false,
    fallbackAction,
  });
}

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
  path.push(`Ask or block → ${input.fallbackAction}`);
  return {
    outcome: input.fallbackAction,
    winningStep: "Ask or block",
    path,
  };
}
