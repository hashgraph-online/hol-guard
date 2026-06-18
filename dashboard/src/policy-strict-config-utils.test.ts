import {
  resolveStrictScenarioOutcome,
  resolveStrictScenarioSimulation,
  fingerprintLocalPolicySettings,
  simulateStrictPolicyOutcome,
  STRICT_POLICY_EVALUATION_ORDER,
} from "./policy-strict-config-utils";
import type { GuardSettings } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const baseSettings: GuardSettings = {
  mode: "prompt",
  security_level: "strict",
  default_action: "review",
  unknown_publisher_action: "review",
  changed_hash_action: "require-reapproval",
  new_network_domain_action: "review",
  subprocess_action: "review",
  risk_actions: {
    destructive_shell: "review",
  },
  risk_action_overrides: {},
  harness_risk_actions: {},
  approval_wait_timeout_seconds: 120,
  approval_surface_policy: "auto-open-once",
  telemetry: false,
  sync: true,
  billing: false,
};

assert(
  fingerprintLocalPolicySettings(baseSettings).startsWith("local-"),
  "policy hash uses local prefix",
);
assert(STRICT_POLICY_EVALUATION_ORDER.length === 5, "evaluation order has five steps");

const remembered = simulateStrictPolicyOutcome({
  rememberedRuleAction: "allow",
  cloudPolicyAction: "block",
  cloudExceptionActive: true,
  fallbackAction: "block",
});
assert(remembered.winningStep === "Local remembered rule", "remembered rule wins first");

const cloudException = simulateStrictPolicyOutcome({
  rememberedRuleAction: "none",
  cloudPolicyAction: "none",
  cloudExceptionActive: true,
  fallbackAction: "block",
});
assert(cloudException.winningStep === "Cloud exception", "cloud exception wins after empty policy layers");

const sandboxFallback = simulateStrictPolicyOutcome({
  rememberedRuleAction: "none",
  cloudPolicyAction: "none",
  cloudExceptionActive: false,
  fallbackAction: "sandbox-required",
});
assert(
  sandboxFallback.outcome === "sandbox-required",
  "sandbox-required fallback preserves configured outcome",
);

const reapprovalFallback = simulateStrictPolicyOutcome({
  rememberedRuleAction: "none",
  cloudPolicyAction: "none",
  cloudExceptionActive: false,
  fallbackAction: "require-reapproval",
});
assert(
  reapprovalFallback.outcome === "require-reapproval",
  "require-reapproval fallback preserves configured outcome",
);

const scenario = resolveStrictScenarioOutcome("first-time", baseSettings);
assert(scenario.outcome === "review", "first-time scenario uses network domain action");
assert(scenario.reasoning.includes("New network domain action"), "scenario reasoning names control");

const firstTimeSimulation = resolveStrictScenarioSimulation(baseSettings, "first-time");
assert(firstTimeSimulation.outcome === "review", "first-time simulation uses network domain fallback");
assert(firstTimeSimulation.winningStep === "Ask or block", "first-time simulation reaches strict fallback");

const rememberedSimulation = resolveStrictScenarioSimulation(baseSettings, "remembered-allow");
assert(rememberedSimulation.outcome === "allow", "remembered-allow simulation wins at remembered rule");

console.log("policy-strict-config-utils.test.ts: all assertions passed");
