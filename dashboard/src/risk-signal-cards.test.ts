import {
  deriveSkillRiskSignals,
  deriveSupplyChainRiskSignals,
  deriveEncodedLayerSignals,
} from "./approval-center-utils";
import { packageExecutionContextMessages } from "./risk-signal-cards";
import type {
  GuardApprovalRequest,
  GuardDecisionV2,
  PackageExecutionContextEvidence,
  RiskSignalV2,
} from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function makeSignal(overrides: Partial<RiskSignalV2>): RiskSignalV2 {
  return {
    signal_id: "test-signal",
    category: "skill",
    severity: "medium",
    confidence: "likely",
    detector: "skill.detector",
    title: "Test signal",
    plain_reason: "Test reason",
    technical_detail: null,
    evidence_ref: null,
    redaction_level: "none",
    false_positive_hint: null,
    advisory_id: null,
    ...overrides,
  };
}

function makeDecisionV2(signals: RiskSignalV2[]): GuardDecisionV2 {
  return {
    action: "ask",
    reason: "test",
    user_title: "Test",
    user_body: "Body",
    harness_message: "msg",
    dashboard_primary_detail: "detail",
    approval_scopes: ["artifact"],
    retry_instruction: null,
    signals,
    confidence: "likely",
  };
}

const BASE_REQUEST: GuardApprovalRequest = {
  request_id: "req-risk-test",
  harness: "claude-code",
  artifact_id: "claude-code:project:bash",
  artifact_name: "bash",
  artifact_type: "command",
  artifact_hash: "sha256-risk",
  publisher: null,
  policy_action: "require-reapproval",
  recommended_scope: "artifact",
  changed_fields: [],
  source_scope: "project",
  config_path: "./claude.json",
  launch_target: null,
  transport: null,
  review_command: "hol-guard approvals approve req-risk-test",
  approval_url: "http://127.0.0.1:4781/approvals/req-risk-test",
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: "2026-04-11T12:00:00Z",
  resolved_at: null,
  action_envelope_json: null,
};

const skillSignal = makeSignal({ signal_id: "skill-001", category: "execution", detector: "skill.content", title: "Skill risk" });
const scSignal = makeSignal({ signal_id: "sc-001", category: "secret", detector: "supply-chain.content", title: "SC risk" });
const encodedSignal = makeSignal({ signal_id: "encoded.code-execution", category: "execution", detector: "safe-decode.content", title: "Encoded payload" });
const networkSignal = makeSignal({ signal_id: "net-001", category: "network", title: "Network risk" });

const requestWithAll: GuardApprovalRequest = {
  ...BASE_REQUEST,
  decision_v2_json: makeDecisionV2([skillSignal, scSignal, encodedSignal, networkSignal]),
};

const requestEmpty: GuardApprovalRequest = {
  ...BASE_REQUEST,
  decision_v2_json: makeDecisionV2([networkSignal]),
};

const requestNoDecision: GuardApprovalRequest = { ...BASE_REQUEST };

assert(
  deriveSkillRiskSignals(requestWithAll).length === 1,
  "T282: deriveSkillRiskSignals returns exactly skill-detector signals"
);
assert(
  deriveSkillRiskSignals(requestWithAll)[0].signal_id === "skill-001",
  "T282: deriveSkillRiskSignals returns the correct signal"
);
assert(
  deriveSkillRiskSignals(requestEmpty).length === 0,
  "T282: deriveSkillRiskSignals returns empty array when no skill signals"
);
assert(
  deriveSkillRiskSignals(requestNoDecision).length === 0,
  "T282: deriveSkillRiskSignals returns empty array when decision_v2_json absent"
);

assert(
  deriveSupplyChainRiskSignals(requestWithAll).length === 1,
  "T317: deriveSupplyChainRiskSignals returns exactly supply-chain-detector signals"
);
assert(
  deriveSupplyChainRiskSignals(requestWithAll)[0].signal_id === "sc-001",
  "T317: deriveSupplyChainRiskSignals returns the correct signal"
);
assert(
  deriveSupplyChainRiskSignals(requestEmpty).length === 0,
  "T317: deriveSupplyChainRiskSignals returns empty array when no supply-chain signals"
);
assert(
  deriveSupplyChainRiskSignals(requestNoDecision).length === 0,
  "T317: deriveSupplyChainRiskSignals returns empty array when decision_v2_json absent"
);

assert(
  deriveEncodedLayerSignals(requestWithAll).length === 1,
  "T349: deriveEncodedLayerSignals returns exactly safe-decode-detector signals"
);
assert(
  deriveEncodedLayerSignals(requestWithAll)[0].signal_id === "encoded.code-execution",
  "T349: deriveEncodedLayerSignals returns the correct signal"
);
assert(
  deriveEncodedLayerSignals(requestEmpty).length === 0,
  "T349: deriveEncodedLayerSignals returns empty array when no encoded signals"
);
assert(
  deriveEncodedLayerSignals(requestNoDecision).length === 0,
  "T349: deriveEncodedLayerSignals returns empty array when decision_v2_json absent"
);

const packageContext: PackageExecutionContextEvidence = {
  kind: "package_execution_context",
  schema_version: 2,
  portable: true,
  context_digest: "a".repeat(64),
  components: [],
  portable_summary: "Portable only when the context matches.",
  changed_components: ["registry_and_proxy_configuration", "package_manager_executable"],
};
const packageMessages = packageExecutionContextMessages(packageContext);
assert(
  packageMessages[0].includes("linked Git worktrees"),
  "P05: package approval copy explains the narrow portable boundary"
);
assert(
  packageMessages[1].includes("registry or proxy configuration") &&
    packageMessages[1].includes("package manager executable"),
  "P05: package approval copy identifies the exact context components that changed"
);
assert(
  packageExecutionContextMessages({
    ...packageContext,
    portable: false,
    non_portable_reason: "dynamic_manager_configuration",
    changed_components: [],
  })[0].includes("limited to one retry"),
  "P05: non-portable package context copy documents the DX limitation"
);
assert(
  packageExecutionContextMessages({
    ...packageContext,
    portable: false,
    non_portable_reason: "dynamic_lifecycle_hook",
    changed_components: [],
  })[0].includes("lifecycle hook"),
  "P05: lifecycle-hook context copy explains why reuse is limited"
);

const multiSkillRequest: GuardApprovalRequest = {
  ...BASE_REQUEST,
  decision_v2_json: makeDecisionV2([
    makeSignal({ signal_id: "skill-a", category: "execution", detector: "skill.content" }),
    makeSignal({ signal_id: "skill-b", category: "secret", detector: "skill.content" }),
    networkSignal,
  ]),
};
assert(
  deriveSkillRiskSignals(multiSkillRequest).length === 2,
  "T282: deriveSkillRiskSignals returns all skill signals when multiple exist"
);
assert(
  deriveSkillRiskSignals(multiSkillRequest).every((s) => s.detector === "skill.content"),
  "T282: deriveSkillRiskSignals never returns non-skill-detector signals"
);

console.log("risk-signal-cards: all assertions passed");
