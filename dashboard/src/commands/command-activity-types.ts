export const COMMAND_ACTIVITY_API_SCHEMA_VERSION = "guard.command-activity-api.v1" as const;
export const COMMAND_ACTIVITY_RECORD_SCHEMA_VERSION = "1.0.0" as const;
export const COMMAND_EXTENSION_SCHEMA_VERSION = 2 as const;

export const COMMAND_ACTIVITY_HARNESSES = [
  "antigravity", "claude-code", "codex", "copilot", "cursor", "gemini", "grok",
  "hermes", "kimi", "openclaw", "opencode", "pi", "zcode",
] as const;
export const COMMAND_EXECUTION_STATUSES = [
  "attempted", "prevented", "allowed_unconfirmed", "confirmed_success", "confirmed_failure", "unpaired_post",
] as const;
export const COMMAND_PROOF_LEVELS = ["pre_hook", "post_hook", "unpaired_post"] as const;
export const COMMAND_APPROVAL_REUSE_STATUSES = ["accepted", "rejected", "not-applicable"] as const;
export const COMMAND_POLICY_ACTIONS = [
  "allow", "warn", "review", "require-reapproval", "sandbox-required", "block",
] as const;
export const COMMAND_HOOK_PHASES = ["pre", "post_success", "post_failure"] as const;
export const COMMAND_PARSE_CONFIDENCES = ["exact", "fallback", "uncertain"] as const;
export const COMMAND_DECISION_REASONS = [
  "no_match", "extension_match", "uncertainty", "policy", "approval_reuse", "containment", "capability",
] as const;
export const COMMAND_UNCERTAINTY_CLASSES = [
  "partial-parse", "dynamic-input", "unsupported-input", "malformed-input", "parser-budget-exhausted",
  "matcher-failure", "parser-failure", "unresolved-launch-identity", "unknown-effect", "degraded-containment",
  "protection-health-degraded", "policy-version-mismatch", "malformed-boundary-version",
  "unknown-boundary-version", "rollback-boundary-version",
] as const;
export const COMMAND_MATCH_CLASSES = ["unsafe", "safe_variant", "uncertainty"] as const;
export const COMMAND_EVIDENCE_SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export const COMMAND_LATENCY_BUCKETS = [
  "not_measured", "le_1_ms", "le_2_ms", "le_5_ms", "le_10_ms", "le_20_ms", "le_50_ms", "le_100_ms", "gt_100_ms",
] as const;
export const COMMAND_FEEDBACK_LABELS = [
  "should_not_have_interrupted", "expected_guard_to_stop_this",
] as const;
export const COMMAND_RULE_MODES = ["required", "enforce", "review", "monitor", "disabled"] as const;
export const COMMAND_EFFECT_CLASSES = [
  "workspace-or-public-read", "sensitive-read", "workspace-write", "external-filesystem-write",
  "process-execution", "network-read", "network-write", "remote-state-read", "remote-state-mutation",
  "permission-or-access-change", "credential-or-secret-operation", "system-or-privilege-operation",
  "package-or-source-installation", "destructive-or-irreversible-operation", "guard-control-operation",
] as const;

export type CommandActivityHarness = (typeof COMMAND_ACTIVITY_HARNESSES)[number];
export type CommandExecutionStatus = (typeof COMMAND_EXECUTION_STATUSES)[number];
export type CommandProofLevel = (typeof COMMAND_PROOF_LEVELS)[number];
export type CommandApprovalReuseStatus = (typeof COMMAND_APPROVAL_REUSE_STATUSES)[number];
export type CommandPolicyAction = (typeof COMMAND_POLICY_ACTIONS)[number];
export type CommandHookPhase = (typeof COMMAND_HOOK_PHASES)[number];
export type CommandParseConfidence = (typeof COMMAND_PARSE_CONFIDENCES)[number];
export type CommandDecisionReason = (typeof COMMAND_DECISION_REASONS)[number];
export type CommandUncertaintyClass = (typeof COMMAND_UNCERTAINTY_CLASSES)[number];
export type CommandMatchClass = (typeof COMMAND_MATCH_CLASSES)[number];
export type CommandEvidenceSeverity = (typeof COMMAND_EVIDENCE_SEVERITIES)[number];
export type CommandLatencyBucket = (typeof COMMAND_LATENCY_BUCKETS)[number];
export type CommandFeedbackLabel = (typeof COMMAND_FEEDBACK_LABELS)[number];
export type CommandRuleMode = (typeof COMMAND_RULE_MODES)[number];
export type CommandEffectClass = (typeof COMMAND_EFFECT_CLASSES)[number];

export interface CommandActivityMatch {
  ordinal: number;
  extension_id: string;
  extension_version: string;
  rule_id: string;
  rule_version: string;
  match_class: CommandMatchClass;
  severity: CommandEvidenceSeverity;
  default_floor: CommandPolicyAction;
  safe_variant_id: string | null;
  effect_classes: CommandEffectClass[];
  schema_version: typeof COMMAND_ACTIVITY_RECORD_SCHEMA_VERSION;
}

export interface CommandActivityItem {
  activity_id: string;
  occurred_at: string;
  harness: CommandActivityHarness;
  hook_phase: CommandHookPhase;
  execution_status: CommandExecutionStatus;
  proof_level: CommandProofLevel;
  policy_action: CommandPolicyAction | null;
  decision_reason_code: CommandDecisionReason | null;
  controlling_rule_id: string | null;
  parse_confidence: CommandParseConfidence | null;
  uncertainty_class: CommandUncertaintyClass | null;
  match_count: number;
  prompted: boolean;
  approval_reuse_status: CommandApprovalReuseStatus;
  receipt_link_status: "not_applicable" | "linked";
  receipt_id: string | null;
  evaluation_latency_bucket: CommandLatencyBucket;
  persistence_latency_bucket: CommandLatencyBucket;
  feedback_label: CommandFeedbackLabel | null;
  schema_version: typeof COMMAND_ACTIVITY_RECORD_SCHEMA_VERSION;
  matches: CommandActivityMatch[];
}

export interface CommandActivityPage {
  schema_version: typeof COMMAND_ACTIVITY_API_SCHEMA_VERSION;
  items: CommandActivityItem[];
  next_cursor: string | null;
}

export interface CommandActivityDimensionValue { value: string; count: number }
export type CommandActivityDimension =
  | "harness" | "extension" | "rule" | "disposition" | "execution_status"
  | "prompt_status" | "proof_level" | "latency";

export interface CommandActivityHealth {
  status: "healthy" | "degraded";
  dropped_events: number;
  persistence_errors: number;
  last_error_class: string | null;
  last_error_at: string | null;
}

export interface CommandActivityAnalytics {
  schema_version: typeof COMMAND_ACTIVITY_API_SCHEMA_VERSION;
  window: { from: string; through: string; days: number };
  scope: { dimension: "harness" | "extension" | "rule" | null; dimension_value: string | null };
  commands_checked: number;
  trend: Array<{ day: string; count: number }>;
  dimensions: Record<CommandActivityDimension, CommandActivityDimensionValue[]>;
  dimension_breakdowns_scope: "global";
  feedback: Array<{ label: CommandFeedbackLabel; count: number }>;
  health: CommandActivityHealth;
}

export interface CommandExtensionRule {
  rule_id: string;
  title: string;
  description: string;
  severity: CommandEvidenceSeverity;
  risk_classes: string[];
  action_classes: string[];
  default_mode: CommandRuleMode;
  safe_variant_ids: string[];
  compatibility_fallback: boolean;
}

export interface CommandExtension {
  extension_id: string;
  version: string;
  name: string;
  description: string;
  enabled: boolean;
  required: boolean;
  source: "built-in" | "local-admin" | "signed-cloud";
  dependencies: string[];
  conflicts: string[];
  delegated_protection: "package-firewall" | null;
  action_classes: string[];
  risk_classes: string[];
  rule_count: number;
  rules: CommandExtensionRule[];
}

export interface CommandExtensionsPage {
  schema_version: typeof COMMAND_EXTENSION_SCHEMA_VERSION;
  source: "built-in";
  items: CommandExtension[];
  next_cursor: string | null;
}

export interface CommandActivityFeedbackResult {
  schema_version: typeof COMMAND_ACTIVITY_API_SCHEMA_VERSION;
  activity_id: string;
  label: CommandFeedbackLabel;
  created_at: string;
  updated_at: string;
  changed: boolean;
}
