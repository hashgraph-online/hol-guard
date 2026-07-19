export const COMMAND_ACTIVITY_API_SCHEMA_VERSION = "guard.command-activity-api.v1";
export const COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION = "guard.command-activity-diagnostics.v1";
export const COMMAND_EXTENSION_SCHEMA_VERSION = 2;

export type GuardAction = "allow" | "warn" | "review" | "require-reapproval" | "sandbox-required" | "block";
export type CommandHookPhase = "pre" | "post_success" | "post_failure";
export type CommandExecutionStatus =
  | "attempted"
  | "prevented"
  | "allowed_unconfirmed"
  | "confirmed_success"
  | "confirmed_failure"
  | "unpaired_post";
export type CommandProofLevel = "pre_hook" | "post_hook" | "unpaired_post";
export type CommandApprovalReuseStatus = "accepted" | "rejected" | "not-applicable";
export type CommandFeedbackLabel = "should_not_have_interrupted" | "expected_guard_to_stop_this";
export type CommandAnalyticsDimension = "harness" | "extension" | "rule";
export type CommandActivityHealthStatus = "healthy" | "degraded";

export interface CommandActivityMatch {
  ordinal: number;
  extension_id: string;
  extension_version: string;
  rule_id: string;
  rule_version: string;
  match_class: "unsafe" | "safe_variant" | "uncertainty";
  severity: string;
  default_floor: GuardAction;
  safe_variant_id: string | null;
  effect_classes: string[];
  schema_version: string;
}

export interface CommandActivityItem {
  activity_id: string;
  occurred_at: string;
  harness: string;
  hook_phase: CommandHookPhase;
  execution_status: CommandExecutionStatus;
  proof_level: CommandProofLevel;
  policy_action: GuardAction | null;
  decision_reason_code: string | null;
  controlling_rule_id: string | null;
  parse_confidence: "exact" | "fallback" | "uncertain" | null;
  uncertainty_class: string | null;
  match_count: number;
  prompted: boolean;
  approval_reuse_status: CommandApprovalReuseStatus;
  receipt_link_status: "not_applicable" | "linked";
  receipt_id: string | null;
  evaluation_latency_bucket: string;
  persistence_latency_bucket: string;
  feedback_label: CommandFeedbackLabel | null;
  schema_version: string;
  matches: CommandActivityMatch[];
}

export interface CommandActivityPage {
  schema_version: typeof COMMAND_ACTIVITY_API_SCHEMA_VERSION;
  items: CommandActivityItem[];
  next_cursor: string | null;
}

export interface CommandActivityHealth {
  status: CommandActivityHealthStatus;
  dropped_events: number;
  persistence_errors: number;
  last_error_class: string | null;
  last_error_at: string | null;
}

export interface CommandCountBucket {
  value: string;
  count: number;
}

export interface CommandActivityAnalytics {
  schema_version: typeof COMMAND_ACTIVITY_API_SCHEMA_VERSION;
  window: { from: string; through: string; days: number };
  scope: { dimension: CommandAnalyticsDimension | null; dimension_value: string | null };
  commands_checked: number;
  trend: { day: string; count: number }[];
  dimensions: Record<
    "harness" | "extension" | "rule" | "disposition" | "execution_status" | "prompt_status" | "proof_level" | "latency",
    CommandCountBucket[]
  >;
  dimension_breakdowns_scope: "global";
  feedback: { label: CommandFeedbackLabel; count: number }[];
  health: CommandActivityHealth;
}

export interface CommandExtensionRule {
  rule_id: string;
  title: string;
  description: string;
  severity: string;
  risk_classes: string[];
  action_classes: string[];
  default_mode: string;
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
  source: string;
  dependencies: string[];
  conflicts: string[];
  delegated_protection: string | null;
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

export interface CommandFeedbackResult {
  schema_version: typeof COMMAND_ACTIVITY_API_SCHEMA_VERSION;
  activity_id: string;
  label: CommandFeedbackLabel;
  created_at: string;
  updated_at: string;
  changed: boolean;
}

export type CommandActivityCountKey =
  | "activities"
  | "matches"
  | "effects"
  | "correlations"
  | "rollup_days"
  | "rollup_cells"
  | "rollup_memberships"
  | "rollup_pending"
  | "feedback"
  | "invalidations";

export interface CommandActivityDiagnostics {
  schema_version: typeof COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION;
  schemas: { activity: string; api: string; health: string; maintenance: string };
  counts: Record<CommandActivityCountKey | "dropped_events" | "persistence_errors", number>;
  proof_coverage: { proof_level: CommandProofLevel; count: number }[];
  stable_ids: { harnesses: string[]; extensions: string[]; rules: string[] };
  error_classes: { error_class: string; count: number }[];
}

export interface CommandActivityDeletionResult {
  schema_version: typeof COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION;
  deleted: Record<CommandActivityCountKey, number>;
}

export type CommandActivityInvalidation =
  | { sequence: number; event: "command_activity_invalidated"; activity_id: string }
  | { sequence: number; event: "command_activity_reset"; reset_required: true };
