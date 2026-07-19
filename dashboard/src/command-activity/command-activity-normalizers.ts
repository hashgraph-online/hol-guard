import {
  COMMAND_ACTIVITY_API_SCHEMA_VERSION,
  COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION,
  COMMAND_EXTENSION_SCHEMA_VERSION,
  type CommandActivityAnalytics,
  type CommandActivityCountKey,
  type CommandActivityDeletionResult,
  type CommandActivityDiagnostics,
  type CommandActivityInvalidation,
  type CommandActivityItem,
  type CommandActivityMatch,
  type CommandActivityPage,
  type CommandApprovalReuseStatus,
  type CommandExecutionStatus,
  type CommandExtensionsPage,
  type CommandFeedbackLabel,
  type CommandFeedbackResult,
  type CommandHookPhase,
  type CommandProofLevel,
  type GuardAction,
} from "./command-activity-types";

const GUARD_ACTIONS = ["allow", "warn", "review", "require-reapproval", "sandbox-required", "block"] as const;
const HOOK_PHASES = ["pre", "post_success", "post_failure"] as const;
const EXECUTION_STATUSES = [
  "attempted",
  "prevented",
  "allowed_unconfirmed",
  "confirmed_success",
  "confirmed_failure",
  "unpaired_post",
] as const;
const PROOF_LEVELS = ["pre_hook", "post_hook", "unpaired_post"] as const;
const REUSE_STATUSES = ["accepted", "rejected", "not-applicable"] as const;
const FEEDBACK_LABELS = ["should_not_have_interrupted", "expected_guard_to_stop_this"] as const;
const ANALYTICS_DIMENSIONS = [
  "harness",
  "extension",
  "rule",
  "disposition",
  "execution_status",
  "prompt_status",
  "proof_level",
  "latency",
] as const;
const COUNT_KEYS = [
  "activities",
  "matches",
  "effects",
  "correlations",
  "rollup_days",
  "rollup_cells",
  "rollup_memberships",
  "rollup_pending",
  "feedback",
  "invalidations",
] as const satisfies readonly CommandActivityCountKey[];
const FORBIDDEN_KEYS = new Set([
  "command",
  "command_text",
  "raw_command",
  "args",
  "argv",
  "c" + "wd",
  "environment",
  "env",
  "token",
  "authorization",
  "correlation",
  "digest",
  "url",
  "redirect",
]);

type JsonRecord = Record<string, unknown>;

function invalid(kind: string): never {
  throw new Error(`Invalid ${kind} payload`);
}

function record(value: unknown, kind: string): JsonRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid(kind);
  return value as JsonRecord;
}

function rejectForbidden(value: unknown, kind: string, depth = 0): void {
  if (depth > 16) invalid(kind);
  if (Array.isArray(value)) {
    if (value.length > 4_096) invalid(kind);
    for (const item of value) rejectForbidden(item, kind, depth + 1);
    return;
  }
  if (value === null || typeof value !== "object") return;
  const entries = Object.entries(value as JsonRecord);
  if (entries.length > 256) invalid(kind);
  for (const [key, child] of entries) {
    if (FORBIDDEN_KEYS.has(key.toLowerCase())) invalid(kind);
    rejectForbidden(child, kind, depth + 1);
  }
}

function stringValue(value: unknown, kind: string, max = 256): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max) invalid(kind);
  return value;
}

function nullableString(value: unknown, kind: string, max = 256): string | null {
  return value === null ? null : stringValue(value, kind, max);
}

function booleanValue(value: unknown, kind: string): boolean {
  if (typeof value !== "boolean") invalid(kind);
  return value;
}

function integer(value: unknown, kind: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) invalid(kind);
  return value as number;
}

function enumValue<T extends string>(value: unknown, values: readonly T[], kind: string): T {
  if (typeof value !== "string" || !values.includes(value as T)) invalid(kind);
  return value as T;
}

function stringArray(value: unknown, kind: string, limit = 100): string[] {
  if (!Array.isArray(value) || value.length > limit) invalid(kind);
  return value.map((item) => stringValue(item, kind));
}

function objectArray(value: unknown, kind: string, limit = 100): unknown[] {
  if (!Array.isArray(value) || value.length > limit) invalid(kind);
  return value;
}

function normalizeMatch(value: unknown): CommandActivityMatch {
  const item = record(value, "command activity");
  return {
    ordinal: integer(item.ordinal, "command activity"),
    extension_id: stringValue(item.extension_id, "command activity"),
    extension_version: stringValue(item.extension_version, "command activity"),
    rule_id: stringValue(item.rule_id, "command activity"),
    rule_version: stringValue(item.rule_version, "command activity"),
    match_class: enumValue(item.match_class, ["unsafe", "safe_variant", "uncertainty"], "command activity"),
    severity: stringValue(item.severity, "command activity"),
    default_floor: enumValue(item.default_floor, GUARD_ACTIONS, "command activity") as GuardAction,
    safe_variant_id: nullableString(item.safe_variant_id, "command activity"),
    effect_classes: stringArray(item.effect_classes, "command activity", 32),
    schema_version: stringValue(item.schema_version, "command activity"),
  };
}

function normalizeActivity(value: unknown): CommandActivityItem {
  const item = record(value, "command activity");
  const matches = objectArray(item.matches, "command activity").map(normalizeMatch);
  const matchCount = integer(item.match_count, "command activity");
  if (matches.length !== matchCount) invalid("command activity");
  return {
    activity_id: stringValue(item.activity_id, "command activity"),
    occurred_at: stringValue(item.occurred_at, "command activity"),
    harness: stringValue(item.harness, "command activity"),
    hook_phase: enumValue(item.hook_phase, HOOK_PHASES, "command activity") as CommandHookPhase,
    execution_status: enumValue(
      item.execution_status,
      EXECUTION_STATUSES,
      "command activity",
    ) as CommandExecutionStatus,
    proof_level: enumValue(item.proof_level, PROOF_LEVELS, "command activity") as CommandProofLevel,
    policy_action:
      item.policy_action === null
        ? null
        : (enumValue(item.policy_action, GUARD_ACTIONS, "command activity") as GuardAction),
    decision_reason_code: nullableString(item.decision_reason_code, "command activity"),
    controlling_rule_id: nullableString(item.controlling_rule_id, "command activity"),
    parse_confidence:
      item.parse_confidence === null
        ? null
        : (enumValue(item.parse_confidence, ["exact", "fallback", "uncertain"], "command activity") as CommandActivityItem["parse_confidence"]),
    uncertainty_class: nullableString(item.uncertainty_class, "command activity"),
    match_count: matchCount,
    prompted: booleanValue(item.prompted, "command activity"),
    approval_reuse_status: enumValue(
      item.approval_reuse_status,
      REUSE_STATUSES,
      "command activity",
    ) as CommandApprovalReuseStatus,
    receipt_link_status: enumValue(item.receipt_link_status, ["not_applicable", "linked"], "command activity"),
    receipt_id: nullableString(item.receipt_id, "command activity"),
    evaluation_latency_bucket: stringValue(item.evaluation_latency_bucket, "command activity"),
    persistence_latency_bucket: stringValue(item.persistence_latency_bucket, "command activity"),
    feedback_label:
      item.feedback_label === null
        ? null
        : (enumValue(item.feedback_label, FEEDBACK_LABELS, "command activity") as CommandFeedbackLabel),
    schema_version: stringValue(item.schema_version, "command activity"),
    matches,
  };
}

export function normalizeCommandActivityPage(value: unknown): CommandActivityPage {
  rejectForbidden(value, "command activity");
  const payload = record(value, "command activity");
  if (payload.schema_version !== COMMAND_ACTIVITY_API_SCHEMA_VERSION) invalid("command activity");
  return {
    schema_version: COMMAND_ACTIVITY_API_SCHEMA_VERSION,
    items: objectArray(payload.items, "command activity").map(normalizeActivity),
    next_cursor: nullableString(payload.next_cursor, "command activity", 2_048),
  };
}

function countBuckets(value: unknown, kind: string): { value: string; count: number }[] {
  return objectArray(value, kind, 50).map((raw) => {
    const item = record(raw, kind);
    return { value: stringValue(item.value, kind), count: integer(item.count, kind) };
  });
}

export function normalizeCommandActivityAnalytics(value: unknown): CommandActivityAnalytics {
  rejectForbidden(value, "command activity analytics");
  const payload = record(value, "command activity analytics");
  const window = record(payload.window, "command activity analytics");
  const scope = record(payload.scope, "command activity analytics");
  const dimensions = record(payload.dimensions, "command activity analytics");
  const health = record(payload.health, "command activity analytics");
  if (payload.schema_version !== COMMAND_ACTIVITY_API_SCHEMA_VERSION) invalid("command activity analytics");
  const normalizedDimensions = Object.fromEntries(
    ANALYTICS_DIMENSIONS.map((name) => [name, countBuckets(dimensions[name], "command activity analytics")]),
  ) as CommandActivityAnalytics["dimensions"];
  return {
    schema_version: COMMAND_ACTIVITY_API_SCHEMA_VERSION,
    window: {
      from: stringValue(window.from, "command activity analytics"),
      through: stringValue(window.through, "command activity analytics"),
      days: integer(window.days, "command activity analytics"),
    },
    scope: {
      dimension:
        scope.dimension === null
          ? null
          : (enumValue(scope.dimension, ["harness", "extension", "rule"], "command activity analytics") as CommandActivityAnalytics["scope"]["dimension"]),
      dimension_value: nullableString(scope.dimension_value, "command activity analytics"),
    },
    commands_checked: integer(payload.commands_checked, "command activity analytics"),
    trend: objectArray(payload.trend, "command activity analytics", 397).map((raw) => {
      const item = record(raw, "command activity analytics");
      return { day: stringValue(item.day, "command activity analytics"), count: integer(item.count, "command activity analytics") };
    }),
    dimensions: normalizedDimensions,
    dimension_breakdowns_scope: enumValue(payload.dimension_breakdowns_scope, ["global"], "command activity analytics"),
    feedback: objectArray(payload.feedback, "command activity analytics", 2).map((raw) => {
      const item = record(raw, "command activity analytics");
      return {
        label: enumValue(item.label, FEEDBACK_LABELS, "command activity analytics") as CommandFeedbackLabel,
        count: integer(item.count, "command activity analytics"),
      };
    }),
    health: {
      status: enumValue(health.status, ["healthy", "degraded"], "command activity analytics"),
      dropped_events: integer(health.dropped_events, "command activity analytics"),
      persistence_errors: integer(health.persistence_errors, "command activity analytics"),
      last_error_class: nullableString(health.last_error_class ?? null, "command activity analytics"),
      last_error_at: nullableString(health.last_error_at ?? null, "command activity analytics"),
    },
  };
}

export function normalizeCommandExtensionsPage(value: unknown): CommandExtensionsPage {
  rejectForbidden(value, "command extensions");
  const payload = record(value, "command extensions");
  if (payload.schema_version !== COMMAND_EXTENSION_SCHEMA_VERSION || payload.source !== "built-in") {
    invalid("command extensions");
  }
  return {
    schema_version: COMMAND_EXTENSION_SCHEMA_VERSION,
    source: "built-in",
    items: objectArray(payload.items, "command extensions").map((raw) => {
      const item = record(raw, "command extensions");
      const rules = objectArray(item.rules, "command extensions").map((ruleRaw) => {
        const rule = record(ruleRaw, "command extensions");
        return {
          rule_id: stringValue(rule.rule_id, "command extensions"),
          title: stringValue(rule.title, "command extensions", 512),
          description: stringValue(rule.description, "command extensions", 2_048),
          severity: stringValue(rule.severity, "command extensions"),
          risk_classes: stringArray(rule.risk_classes, "command extensions"),
          action_classes: stringArray(rule.action_classes, "command extensions"),
          default_mode: stringValue(rule.default_mode, "command extensions"),
          safe_variant_ids: stringArray(rule.safe_variant_ids, "command extensions"),
          compatibility_fallback: booleanValue(rule.compatibility_fallback, "command extensions"),
        };
      });
      const ruleCount = integer(item.rule_count, "command extensions");
      if (rules.length !== ruleCount) invalid("command extensions");
      return {
        extension_id: stringValue(item.extension_id, "command extensions"),
        version: stringValue(item.version, "command extensions"),
        name: stringValue(item.name, "command extensions", 512),
        description: stringValue(item.description, "command extensions", 2_048),
        enabled: booleanValue(item.enabled, "command extensions"),
        required: booleanValue(item.required, "command extensions"),
        source: stringValue(item.source, "command extensions"),
        dependencies: stringArray(item.dependencies, "command extensions"),
        conflicts: stringArray(item.conflicts, "command extensions"),
        delegated_protection: nullableString(item.delegated_protection, "command extensions"),
        action_classes: stringArray(item.action_classes, "command extensions"),
        risk_classes: stringArray(item.risk_classes, "command extensions"),
        rule_count: ruleCount,
        rules,
      };
    }),
    next_cursor: nullableString(payload.next_cursor, "command extensions", 2_048),
  };
}

export function normalizeCommandFeedbackResult(value: unknown): CommandFeedbackResult {
  rejectForbidden(value, "command feedback");
  const payload = record(value, "command feedback");
  if (payload.schema_version !== COMMAND_ACTIVITY_API_SCHEMA_VERSION) invalid("command feedback");
  return {
    schema_version: COMMAND_ACTIVITY_API_SCHEMA_VERSION,
    activity_id: stringValue(payload.activity_id, "command feedback"),
    label: enumValue(payload.label, FEEDBACK_LABELS, "command feedback") as CommandFeedbackLabel,
    created_at: stringValue(payload.created_at, "command feedback"),
    updated_at: stringValue(payload.updated_at, "command feedback"),
    changed: booleanValue(payload.changed, "command feedback"),
  };
}

function normalizedCounts(value: unknown, keys: readonly string[], kind: string): Record<string, number> {
  const payload = record(value, kind);
  return Object.fromEntries(keys.map((key) => [key, integer(payload[key], kind)]));
}

export function normalizeCommandActivityDiagnostics(value: unknown): CommandActivityDiagnostics {
  rejectForbidden(value, "command activity diagnostics");
  const payload = record(value, "command activity diagnostics");
  const schemas = record(payload.schemas, "command activity diagnostics");
  const stableIds = record(payload.stable_ids, "command activity diagnostics");
  if (payload.schema_version !== COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION) invalid("command activity diagnostics");
  return {
    schema_version: COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION,
    schemas: {
      activity: stringValue(schemas.activity, "command activity diagnostics"),
      api: stringValue(schemas.api, "command activity diagnostics"),
      health: stringValue(schemas.health, "command activity diagnostics"),
      maintenance: stringValue(schemas.maintenance, "command activity diagnostics"),
    },
    counts: normalizedCounts(
      payload.counts,
      [...COUNT_KEYS, "dropped_events", "persistence_errors"],
      "command activity diagnostics",
    ) as CommandActivityDiagnostics["counts"],
    proof_coverage: objectArray(payload.proof_coverage, "command activity diagnostics", 3).map((raw) => {
      const item = record(raw, "command activity diagnostics");
      return {
        proof_level: enumValue(item.proof_level, PROOF_LEVELS, "command activity diagnostics") as CommandProofLevel,
        count: integer(item.count, "command activity diagnostics"),
      };
    }),
    stable_ids: {
      harnesses: stringArray(stableIds.harnesses, "command activity diagnostics"),
      extensions: stringArray(stableIds.extensions, "command activity diagnostics"),
      rules: stringArray(stableIds.rules, "command activity diagnostics", 1_000),
    },
    error_classes: objectArray(payload.error_classes, "command activity diagnostics", 4).map((raw) => {
      const item = record(raw, "command activity diagnostics");
      return {
        error_class: stringValue(item.error_class, "command activity diagnostics"),
        count: integer(item.count, "command activity diagnostics"),
      };
    }),
  };
}

export function normalizeCommandActivityDeletion(value: unknown): CommandActivityDeletionResult {
  rejectForbidden(value, "command activity deletion");
  const payload = record(value, "command activity deletion");
  if (payload.schema_version !== COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION) invalid("command activity deletion");
  return {
    schema_version: COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION,
    deleted: normalizedCounts(payload.deleted, COUNT_KEYS, "command activity deletion") as Record<CommandActivityCountKey, number>,
  };
}

export function normalizeCommandActivityInvalidation(sequence: unknown, value: unknown): CommandActivityInvalidation {
  rejectForbidden(value, "command activity invalidation");
  const id = integer(sequence, "command activity invalidation");
  const payload = record(value, "command activity invalidation");
  if (payload.event === "command_activity_invalidated") {
    return {
      sequence: id,
      event: "command_activity_invalidated",
      activity_id: stringValue(payload.activity_id, "command activity invalidation"),
    };
  }
  if (payload.event === "command_activity_reset" && payload.reset_required === true) {
    return { sequence: id, event: "command_activity_reset", reset_required: true };
  }
  return invalid("command activity invalidation");
}
