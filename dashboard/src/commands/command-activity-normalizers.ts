import {
  COMMAND_ACTIVITY_API_SCHEMA_VERSION,
  COMMAND_ACTIVITY_HARNESSES,
  COMMAND_ACTIVITY_RECORD_SCHEMA_VERSION,
  COMMAND_APPROVAL_REUSE_STATUSES,
  COMMAND_DECISION_REASONS,
  COMMAND_EFFECT_CLASSES,
  COMMAND_EVIDENCE_SEVERITIES,
  COMMAND_EXECUTION_STATUSES,
  COMMAND_EXTENSION_SCHEMA_VERSION,
  COMMAND_FEEDBACK_LABELS,
  COMMAND_HOOK_PHASES,
  COMMAND_LATENCY_BUCKETS,
  COMMAND_MATCH_CLASSES,
  COMMAND_PARSE_CONFIDENCES,
  COMMAND_POLICY_ACTIONS,
  COMMAND_PROOF_LEVELS,
  COMMAND_RULE_MODES,
  COMMAND_UNCERTAINTY_CLASSES,
} from "./command-activity-types";
import type {
  CommandActivityAnalytics,
  CommandActivityDimension,
  CommandActivityDimensionValue,
  CommandActivityFeedbackResult,
  CommandActivityHealth,
  CommandActivityItem,
  CommandActivityMatch,
  CommandActivityPage,
  CommandExtension,
  CommandExtensionRule,
  CommandExtensionsPage,
} from "./command-activity-types";

const DIMENSIONS = [
  "harness", "extension", "rule", "disposition", "execution_status", "prompt_status", "proof_level", "latency",
] as const satisfies readonly CommandActivityDimension[];

export class CommandActivityContractError extends Error {
  constructor(readonly field: string) {
    super(`Invalid command activity response at ${field}`);
    this.name = "CommandActivityContractError";
  }
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new CommandActivityContractError(field);
  }
  return value as Record<string, unknown>;
}

function string(value: unknown, field: string): string {
  if (typeof value !== "string") throw new CommandActivityContractError(field);
  return value;
}

function nonEmptyString(value: unknown, field: string): string {
  const result = string(value, field);
  if (!result || result.length > 2_048) throw new CommandActivityContractError(field);
  return result;
}

function nullableString(value: unknown, field: string): string | null {
  return value === null ? null : nonEmptyString(value, field);
}

function boolean(value: unknown, field: string): boolean {
  if (typeof value !== "boolean") throw new CommandActivityContractError(field);
  return value;
}

function count(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new CommandActivityContractError(field);
  return value as number;
}

function positiveInteger(value: unknown, field: string): number {
  const result = count(value, field);
  if (result === 0) throw new CommandActivityContractError(field);
  return result;
}

function array(value: unknown, field: string): unknown[] {
  if (!Array.isArray(value)) throw new CommandActivityContractError(field);
  return value;
}

function stringArray(value: unknown, field: string): string[] {
  return array(value, field).map((item, index) => nonEmptyString(item, `${field}[${index}]`));
}

function member<const T extends readonly string[]>(value: unknown, values: T, field: string): T[number] {
  if (typeof value !== "string" || !values.includes(value)) throw new CommandActivityContractError(field);
  return value as T[number];
}

function nullableMember<const T extends readonly string[]>(
  value: unknown,
  values: T,
  field: string,
): T[number] | null {
  return value === null ? null : member(value, values, field);
}

function isoDate(value: unknown, field: string): string {
  const result = string(value, field);
  const timestamp = Date.parse(`${result}T00:00:00Z`);
  if (
    !/^\d{4}-\d{2}-\d{2}$/.test(result) ||
    result.startsWith("0000-") ||
    Number.isNaN(timestamp) ||
    new Date(timestamp).toISOString().slice(0, 10) !== result
  ) {
    throw new CommandActivityContractError(field);
  }
  return result;
}

function isoTimestamp(value: unknown, field: string): string {
  const result = nonEmptyString(value, field);
  if (Number.isNaN(Date.parse(result))) throw new CommandActivityContractError(field);
  return result;
}

function nullableTimestamp(value: unknown, field: string): string | null {
  return value === null ? null : isoTimestamp(value, field);
}

function normalizeMatch(value: unknown, field: string): CommandActivityMatch {
  const item = record(value, field);
  return {
    ordinal: count(item.ordinal, `${field}.ordinal`),
    extension_id: nonEmptyString(item.extension_id, `${field}.extension_id`),
    extension_version: nonEmptyString(item.extension_version, `${field}.extension_version`),
    rule_id: nonEmptyString(item.rule_id, `${field}.rule_id`),
    rule_version: nonEmptyString(item.rule_version, `${field}.rule_version`),
    match_class: member(item.match_class, COMMAND_MATCH_CLASSES, `${field}.match_class`),
    severity: member(item.severity, COMMAND_EVIDENCE_SEVERITIES, `${field}.severity`),
    default_floor: member(item.default_floor, COMMAND_POLICY_ACTIONS, `${field}.default_floor`),
    safe_variant_id: nullableString(item.safe_variant_id, `${field}.safe_variant_id`),
    effect_classes: array(item.effect_classes, `${field}.effect_classes`).map((effect, index) =>
      member(effect, COMMAND_EFFECT_CLASSES, `${field}.effect_classes[${index}]`),
    ),
    schema_version: member(
      item.schema_version,
      [COMMAND_ACTIVITY_RECORD_SCHEMA_VERSION] as const,
      `${field}.schema_version`,
    ),
  };
}

function normalizeActivity(value: unknown, field: string): CommandActivityItem {
  const item = record(value, field);
  const matches = array(item.matches, `${field}.matches`).map((match, index) =>
    normalizeMatch(match, `${field}.matches[${index}]`),
  );
  const matchCount = count(item.match_count, `${field}.match_count`);
  if (matchCount !== matches.length) throw new CommandActivityContractError(`${field}.match_count`);
  return {
    activity_id: nonEmptyString(item.activity_id, `${field}.activity_id`),
    occurred_at: isoTimestamp(item.occurred_at, `${field}.occurred_at`),
    harness: member(item.harness, COMMAND_ACTIVITY_HARNESSES, `${field}.harness`),
    hook_phase: member(item.hook_phase, COMMAND_HOOK_PHASES, `${field}.hook_phase`),
    execution_status: member(item.execution_status, COMMAND_EXECUTION_STATUSES, `${field}.execution_status`),
    proof_level: member(item.proof_level, COMMAND_PROOF_LEVELS, `${field}.proof_level`),
    policy_action: nullableMember(item.policy_action, COMMAND_POLICY_ACTIONS, `${field}.policy_action`),
    decision_reason_code: nullableMember(
      item.decision_reason_code, COMMAND_DECISION_REASONS, `${field}.decision_reason_code`,
    ),
    controlling_rule_id: nullableString(item.controlling_rule_id, `${field}.controlling_rule_id`),
    parse_confidence: nullableMember(item.parse_confidence, COMMAND_PARSE_CONFIDENCES, `${field}.parse_confidence`),
    uncertainty_class: nullableMember(
      item.uncertainty_class, COMMAND_UNCERTAINTY_CLASSES, `${field}.uncertainty_class`,
    ),
    match_count: matchCount,
    prompted: boolean(item.prompted, `${field}.prompted`),
    approval_reuse_status: member(
      item.approval_reuse_status, COMMAND_APPROVAL_REUSE_STATUSES, `${field}.approval_reuse_status`,
    ),
    receipt_link_status: member(
      item.receipt_link_status, ["not_applicable", "linked"] as const, `${field}.receipt_link_status`,
    ),
    receipt_id: nullableString(item.receipt_id, `${field}.receipt_id`),
    evaluation_latency_bucket: member(
      item.evaluation_latency_bucket, COMMAND_LATENCY_BUCKETS, `${field}.evaluation_latency_bucket`,
    ),
    persistence_latency_bucket: member(
      item.persistence_latency_bucket, COMMAND_LATENCY_BUCKETS, `${field}.persistence_latency_bucket`,
    ),
    feedback_label: nullableMember(item.feedback_label, COMMAND_FEEDBACK_LABELS, `${field}.feedback_label`),
    schema_version: member(
      item.schema_version, [COMMAND_ACTIVITY_RECORD_SCHEMA_VERSION] as const, `${field}.schema_version`,
    ),
    matches,
  };
}

function normalizeDimensionValues(value: unknown, field: string): CommandActivityDimensionValue[] {
  return array(value, field).map((entry, index) => {
    const item = record(entry, `${field}[${index}]`);
    return {
      value: nonEmptyString(item.value, `${field}[${index}].value`),
      count: count(item.count, `${field}[${index}].count`),
    };
  });
}

function normalizeHealth(value: unknown, field: string): CommandActivityHealth {
  const item = record(value, field);
  return {
    status: member(item.status, ["healthy", "degraded"] as const, `${field}.status`),
    dropped_events: count(item.dropped_events, `${field}.dropped_events`),
    persistence_errors: count(item.persistence_errors, `${field}.persistence_errors`),
    last_error_class: item.last_error_class === undefined
      ? null
      : nullableString(item.last_error_class, `${field}.last_error_class`),
    last_error_at: item.last_error_at === undefined
      ? null
      : nullableTimestamp(item.last_error_at, `${field}.last_error_at`),
  };
}

export function normalizeCommandActivityPage(value: unknown): CommandActivityPage {
  const payload = record(value, "response");
  return {
    schema_version: member(
      payload.schema_version, [COMMAND_ACTIVITY_API_SCHEMA_VERSION] as const, "response.schema_version",
    ),
    items: array(payload.items, "response.items").map((item, index) =>
      normalizeActivity(item, `response.items[${index}]`),
    ),
    next_cursor: nullableString(payload.next_cursor, "response.next_cursor"),
  };
}

export function normalizeCommandActivityAnalytics(value: unknown): CommandActivityAnalytics {
  const payload = record(value, "response");
  const window = record(payload.window, "response.window");
  const scope = record(payload.scope, "response.scope");
  const dimensions = record(payload.dimensions, "response.dimensions");
  const scopeDimension = nullableMember(
    scope.dimension, ["harness", "extension", "rule"] as const, "response.scope.dimension",
  );
  const scopeValue = nullableString(scope.dimension_value, "response.scope.dimension_value");
  if ((scopeDimension === null) !== (scopeValue === null)) {
    throw new CommandActivityContractError("response.scope");
  }
  const normalizedDimensions = Object.fromEntries(
    DIMENSIONS.map((dimension) => [
      dimension,
      normalizeDimensionValues(dimensions[dimension], `response.dimensions.${dimension}`),
    ]),
  ) as Record<CommandActivityDimension, CommandActivityDimensionValue[]>;
  return {
    schema_version: member(
      payload.schema_version, [COMMAND_ACTIVITY_API_SCHEMA_VERSION] as const, "response.schema_version",
    ),
    window: {
      from: isoDate(window.from, "response.window.from"),
      through: isoDate(window.through, "response.window.through"),
      days: positiveInteger(window.days, "response.window.days"),
    },
    scope: {
      dimension: scopeDimension,
      dimension_value: scopeValue,
    },
    commands_checked: count(payload.commands_checked, "response.commands_checked"),
    trend: array(payload.trend, "response.trend").map((entry, index) => {
      const item = record(entry, `response.trend[${index}]`);
      return {
        day: isoDate(item.day, `response.trend[${index}].day`),
        count: count(item.count, `response.trend[${index}].count`),
      };
    }),
    dimensions: normalizedDimensions,
    dimension_breakdowns_scope: member(
      payload.dimension_breakdowns_scope, ["global"] as const, "response.dimension_breakdowns_scope",
    ),
    feedback: array(payload.feedback, "response.feedback").map((entry, index) => {
      const item = record(entry, `response.feedback[${index}]`);
      return {
        label: member(item.label, COMMAND_FEEDBACK_LABELS, `response.feedback[${index}].label`),
        count: count(item.count, `response.feedback[${index}].count`),
      };
    }),
    health: normalizeHealth(payload.health, "response.health"),
  };
}

function normalizeExtensionRule(value: unknown, field: string): CommandExtensionRule {
  const item = record(value, field);
  return {
    rule_id: nonEmptyString(item.rule_id, `${field}.rule_id`),
    title: nonEmptyString(item.title, `${field}.title`),
    description: nonEmptyString(item.description, `${field}.description`),
    severity: member(item.severity, COMMAND_EVIDENCE_SEVERITIES, `${field}.severity`),
    risk_classes: stringArray(item.risk_classes, `${field}.risk_classes`),
    action_classes: stringArray(item.action_classes, `${field}.action_classes`),
    default_mode: member(item.default_mode, COMMAND_RULE_MODES, `${field}.default_mode`),
    safe_variant_ids: stringArray(item.safe_variant_ids, `${field}.safe_variant_ids`),
    compatibility_fallback: boolean(item.compatibility_fallback, `${field}.compatibility_fallback`),
  };
}

function normalizeExtension(value: unknown, field: string): CommandExtension {
  const item = record(value, field);
  const rules = array(item.rules, `${field}.rules`).map((rule, index) =>
    normalizeExtensionRule(rule, `${field}.rules[${index}]`),
  );
  const ruleCount = count(item.rule_count, `${field}.rule_count`);
  if (ruleCount !== rules.length) throw new CommandActivityContractError(`${field}.rule_count`);
  return {
    extension_id: nonEmptyString(item.extension_id, `${field}.extension_id`),
    version: nonEmptyString(item.version, `${field}.version`),
    name: nonEmptyString(item.name, `${field}.name`),
    description: nonEmptyString(item.description, `${field}.description`),
    enabled: boolean(item.enabled, `${field}.enabled`),
    required: boolean(item.required, `${field}.required`),
    source: member(item.source, ["built-in", "local-admin", "signed-cloud"] as const, `${field}.source`),
    dependencies: stringArray(item.dependencies, `${field}.dependencies`),
    conflicts: stringArray(item.conflicts, `${field}.conflicts`),
    delegated_protection: nullableMember(
      item.delegated_protection, ["package-firewall"] as const, `${field}.delegated_protection`,
    ),
    action_classes: stringArray(item.action_classes, `${field}.action_classes`),
    risk_classes: stringArray(item.risk_classes, `${field}.risk_classes`),
    rule_count: ruleCount,
    rules,
  };
}

export function normalizeCommandExtensionsPage(value: unknown): CommandExtensionsPage {
  const payload = record(value, "response");
  if (payload.schema_version !== COMMAND_EXTENSION_SCHEMA_VERSION) {
    throw new CommandActivityContractError("response.schema_version");
  }
  return {
    schema_version: COMMAND_EXTENSION_SCHEMA_VERSION,
    source: member(payload.source, ["built-in"] as const, "response.source"),
    items: array(payload.items, "response.items").map((item, index) =>
      normalizeExtension(item, `response.items[${index}]`),
    ),
    next_cursor: nullableString(payload.next_cursor, "response.next_cursor"),
  };
}

export function normalizeCommandActivityFeedback(value: unknown): CommandActivityFeedbackResult {
  const payload = record(value, "response");
  return {
    schema_version: member(
      payload.schema_version, [COMMAND_ACTIVITY_API_SCHEMA_VERSION] as const, "response.schema_version",
    ),
    activity_id: nonEmptyString(payload.activity_id, "response.activity_id"),
    label: member(payload.label, COMMAND_FEEDBACK_LABELS, "response.label"),
    created_at: isoTimestamp(payload.created_at, "response.created_at"),
    updated_at: isoTimestamp(payload.updated_at, "response.updated_at"),
    changed: boolean(payload.changed, "response.changed"),
  };
}
