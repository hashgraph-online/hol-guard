import type { GuardActionExplanationV1, GuardEverydayActionKind } from "./guard-types";

type UnknownRecord = Record<string, unknown>;
type EverydayTarget = GuardActionExplanationV1["everyday"]["targets"][number];
type EverydayConsequence = GuardActionExplanationV1["everyday"]["consequences"][number];
type EverydayAlternative = GuardActionExplanationV1["everyday"]["safer_alternatives"][number];
type TechnicalSegment = GuardActionExplanationV1["technical"]["segments"][number];

const ACTION_KINDS = new Set<GuardEverydayActionKind>([
  "file_read", "file_write", "file_delete", "file_move", "permission_change",
  "process_start", "process_stop", "system_change", "disk_change", "network_read",
  "network_send", "download", "download_and_execute", "package_install", "package_remove",
  "package_update", "package_script", "git_read", "git_local_change", "git_history_rewrite",
  "git_remote_change", "secret_read", "secret_send", "container_change", "cluster_change",
  "cloud_change", "database_read", "database_change", "mcp_tool", "browser_action",
  "prompt_submission", "skill_install", "extension_change", "guard_control_change",
  "compound_action", "unknown_action",
]);

const CONFIDENCES = ["exact", "derived", "limited"] as const;
const REDACTION_LEVELS = ["none", "summary", "redacted"] as const;
const SENSITIVITIES = ["normal", "private", "secret", "unknown"] as const;
const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
const ALTERNATIVE_KINDS = ["review", "narrow", "preview", "backup", "isolate", "cancel", "manual"] as const;
const MESSAGE_ID_PATTERN = /^[a-z][a-z0-9_.-]{0,127}$/;
const LOCALE_PATTERN = /^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/;
const TARGET_KIND_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
const UNCERTAINTY_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;

const ROOT_KEYS = [
  "schema_version", "explanation_version", "renderer_version", "action_identity",
  "canonical_identity", "catalog_digest", "locale", "kind", "confidence",
  "uncertainty_reasons", "everyday", "technical", "redaction",
] as const;
const EVERYDAY_KEYS = [
  "headline_message_id", "headline", "summary_message_id", "summary", "impact_message_id", "impact",
  "why_guard_intervened_message_id", "why_guard_intervened", "recommendation_message_id", "recommendation",
  "actor_label", "targets", "consequences", "safer_alternatives",
] as const;
const TARGET_KEYS = ["kind", "label", "scope", "sensitivity"] as const;
const CONSEQUENCE_KEYS = ["message_id", "message", "severity", "confirmed"] as const;
const ALTERNATIVE_KEYS = ["message_id", "message", "kind"] as const;
const TECHNICAL_KEYS = [
  "available", "unavailable_reason", "action_type", "command_display", "normalized_command_display",
  "executable", "arguments_display", "dialect", "transport", "working_scope_display", "wrappers",
  "segments", "extension_ids", "rule_ids", "reason_codes", "policy_source", "parse_confidence",
  "proof_level", "receipt_id", "action_id",
] as const;
const SEGMENT_KEYS = ["executable", "arguments_display", "execution_context", "pipeline_index"] as const;
const REDACTION_KEYS = ["level", "policy_version", "omitted_fields", "truncated_fields", "secret_like_values_removed"] as const;

export type ParsedActionExplanation = {
  explanation: GuardActionExplanationV1 | null;
  error: "malformed" | "identity_mismatch" | null;
};

function record(value: unknown): UnknownRecord | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as UnknownRecord;
}

function hasShape(value: UnknownRecord, keys: readonly string[]): boolean {
  const allowed = new Set(keys);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      return false;
    }
  }
  return keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function boundedString(value: unknown, maxLength: number, minLength = 0): string | null {
  if (typeof value !== "string" || value.length < minLength || value.length > maxLength) {
    return null;
  }
  return value;
}

function nullableString(value: unknown): string | null | undefined {
  if (value === null) {
    return null;
  }
  if (typeof value === "string") {
    return value;
  }
  return undefined;
}

function nullableBoundedString(value: unknown, maxLength: number): string | null | undefined {
  const parsed = nullableString(value);
  if (parsed === null || parsed === undefined) {
    return parsed;
  }
  return parsed.length <= maxLength ? parsed : undefined;
}

function boundedStringArray(value: unknown, maxItems: number, maxLength: number, pattern?: RegExp): string[] | null {
  if (!Array.isArray(value) || value.length > maxItems) {
    return null;
  }
  const result: string[] = [];
  for (const item of value) {
    if (typeof item !== "string" || item.length > maxLength || (pattern !== undefined && !pattern.test(item))) {
      return null;
    }
    result.push(item);
  }
  return result;
}

function nullableStringArray(value: unknown, maxItems: number, maxLength: number): string[] | null | undefined {
  if (value === null) {
    return null;
  }
  if (value === undefined) {
    return undefined;
  }
  return boundedStringArray(value, maxItems, maxLength) ?? undefined;
}

function enumValue<T extends string>(value: unknown, values: readonly T[]): T | null {
  if (typeof value !== "string") {
    return null;
  }
  return values.includes(value as T) ? (value as T) : null;
}

function actionKind(value: unknown): GuardEverydayActionKind | null {
  if (typeof value !== "string" || !ACTION_KINDS.has(value as GuardEverydayActionKind)) {
    return null;
  }
  return value as GuardEverydayActionKind;
}

function nullableMessageId(value: unknown): string | null | undefined {
  const parsed = nullableBoundedString(value, 128);
  if (parsed === null || parsed === undefined) {
    return parsed;
  }
  return MESSAGE_ID_PATTERN.test(parsed) ? parsed : undefined;
}

function requiredMessageId(value: unknown): string | null {
  const parsed = nullableMessageId(value);
  return typeof parsed === "string" ? parsed : null;
}

function requiredMessage(value: unknown, maxLength: number): string | null | undefined {
  const parsed = nullableBoundedString(value, maxLength);
  if (parsed === undefined) {
    return undefined;
  }
  return parsed;
}

function parseTarget(value: unknown): EverydayTarget | null {
  const target = record(value);
  if (target === null || !hasShape(target, TARGET_KEYS)) {
    return null;
  }
  const kind = boundedString(target.kind, 64);
  const label = boundedString(target.label, 240);
  const scope = nullableBoundedString(target.scope, 120);
  const sensitivity = enumValue(target.sensitivity, SENSITIVITIES);
  if (kind === null || !TARGET_KIND_PATTERN.test(kind) || label === null || scope === undefined || sensitivity === null) {
    return null;
  }
  return { kind, label, scope, sensitivity };
}

function parseConsequence(value: unknown): EverydayConsequence | null {
  const consequence = record(value);
  if (consequence === null || !hasShape(consequence, CONSEQUENCE_KEYS)) {
    return null;
  }
  const messageId = requiredMessageId(consequence.message_id);
  const message = boundedString(consequence.message, 500);
  const severity = enumValue(consequence.severity, SEVERITIES);
  if (messageId === null || message === null || severity === null || typeof consequence.confirmed !== "boolean") {
    return null;
  }
  return { message_id: messageId, message, severity, confirmed: consequence.confirmed };
}

function parseAlternative(value: unknown): EverydayAlternative | null {
  const alternative = record(value);
  if (alternative === null || !hasShape(alternative, ALTERNATIVE_KEYS)) {
    return null;
  }
  const messageId = requiredMessageId(alternative.message_id);
  const message = boundedString(alternative.message, 500);
  const kind = enumValue(alternative.kind, ALTERNATIVE_KINDS);
  if (messageId === null || message === null || kind === null) {
    return null;
  }
  return { message_id: messageId, message, kind };
}

function parseSegment(value: unknown): TechnicalSegment | null {
  const segment = record(value);
  if (segment === null || !hasShape(segment, SEGMENT_KEYS)) {
    return null;
  }
  const executable = nullableBoundedString(segment.executable, 240);
  const argumentsDisplay = boundedStringArray(segment.arguments_display, 128, 240);
  const executionContext = boundedString(segment.execution_context, 120);
  const pipelineIndex = segment.pipeline_index;
  if (
    executable === undefined || argumentsDisplay === null || executionContext === null ||
    typeof pipelineIndex !== "number" || !Number.isSafeInteger(pipelineIndex) || pipelineIndex < 0 || pipelineIndex > 128
  ) {
    return null;
  }
  return { executable, arguments_display: argumentsDisplay, execution_context: executionContext, pipeline_index: pipelineIndex };
}

function parseEveryday(value: unknown): GuardActionExplanationV1["everyday"] | null {
  const everyday = record(value);
  if (everyday === null || !hasShape(everyday, EVERYDAY_KEYS)) {
    return null;
  }
  const headlineMessageId = requiredMessageId(everyday.headline_message_id);
  const headline = boundedString(everyday.headline, 240);
  const summaryMessageId = requiredMessageId(everyday.summary_message_id);
  const summary = boundedString(everyday.summary, 800);
  const impactMessageId = nullableMessageId(everyday.impact_message_id);
  const impact = requiredMessage(everyday.impact, 800);
  const whyMessageId = nullableMessageId(everyday.why_guard_intervened_message_id);
  const why = requiredMessage(everyday.why_guard_intervened, 800);
  const recommendationMessageId = nullableMessageId(everyday.recommendation_message_id);
  const recommendation = requiredMessage(everyday.recommendation, 800);
  const actorLabel = boundedString(everyday.actor_label, 120);
  const targetsRaw = everyday.targets;
  const consequencesRaw = everyday.consequences;
  const alternativesRaw = everyday.safer_alternatives;
  if (
    headlineMessageId === null || headline === null || summaryMessageId === null || summary === null ||
    impactMessageId === undefined || impact === undefined || whyMessageId === undefined || why === undefined ||
    recommendationMessageId === undefined || recommendation === undefined || actorLabel === null ||
    !Array.isArray(targetsRaw) || targetsRaw.length > 16 || !Array.isArray(consequencesRaw) || consequencesRaw.length > 16 ||
    !Array.isArray(alternativesRaw) || alternativesRaw.length > 12
  ) {
    return null;
  }
  const targets: EverydayTarget[] = [];
  for (const item of targetsRaw) {
    const parsed = parseTarget(item);
    if (parsed === null) return null;
    targets.push(parsed);
  }
  const consequences: EverydayConsequence[] = [];
  for (const item of consequencesRaw) {
    const parsed = parseConsequence(item);
    if (parsed === null) return null;
    consequences.push(parsed);
  }
  const saferAlternatives: EverydayAlternative[] = [];
  for (const item of alternativesRaw) {
    const parsed = parseAlternative(item);
    if (parsed === null) return null;
    saferAlternatives.push(parsed);
  }
  return {
    headline_message_id: headlineMessageId,
    headline,
    summary_message_id: summaryMessageId,
    summary,
    impact_message_id: impactMessageId,
    impact,
    why_guard_intervened_message_id: whyMessageId,
    why_guard_intervened: why,
    recommendation_message_id: recommendationMessageId,
    recommendation,
    actor_label: actorLabel,
    targets,
    consequences,
    safer_alternatives: saferAlternatives,
  };
}

function parseTechnical(value: unknown): GuardActionExplanationV1["technical"] | null {
  const technical = record(value);
  if (technical === null || !hasShape(technical, TECHNICAL_KEYS)) {
    return null;
  }
  const unavailableReason = nullableBoundedString(technical.unavailable_reason, 240);
  const actionType = boundedString(technical.action_type, 120);
  const commandDisplay = nullableBoundedString(technical.command_display, 4096);
  const normalizedCommandDisplay = nullableBoundedString(technical.normalized_command_display, 4096);
  const executable = nullableBoundedString(technical.executable, 240);
  const argumentsDisplay = nullableStringArray(technical.arguments_display, 128, 240);
  const dialect = nullableBoundedString(technical.dialect, 64);
  const transport = nullableBoundedString(technical.transport, 64);
  const workingScopeDisplay = nullableBoundedString(technical.working_scope_display, 240);
  const wrappers = boundedStringArray(technical.wrappers, 32, 120);
  const extensionIds = boundedStringArray(technical.extension_ids, 64, 128);
  const ruleIds = boundedStringArray(technical.rule_ids, 64, 128);
  const reasonCodes = boundedStringArray(technical.reason_codes, 64, 128);
  const policySource = nullableBoundedString(technical.policy_source, 128);
  const parseConfidence = nullableBoundedString(technical.parse_confidence, 64);
  const proofLevel = nullableBoundedString(technical.proof_level, 64);
  const receiptId = nullableBoundedString(technical.receipt_id, 256);
  const actionId = nullableBoundedString(technical.action_id, 512);
  const segmentsRaw = technical.segments;
  if (
    typeof technical.available !== "boolean" || unavailableReason === undefined || actionType === null ||
    commandDisplay === undefined || normalizedCommandDisplay === undefined || executable === undefined ||
    argumentsDisplay === undefined || dialect === undefined || transport === undefined || workingScopeDisplay === undefined ||
    wrappers === null || extensionIds === null || ruleIds === null || reasonCodes === null || policySource === undefined ||
    parseConfidence === undefined || proofLevel === undefined || receiptId === undefined || actionId === undefined ||
    !Array.isArray(segmentsRaw) || segmentsRaw.length > 128 ||
    (technical.available === false && unavailableReason === null)
  ) {
    return null;
  }
  const segments: TechnicalSegment[] = [];
  for (const item of segmentsRaw) {
    const parsed = parseSegment(item);
    if (parsed === null) return null;
    segments.push(parsed);
  }
  return {
    available: technical.available,
    unavailable_reason: unavailableReason,
    action_type: actionType,
    command_display: commandDisplay,
    normalized_command_display: normalizedCommandDisplay,
    executable,
    arguments_display: argumentsDisplay,
    dialect,
    transport,
    working_scope_display: workingScopeDisplay,
    wrappers,
    segments,
    extension_ids: extensionIds,
    rule_ids: ruleIds,
    reason_codes: reasonCodes,
    policy_source: policySource,
    parse_confidence: parseConfidence,
    proof_level: proofLevel,
    receipt_id: receiptId,
    action_id: actionId,
  };
}

function parseRedaction(value: unknown): GuardActionExplanationV1["redaction"] | null {
  const redaction = record(value);
  if (redaction === null || !hasShape(redaction, REDACTION_KEYS)) {
    return null;
  }
  const level = enumValue(redaction.level, REDACTION_LEVELS);
  const policyVersion = boundedString(redaction.policy_version, 64);
  const omittedFields = boundedStringArray(redaction.omitted_fields, 64, 128);
  const truncatedFields = boundedStringArray(redaction.truncated_fields, 64, 128);
  if (level === null || policyVersion === null || omittedFields === null || truncatedFields === null || typeof redaction.secret_like_values_removed !== "boolean") {
    return null;
  }
  return {
    level,
    policy_version: policyVersion,
    omitted_fields: omittedFields,
    truncated_fields: truncatedFields,
    secret_like_values_removed: redaction.secret_like_values_removed,
  };
}

export function parseActionExplanation(
  value: unknown,
  expectedActionIdentity?: string | null,
): ParsedActionExplanation {
  const root = record(value);
  if (root === null || root.schema_version !== "guard.action-explanation.v1") {
    return { explanation: null, error: value == null ? null : "malformed" };
  }
  if (!hasShape(root, ROOT_KEYS)) {
    return { explanation: null, error: "malformed" };
  }
  const explanationVersion = boundedString(root.explanation_version, 64, 1);
  const rendererVersion = boundedString(root.renderer_version, 64, 1);
  const actionIdentity = boundedString(root.action_identity, 512, 1);
  const canonicalIdentity = nullableBoundedString(root.canonical_identity, 256);
  const catalogDigest = nullableBoundedString(root.catalog_digest, 256);
  const locale = boundedString(root.locale, 35);
  const kind = actionKind(root.kind);
  const confidence = enumValue(root.confidence, CONFIDENCES);
  const uncertaintyReasons = boundedStringArray(root.uncertainty_reasons, 16, 64, UNCERTAINTY_PATTERN);
  const everyday = parseEveryday(root.everyday);
  const technical = parseTechnical(root.technical);
  const redaction = parseRedaction(root.redaction);
  if (
    explanationVersion === null || rendererVersion === null || actionIdentity === null || canonicalIdentity === undefined ||
    catalogDigest === undefined || locale === null || !LOCALE_PATTERN.test(locale) || kind === null || confidence === null ||
    uncertaintyReasons === null || everyday === null || technical === null || redaction === null
  ) {
    return { explanation: null, error: "malformed" };
  }
  if (expectedActionIdentity !== undefined && expectedActionIdentity !== null && actionIdentity !== expectedActionIdentity) {
    return { explanation: null, error: "identity_mismatch" };
  }
  const explanation: GuardActionExplanationV1 = {
    schema_version: "guard.action-explanation.v1",
    explanation_version: explanationVersion,
    renderer_version: rendererVersion,
    action_identity: actionIdentity,
    canonical_identity: canonicalIdentity,
    catalog_digest: catalogDigest,
    locale,
    kind,
    confidence,
    uncertainty_reasons: uncertaintyReasons,
    everyday,
    technical,
    redaction,
  };
  return { explanation, error: null };
}
