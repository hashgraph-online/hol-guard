import type { GuardActionExplanationV1, GuardEverydayActionKind } from "./guard-types";

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

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}
function string(value: unknown): string | null { return typeof value === "string" ? value : null; }
function nullableString(value: unknown): string | null | undefined {
  return value === null ? null : typeof value === "string" ? value : undefined;
}
function stringArray(value: unknown): string[] | null {
  return Array.isArray(value) && value.every((item) => typeof item === "string") ? [...value] : null;
}

export type ParsedActionExplanation = {
  explanation: GuardActionExplanationV1 | null;
  error: "malformed" | "identity_mismatch" | null;
};

export function parseActionExplanation(
  value: unknown,
  expectedActionIdentity?: string | null,
): ParsedActionExplanation {
  const root = record(value);
  if (root === null || root.schema_version !== "guard.action-explanation.v1") {
    return { explanation: null, error: value == null ? null : "malformed" };
  }
  const actionIdentity = string(root.action_identity);
  const kind = string(root.kind) as GuardEverydayActionKind | null;
  const confidence = string(root.confidence);
  const everyday = record(root.everyday);
  const technical = record(root.technical);
  const redaction = record(root.redaction);
  if (
    actionIdentity === null || !ACTION_KINDS.has(kind as GuardEverydayActionKind) ||
    !["exact", "derived", "limited"].includes(confidence ?? "") ||
    everyday === null || technical === null || redaction === null
  ) {
    return { explanation: null, error: "malformed" };
  }
  if (expectedActionIdentity && actionIdentity !== expectedActionIdentity) {
    return { explanation: null, error: "identity_mismatch" };
  }
  const headline = string(everyday.headline);
  const summary = string(everyday.summary);
  const actorLabel = string(everyday.actor_label);
  const headlineMessageId = string(everyday.headline_message_id);
  const summaryMessageId = string(everyday.summary_message_id);
  const uncertaintyReasons = stringArray(root.uncertainty_reasons);
  const wrappers = stringArray(technical.wrappers);
  const extensionIds = stringArray(technical.extension_ids);
  const ruleIds = stringArray(technical.rule_ids);
  const reasonCodes = stringArray(technical.reason_codes);
  const omittedFields = stringArray(redaction.omitted_fields);
  const truncatedFields = stringArray(redaction.truncated_fields);
  const unavailableReason = nullableString(technical.unavailable_reason);
  if (
    headline === null || summary === null || actorLabel === null ||
    headlineMessageId === null || summaryMessageId === null || uncertaintyReasons === null ||
    typeof technical.available !== "boolean" || unavailableReason === undefined ||
    (technical.available === false && unavailableReason === null) ||
    string(technical.action_type) === null || wrappers === null || extensionIds === null ||
    ruleIds === null || reasonCodes === null || omittedFields === null || truncatedFields === null ||
    typeof redaction.secret_like_values_removed !== "boolean" || string(redaction.policy_version) === null ||
    !["none", "summary", "redacted"].includes(string(redaction.level) ?? "")
  ) {
    return { explanation: null, error: "malformed" };
  }
  if (!Array.isArray(everyday.targets) || !Array.isArray(everyday.consequences) || !Array.isArray(everyday.safer_alternatives) || !Array.isArray(technical.segments)) {
    return { explanation: null, error: "malformed" };
  }
  const explanation = value as GuardActionExplanationV1;
  return { explanation, error: null };
}
