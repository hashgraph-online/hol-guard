import type { GuardActionEnvelope, GuardApprovalRequest } from "./guard-types";

const DUPLICATE_REVIEW_SUBSTRING_MIN_LENGTH = 24;
const DUPLICATE_REVIEW_PREFIX_MIN_LENGTH = 80;
const DUPLICATE_REVIEW_SAFETY_CONTEXT_PATTERNS = [
  /\b(api[-_\s]?keys?|credentials?|secrets?|tokens?|passwords?|sensitive|malicious|destructive|unauthorized)\b/i,
  /\b(expose|exposes|exposed|leak|leaks|leaked|exfiltrate|exfiltrates|exfiltration)\b/i,
  /\b(may|could|can|would|will)\s+(expose|leak|send|upload|exfiltrate|transmit|delete|remove|modify|overwrite|execute|run)\b/i,
  /\bruns?\s+as\s+(root|admin|administrator)\b/i,
  /\bsends?\s+(data|contents|files?|credentials?|secrets?|tokens?)\s+to\b/i,
  /\b(third[-\s]?party|remote|external)\s+host\b/i,
];
const COMPOUND_FINDINGS_SUMMARY_PREFIX = /^\s*compound command findings:\s*/i;
const DUPLICATE_REVIEW_BOILERPLATE_REMAINDERS = [
  "Guard requires one review because part of this shell command is unresolved.",
].map((value) => normalizeDuplicateReviewText(value));

export function isApplyPatchEnvelope(envelope: GuardActionEnvelope): boolean {
  return (
    envelope.action_type === "file_write" &&
    envelope.tool_name?.trim().toLowerCase() === "apply_patch" &&
    envelope.command?.trim().startsWith("*** Begin Patch") === true
  );
}

export function resolveEnvelopeDisplayText(envelope: GuardActionEnvelope): string | null {
  if (isApplyPatchEnvelope(envelope) && envelope.command !== null && envelope.command.length > 0) {
    return envelope.command;
  }
  if (envelope.action_type === "shell_command" && envelope.command !== null && envelope.command.length > 0) {
    return envelope.command;
  }
  const promptText = envelope.prompt_text ?? envelope.prompt_excerpt;
  if (envelope.action_type === "prompt" && promptText !== null && promptText.length > 0) {
    return promptText;
  }
  if (envelope.action_type === "mcp_tool" && envelope.mcp_server !== null && envelope.mcp_tool !== null) {
    return `${envelope.mcp_server} / ${envelope.mcp_tool}`;
  }
  if (envelope.tool_name !== null) {
    return envelope.tool_name;
  }
  if (envelope.target_paths.length > 0) {
    return envelope.target_paths[0];
  }
  return envelope.action_type === "harness_start" ? null : envelope.action_type;
}

export function resolveDecisionV2Detail(item: GuardApprovalRequest): string | null {
  const detail = item.decision_v2_json?.dashboard_primary_detail;
  return detail !== undefined && detail.trim().length > 0 ? detail : null;
}

export function resolveStoppedCommandText(item: GuardApprovalRequest): string {
  if (item.action_envelope_json) {
    const envelope = item.action_envelope_json;
    const envelopeText = resolveEnvelopeDisplayText(envelope);
    const shouldFallbackFromGenericActionType =
      envelopeText !== null &&
      (envelope.action_type === "shell_command" || envelope.action_type === "prompt") &&
      envelopeText === envelope.action_type;
    if (envelopeText !== null && !shouldFallbackFromGenericActionType) {
      return envelopeText;
    }
  }
  const launchTarget = item.launch_target?.trim();
  const launchTargetIsRequestSummary =
    item.artifact_type === "tool_action_request" &&
    launchTarget?.startsWith("Requested `") &&
    launchTarget.includes(" action `");
  const launchSummary = item.launch_summary?.trim();
  if (launchTargetIsRequestSummary && launchSummary) {
    const launchSummaryCommand = launchSummary.match(/^Launches with `(.+)`\.$/);
    if (launchSummaryCommand?.[1]) {
      return launchSummaryCommand[1];
    }
  }
  if (launchTarget) {
    return launchTarget;
  }
  if (item.launch_summary?.trim()) {
    const commandMatch = item.launch_summary.match(/`([^`]+)`/);
    if (commandMatch?.[1]) {
      return commandMatch[1];
    }
    return item.launch_summary;
  }
  return item.artifact_name.trim() || item.artifact_id;
}

export function resolveSecondaryRiskSummary(item: GuardApprovalRequest): string | null {
  const summary = item.risk_summary?.trim();
  if (!summary) {
    return null;
  }
  if (duplicatesStoppedActionText(item, summary)) {
    return null;
  }
  const primaryDetail = resolveDecisionV2Detail(item) ?? resolveTriggerSummaryDetail(item);
  if (primaryDetail) {
    if (normalizeDuplicateReviewText(summary) === normalizeDuplicateReviewText(primaryDetail)) {
      return null;
    }
    if (compoundSummaryRestatesPrimaryDetail(summary, primaryDetail)) {
      return null;
    }
  }
  return summary;
}

function resolveTriggerSummaryDetail(item: GuardApprovalRequest): string | null {
  const detail = item.trigger_summary?.trim();
  return detail ? detail : null;
}

// Compound shell reviews fold every segment finding into one prefixed risk
// summary. When that text only restates the detail already shown in the
// primary review card — plus generic Guard review boilerplate — the secondary
// section would read as the same finding twice.
function compoundSummaryRestatesPrimaryDetail(summary: string, primaryDetail: string): boolean {
  const withoutPrefix = summary.replace(COMPOUND_FINDINGS_SUMMARY_PREFIX, "").trim();
  if (!withoutPrefix) {
    return false;
  }
  const normalizedSummary = normalizeDuplicateReviewText(withoutPrefix);
  const normalizedDetail = normalizeDuplicateReviewText(primaryDetail);
  if (
    normalizedDetail.length < DUPLICATE_REVIEW_SUBSTRING_MIN_LENGTH ||
    !normalizedSummary.includes(normalizedDetail)
  ) {
    return false;
  }
  const remainder = normalizedSummary.replace(normalizedDetail, " ").trim();
  return remainder.length === 0 || DUPLICATE_REVIEW_BOILERPLATE_REMAINDERS.includes(remainder);
}

function duplicatesStoppedActionText(item: GuardApprovalRequest, value: string): boolean {
  const stoppedActionText = resolveStoppedCommandText(item);
  const canUseLongPromptPrefix =
    item.action_envelope_json?.action_type === "prompt" || item.artifact_type === "prompt_request";
  const stoppedText = normalizeDuplicateReviewText(stoppedActionText);
  const candidateText = normalizeDuplicateReviewText(value);
  const contextStrippedValue = stripDuplicateReviewContextPrefix(value);
  const candidateWithoutContext =
    contextStrippedValue === null ? "" : normalizeDuplicateReviewText(contextStrippedValue);
  const candidateRemainder =
    contextStrippedValue === null ? "" : extractDuplicateReviewRemainder(contextStrippedValue, stoppedActionText);
  if (stoppedText.length === 0 || candidateText.length === 0) {
    return false;
  }
  if (stoppedText === candidateText || stoppedText === candidateWithoutContext) {
    return true;
  }
  if (
    stoppedText.length < DUPLICATE_REVIEW_SUBSTRING_MIN_LENGTH ||
    candidateText.length < DUPLICATE_REVIEW_SUBSTRING_MIN_LENGTH
  ) {
    return false;
  }
  if (
    candidateWithoutContext.length >= DUPLICATE_REVIEW_SUBSTRING_MIN_LENGTH &&
    stoppedText.includes(candidateWithoutContext)
  ) {
    return true;
  }
  if (
    canUseLongPromptPrefix &&
    stoppedText.length >= DUPLICATE_REVIEW_PREFIX_MIN_LENGTH &&
    candidateWithoutContext.startsWith(stoppedText) &&
    !hasDuplicateReviewSafetyContextRemainder(candidateRemainder)
  ) {
    return true;
  }
  return false;
}

function extractDuplicateReviewRemainder(candidateText: string, stoppedText: string): string {
  const candidate = candidateText.trim();
  const stopped = normalizeDuplicateReviewText(stoppedText);
  if (stopped.length === 0) {
    return "";
  }
  let normalizedPrefix = "";
  for (let index = 0; index < candidate.length; index += 1) {
    normalizedPrefix += normalizeDuplicateReviewText(candidate[index]);
    if (normalizedPrefix.length >= stopped.length) {
      return normalizedPrefix.startsWith(stopped) ? candidate.slice(index + 1).trim() : "";
    }
  }
  return "";
}

function hasDuplicateReviewSafetyContextRemainder(remainder: string): boolean {
  return DUPLICATE_REVIEW_SAFETY_CONTEXT_PATTERNS.some((pattern) => pattern.test(remainder));
}

function normalizeDuplicateReviewText(value: string): string {
  return value
    .toLowerCase()
    .replace(/[`"'\s:.,;!?()[\]{}_\-…]+/g, "")
    .trim();
}

function stripDuplicateReviewContextPrefix(value: string): string | null {
  const stripped = value.replace(
    /^\s*(codex|claude|claude code|claudecode|copilot|opencode|gemini|grok|kimi)?\s*(prompt|command|tool)\s+for\s+[`"']?[^:`"']+[`"']?\s*:\s*/i,
    "",
  );
  return stripped === value ? null : stripped;
}
