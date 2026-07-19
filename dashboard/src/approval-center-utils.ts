import type {
  GuardActionEnvelope,
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardCodexResumeResult,
  GuardReceipt,
  RiskSignalV2
} from "./guard-types";
import { guardAwareHref } from "./guard-api";
import { resolveQueueCategory } from "./queue-state";
import { whyPaused } from "./evidence/plain-english";
import { guardActionPresentation } from "./guard-action";

export const EMPTY_QUEUE_TITLE = "Review queue is clear";
export const STALE_REQUEST_COPY = "This request was already decided.";
export const QUEUE_CONNECTION_ERROR_HEADLINE = "Guard daemon not reachable: approval links work when Guard is running on this device.";
export const QUEUE_CONNECTION_ERROR_INSTRUCTION = "Start Guard on this machine, then reload to continue approving or blocking.";

export type DataFlowEvidenceSummary = {
  signalTitle: string;
  sourceLabel: string;
  sinkLabel: string;
  signalId: string;
  count: number;
};

export function deriveDataFlowEvidence(item: GuardApprovalRequest): DataFlowEvidenceSummary | null {
  const signals = item.decision_v2_json?.signals ?? [];
  const dataFlowSignals = signals.filter(
    (s) => s.detector === "data_flow.exfiltration" || s.signal_id.startsWith("data-flow:")
  );
  if (dataFlowSignals.length === 0) {
    return null;
  }
  const primary = dataFlowSignals[0];
  return {
    signalTitle: primary.title,
    sourceLabel: "Local secret",
    sinkLabel: resolveDataFlowSinkLabel(primary),
    signalId: primary.signal_id,
    count: dataFlowSignals.length,
  };
}

export function deriveSkillRiskSignals(item: GuardApprovalRequest): RiskSignalV2[] {
  return (item.decision_v2_json?.signals ?? []).filter((s) => s.detector === "skill.content");
}

export function deriveSupplyChainRiskSignals(item: GuardApprovalRequest): RiskSignalV2[] {
  return (item.decision_v2_json?.signals ?? []).filter((s) => s.detector === "supply-chain.content");
}

export function deriveEncodedLayerSignals(item: GuardApprovalRequest): RiskSignalV2[] {
  return (item.decision_v2_json?.signals ?? []).filter(
    (s) => s.detector === "safe-decode.content" || s.signal_id.startsWith("encoded.")
  );
}

function resolveDataFlowSinkLabel(signal: RiskSignalV2): string {
  if (signal.category === "network") {
    return "Network host";
  }
  if (signal.signal_id === "data-flow:clipboard-secret") {
    return "Clipboard";
  }
  if (signal.signal_id === "data-flow:world-readable-temp-secret") {
    return "World-readable temp file";
  }
  if (signal.signal_id === "data-flow:git-remote-token") {
    return "Git remote config";
  }
  return "External sink";
}

export function buildRetryAfterApprovalCopy(item: GuardApprovalRequest, action: "allow" | "block"): string {
  const harness = harnessDisplayName(item.harness);
  if (action === "allow") {
    return `Approved. Return to ${harness} to resume, or it will continue automatically if still running.`;
  }
  return `Blocked. Return to ${harness} to continue with a different action, or ask it to try something else.`;
}

export function resolveEnvelopeDisplayText(envelope: GuardActionEnvelope): string | null {
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

export function resolveActionEnvelopeDetailText(
  envelope: GuardActionEnvelope,
  options: { mcpInputMaxLength?: number | null } = {}
): string | null {
  if (envelope.action_type === "shell_command") {
    return envelope.command !== null && envelope.command.length > 0 ? envelope.command : null;
  }
  const promptText = envelope.prompt_text ?? envelope.prompt_excerpt;
  if (envelope.action_type === "prompt") {
    return promptText !== null && promptText.length > 0 ? promptText : null;
  }
  if (
    (envelope.action_type === "file_read" || envelope.action_type === "file_write") &&
    envelope.target_paths.length > 0
  ) {
    return envelope.target_paths.join("\n");
  }
  if (envelope.action_type === "network_request" && envelope.network_hosts.length > 0) {
    return envelope.network_hosts.join("\n");
  }
  if (envelope.action_type === "mcp_tool") {
    const baseText =
      resolveEnvelopeDisplayText(envelope) ?? envelope.mcp_tool ?? envelope.tool_name ?? envelope.action_type;
    const inputSummary = serializeMcpInput(envelope.raw_payload_redacted, options.mcpInputMaxLength ?? null);
    return inputSummary === null ? baseText : `${baseText}\n\nInput:\n${inputSummary}`;
  }
  if (envelope.action_type === "package_script") {
    if (envelope.package_manager && envelope.package_name) {
      return `${envelope.package_manager} install ${envelope.package_name}`;
    }
    if (envelope.package_name) {
      return envelope.package_name;
    }
  }
  return resolveEnvelopeDisplayText(envelope);
}

export function humanizeList(values: string[]): string {
  if (values.length === 0) {
    return "nothing tracked yet";
  }
  if (values.length === 1) {
    return values[0];
  }
  if (values.length === 2) {
    return `${values[0]} and ${values[1]}`;
  }
  return `${values.slice(0, -1).join(", ")}, and ${values.at(-1)}`;
}

export function humanizeChangedFields(values: string[]): string {
  const translated = values.map((value) => {
    if (value === "first_seen") {
      return "this action";
    }
    if (value === "args") {
      return "the command details";
    }
    if (value === "command") {
      return "the command";
    }
    if (value === "headers") {
      return "network details";
    }
    if (value === "tool_action_request") {
      return "the requested action";
    }
    return value.replaceAll("_", " ");
  });
  return humanizeList(translated);
}

export function buildPauseLine(item: GuardApprovalRequest): string {
  const resolutionBlockReason = requestResolutionBlockReason(item);
  if (resolutionBlockReason !== null) {
    return resolutionBlockReason;
  }
  if (item.policy_action === "block") {
    return `${harnessDisplayName(item.harness)} kept this blocked because you already saved a block decision for it.`;
  }
  if (item.changed_fields.length === 1 && item.changed_fields[0] === "first_seen") {
    return `${harnessDisplayName(item.harness)} has not run this exact action here before, so HOL Guard paused it for you to review.`;
  }
  return `${harnessDisplayName(item.harness)} wants to run something that changed since your last saved decision: ${humanizeChangedFields(item.changed_fields)}.`;
}

export function buildRecommendation(item: GuardApprovalRequest): string {
  const resolutionBlockReason = requestResolutionBlockReason(item);
  if (resolutionBlockReason !== null) {
    return resolutionBlockReason;
  }
  if (item.changed_fields.length === 1 && item.changed_fields[0] === "first_seen") {
    return "If this is what you expected, approve this retry. Project approval remembers this same action here without trusting new sensitive actions.";
  }
  if (item.policy_action === "block") {
    return "Keep it blocked unless you are sure this action is safe and expected.";
  }
  return "Approve the smallest choice that matches what you meant to do. Different commands, prompts, paths, hosts, or tools should ask again.";
}

export function buildQueueSummary(item: GuardApprovalRequest): string {
  const resolutionBlockReason = requestResolutionBlockReason(item);
  if (resolutionBlockReason !== null) {
    return resolutionBlockReason;
  }
  if (item.policy_action === "block") {
    return "You already chose to block this action.";
  }
  if (item.changed_fields.length === 1 && item.changed_fields[0] === "first_seen") {
    return "First time HOL Guard has seen this here.";
  }
  return `Changed since your last decision: ${humanizeChangedFields(item.changed_fields)}.`;
}

export function buildMemorySummary(
  item: GuardApprovalRequest,
  receipt: GuardReceipt | null
): string {
  if (receipt === null) {
    return `HOL Guard has not saved an earlier approval for ${item.artifact_name}.`;
  }
  return `The last saved decision for ${item.artifact_name} was ${receipt.policy_decision}.`;
}

export function scopeLabel(scope: string, variant: "review" | "policy" = "review"): string {
  if (variant === "policy") {
    switch (scope) {
      case "artifact":
        return "Once";
      case "workspace":
        return "This project";
      case "harness":
        return "This harness";
      case "publisher":
        return "This cwd";
      case "global":
        return "Team policy";
      default:
        return scope;
    }
  }
  switch (scope) {
    case "artifact":
      return "This retry only";
    case "workspace":
      return "Same action in this project";
    case "publisher":
      return "This source in this app";
    case "harness":
      return "This app";
    case "global":
      return "Every project on this machine";
    default:
      return scope;
  }
}

export function policyActionLabel(action: string): string {
  return guardActionPresentation(action).label;
}

export function artifactTypeLabel(artifactType: string): string {
  switch (artifactType) {
    case "mcp_server":
      return "MCP server";
    case "extension":
      return "Extension";
    case "hook":
      return "Hook";
    case "agent":
      return "Agent";
    case "command":
      return "Command";
    case "tool_action_request":
      return "Tool action";
    default:
      return artifactType.replaceAll("_", " ");
  }
}

export function buildTriggerHeading(item: GuardApprovalRequest): string {
  return `${harnessDisplayName(item.harness)} wants to run this`;
}

export function buildTriggerSummary(item: GuardApprovalRequest): string {
  const location = shortConfigPath(item.config_path);
  const target = item.launch_target ?? "the recorded launch target";
  return `HOL Guard found ${item.artifact_name} in ${location}. It was about to run ${target}.`;
}

export function buildStoppedReason(item: GuardApprovalRequest, receipt: GuardReceipt | null): string {
  if (item.policy_action === "block") {
    const changed = item.changed_fields.length > 0 ? ` ${humanizeChangedFields(item.changed_fields)} also changed.` : "";
    return `A saved block decision already covers this action, so HOL Guard kept it paused.${changed}`;
  }
  if (item.changed_fields.length === 1 && item.changed_fields[0] === "first_seen") {
    return "HOL Guard has never seen this action in this project folder before, so there is no saved approval for it yet.";
  }
  if (receipt !== null) {
    return `HOL Guard found an earlier ${receipt.policy_decision} decision, but ${humanizeChangedFields(item.changed_fields)} no longer matches what you approved before.`;
  }
  return "This action changed after the last known state, so HOL Guard needs a new decision before it can run.";
}

export function buildResumeInstruction(item: GuardApprovalRequest): string {
  const resolutionBlockReason = requestResolutionBlockReason(item);
  if (resolutionBlockReason !== null) {
    return resolutionBlockReason;
  }
  return `Choose the smallest approval that matches what you meant to do, save it, then retry in ${harnessDisplayName(item.harness)}.`;
}

export function requestResolutionBlockReason(item: GuardApprovalRequest): string | null {
  if (item.decision_contract_error !== undefined) {
    return "HOL Guard found inconsistent stored decision data. This request cannot be approved; rerun the action to create a fresh, consistent review request.";
  }
  if (item.policy_action === "sandbox-required") {
    return "Policy requires this action to run in an approved sandbox. An approval cannot bypass the sandbox requirement.";
  }
  if (item.policy_action === "block") {
    return "Policy terminally blocked this action. This queue record is diagnostic and cannot be overridden by an approval.";
  }
  return null;
}

export function shortConfigPath(path: string): string {
  const sanitizedPath = path.replace(/\/Users\/[^/\s]+/g, "~");
  const marker = "/.codex/";
  const index = sanitizedPath.lastIndexOf(marker);
  if (index >= 0) {
    return `...${sanitizedPath.slice(index)}`;
  }
  return sanitizedPath;
}

export function buildTechnicalSummary(_diff: GuardArtifactDiff | null, item: GuardApprovalRequest): Array<[string, string]> {
  return [["Approval command", item.review_command]];
}

export function inferProjectFolder(configPath: string): string {
  const marker = "/.codex/config.toml";
  if (configPath.endsWith(marker)) {
    return configPath.slice(0, -marker.length);
  }
  const segments = configPath.split("/");
  if (segments.length > 1) {
    return segments.slice(0, -1).join("/") || configPath;
  }
  return configPath;
}

function capitalizeHarness(harness: string): string {
  if (harness.length === 0) {
    return harness;
  }
  return `${harness.charAt(0).toUpperCase()}${harness.slice(1)}`;
}

const HARNESS_SLUG_PATTERN = /^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$/;
const HEX_TOKEN_HARNESS_PATTERN = /^[a-f0-9]{16,64}$/;
const UUID_HARNESS_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const NON_APP_HARNESS_SLUGS = new Set(["*", "all", "any", "global"]);

export function normalizeHarnessSlug(harness: string | null | undefined): string | null {
  const slug = typeof harness === "string" ? harness.trim().toLowerCase() : "";
  if (
    slug.length === 0 ||
    NON_APP_HARNESS_SLUGS.has(slug) ||
    HEX_TOKEN_HARNESS_PATTERN.test(slug) ||
    UUID_HARNESS_PATTERN.test(slug) ||
    !HARNESS_SLUG_PATTERN.test(slug)
  ) {
    return null;
  }
  return slug;
}

export function isDisplayableHarness(harness: string | null | undefined): harness is string {
  return normalizeHarnessSlug(harness) !== null;
}

export function normalizeHarnessFilter(harness: string | null | undefined): string {
  return harness === "all" ? "all" : normalizeHarnessSlug(harness) ?? "all";
}

export function resolveDecisionV2Title(item: GuardApprovalRequest): string | null {
  const title = item.decision_v2_json?.user_title;
  return title !== undefined && title.trim().length > 0 ? title : null;
}

export function resolveDecisionV2Detail(item: GuardApprovalRequest): string | null {
  const detail = item.decision_v2_json?.dashboard_primary_detail;
  return detail !== undefined && detail.trim().length > 0 ? detail : null;
}

export type PrimaryReviewAction = {
  label: string;
  text: string;
  detail: string | null;
};

const DUPLICATE_REVIEW_SUBSTRING_MIN_LENGTH = 24;
const DUPLICATE_REVIEW_PREFIX_MIN_LENGTH = 80;
const DUPLICATE_REVIEW_SAFETY_CONTEXT_PATTERNS = [
  /\b(api[-_\s]?keys?|credentials?|secrets?|tokens?|passwords?|sensitive|malicious|destructive|unauthorized)\b/i,
  /\b(expose|exposes|exposed|leak|leaks|leaked|exfiltrate|exfiltrates|exfiltration)\b/i,
  /\b(may|could|can|would|will)\s+(expose|leak|send|upload|exfiltrate|delete|remove|modify|overwrite|execute|run)\b/i,
  /\bruns?\s+as\s+(root|admin|administrator)\b/i,
  /\bsends?\s+(data|contents|files?|credentials?|secrets?|tokens?)\s+to\b/i,
  /\b(third[-\s]?party|remote|external)\s+host\b/i,
];

export function buildPrimaryReviewAction(item: GuardApprovalRequest): PrimaryReviewAction {
  return {
    label: resolveTerminalLabel(item),
    text: resolvePrimaryReviewText(item),
    detail: resolveDecisionV2Detail(item) ?? item.trigger_summary ?? null,
  };
}

export function resolveSecondaryRiskSummary(item: GuardApprovalRequest): string | null {
  const summary = item.risk_summary?.trim();
  if (!summary) {
    return null;
  }
  if (duplicatesStoppedActionText(item, summary)) {
    return null;
  }
  return summary;
}

export function hasReviewEvidence(item: GuardApprovalRequest): boolean {
  return (
    (item.risk_signals?.length ?? 0) > 0 ||
    hasRenderableDecisionEvidence(item) ||
    resolveSecondaryRiskSummary(item) !== null ||
    !!item.why_now ||
    whyPaused(item) !== null
  );
}

function hasRenderableDecisionEvidence(item: GuardApprovalRequest): boolean {
  const signals = item.decision_v2_json?.signals ?? [];
  return (
    signals.some((signal) => signal.category === "skill" || signal.category === "mcp") ||
    deriveDataFlowEvidence(item) !== null ||
    deriveSkillRiskSignals(item).length > 0 ||
    deriveSupplyChainRiskSignals(item).length > 0 ||
    deriveEncodedLayerSignals(item).length > 0 ||
    hasSupplyChainArtifactEvidence(item)
  );
}

function hasSupplyChainArtifactEvidence(item: GuardApprovalRequest): boolean {
  return (
    item.artifact_type === "supply_chain" ||
    item.artifact_type === "package_request" ||
    (typeof item.artifact_type === "string" && item.artifact_type.endsWith("_package"))
  );
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

export function primaryReviewActionToggleLabel(isVisible: boolean): string {
  return isVisible ? "Collapse" : "Expand";
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
  if (item.launch_target?.trim()) {
    return item.launch_target;
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

function resolvePrimaryReviewText(item: GuardApprovalRequest): string {
  const envelope = item.action_envelope_json;
  if (envelope) {
    const envelopeText = resolveActionEnvelopeDetailText(envelope, { mcpInputMaxLength: null });
    if (envelopeText !== null) {
      return envelopeText;
    }
  }
  return resolveStoppedCommandText(item);
}

function serializeMcpInput(payload: Record<string, unknown>, maxLength: number | null = null): string | null {
  const input = payload.arguments ?? payload.input ?? payload.params ?? null;
  if (input === null || input === undefined) {
    return null;
  }

  try {
    const serialized = typeof input === "string" ? input : JSON.stringify(input, null, 2);
    if (serialized === undefined || serialized.trim().length === 0 || serialized === "{}") {
      return null;
    }
    if (maxLength !== null && serialized.length > maxLength) {
      return `${serialized.slice(0, maxLength)}...`;
    }
    return serialized;
  } catch {
    return null;
  }
}

export function harnessDisplayName(harness: string): string {
  if (typeof harness !== "string") {
    return "Unknown app";
  }
  const normalized = normalizeHarnessSlug(harness);
  if (normalized === null) {
    switch (harness.trim().toLowerCase()) {
      case "*":
      case "all":
      case "any":
      case "global":
        return "All apps";
      default:
        return "Unknown app";
    }
  }

  switch (normalized) {
    case "claude-code":
      return "Claude Code";
    case "copilot":
      return "Copilot";
    case "codex":
      return "Codex";
    case "opencode":
      return "OpenCode";
    case "gemini":
      return "Gemini";
    case "cursor":
      return "Cursor";
    case "hermes":
      return "Hermes";
    case "openclaw":
      return "OpenClaw";
    case "kimi":
      return "Kimi";
    case "grok":
      return "Grok";
    default:
      return capitalizeHarness(normalized);
  }
}

export function displayArtifactName(item: GuardApprovalRequest): string {
  return item.artifact_name || item.artifact_id || "this action";
}

export function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1).replace(/\.0$/, "")}K`;
  return String(n);
}

export function formatRelativeTime(timestamp: string): string {
  try {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins < 1) return "just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    if (diffDays === 1) {
      return `Yesterday at ${date.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}`;
    }
    if (diffDays < 7) {
      return `${date.toLocaleDateString([], { weekday: "long" })} at ${date.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}`;
    }
    return `${date.toLocaleDateString([], { month: "short", day: "numeric" })} at ${date.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}`;
  } catch {
    return timestamp;
  }
}

export function resolveFileReadPath(item: GuardApprovalRequest): string | null {
  const actionType = item.action_envelope_json?.action_type;
  const isFileRead =
    actionType === "file_read" ||
    actionType === "file_write" ||
    item.artifact_type === "file_read_request";
  if (!isFileRead) return null;
  const paths = item.action_envelope_json?.target_paths ?? [];
  if (paths.length > 0) return paths[0];
  return item.launch_target ?? null;
}

export function buildApprovalSharePath(item: GuardApprovalRequest): string | null {
  const requestId = item.request_id?.trim();
  if (requestId) {
    return `/requests/${requestId}`;
  }
  const stored = item.approval_url?.trim();
  if (!stored) {
    return null;
  }
  try {
    const parsed = new URL(stored, "http://guard.local");
    parsed.pathname = parsed.pathname.replace("/approvals/", "/requests/");
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return stored.replace("/approvals/", "/requests/");
  }
}

export function resolveApprovalShareUrl(item: GuardApprovalRequest): string | null {
  const requestId = item.request_id?.trim();
  const stored = item.approval_url?.trim();
  let absolute: string | null = null;
  if (stored) {
    absolute = stored.replace("/approvals/", "/requests/");
    if (requestId) {
      absolute = absolute.replace(/\/(?:approvals|requests)\/[^/?#]+/, `/requests/${requestId}`);
    }
  } else if (requestId && typeof window !== "undefined") {
    absolute = `${window.location.origin}/requests/${requestId}`;
  }
  if (absolute === null) {
    const path = buildApprovalSharePath(item);
    if (path === null) {
      return null;
    }
    if (typeof window === "undefined") {
      return path;
    }
    absolute = `${window.location.origin}${path}`;
  }
  if (typeof window === "undefined") {
    return absolute;
  }
  return guardAwareHref(absolute);
}

export function resolveTerminalLabel(item: GuardApprovalRequest): string {
  const actionType = item.action_envelope_json?.action_type;
  if (actionType === "shell_command") return "Command";
  if (actionType === "prompt") return "Prompt excerpt";
  if (actionType === "file_read" || actionType === "file_write") return "File path";
  if (actionType === "mcp_tool") return "MCP server / tool";
  if (actionType === "package_script") return "Package";
  if (actionType === "network_request") return "Network destination";

  if (item.artifact_type === "file_read_request") return "File path";
  if (item.artifact_type === "prompt_request") return "Prompt excerpt";
  if (item.artifact_type === "tool_action_request") return "Tool action";

  return "Command";
}

export type CodexResumeUx = {
  headline: string;
  body: string | null;
  showRetry: boolean;
};

export function isCodexHarness(harness: string): boolean {
  return normalizeHarnessSlug(harness) === "codex";
}

export type BulkApproveRiskLine = {
  requestId: string;
  title: string;
  path: string | null;
  harnessLabel: string;
  duplicateCount: number;
  summary: string;
  categoryLabel: string;
};

export function summarizeBulkApproveSelection(
  groups: Array<{ primary: GuardApprovalRequest; duplicateCount: number }>
): BulkApproveRiskLine[] {
  return groups.map((group) => {
    const category = resolveQueueCategory(group.primary);
    return {
      requestId: group.primary.request_id,
      title: resolveDecisionV2Title(group.primary) ?? displayArtifactName(group.primary),
      path: resolveFileReadPath(group.primary),
      harnessLabel: harnessDisplayName(group.primary.harness),
      duplicateCount: group.duplicateCount,
      summary: buildQueueSummary(group.primary),
      categoryLabel: category.shortLabel,
    };
  });
}

export function buildBulkApproveConsequenceCopy(actionCount: number): string {
  if (actionCount <= 0) {
    return "No actions are selected.";
  }
  if (actionCount === 1) {
    return "Guard will approve this action once. It applies to the current retry only and does not remember future runs.";
  }
  return `Guard will approve ${actionCount} actions once. Mass approval skips opening each request, so an unexpected action is harder to catch. Each decision applies to its retry only and is not remembered.`;
}

export function buildCodexResumeUx(resume: GuardCodexResumeResult): CodexResumeUx {
  if (resume.status === "pending" || resume.status === "in_progress") {
    return {
      headline: "Codex is continuing.",
      body: resume.message ?? "HOL Guard saved your choice and the original Codex action is still waiting for it.",
      showRetry: false
    };
  }
  if (resume.status === "sent" || resume.status === "already_sent") {
    if (resume.strategy === "codex-headless-exec" || resume.reason === "headless_resume_started") {
      return {
        headline: "Codex resumed in background.",
        body:
          resume.message ??
          "HOL Guard started a background Codex resume. This open Codex App chat may not visibly continue until Codex remote control is enabled.",
        showRetry: false
      };
    }
    return {
      headline: "Codex chat notified.",
      body: resume.message ?? "HOL Guard sent Codex a continuation message in the original chat.",
      showRetry: false
    };
  }
  if (resume.status === "failed") {
    return {
      headline: "Guard could not message the Codex chat.",
      body: resume.message ?? resume.last_error ?? resume.reason ?? "Continuation message failed.",
      showRetry: true
    };
  }
  return {
    headline: "Guard could not locate the Codex chat.",
    body: resume.message ?? "Return to Codex and retry the same request.",
    showRetry: false
  };
}
