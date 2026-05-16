import type {
  GuardActionEnvelope,
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardReceipt,
  RiskSignalV2
} from "./guard-types";

export const EMPTY_QUEUE_TITLE = "No blocked actions";
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
  if (envelope.action_type === "shell_command" && envelope.command !== null) {
    return envelope.command;
  }
  if (envelope.action_type === "prompt" && envelope.prompt_excerpt !== null) {
    return envelope.prompt_excerpt;
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
  if (item.policy_action === "block") {
    return `${harnessDisplayName(item.harness)} kept this blocked because you already saved a block decision for it.`;
  }
  if (item.changed_fields.length === 1 && item.changed_fields[0] === "first_seen") {
    return `${harnessDisplayName(item.harness)} has not run this exact action here before, so HOL Guard paused it for you to review.`;
  }
  return `${harnessDisplayName(item.harness)} wants to run something that changed since your last saved decision: ${humanizeChangedFields(item.changed_fields)}.`;
}

export function buildRecommendation(item: GuardApprovalRequest): string {
  if (item.changed_fields.length === 1 && item.changed_fields[0] === "first_seen") {
    return "If this is what you expected, approve this retry. Project approval remembers this same action here without trusting new sensitive actions.";
  }
  if (item.policy_action === "block") {
    return "Keep it blocked unless you are sure this action is safe and expected.";
  }
  return "Approve the smallest choice that matches what you meant to do. Different commands, prompts, paths, hosts, or tools should ask again.";
}

export function buildQueueSummary(item: GuardApprovalRequest): string {
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

export function scopeLabel(scope: string): string {
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
  switch (action) {
    case "require-reapproval":
      return "Needs review";
    case "block":
      return "Blocked";
    case "allow":
      return "Allowed";
    default:
      return action;
  }
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
  return `Choose the smallest approval that matches what you meant to do, save it, then retry in ${harnessDisplayName(item.harness)}.`;
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
const DUPLICATE_REVIEW_CONTEXT_MAX_LENGTH = 32;

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
    !!item.why_now
  );
}

function hasRenderableDecisionEvidence(item: GuardApprovalRequest): boolean {
  const signals = item.decision_v2_json?.signals ?? [];
  return (
    signals.some((signal) => signal.category === "skill" || signal.category === "mcp") ||
    deriveDataFlowEvidence(item) !== null ||
    deriveSkillRiskSignals(item).length > 0 ||
    deriveSupplyChainRiskSignals(item).length > 0 ||
    deriveEncodedLayerSignals(item).length > 0
  );
}

function duplicatesStoppedActionText(item: GuardApprovalRequest, value: string): boolean {
  const stoppedText = normalizeDuplicateReviewText(resolveStoppedCommandText(item));
  const candidateText = normalizeDuplicateReviewText(value);
  if (stoppedText.length === 0 || candidateText.length === 0) {
    return false;
  }
  if (stoppedText === candidateText) {
    return true;
  }
  if (
    stoppedText.length < DUPLICATE_REVIEW_SUBSTRING_MIN_LENGTH ||
    candidateText.length < DUPLICATE_REVIEW_SUBSTRING_MIN_LENGTH
  ) {
    return false;
  }
  if (!candidateText.includes(stoppedText)) {
    return false;
  }
  const remainingContext = candidateText.replace(stoppedText, "");
  return remainingContext.length <= DUPLICATE_REVIEW_CONTEXT_MAX_LENGTH;
}

function normalizeDuplicateReviewText(value: string): string {
  return value
    .toLowerCase()
    .replace(/[`"'\s:.,;!?()[\]{}_-]+/g, "")
    .trim();
}

export function primaryReviewActionToggleLabel(isVisible: boolean): string {
  return isVisible ? "Hide" : "Show";
}

export function resolveStoppedCommandText(item: GuardApprovalRequest): string {
  if (item.action_envelope_json) {
    const envelopeText = resolveEnvelopeDisplayText(item.action_envelope_json);
    if (envelopeText !== null) {
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
  const baseText = resolveStoppedCommandText(item);
  const envelope = item.action_envelope_json;
  if (envelope?.action_type !== "mcp_tool") {
    return baseText;
  }

  const inputSummary = serializeMcpInput(envelope.raw_payload_redacted);
  if (inputSummary === null) {
    return baseText;
  }
  return `${baseText}\n\nInput:\n${inputSummary}`;
}

function serializeMcpInput(payload: Record<string, unknown>): string | null {
  const input = payload.arguments ?? payload.input ?? payload.params ?? null;
  if (input === null || input === undefined) {
    return null;
  }

  try {
    const serialized = typeof input === "string" ? input : JSON.stringify(input, null, 2);
    if (serialized === undefined || serialized.trim().length === 0 || serialized === "{}") {
      return null;
    }
    return serialized.length > 4000 ? `${serialized.slice(0, 4000)}...` : serialized;
  } catch {
    return null;
  }
}

export function harnessDisplayName(harness: string): string {
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

  return "Stopped command";
}
