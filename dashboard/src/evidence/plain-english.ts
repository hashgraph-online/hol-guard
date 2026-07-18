import type {
  GuardReceipt,
  GuardApprovalRequest,
  GuardActionEnvelope,
} from "../guard-types";
import { isRiskSignalEvidence } from "../guard-types";
import { harnessDisplayName, resolveActionEnvelopeDetailText } from "../approval-center-utils";
import { detectCategory, type ReceiptCategory } from "./categories";
import {
  guardActionActivityCopy,
  guardActionPresentation,
  normalizeGuardAction,
} from "../guard-action";

function getArtifactType(receipt: GuardReceipt): string {
  return (receipt.artifact_type ?? "").toLowerCase();
}

function getEnvelope(receipt: GuardReceipt): GuardActionEnvelope | null {
  return receipt.action_envelope_json ?? null;
}

export function humanFileName(artifactName: string | null | undefined): string {
  if (!artifactName) return "a file";
  const name = artifactName.split("/").pop() ?? artifactName;
  if (name === ".env") return "your secrets file";
  if (name === ".npmrc") return "your npm config";
  if (name.endsWith(".json")) return "a settings file";
  if (name.endsWith(".js") || name.endsWith(".ts")) return "a script file";
  if (name.endsWith(".sh")) return "a shell script";
  if (name.endsWith(".py")) return "a Python script";
  return name;
}

export function resolveActionType(receipt: GuardReceipt): string {
  const envelope = getEnvelope(receipt);
  const actionType = (envelope?.action_type ?? "").toLowerCase();
  const artifactType = getArtifactType(receipt);
  const artifactName = (receipt.artifact_name ?? "").toLowerCase();

  if (actionType === "shell_command" || artifactType.includes("shell") || artifactType.includes("command")) return "Shell command";
  if (
    artifactName === "bash" &&
    receipt.provenance_summary?.trim().toLowerCase().startsWith("hook event for")
  ) return "Shell command";
  if (actionType === "prompt" || artifactType === "prompt_request") return "Prompt";
  if (actionType === "file_read" || artifactType === "file_read_request" || artifactType.includes("file_read")) return "File read";
  if (actionType === "file_write" || artifactType.includes("file_write") || artifactType.includes("write")) return "File write";
  if (actionType === "mcp_tool" || artifactType === "tool_action_request" || artifactType.includes("mcp") || artifactType.includes("tool")) return "Tool call";
  if (actionType === "package_script" || artifactType.includes("package") || artifactType.includes("supply_chain")) return "Package";
  if (actionType === "network_request" || artifactType.includes("network")) return "Network request";
  if (actionType === "config_change" || artifactType.includes("config")) return "Config change";
  if (actionType === "browser_action" || artifactType.includes("browser")) return "Browser action";
  if (actionType === "harness_start") return "Harness start";
  if (artifactType.includes("plugin")) return "Plugin";
  return "Action";
}

function looksLikeId(text: string): boolean {
  if (/^\w+:[a-f0-9]{8,}$/i.test(text)) return true;
  if (/^[a-f0-9]{8,}$/i.test(text)) return true;
  return false;
}

export function resolveActionTitle(receipt: GuardReceipt): string {
  const envelope = getEnvelope(receipt);
  const type = resolveActionType(receipt);

  // Shell command: show the actual command if available
  const command = envelope?.command?.trim();
  if (type === "Shell command" && command && command.length > 0) {
    return truncate(command, 80);
  }

  // File access: show the actual path
  const targetPath = envelope?.target_paths?.[0]?.trim();
  if ((type === "File read" || type === "File write") && targetPath && targetPath.length > 0) {
    return truncate(targetPath, 80);
  }

  // Prompt: show full text (prefer prompt_text, fall back to excerpt)
  const promptText = (envelope?.prompt_text ?? envelope?.prompt_excerpt)?.trim();
  if (type === "Prompt" && promptText && promptText.length > 0) {
    return truncate(promptText, 80);
  }

  // Network: show host
  const host = envelope?.network_hosts?.[0]?.trim();
  if (type === "Network request" && host && host.length > 0) {
    return host;
  }

  // MCP tool: show tool name
  const mcpTool = envelope?.mcp_tool?.trim() ?? envelope?.tool_name?.trim();
  if (type === "Tool call" && mcpTool && mcpTool.length > 0) {
    return mcpTool;
  }

  // Package: show package name
  const packageName = envelope?.package_name?.trim();
  if (type === "Package" && packageName && packageName.length > 0) {
    return packageName;
  }

  // Scanner evidence title is usually more descriptive than raw artifact_name
  const signals = (receipt.scanner_evidence ?? []).filter(isRiskSignalEvidence);
  if (signals.length > 0 && signals[0]?.title) {
    return signals[0].title;
  }

  // provenance_summary for hook events is more descriptive than a generic tool name like "Bash"
  const provenance = receipt.provenance_summary?.trim();
  const artifactName = receipt.artifact_name?.trim();
  if (
    provenance &&
    provenance.toLowerCase().startsWith("hook event for") &&
    artifactName &&
    provenance.toLowerCase().endsWith(artifactName.toLowerCase())
  ) {
    return provenance;
  }

  // artifact_name when it is human-readable
  if (artifactName && artifactName.length > 0 && !looksLikeId(artifactName)) {
    return artifactName;
  }

  // capabilities_summary
  const caps = receipt.capabilities_summary?.trim();
  if (caps && caps.length > 0 && !caps.startsWith("Guard local daemon completed")) {
    return caps;
  }

  // provenance_summary when it is descriptive
  if (provenance && provenance.length > 0 && !provenance.toLowerCase().startsWith("hook event for")) {
    return provenance;
  }

  const name = humanFileName(receipt.artifact_name ?? receipt.artifact_id);
  if (name && name.toLowerCase() !== type.toLowerCase()) {
    return `${type}: ${name}`;
  }
  return type;
}

export function resolveActionSubtitle(receipt: GuardReceipt): string | null {
  const signals = (receipt.scanner_evidence ?? []).filter(isRiskSignalEvidence);
  const firstSignal = signals[0];

  // Highest priority: scanner plain_reason explains the actual risk
  if (firstSignal?.plain_reason) {
    return firstSignal.plain_reason;
  }

  // Fallback to a human-readable context string built from envelope + metadata
  const envelope = getEnvelope(receipt);
  const type = resolveActionType(receipt);
  const parts: string[] = [];

  if (type === "Shell command" && envelope?.command) {
    // Already shown as title; subtitle can be empty or show tool_name
    if (envelope.tool_name) parts.push(`via ${envelope.tool_name}`);
  }

  if ((type === "File read" || type === "File write") && envelope?.target_paths && envelope.target_paths.length > 1) {
    parts.push(`${envelope.target_paths.length} paths`);
  }

  if (type === "Network request" && envelope?.network_hosts && envelope.network_hosts.length > 1) {
    parts.push(`${envelope.network_hosts.length} hosts`);
  }

  const caps = receipt.capabilities_summary?.trim();
  const provenance = receipt.provenance_summary?.trim();
  const isCapsUseful = caps && caps !== "hook artifact · codex" && !caps.toLowerCase().startsWith("guard local daemon completed");
  const isProvenanceUseful = provenance && provenance !== "hook artifact · codex" && !provenance.toLowerCase().startsWith("guard local daemon completed");

  if (isCapsUseful) {
    parts.push(caps);
  } else if (isProvenanceUseful && provenance?.toLowerCase() !== caps?.toLowerCase() && provenance !== resolveActionTitle(receipt)) {
    parts.push(provenance);
  }

  if (parts.length > 0) {
    return parts.join(" · ");
  }

  return null;
}

export function resolveActionDetail(receipt: GuardReceipt): string | null {
  const envelope = getEnvelope(receipt);
  if (!envelope) return null;
  return resolveActionEnvelopeDetailText(envelope, { mcpInputMaxLength: null });
}

function formatSubtitle(subtitle: string): string {
  if (subtitle.endsWith(".") || subtitle.endsWith("?") || subtitle.endsWith("!")) return subtitle + " ";
  return subtitle + ". ";
}

function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return text.slice(0, max - 1) + "…";
}

export function plainEnglishDescription(receipt: GuardReceipt): string {
  const app = harnessDisplayName(receipt.harness);
  const type = resolveActionType(receipt);
  const title = resolveActionTitle(receipt);
  const subtitle = resolveActionSubtitle(receipt);

  const action = guardActionPresentation(receipt.policy_decision);
  if (action.disposition === "allowed") {
    const outcome = action.action === "warn" ? "allowed it with a warning" : "allowed it";
    if (receipt.user_override !== null) {
      return subtitle
        ? `${app} ${pastTenseVerb(type)} ${title}. ${formatSubtitle(subtitle)} You reviewed and ${outcome}.`
        : `${app} ${pastTenseVerb(type)} ${title}. You reviewed and ${outcome}.`;
    }
    const automaticOutcome = action.action === "warn"
      ? "Guard allowed it automatically with a warning."
      : "Guard allowed it automatically.";
    return subtitle
      ? `${app} ${pastTenseVerb(type)} ${title}. ${formatSubtitle(subtitle)} ${automaticOutcome}`
      : `${app} ${pastTenseVerb(type)} ${title}. ${automaticOutcome}`;
  }

  const enforcementCopy = `${guardActionActivityCopy(action.action, "Guard", "it")}.`;
  return subtitle
    ? `${app} tried to ${infinitiveVerb(type)} ${title}. ${enforcementCopy} ${formatSubtitle(subtitle)}`
    : `${app} tried to ${infinitiveVerb(type)} ${title}. ${enforcementCopy}`;
}

function pastTenseVerb(type: string): string {
  switch (type) {
    case "Shell command": return "ran";
    case "File read": return "read";
    case "File write": return "wrote to";
    case "Tool call": return "used";
    case "Package": return "installed";
    case "Network request": return "made";
    case "Prompt": return "submitted";
    case "Plugin": return "loaded";
    case "Config change": return "changed";
    case "Browser action": return "performed";
    case "Harness start": return "started";
    default: return "ran";
  }
}

function infinitiveVerb(type: string): string {
  switch (type) {
    case "Shell command": return "run";
    case "File read": return "read";
    case "File write": return "write to";
    case "Tool call": return "use";
    case "Package": return "install";
    case "Network request": return "make";
    case "Prompt": return "submit";
    case "Plugin": return "load";
    case "Config change": return "change";
    case "Browser action": return "perform";
    case "Harness start": return "start";
    default: return "run";
  }
}

function allowedDescription(category: ReceiptCategory, app: string, name: string): string {
  switch (category) {
    case "secret":
      return `${app} read ${name}. You allowed this before.`;
    case "network":
      return `${app} connected to a website.`;
    case "destructive":
      return `${app} ran a command that could change files.`;
    case "hidden":
      return `${app} ran hidden code. You trusted this source.`;
    case "file-write":
      return `${app} wrote to ${name}.`;
    case "tool-call":
      return `${app} used a tool.`;
    default:
      return `${app} did something with ${name}.`;
  }
}

function blockedDescription(category: ReceiptCategory, app: string, name: string): string {
  switch (category) {
    case "secret":
      return `${app} tried to read ${name}. Guard stopped it.`;
    case "network":
      return `${app} tried to connect somewhere new. Guard stopped it.`;
    case "destructive":
      return `${app} tried to run a destructive command. Guard stopped it.`;
    case "hidden":
      return `${app} tried to run hidden code. Guard stopped it.`;
    case "file-write":
      return `${app} tried to write to ${name}. Guard stopped it.`;
    case "tool-call":
      return `${app} tried to use a tool. Guard stopped it.`;
    default:
      return `${app} tried to do something with ${name}. Guard stopped it.`;
  }
}

export function plainEnglishRequestTitle(request: GuardApprovalRequest): string {
  const category = detectCategory({
    ...request,
    timestamp: request.created_at,
    policy_decision: normalizeGuardAction(request.policy_action),
    receipt_id: request.request_id,
  } as unknown as GuardReceipt);
  const app = harnessDisplayName(request.harness);
  const name = humanFileName(request.artifact_name ?? request.artifact_id);

  switch (category) {
    case "secret":
      return `${app} wants to read ${name}`;
    case "network":
      return `${app} wants to connect to a website`;
    case "destructive":
      return `${app} wants to run a destructive command`;
    case "hidden":
      return `${app} wants to run hidden code`;
    case "file-write":
      return `${app} wants to write to ${name}`;
    case "tool-call":
      return `${app} wants to use a tool`;
    default:
      return `${app} wants to do something with ${name}`;
  }
}

export function whyPaused(request: GuardApprovalRequest): string {
  const category = detectCategory({
    ...request,
    timestamp: request.created_at,
    policy_decision: normalizeGuardAction(request.policy_action),
    receipt_id: request.request_id,
  } as unknown as GuardReceipt);

  switch (category) {
    case "secret":
      return "This file may contain passwords or keys. Guard stops this by default.";
    case "network":
      return "This connects to an outside website. Guard stops new destinations by default.";
    case "destructive":
      return "This command could delete or overwrite your files. Guard stops this by default.";
    case "hidden":
      return "This code is hidden or encoded. Guard stops this by default.";
    case "file-write":
      return "This writes to a file on your computer. Guard stops this by default.";
    case "tool-call":
      return "This uses an outside tool. Guard stops new tools by default.";
    default:
      return "Guard paused this so you can review it first.";
  }
}
