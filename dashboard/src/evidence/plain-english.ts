import type { GuardReceipt, GuardApprovalRequest } from "../guard-types";
import { harnessDisplayName } from "../approval-center-utils";
import { detectCategory, type ReceiptCategory } from "./categories";

function getArtifactType(receipt: GuardReceipt): string {
  return (receipt.artifact_type ?? "").toLowerCase();
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
  const artifactType = getArtifactType(receipt);
  const actionType = ((receipt.action_envelope_json as { action_type?: string } | null | undefined)?.action_type ?? "").toLowerCase();

  if (actionType === "shell_command" || artifactType.includes("shell") || artifactType.includes("command")) return "Shell command";
  if (actionType === "prompt" || artifactType === "prompt_request") return "Prompt";
  if (actionType === "file_read" || artifactType === "file_read_request" || artifactType.includes("file_read")) return "File read";
  if (actionType === "file_write" || artifactType.includes("file_write") || artifactType.includes("write")) return "File write";
  if (actionType === "mcp_tool" || artifactType === "tool_action_request" || artifactType.includes("mcp") || artifactType.includes("tool")) return "Tool call";
  if (actionType === "package_script" || artifactType.includes("package") || artifactType.includes("supply_chain")) return "Package";
  if (actionType === "network_request" || artifactType.includes("network")) return "Network request";
  if (artifactType.includes("plugin")) return "Plugin";
  return "Action";
}

export function resolveActionTitle(receipt: GuardReceipt): string {
  const artifactName = receipt.artifact_name?.trim();
  if (artifactName && artifactName.length > 0 && !looksLikeId(artifactName)) {
    return artifactName;
  }

  const caps = receipt.capabilities_summary?.trim();
  if (caps && caps.length > 0 && !caps.startsWith("Guard local daemon completed")) {
    return caps;
  }

  const signals = receipt.scanner_evidence ?? [];
  if (signals.length > 0 && signals[0]?.title) {
    return signals[0].title;
  }

  const provenance = receipt.provenance_summary?.trim();
  if (provenance && provenance.length > 0 && !provenance.startsWith("hook event for")) {
    return provenance;
  }

  const name = humanFileName(receipt.artifact_name ?? receipt.artifact_id);
  const type = resolveActionType(receipt);
  if (name && name !== type.toLowerCase()) {
    return `${type}: ${name}`;
  }
  return type;
}

function looksLikeId(text: string): boolean {
  if (text.includes(":")) return true;
  if (/^[a-f0-9]{8,}$/i.test(text)) return true;
  return false;
}

export function plainEnglishDescription(receipt: GuardReceipt): string {
  const app = harnessDisplayName(receipt.harness);
  const type = resolveActionType(receipt);
  const title = resolveActionTitle(receipt);
  const signals = receipt.scanner_evidence ?? [];
  const firstSignal = signals[0];

  if (receipt.policy_decision === "allow") {
    if (firstSignal?.plain_reason) {
      return `${app} ${pastTenseVerb(type)} ${title}. Guard reviewed it and allowed it.`;
    }
    return `${app} ${pastTenseVerb(type)} ${title}. Guard allowed it.`;
  }

  if (firstSignal?.plain_reason) {
    return `${app} tried to ${infinitiveVerb(type)} ${title}. Guard stopped it: ${firstSignal.plain_reason}`;
  }
  return `${app} tried to ${infinitiveVerb(type)} ${title}. Guard stopped it.`;
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
    policy_decision: request.policy_action === "block" ? "block" : "allow",
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
    policy_decision: request.policy_action === "block" ? "block" : "allow",
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
