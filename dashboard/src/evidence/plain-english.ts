import type { GuardReceipt, GuardApprovalRequest } from "../guard-types";
import { harnessDisplayName } from "../approval-center-utils";
import { detectCategory, type ReceiptCategory } from "./categories";

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

export function plainEnglishDescription(receipt: GuardReceipt): string {
  const category = detectCategory(receipt);
  const app = harnessDisplayName(receipt.harness);
  const name = humanFileName(receipt.artifact_name ?? receipt.artifact_id);

  if (receipt.policy_decision === "allow") {
    return allowedDescription(category, app, name);
  }
  return blockedDescription(category, app, name);
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
  } as GuardReceipt);
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
  } as GuardReceipt);

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
