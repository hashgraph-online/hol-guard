import type {
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardReceipt
} from "./guard-types";

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
    return "If this is what you expected, approve the exact action. Use broader trust only when you deliberately want Guard to ask less often.";
  }
  if (item.policy_action === "block") {
    return "Keep it blocked unless you are sure this action is safe and expected.";
  }
  return "Approve the smallest choice that matches what you meant to do. Broader trust should be a deliberate second step.";
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
      return "This exact action";
    case "workspace":
      return "This project folder";
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
    return `…${sanitizedPath.slice(index)}`;
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

export function harnessDisplayName(harness: string): string {
  switch (harness) {
    case "claude-code":
      return "Claude Code";
    case "copilot":
      return "Copilot";
    case "codex":
      return "Codex";
    case "opencode":
      return "OpenCode";
    default:
      return capitalizeHarness(harness);
  }
}
