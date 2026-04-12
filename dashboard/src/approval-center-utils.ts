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
      return "new tool";
    }
    if (value === "args") {
      return "startup arguments";
    }
    if (value === "command") {
      return "launch command";
    }
    if (value === "headers") {
      return "network headers";
    }
    return value.replaceAll("_", " ");
  });
  return humanizeList(translated);
}

export function buildPauseLine(item: GuardApprovalRequest): string {
  const typeLabel = artifactTypeLabel(item.artifact_type);
  if (item.policy_action === "block") {
    return `${capitalizeHarness(item.harness)} stopped before it launched this ${typeLabel.toLowerCase()} because a saved block rule already covers it.`;
  }
  if (item.changed_fields.length === 1 && item.changed_fields[0] === "first_seen") {
    return `${capitalizeHarness(item.harness)} found this ${typeLabel.toLowerCase()} for the first time in this project folder, so Guard paused it before launch.`;
  }
  return `${capitalizeHarness(item.harness)} paused this ${typeLabel.toLowerCase()} because ${humanizeChangedFields(item.changed_fields)} changed since the last saved decision.`;
}

export function buildRecommendation(item: GuardApprovalRequest): string {
  if (item.changed_fields.length === 1 && item.changed_fields[0] === "first_seen") {
    return "This tool has not been approved in this workspace before. Start with the exact version unless you are certain you want a broader rule.";
  }
  if (item.policy_action === "block") {
    return "Keep it blocked until you understand why this tool changed.";
  }
  return "Approve the smallest scope that gets you moving again. Broader trust should be a deliberate second step.";
}

export function buildQueueSummary(item: GuardApprovalRequest): string {
  const typeLabel = artifactTypeLabel(item.artifact_type);
  if (item.policy_action === "block") {
    return `Saved block rule is still active for this ${typeLabel.toLowerCase()}`;
  }
  if (item.changed_fields.length === 1 && item.changed_fields[0] === "first_seen") {
    return `First time Guard has seen this ${typeLabel.toLowerCase()} in this project folder`;
  }
  return `${humanizeChangedFields(item.changed_fields)} changed since the last saved decision`;
}

export function buildMemorySummary(
  item: GuardApprovalRequest,
  receipt: GuardReceipt | null
): string {
  if (receipt === null) {
    return `Guard has not saved an earlier approval for ${item.artifact_name}.`;
  }
  return `The last saved decision for ${item.artifact_name} was ${receipt.policy_decision}.`;
}

export function scopeLabel(scope: string): string {
  switch (scope) {
    case "artifact":
      return "This exact version";
    case "workspace":
      return "This project folder";
    case "publisher":
      return "This publisher in this harness";
    case "harness":
      return "This harness";
    case "global":
      return "All projects on this machine";
    default:
      return scope;
  }
}

export function policyActionLabel(action: string): string {
  switch (action) {
    case "require-reapproval":
      return "Review again";
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
    default:
      return artifactType.replaceAll("_", " ");
  }
}

export function buildTriggerHeading(item: GuardApprovalRequest): string {
  return `${capitalizeHarness(item.harness)} tried to start this ${artifactTypeLabel(item.artifact_type).toLowerCase()}`;
}

export function buildTriggerSummary(item: GuardApprovalRequest): string {
  const location = shortConfigPath(item.config_path);
  const target = item.launch_target ?? "the recorded launch target";
  return `Guard read the ${artifactTypeLabel(item.artifact_type).toLowerCase()} entry ${item.artifact_name} from ${location} and was about to run ${target}.`;
}

export function buildStoppedReason(item: GuardApprovalRequest, receipt: GuardReceipt | null): string {
  const typeLabel = artifactTypeLabel(item.artifact_type).toLowerCase();
  if (item.policy_action === "block") {
    const changed = item.changed_fields.length > 0 ? ` ${humanizeChangedFields(item.changed_fields)} also changed.` : "";
    return `A saved block rule already covers this ${typeLabel}, so Guard kept the launch paused.${changed}`;
  }
  if (item.changed_fields.length === 1 && item.changed_fields[0] === "first_seen") {
    return `Guard has never seen this ${typeLabel} in this project folder before, so there is no saved approval for it yet.`;
  }
  if (receipt !== null) {
    return `Guard found an earlier ${receipt.policy_decision} receipt, but the ${humanizeChangedFields(item.changed_fields)} no longer matches what you approved before.`;
  }
  return `This ${typeLabel} changed after the last known state, so Guard needs a new decision before it can run.`;
}

export function buildResumeInstruction(item: GuardApprovalRequest): string {
  return `Pick the narrowest rule that matches what you meant to run, save it, then rerun the same ${capitalizeHarness(item.harness)} command.`;
}

export function shortConfigPath(path: string): string {
  const marker = "/.codex/";
  const index = path.lastIndexOf(marker);
  if (index >= 0) {
    return `…${path.slice(index)}`;
  }
  return path;
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
