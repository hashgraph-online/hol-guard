import { approvalProofRecentlySatisfied } from "../approval-proof-inline";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import type { LocalCliItem, LocalCliListResponse, LocalCliState } from "../local-cli-api";
import { customExtensionContinuityView } from "../managed-controls/custom-extension-continuity";
import { hasSuggestedRules } from "./custom-extension-profile";
import { mcpToolCanReceiveDirectAllow } from "./mcp-catalog-state";

export function customExtensionActionLabel(item: LocalCliItem): string | null {
  if (item.seeded === true) return `Set up ${item.display_name ?? item.name}`;
  if (item.state !== "unset" || item.surface !== "cli" || !item.suggestable) return null;
  return hasSuggestedRules(item) ? "Review suggested rules" : "Review and add";
}

export const SUGGESTED_RULES_NOTICE =
  "Suggested rules are pre-selected for commands you have not set yet. Nothing changes until you review and confirm.";

export function randomToken(): string {
  return crypto.randomUUID().replaceAll("-", "");
}

export function customExtensionRowDescription(item: LocalCliItem, catalogTitle: string | null): string {
  if (item.seeded === true) return `${item.display_name ?? item.name} is not set up yet. Set it up to review its commands.`;
  if (catalogTitle) return [item.source_label, catalogTitle].filter(Boolean).join(" · ");
  if (item.source_label) return `${item.example_label} · ${item.source_label}`;
  return item.example_label;
}

export function nativePublicationMessage(
  publication: LocalCliListResponse["native_publication"],
  permissionScope?: LocalCliItem["permission_scope"],
): string {
  if (permissionScope === "configured-connection") {
    return publication?.state === "failed"
      ? "Your choices are stored, but policy publication failed. Guard has not confirmed enforcement for this connection."
      : "Your choices are stored for this configured connection. Native host-hook calls use separately observed tool permissions until Guard verifies a binding to this connection.";
  }
  if (publication?.state === "acknowledged") {
    return `Native policy acknowledged saved revision ${publication.revision}. Live calls still check host namespace and tool authority.`;
  }
  if (publication?.state === "pending") {
    return "Your choices are stored. Waiting for the native runtime to acknowledge this revision before showing them as enforced.";
  }
  if (publication?.state === "failed") {
    return "Your choices are stored, but native publication failed. Enforcement readiness is not confirmed.";
  }
  return "Your choices are stored. Native enforcement readiness has not been confirmed.";
}

export function mcpPermissionStatusLabel(
  publication: LocalCliListResponse["native_publication"],
  permissionScope?: LocalCliItem["permission_scope"],
): string {
  if (permissionScope === "configured-connection") return "Connection choices stored · host binding unverified";
  if (publication?.state === "acknowledged") return "Tool permissions saved and acknowledged";
  if (publication?.state === "pending") return "Waiting for policy confirmation";
  return "Policy confirmation unavailable";
}

export function detailPolicyCopy(surface: LocalCliItem["surface"]): string {
  if (surface === "mcp") {
    return "Ask requires approval. Allow and Deny apply within the scope shown in Connection details. Allow does not override stricter Guard policy, so protected MCP actions may still need fresh approval. Execution wrappers require review of their underlying actions.";
  }
  if (surface === "package-scripts") {
    return "Recommended keeps Guard's usual review. Allow or block applies to that npm, pnpm, yarn, or bun script in this project. Nested names such as guard:audit stay grouped.";
  }
  return "Recommended keeps Guard's usual review. Allow or block applies to that command from this file. Pipes, wrappers, and destructive commands stay under Guard's usual rules.";
}

export function detailCatalogHeading(surface: LocalCliItem["surface"]): string {
  if (surface === "mcp") return "MCP tools";
  if (surface === "package-scripts") return "Package scripts";
  return "Command patterns";
}

export function detailCatalogHelper(surface: LocalCliItem["surface"]): string {
  if (surface === "mcp") {
    return "Choose Allow, Ask, or Deny for each tool. Policy follows Guard's existing rules.";
  }
  if (surface === "package-scripts") {
    return "Same settings as built-in tools. Nested scripts stay indented under their prefix.";
  }
  return "Same settings as built-in tools. Recommended is the safe default.";
}

export function bulkPolicyCopy(surface: LocalCliItem["surface"]): { groupLabel: string; mixedCopy: string } {
  if (surface === "mcp") {
    return {
      groupLabel: "Listed tools with direct permissions",
      mixedCopy: "Custom mix. Use policy, allow, ask, or deny the listed tools with direct permissions.",
    };
  }
  if (surface === "package-scripts") {
    return {
      groupLabel: "All scripts protection setting",
      mixedCopy: "Custom mix. Pick Recommended, Allow all, or Block all to reset every script.",
    };
  }
  return {
    groupLabel: "All commands protection setting",
    mixedCopy: "Custom mix. Pick Recommended, Allow all, or Block all to reset every command.",
  };
}

export function reviewTitle(name: string, state: LocalCliState): string {
  if (state === "allowed") return `Save ${name} command settings`;
  if (state === "blocked") return `Block ${name}`;
  return `Remove ${name}`;
}

export function reviewModalDetail(gate: GuardApprovalGatePublicConfig | null): string {
  if (approvalProofRecentlySatisfied(gate)) {
    return "Recently confirmed with your authenticator. A new code is not needed yet.";
  }
  if (gate?.totp_enabled === true) {
    return "Enter the current authenticator code to save these settings on this device.";
  }
  return "This custom Extension remains local to this device until portable continuity is enabled.";
}

function customExtensionUnits(surface: LocalCliItem["surface"]): { unit: string; units: string; source: string } {
  if (surface === "mcp") return { unit: "tool", units: "tools", source: "this server" };
  if (surface === "package-scripts") return { unit: "script", units: "scripts", source: "this project" };
  return { unit: "command", units: "commands", source: "this file" };
}

export function customExtensionStateLabel(item: LocalCliItem): string {
  if (item.seeded === true) return "Not set up yet. Guard keeps its usual review until you add it.";
  if (item.state === "unset" && item.surface === "cli" && item.suggestable) {
    return hasSuggestedRules(item)
      ? "Guard detected this tool. Review suggested rules before adding it."
      : "Guard detected this tool. Review it before adding it.";
  }
  const { unit, units, source } = customExtensionUnits(item.surface);
  if (item.stale) {
    if (item.surface === "mcp") return "This connection changed. Review its permissions again.";
    return item.surface === "package-scripts"
      ? "package.json scripts changed. Review the extension again."
      : "This file changed. Review the extension again.";
  }
  if (item.state === "blocked") return `Every ${unit} from ${source} is blocked.`;
  if (item.state === "allowed") {
    if (item.surface === "mcp") {
      const tools = item.commands.filter((command) => command.command_id !== "other");
      if (tools.length === 0) return "No tools allowed yet. List the inventory to choose permissions.";
      const allowed = tools.filter((command) => command.state === "allow" && mcpToolCanReceiveDirectAllow(command)).length;
      const denied = tools.filter((command) => command.state === "block").length;
      const ask = tools.filter((command) => command.state === "review"
        || (!mcpToolCanReceiveDirectAllow(command) && command.state !== "block")).length;
      return `${allowed} allowed · ${ask} ask · ${denied} denied. New tools require review.`;
    }
    if (item.commands.length === 0) {
      return `Matching ${units} from ${source} are allowed.`;
    }
    const allowed = item.commands.filter((command) => command.state === "allow").length;
    if (allowed > 0) return `${allowed} ${allowed === 1 ? unit : units} allowed. The rest follow Recommended.`;
    return `${units.charAt(0).toUpperCase()}${units.slice(1)} follow Recommended until you allow or block them.`;
  }
  return item.surface === "mcp" ? "Detected · Permissions not configured. Inspect this connection." : item.example_label;
}

export function continuityCopy(item: LocalCliItem): { title: string; description: string } | null {
  const status = item.continuity?.status;
  if (status === "applied") {
    const view = customExtensionContinuityView("identity-matched");
    return { title: view.title, description: view.description };
  }
  if (status === "pending_observation") return customExtensionContinuityView("pending-observation");
  if (status === "changed_identity") return customExtensionContinuityView("changed-identity");
  if (status === "locally_overridden") return customExtensionContinuityView("locally-overridden");
  if (status === "removed") return customExtensionContinuityView("removed");
  if (status === "stale") return customExtensionContinuityView("stale");
  return null;
}
