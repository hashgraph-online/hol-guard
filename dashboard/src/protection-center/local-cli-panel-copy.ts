import { approvalProofRecentlySatisfied } from "../approval-proof-inline";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { LocalCliApiError, type LocalCliItem, type LocalCliListResponse, type LocalCliState } from "../local-cli-api";
import { customExtensionContinuityView } from "../managed-controls/custom-extension-continuity";
import { hasSuggestedRules, type ConnectorGroupOutcome, type ConnectorSetupMatch } from "./custom-extension-profile";
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
    return "Recommended keeps Guard's usual review. Allow or Block applies to that script in this project. Scripts that share a prefix, such as build:web, sit together.";
  }
  return "Recommended keeps Guard's usual review. Allow or Block applies to that command from this file. Pipes, wrappers, and destructive commands stay under Guard's usual rules.";
}

export function commandBrowserCopy(surface: LocalCliItem["surface"] | undefined): {
  searchLabel: string;
  searchPlaceholder: string;
  catalogOrder: string;
  units: string;
  unit: (count: number) => string;
} {
  if (surface === "mcp") {
    return { searchLabel: "Find a tool", searchPlaceholder: "Find a tool by name or description", catalogOrder: "Server order",
      units: "tools", unit: (count) => (count === 1 ? "tool" : "tools") };
  }
  if (surface === "package-scripts") {
    return { searchLabel: "Find a script", searchPlaceholder: "Find a script by name or what it runs", catalogOrder: "package.json order",
      units: "scripts", unit: (count) => (count === 1 ? "script" : "scripts") };
  }
  return { searchLabel: "Find a command", searchPlaceholder: "Find a command by name or usage", catalogOrder: "Help order",
    units: "commands", unit: (count) => (count === 1 ? "command" : "commands") };
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

export function keepChoicesCopy(count: number): string {
  const tools = count === 1 ? "1 tool is" : `${count} tools are`;
  return `${tools} new or changed since you last saved. Keep the choices shown to mark them reviewed.`;
}

export const FRESH_TOTP_REQUIRED_MESSAGE = "Enter the current six-digit code from your authenticator.";

/**
 * Whether a save was refused for a missing authenticator code. A recent code
 * only stands in for about a minute, so it can lapse while the dialog is open;
 * the dialog must then ask for a code instead of hiding the field.
 */
export function isFreshTotpRequired(error: unknown): boolean {
  return error instanceof LocalCliApiError && error.code === "approval_gate_totp_required";
}

export function reviewTitle(name: string, state: LocalCliState): string {
  if (state === "allowed") return `Save ${name} command settings`;
  if (state === "blocked") return `Block ${name}`;
  return `Remove ${name}`;
}

export function reviewModalDetail(gate: GuardApprovalGatePublicConfig | null, requireFreshTotp = false): string {
  if (!requireFreshTotp && approvalProofRecentlySatisfied(gate)) {
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
      if (tools.length === 0) return item.remote_origin
        ? "No tools seen yet. Use one of its tools in your host app, then choose permissions here."
        : "No tools allowed yet. List the inventory to choose permissions.";
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

/** The status line under a custom extension in the list. */
export function customExtensionRowBehavior(item: LocalCliItem): string {
  const continuity = continuityCopy(item);
  return continuity ? `${continuity.title}. ${continuity.description}` : customExtensionStateLabel(item);
}

/**
 * The app an MCP row comes from. A server is listed once per app that
 * configures it, so the list names that app beside the server name; the
 * detail page already shows it under the title.
 */
export function customExtensionRowSource(item: LocalCliItem): string | undefined {
  return item.surface === "mcp" && item.source_label ? item.source_label : undefined;
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

export function connectorSetupCopy(match: ConnectorSetupMatch, name: string): { title: string; body: string } {
  if (match === "identity_changed") {
    return {
      title: "This connector changed since the request was held",
      body: `The ${name} Guard sees now has a different identity from the one an agent was held on. Review it before you allow it. The held request stays in the Inbox.`,
    };
  }
  if (match === "decided") {
    return {
      title: `${name} already has a decision`,
      body: "Requests held on it stay in the Inbox for a normal decision.",
    };
  }
  return {
    title: `Set up ${name} for the held request`,
    body: "Guard held an agent action because it does not know this connector yet. Setting it up with the recommended settings allows its commands on this device, then approves the requests held on it once. Detector floors and sensitive-file reviews still apply, and nothing changes until you confirm.",
  };
}

function heldRequests(count: number): string {
  return `${count} held request${count === 1 ? "" : "s"}`;
}

export function connectorGroupOutcomeCopy(outcome: ConnectorGroupOutcome): string {
  const hint = outcome.retryHint ? ` ${outcome.retryHint.replace(/\.?$/, ".")}` : "";
  if (outcome.status === "resolved") return `Set up. Guard approved ${heldRequests(outcome.resolvedCount)} once.${hint}`;
  if (outcome.status === "partial") {
    return `Set up. Guard approved ${heldRequests(outcome.resolvedCount)} once; the rest still need a decision in the Inbox.${hint}`;
  }
  if (outcome.status === "not_in_group") return "Set up. The held request is no longer waiting on this connector.";
  return "Set up. Guard could not approve the held requests here, so they are still in the Inbox.";
}
