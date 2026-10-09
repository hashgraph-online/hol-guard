import type { LocalCliCommand, LocalCliItem } from "../local-cli-api";

/** Commands the set-up flow may be prefilled with. Anything else in the URL is ignored. */
const PROFILE_SETUP_COMMANDS: Record<string, string> = { wrangler: "npx wrangler" };
export const PROFILE_COMMAND_PARAM = "command";

export function profileSetupCommand(item: LocalCliItem): string | null {
  return item.profile_id ? PROFILE_SETUP_COMMANDS[item.profile_id] ?? null : null;
}

export function customExtensionDisplayName(item: LocalCliItem): string {
  return item.display_name ?? item.name;
}

export function customExtensionBadge(item: LocalCliItem): "Detected" | "Set up" | null {
  if (item.seeded === true) return "Set up";
  if (item.surface === "cli" && item.state === "unset" && item.suggestable) return "Detected";
  return null;
}

export function hasSuggestedRules(item: LocalCliItem): boolean {
  return item.commands.some((command) => command.suggested_state !== undefined);
}

/**
 * Pre-select suggested rules while an extension has not been added yet. Once
 * added, its saved rules are shown as-is, including deliberate "inherit"
 * choices. Nothing is applied until the user confirms.
 */
export function prefillSuggestedStates(item: Pick<LocalCliItem, "state" | "commands">): LocalCliCommand[] {
  if (item.state !== "unset") return item.commands;
  return item.commands.map((command) => command.state === "inherit"
    && command.suggested_state !== undefined && command.suggested_state !== "inherit"
    ? { ...command, state: command.suggested_state }
    : command);
}

export function addCustomExtensionPrefillHref(base: string, command: string | undefined): string {
  if (!command || !Object.values(PROFILE_SETUP_COMMANDS).includes(command)) return base;
  return `${base}?${PROFILE_COMMAND_PARAM}=${encodeURIComponent(command)}`;
}

export function initialAddCommand(search: string): string {
  const value = new URLSearchParams(search).get(PROFILE_COMMAND_PARAM);
  return value !== null && Object.values(PROFILE_SETUP_COMMANDS).includes(value) ? value : "";
}
