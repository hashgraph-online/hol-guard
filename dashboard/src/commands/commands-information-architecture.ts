import type { CommandActivityHarness } from "./command-activity-types";

export type CommandsSurfaceId = "evidence" | "app-activity" | "home";
export type CommandsDataSource = "activity" | "analytics" | "extensions" | "invalidations";

export interface CommandsSurfaceContract {
  id: CommandsSurfaceId;
  parentLabel: string;
  label: string;
  route: string;
  data: readonly CommandsDataSource[];
  visibility: "always" | "when-command-data-exists";
  scope: "all-apps" | "selected-app";
}

export const COMMANDS_INFORMATION_ARCHITECTURE: readonly CommandsSurfaceContract[] = [
  {
    id: "evidence",
    parentLabel: "Evidence",
    label: "Commands",
    route: "/evidence?view=commands",
    data: ["activity", "analytics", "extensions", "invalidations"],
    visibility: "always",
    scope: "all-apps",
  },
  {
    id: "app-activity",
    parentLabel: "Activity",
    label: "Command protection",
    route: "/apps/:harness?tab=activity&activity=commands",
    data: ["activity", "analytics", "extensions", "invalidations"],
    visibility: "always",
    scope: "selected-app",
  },
  {
    id: "home",
    parentLabel: "Home",
    label: "Commands checked",
    route: "/",
    data: ["analytics", "invalidations"],
    visibility: "when-command-data-exists",
    scope: "all-apps",
  },
] as const;

export const COMMAND_ACTIVITY_TRUTH_COPY = {
  activityMeaning: "A command match is local activity evidence, not a threat classification.",
  allowedUnconfirmed: "Allowed; execution not confirmed",
  confirmedSuccess: "Execution confirmed",
  confirmedFailure: "Execution failure confirmed",
  evidenceGap: "Some command activity may be missing.",
} as const;

export const COMMAND_DECISIONS_SIBLING = {
  label: "Decisions",
  route: "/evidence?view=actions",
  meaning: "Saved policy decisions and receipts remain separate from command checks.",
} as const;

export function commandsSurface(id: CommandsSurfaceId): CommandsSurfaceContract {
  const surface = COMMANDS_INFORMATION_ARCHITECTURE.find((item) => item.id === id);
  if (!surface) throw new Error(`Unknown Commands surface: ${id}`);
  return surface;
}

export function commandActivityPathForHarness(
  harness: CommandActivityHarness,
): string {
  return `/apps/${encodeURIComponent(harness)}?tab=activity&activity=commands`;
}

export function shouldShowHomeCommands(commandsChecked: number): boolean {
  return Number.isSafeInteger(commandsChecked) && commandsChecked > 0;
}
