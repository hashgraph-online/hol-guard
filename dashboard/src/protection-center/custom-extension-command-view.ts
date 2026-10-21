import type { LocalCliCommand, LocalCliCommandState, LocalCliSurface } from "../local-cli-api";

export type CommandStateFilter = "all" | "changed" | LocalCliCommandState;
export type CommandSort = "catalog" | "name" | "state";

export type CommandGroup = {
  key: string;
  label: string;
  commands: LocalCliCommand[];
};

/** Groups render collapsed by default once a catalog is long enough to need scanning. */
export const COLLAPSE_GROUPS_AT = 30;

const STATE_RANK: Record<LocalCliCommandState, number> = { block: 0, review: 1, allow: 2, inherit: 3 };
const SPECIAL_COMMAND_IDS = new Set(["root", "other"]);

export function commandMatchesQuery(command: LocalCliCommand, query: string): boolean {
  const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return true;
  const haystack = `${command.name}\n${command.usage}\n${command.description}`.toLowerCase();
  return terms.every((term) => haystack.includes(term));
}

export function commandChanged(command: LocalCliCommand, saved: ReadonlyMap<string, LocalCliCommandState>): boolean {
  return (saved.get(command.command_id) ?? "inherit") !== command.state;
}

export function savedStateMap(saved: readonly LocalCliCommand[]): Map<string, LocalCliCommandState> {
  return new Map(saved.map((command) => [command.command_id, command.state]));
}

export function commandMatchesFilter(
  command: LocalCliCommand,
  filter: CommandStateFilter,
  saved: ReadonlyMap<string, LocalCliCommandState>,
): boolean {
  if (filter === "all") return true;
  if (filter === "changed") return commandChanged(command, saved);
  return command.state === filter;
}

export function stateFilterCounts(
  commands: readonly LocalCliCommand[],
  saved: ReadonlyMap<string, LocalCliCommandState>,
): Record<CommandStateFilter, number> {
  const counts: Record<CommandStateFilter, number> = { all: commands.length, changed: 0, inherit: 0, allow: 0, review: 0, block: 0 };
  for (const command of commands) {
    counts[command.state] += 1;
    if (commandChanged(command, saved)) counts.changed += 1;
  }
  return counts;
}

export function sortCommands(commands: readonly LocalCliCommand[], sort: CommandSort): LocalCliCommand[] {
  if (sort === "catalog") return [...commands];
  const byName = (left: LocalCliCommand, right: LocalCliCommand) =>
    left.name.localeCompare(right.name, undefined, { numeric: true, sensitivity: "base" });
  if (sort === "name") return [...commands].sort(byName);
  return [...commands].sort((left, right) => STATE_RANK[left.state] - STATE_RANK[right.state] || byName(left, right));
}

/**
 * The family a command belongs to: the `build` in `build:web`, or the root of
 * a CLI subcommand's parent chain. Root and catch-all rows never group.
 */
export function commandGroupKey(command: LocalCliCommand, surface: LocalCliSurface | undefined): string {
  if (SPECIAL_COMMAND_IDS.has(command.command_id) || surface === "mcp") return `id:${command.command_id}`;
  if (surface === "package-scripts") {
    const colon = command.name.indexOf(":");
    return `name:${colon > 0 ? command.name.slice(0, colon) : command.name}`;
  }
  return `id:${command.parent_id ? command.parent_id.split(".")[0] : command.command_id}`;
}

/** Groups keep the order of their first member, so sorting the flat list orders the groups too. */
export function groupCommands(commands: readonly LocalCliCommand[], surface: LocalCliSurface | undefined): CommandGroup[] {
  const groups = new Map<string, CommandGroup>();
  const names = new Map(commands.map((command) => [command.command_id, command.name]));
  for (const command of commands) {
    const key = commandGroupKey(command, surface);
    let group = groups.get(key);
    if (!group) {
      const raw = key.slice(key.indexOf(":") + 1);
      group = { key, label: key.startsWith("name:") ? raw : names.get(raw) ?? raw, commands: [] };
      groups.set(key, group);
    }
    group.commands.push(command);
  }
  return [...groups.values()];
}

/** The part of a grouped command's name that repeats its group label, shown dimmed. */
export function commandNamePrefix(name: string, groupLabel: string): string {
  return name.startsWith(`${groupLabel}:`) ? `${groupLabel}:` : "";
}

export function groupStateSummary(commands: readonly LocalCliCommand[]): string {
  const counts = stateFilterCounts(commands, new Map());
  const parts = [
    counts.allow > 0 ? `${counts.allow} allowed` : "",
    counts.review > 0 ? `${counts.review} ask` : "",
    counts.block > 0 ? `${counts.block} blocked` : "",
  ].filter(Boolean);
  if (parts.length === 0) return "All Recommended";
  if (counts.inherit > 0) parts.push(`${counts.inherit} Recommended`);
  return parts.join(" · ");
}

/** Package scripts repeat `<runner> run <name>` as usage; the script body in the description says more. */
export function commandRowUsageFor(command: LocalCliCommand, surface: LocalCliSurface | undefined): string | null {
  const usage = command.usage.trim();
  if (usage === "" || usage === command.name) return null;
  if (surface === "package-scripts" && usage.endsWith(` ${command.name}`)) return null;
  return usage;
}

export function commandDescriptionIsCode(command: LocalCliCommand, surface: LocalCliSurface | undefined): boolean {
  return surface === "package-scripts" && !SPECIAL_COMMAND_IDS.has(command.command_id);
}
