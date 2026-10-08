import type { LocalCliCommand, LocalCliItem } from "../local-cli-api";

export function mcpToolCanReceiveDirectAllow(command: LocalCliCommand): boolean {
  if (command.command_id === "other") return false;
  const name = command.usage.split("__").at(-1)?.toLowerCase();
  return !name?.startsWith("composio_")
    || ["composio_search_tools", "composio_get_tool_schemas"].includes(name);
}

export function mcpCatalogCopy(item: LocalCliItem): { title: string; description: string } | null {
  if (item.surface !== "mcp") return null;
  const catalog = item.mcp_catalog;
  if (!catalog) return {
    title: "Inventory not checked",
    description: "Guard knows observed tools from this connector. Its full inventory has not been verified.",
  };
  const count = `${catalog.known_count} ${catalog.known_count === 1 ? "tool" : "tools"}`;
  if (catalog.complete && catalog.fresh_until && Date.parse(catalog.fresh_until) <= Date.now()) return {
    title: `${count} cached · Refresh available`,
    description: "This inventory's freshness window ended. Existing choices are kept; list tools again to check for changes.",
  };
  if (catalog.complete) return {
    title: `${count} listed`,
    description: "Discovery finished. Permission choices apply separately to each tool.",
  };
  if (catalog.reason === "catalog_changed") return {
    title: "Inventory changed during discovery",
    description: "Guard kept your choices. List tools again to review a consistent inventory.",
  };
  if (catalog.reason === "refresh_failed" || catalog.reason === "list_failed") return {
    title: catalog.stale ? `${count} cached · Refresh failed` : "Discovery did not finish",
    description: catalog.known_count > 0
      ? "Known tools and choices are still available. Retry discovery to check the current inventory."
      : "Guard could not finish listing tools. Retry discovery to check this connector.",
  };
  return {
    title: `${count} known · Inventory incomplete`,
    description: "Discovery reached a limit or returned an incomplete inventory. Unknown tools still need review.",
  };
}

export function rebaseCommandDraft(
  current: LocalCliCommand[],
  previous: LocalCliCommand[],
  next: LocalCliCommand[],
  changedToolNames: readonly string[] = [],
): LocalCliCommand[] {
  const changed = new Set(changedToolNames);
  const previousStates = new Map(previous.map((command) => [command.command_id, command.state]));
  const edits = new Map(current
    .filter((command) => previousStates.has(command.command_id) && command.state !== previousStates.get(command.command_id))
    .map((command) => [command.command_id, command.state]));
  return next.map((command) => edits.has(command.command_id)
    && !(edits.get(command.command_id) === "allow" && (changed.has(command.command_id) || changed.has(command.usage)))
    ? { ...command, state: edits.get(command.command_id)! }
    : command);
}

export function commandPermissionChanges(previous: LocalCliCommand[], next: LocalCliCommand[]): {
  commandId: string; name: string; before: LocalCliCommand["state"] | null; after: LocalCliCommand["state"];
}[] {
  const states = new Map(previous.map((command) => [command.command_id, command.state]));
  return next.filter((command) => command.state !== states.get(command.command_id))
    .map((command) => ({ commandId: command.command_id, name: command.name,
      before: states.get(command.command_id) ?? null, after: command.state }));
}
