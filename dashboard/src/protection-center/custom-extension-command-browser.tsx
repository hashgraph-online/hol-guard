import { useCallback, useId, useMemo, useState, type ChangeEvent } from "react";
import { HiMiniChevronRight, HiMiniMagnifyingGlass, HiMiniXMark } from "react-icons/hi2";

import { bulkCommandState, type LocalCliCommand, type LocalCliCommandState, type LocalCliSurface } from "../local-cli-api";
import { BulkPolicyPicker } from "./add-custom-extension-catalog";
import { CommandDraftControl, CustomExtensionCommandRow, emptyCommandCopy } from "./custom-extension-commands";
import {
  COLLAPSE_GROUPS_AT,
  commandChanged,
  commandMatchesFilter,
  commandMatchesQuery,
  groupCommands,
  groupStateSummary,
  savedStateMap,
  sortCommands,
  stateFilterCounts,
  type CommandGroup,
  type CommandSort,
  type CommandStateFilter,
} from "./custom-extension-command-view";
import { commandBrowserCopy } from "./local-cli-panel-copy";

type BrowserProps = {
  commands: readonly LocalCliCommand[];
  savedCommands: readonly LocalCliCommand[];
  surface?: LocalCliSurface;
  disabled: boolean;
  /** Commands a bulk or family choice may change; the rest keep their own setting. */
  bulkEligible: (command: LocalCliCommand) => boolean;
  bulkGroupLabel: string;
  bulkMixedCopy: string;
  onChange: (commandId: string, state: LocalCliCommandState) => void;
  onBulkChange: (commandIds: ReadonlySet<string>, state: LocalCliCommandState) => void;
  /** Search text the view opens with, such as a script name pasted into the add flow. */
  initialQuery?: string;
  /** What a row that differs from `savedCommands` is called: "Unsaved" on a saved extension, "Changed" while adding one. */
  changedLabel?: string;
};

/**
 * Search, filter, sort and family grouping for a custom extension's commands.
 * Choices live in the parent's draft, so narrowing the view never discards them,
 * and bulk choices apply only to the rows the current view shows.
 */
export function CustomExtensionCommandBrowser(props: BrowserProps) {
  const copy = commandBrowserCopy(props.surface);
  const searchId = useId();
  const [query, setQuery] = useState(props.initialQuery ?? "");
  const changedLabel = props.changedLabel ?? "Unsaved";
  const [filter, setFilter] = useState<CommandStateFilter>("all");
  const [sort, setSort] = useState<CommandSort>("catalog");
  const saved = useMemo(() => savedStateMap(props.savedCommands), [props.savedCommands]);
  const searched = useMemo(
    () => props.commands.filter((command) => commandMatchesQuery(command, query)),
    [props.commands, query],
  );
  const counts = useMemo(() => stateFilterCounts(searched, saved), [searched, saved]);
  // Which rows show, and in what order, is decided from the settings at the moment the
  // view last changed. Editing a row under a setting filter or sort keeps it in place
  // (and keeps keyboard focus) until the person changes the view or the catalog reloads.
  const viewKey = [query, filter, sort, props.commands.map((command) => command.command_id).join("\n")].join("\u0000");
  const [frozen, setFrozen] = useState({ key: viewKey, saved, commands: props.commands });
  let viewBase = frozen;
  if (frozen.key !== viewKey || frozen.saved !== saved) {
    viewBase = { key: viewKey, saved, commands: props.commands };
    setFrozen(viewBase);
  }
  const visible = useMemo(() => {
    const live = new Map(props.commands.map((command) => [command.command_id, command]));
    return sortCommands(
      viewBase.commands.filter((command) => commandMatchesQuery(command, query) && commandMatchesFilter(command, filter, saved)),
      sort,
    ).flatMap((command) => live.get(command.command_id) ?? []);
  }, [viewBase.commands, props.commands, query, filter, saved, sort]);
  const groups = useMemo(() => groupCommands(visible, props.surface), [visible, props.surface]);
  const families = groups.filter((group) => group.commands.length > 1);
  const narrowed = query.trim() !== "" || filter !== "all";
  const familyKeys = useMemo(
    () => groupCommands(props.commands, props.surface).filter((group) => group.commands.length > 1).map((group) => group.key),
    [props.commands, props.surface],
  );
  const longCatalog = props.commands.length > COLLAPSE_GROUPS_AT;
  const [collapsed, setCollapsed] = useState<ReadonlySet<string>>(() => new Set(longCatalog ? familyKeys : []));
  // Families a refreshed catalog adds follow the long-catalog default; families the
  // person already opened or closed keep that choice.
  const [knownFamilies, setKnownFamilies] = useState<ReadonlySet<string>>(() => new Set(familyKeys));
  const newFamilies = familyKeys.filter((key) => !knownFamilies.has(key));
  if (newFamilies.length > 0) {
    setKnownFamilies(new Set([...knownFamilies, ...newFamilies]));
    if (longCatalog) setCollapsed((current) => new Set([...current, ...newFamilies]));
  }
  const anyCollapsed = !narrowed && families.some((group) => collapsed.has(group.key));
  const bulkTargets = visible.filter(props.bulkEligible);

  const toggleGroup = useCallback((key: string) => {
    setCollapsed((current) => {
      const next = new Set(current);
      if (!next.delete(key)) next.add(key);
      return next;
    });
  }, []);
  const toggleAll = useCallback(() => {
    setCollapsed(anyCollapsed ? new Set() : new Set(families.map((group) => group.key)));
  }, [anyCollapsed, families]);
  const clearView = useCallback(() => {
    setQuery("");
    setFilter("all");
  }, []);
  const applyToVisible = useCallback((state: LocalCliCommandState) => {
    props.onBulkChange(new Set(bulkTargets.map((command) => command.command_id)), state);
  }, [bulkTargets, props]);

  if (props.commands.length === 0) {
    return <p className="mt-4 text-sm leading-6 text-brand-dark/75">{emptyCommandCopy(props.surface)}</p>;
  }
  return (
    <div className="mt-4">
      <div className="sticky top-0 z-10 -mx-1 bg-white px-1 pb-3 pt-2" data-testid="custom-extension-command-toolbar">
        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor={searchId} className="relative block min-w-0 flex-1 basis-56">
            <span className="sr-only">{copy.searchLabel}</span>
            <HiMiniMagnifyingGlass className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-brand-dark/50" aria-hidden="true" />
            <input
              id={searchId}
              type="search"
              value={query}
              placeholder={copy.searchPlaceholder}
              onChange={(event: ChangeEvent<HTMLInputElement>) => setQuery(event.target.value)}
              className="min-h-11 w-full rounded-xl border border-slate-300 bg-white pl-9 pr-3 text-sm text-brand-dark placeholder:text-brand-dark/50 focus-visible:border-brand-blue focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-brand-blue"
            />
          </label>
          <label className="inline-flex min-h-11 items-center gap-2 text-sm text-brand-dark/70">
            Sort
            <select
              value={sort}
              onChange={(event: ChangeEvent<HTMLSelectElement>) => setSort(event.target.value as CommandSort)}
              className="min-h-11 rounded-xl border border-slate-300 bg-white px-3 text-sm font-semibold text-brand-dark focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-brand-blue"
            >
              <option value="catalog">{copy.catalogOrder}</option>
              <option value="name">Name</option>
              <option value="state">Setting</option>
            </select>
          </label>
          {families.length > 0 && !narrowed ? (
            <button type="button" onClick={toggleAll}
              className="min-h-11 rounded-xl px-3 text-sm font-semibold text-brand-dark/80 hover:text-brand-dark">
              {anyCollapsed ? "Expand all" : "Collapse all"}
            </button>
          ) : null}
        </div>
        <StateFilterChips surface={props.surface} filter={filter} counts={counts} changedLabel={changedLabel} onChange={setFilter} />
      </div>
      {bulkTargets.length > 0 ? (
        <div className="mt-3">
          <p className="text-sm font-semibold text-brand-dark" aria-hidden="true">
            {narrowed ? `Set the ${bulkTargets.length} ${copy.unit(bulkTargets.length)} shown` : `Set all ${bulkTargets.length} ${copy.unit(bulkTargets.length)}`}
          </p>
          <BulkPolicyPicker
            className="mt-2"
            value={bulkCommandState(bulkTargets)}
            disabled={props.disabled}
            onChange={applyToVisible}
            groupLabel={narrowed ? `${bulkTargets.length} matching ${copy.unit(bulkTargets.length)} protection setting` : props.bulkGroupLabel}
            allowLabel={props.surface === "mcp" ? "Allow listed" : undefined}
            blockLabel={props.surface === "mcp" ? "Deny listed" : undefined}
            mcpPolicy={props.surface === "mcp"}
            mixedCopy={narrowed ? `Custom mix. Pick one setting for the ${bulkTargets.length} ${copy.unit(bulkTargets.length)} shown.` : props.bulkMixedCopy}
          />
          {narrowed ? (
            <p className="mt-2 text-xs leading-5 text-brand-dark/75" data-testid="custom-extension-bulk-scope">
              Applies to the {bulkTargets.length} {copy.unit(bulkTargets.length)} shown. Hidden {copy.units} keep their setting.
            </p>
          ) : null}
        </div>
      ) : null}
      <p className="sr-only" role="status" aria-live="polite">
        {narrowed ? `${visible.length} of ${props.commands.length} ${copy.units} shown` : ""}
      </p>
      {visible.length === 0 && props.commands.length > 0 ? (
        <div className="mt-6 rounded-xl border border-dashed border-slate-300 px-4 py-6 text-center">
          <p className="text-sm text-brand-dark/75">No {copy.units} match this view.</p>
          <button type="button" onClick={clearView}
            className="mt-2 inline-flex min-h-11 items-center gap-1.5 rounded-xl px-3 text-sm font-semibold text-brand-blue">
            <HiMiniXMark className="size-4" aria-hidden="true" />
            Clear search and filters
          </button>
        </div>
      ) : (
        <div className="mt-3">
          {groups.map((group) => group.commands.length > 1 ? (
            <CommandFamily
              key={group.key}
              group={group}
              open={narrowed || !collapsed.has(group.key)}
              collapsible={!narrowed}
              unitLabel={copy.unit}
              surface={props.surface}
              disabled={props.disabled}
              saved={saved}
              changedLabel={changedLabel}
              bulkEligible={props.bulkEligible}
              onToggle={toggleGroup}
              onChange={props.onChange}
              onBulkChange={props.onBulkChange}
            />
          ) : (
            <CustomExtensionCommandRow
              key={group.key}
              command={group.commands[0]!}
              disabled={props.disabled}
              surface={props.surface}
              groupLabel=""
              changed={commandChanged(group.commands[0]!, saved)}
              changedLabel={changedLabel}
              onChange={props.onChange}
            />
          ))}
        </div>
      )}
    </div>
  );
}

const FILTER_ORDER: readonly CommandStateFilter[] = ["all", "allow", "review", "block", "inherit", "changed"];

function StateFilterChips(props: {
  surface?: LocalCliSurface;
  filter: CommandStateFilter;
  counts: Record<CommandStateFilter, number>;
  changedLabel: string;
  onChange: (filter: CommandStateFilter) => void;
}) {
  const mcp = props.surface === "mcp";
  const label = (value: CommandStateFilter): string => {
    if (value === "all") return "All";
    if (value === "allow") return "Allowed";
    if (value === "review") return "Ask";
    if (value === "block") return mcp ? "Denied" : "Blocked";
    if (value === "inherit") return mcp ? "Policy" : "Recommended";
    return props.changedLabel;
  };
  const shown = FILTER_ORDER.filter((value) => value === "all" || value === props.filter || props.counts[value] > 0);
  // When every row shares one setting, no chip narrows the list, so the row is noise.
  const narrows = shown.some((value) => value !== "all" && props.counts[value] > 0 && props.counts[value] < props.counts.all);
  if (props.filter === "all" && !narrows) return null;
  return (
    <div role="group" aria-label="Show by setting" className="mt-2 flex flex-wrap gap-1.5">
      {shown.map((value) => (
        <button
          key={value}
          type="button"
          aria-pressed={props.filter === value}
          onClick={() => props.onChange(value)}
          className="inline-flex min-h-11 items-center gap-1.5 rounded-full border border-slate-300 bg-white px-3 text-xs font-semibold text-brand-dark/80 transition-colors hover:border-brand-blue/60 hover:text-brand-dark focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue aria-pressed:border-brand-blue aria-pressed:bg-brand-blue/10 aria-pressed:text-brand-dark motion-reduce:transition-none"
        >
          {label(value)}
          <span className="tabular-nums font-medium text-brand-dark/55">{props.counts[value]}</span>
        </button>
      ))}
    </div>
  );
}

function CommandFamily(props: {
  group: CommandGroup;
  open: boolean;
  collapsible: boolean;
  unitLabel: (count: number) => string;
  surface?: LocalCliSurface;
  disabled: boolean;
  saved: ReadonlyMap<string, LocalCliCommandState>;
  changedLabel: string;
  bulkEligible: (command: LocalCliCommand) => boolean;
  onToggle: (key: string) => void;
  onChange: (commandId: string, state: LocalCliCommandState) => void;
  onBulkChange: (commandIds: ReadonlySet<string>, state: LocalCliCommandState) => void;
}) {
  const panelId = useId();
  const eligible = props.group.commands.filter(props.bulkEligible);
  const unsaved = props.group.commands.filter((command) => commandChanged(command, props.saved)).length;
  const handleToggle = useCallback(() => props.onToggle(props.group.key), [props]);
  const handleFamily = useCallback((state: LocalCliCommandState) => {
    props.onBulkChange(new Set(eligible.map((command) => command.command_id)), state);
  }, [eligible, props]);
  const count = props.group.commands.length;
  return (
    <section aria-label={`${props.group.label} ${props.unitLabel(count)}`} className="border-b border-slate-200 last:border-b-0">
      <div className="flex flex-col gap-2 py-2.5 pl-1 pr-4 sm:flex-row sm:items-center sm:justify-between">
        <button
          type="button"
          aria-expanded={props.open}
          aria-controls={panelId}
          disabled={!props.collapsible}
          onClick={handleToggle}
          className="group flex min-h-11 min-w-0 items-center gap-2 rounded-lg px-2 text-left disabled:cursor-default"
        >
          <HiMiniChevronRight
            className={`size-4 shrink-0 text-brand-dark/55 transition-transform duration-150 motion-reduce:transition-none ${props.open ? "rotate-90" : ""}`}
            aria-hidden="true"
          />
          <span className="min-w-0">
            <span className="block truncate font-mono text-sm font-semibold text-brand-dark">{props.group.label}</span>
            <span className="block text-xs text-brand-dark/60">
              {count} {props.unitLabel(count)} · {groupStateSummary(props.group.commands)}
              {unsaved > 0 ? <span className="font-semibold text-brand-blue"> · {unsaved} {props.changedLabel.toLowerCase()}</span> : null}
            </span>
          </span>
        </button>
        {eligible.length > 0 ? (
          <CommandDraftControl
            label={`${props.group.label} family`}
            state={bulkCommandState(eligible)}
            disabled={props.disabled}
            mcpPolicy={props.surface === "mcp"}
            onChange={handleFamily}
          />
        ) : null}
      </div>
      <div id={panelId} hidden={!props.open} className="border-t border-slate-100 sm:pl-6 [&>article:last-child]:border-b-0">
        {props.open ? props.group.commands.map((command) => (
          <CustomExtensionCommandRow
            key={command.command_id}
            command={command}
            disabled={props.disabled}
            surface={props.surface}
            groupLabel={props.group.label}
            changed={commandChanged(command, props.saved)}
            changedLabel={props.changedLabel}
            onChange={props.onChange}
          />
        )) : null}
      </div>
    </section>
  );
}
