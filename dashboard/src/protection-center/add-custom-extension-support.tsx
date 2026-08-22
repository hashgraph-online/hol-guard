import { useCallback } from "react";

import { seenSuggestionMeta, type LocalCliItem, type LocalCliState } from "../local-cli-api";

export function addDialogSubmitLabel(input: {
  recognized: LocalCliItem | null;
  busy: boolean;
  pending: LocalCliState | null;
}): string {
  if (input.recognized === null) {
    return input.busy ? "Looking…" : "Find this tool";
  }
  if (input.busy) {
    return "Saving…";
  }
  if (input.pending === "blocked") {
    return blockActionLabel(input.recognized.surface);
  }
  return allowActionLabel(input.recognized.surface);
}

export function surfaceBadge(surface: LocalCliItem["surface"]): string | null {
  if (surface === "mcp") return "MCP server";
  if (surface === "package-scripts") return "Package scripts";
  return null;
}

export function allowActionLabel(surface: LocalCliItem["surface"]): string {
  if (surface === "mcp") return "Allow this server";
  if (surface === "package-scripts") return "Allow these scripts";
  return "Allow this tool";
}

export function blockActionLabel(surface: LocalCliItem["surface"]): string {
  if (surface === "mcp") return "Block this server";
  if (surface === "package-scripts") return "Block these scripts";
  return "Block this tool";
}

export function dialogIntro(hasProjects: boolean, showingCatalog: boolean): string {
  if (showingCatalog) {
    return "Confirm these project scripts, or type a nested name to find one fast.";
  }
  if (hasProjects) {
    return "Guard already found project scripts on this device. Pick a project, or paste another folder.";
  }
  return "Paste a script, binary, MCP launch, or package scripts such as npm run. Everyday commands such as rg, grep, and whoami are not custom extensions.";
}

export function filterCountCopy(visible: number, total: number): string {
  if (visible === 0) return "No scripts match that name. Try another nested name, or paste a different project folder.";
  if (visible === total) return `${visible} scripts in this project.`;
  return `Showing ${visible} of ${total} scripts. Allow still covers the whole project.`;
}

export function suggestionSummary(item: LocalCliItem): string {
  if (item.surface === "package-scripts" && item.commands.length > 0) {
    const count = item.commands.length;
    const unit = count === 1 ? "script" : "scripts";
    return `Ready to enroll ${count} ${unit} from ${item.source_label ?? item.name}. Nested names stay grouped. Recommended keeps the usual review.`;
  }
  if (item.surface === "package-scripts") {
    return `Find this tool to list npm scripts from ${item.name}.`;
  }
  if (item.surface === "mcp" && item.commands.length > 0) {
    return `Guard listed ${item.commands.length} tools from this MCP server. Recommended keeps the usual review. Allow or block each one.`;
  }
  if (item.surface === "mcp") {
    return `Find this tool to list MCP tools from ${item.name}.`;
  }
  if (item.commands.length > 0) {
    return `Guard loaded ${item.commands.length} commands. Recommended keeps the usual review. Allow or block each one.`;
  }
  return `Find this tool to read ${item.name} --help and load its commands.`;
}

export function SuggestionPanel(props: {
  query: string;
  hasSuggestions: boolean;
  packageScriptSuggestions: LocalCliItem[];
  harnessSuggestions: LocalCliItem[];
  seenSuggestions: LocalCliItem[];
  onSelect: (item: LocalCliItem) => void;
}) {
  if (!props.hasSuggestions) {
    return (
      <p className="mt-5 text-sm leading-6 text-brand-dark/70">
        {suggestionEmptyCopy(props.query)}
      </p>
    );
  }
  return (
    <>
      <SuggestionGroup
        heading="From this device"
        helper="Projects Guard has already seen, including nested names such as guard:audit."
        items={props.packageScriptSuggestions}
        onSelect={props.onSelect}
      />
      <SuggestionGroup
        heading="From your apps"
        helper="MCP servers already configured in apps on this device."
        items={props.harnessSuggestions}
        onSelect={props.onSelect}
      />
      <SuggestionGroup
        heading="Seen on this device"
        helper="Your own tools that agents have run. Common commands stay hidden."
        items={props.seenSuggestions}
        onSelect={props.onSelect}
      />
    </>
  );
}

export function ProjectSwitcher(props: {
  items: LocalCliItem[];
  currentId: string;
  onSelect: (item: LocalCliItem) => void;
}) {
  if (props.items.length < 2) return null;
  return (
    <div className="mt-3 flex flex-wrap gap-2" role="group" aria-label="Remembered projects">
      {props.items.map((item) => (
        <ProjectChip
          key={item.cli_id}
          item={item}
          selected={item.cli_id === props.currentId}
          onSelect={props.onSelect}
        />
      ))}
    </div>
  );
}

function suggestionEmptyCopy(query: string): string {
  if (query.trim() !== "") {
    return "No matching tools. Try npm run, a project folder, or a nested script name. Everyday commands such as rg stay hidden.";
  }
  return "No extra tools yet. Paste npm run, a project folder, a script, or an MCP launch.";
}

function SuggestionGroup(props: {
  heading: string;
  helper: string;
  items: LocalCliItem[];
  onSelect: (item: LocalCliItem) => void;
}) {
  if (props.items.length === 0) return null;
  return (
    <div className="mt-5">
      <p className="text-sm font-semibold text-brand-dark">{props.heading}</p>
      <p className="mt-1 text-xs leading-5 text-brand-dark/60">{props.helper}</p>
      <ul className="mt-2 divide-y divide-slate-200">
        {props.items.map((item) => (
          <li key={item.cli_id}>
            <SuggestionButton item={item} onSelect={props.onSelect} />
          </li>
        ))}
      </ul>
    </div>
  );
}

function ProjectChip(props: {
  item: LocalCliItem;
  selected: boolean;
  onSelect: (item: LocalCliItem) => void;
}) {
  const handleSelect = useCallback(() => {
    props.onSelect(props.item);
  }, [props]);
  return (
    <button
      type="button"
      onClick={handleSelect}
      aria-pressed={props.selected}
      className={`min-h-11 rounded-full px-3 text-xs font-semibold ${
        props.selected
          ? "bg-brand-blue text-white"
          : "border border-slate-300 text-brand-dark"
      }`}
    >
      {props.item.source_label ?? props.item.name}
    </button>
  );
}

function SuggestionButton(props: { item: LocalCliItem; onSelect: (item: LocalCliItem) => void }) {
  const handleSelect = useCallback(() => {
    props.onSelect(props.item);
  }, [props]);
  return (
    <button type="button" onClick={handleSelect} className="flex min-h-11 w-full items-baseline justify-between gap-3 py-2 text-left">
      <span className="min-w-0">
        <span className="block truncate text-sm font-semibold text-brand-dark">{props.item.name}</span>
        <span className="block truncate text-xs text-brand-dark/60">
          {props.item.source_label ?? seenSuggestionMeta(props.item)}
        </span>
      </span>
      <span className="truncate font-mono text-xs text-brand-dark/60">{props.item.example_label}</span>
    </button>
  );
}
