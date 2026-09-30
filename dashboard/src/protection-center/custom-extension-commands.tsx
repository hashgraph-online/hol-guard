import { useCallback } from "react";

import type { LocalCliCommand, LocalCliCommandState, LocalCliSurface } from "../local-cli-api";
import {
  extensionPolicyRadioTabStop,
  nextExtensionPolicyRadioIndex,
} from "../extension-policy-panel";
import { mcpToolCanReceiveDirectAllow } from "./mcp-catalog-state";
import { McpClassificationEvidence } from "./mcp-classification-evidence";

export function commandStatesPayload(
  commands: readonly LocalCliCommand[],
): Array<{ command_id: string; state: LocalCliCommandState }> {
  return commands.map((command) => ({ command_id: command.command_id, state: command.state }));
}

export function withCommandState(
  commands: readonly LocalCliCommand[],
  commandId: string,
  state: LocalCliCommandState,
): LocalCliCommand[] {
  return commands.map((command) => (command.command_id === commandId ? { ...command, state } : command));
}

export function commandNestingDepth(command: LocalCliCommand): number {
  if (command.parent_id) return command.parent_id.split(".").filter(Boolean).length;
  const colons = command.name.split(":").length - 1;
  return colons > 0 ? colons : 0;
}

export function commandRowUsage(name: string, usage: string): string | null {
  const trimmed = usage.trim();
  if (trimmed === "" || trimmed === name) return null;
  return trimmed;
}

export function CustomExtensionCommandList(props: {
  commands: readonly LocalCliCommand[];
  disabled: boolean;
  surface?: LocalCliSurface;
  onChange: (commandId: string, state: LocalCliCommandState) => void;
}) {
  if (props.commands.length === 0) {
    return (
      <p className="text-sm leading-6 text-brand-dark/75">
        {emptyCommandCopy(props.surface)}
      </p>
    );
  }
  return (
    <div className="divide-y divide-slate-200">
      {props.commands.map((command) => (
        <CustomExtensionCommandRow
          key={command.command_id}
          command={command}
          disabled={props.disabled}
          surface={props.surface}
          onChange={props.onChange}
        />
      ))}
    </div>
  );
}

function emptyCommandCopy(surface: LocalCliSurface | undefined): string {
  if (surface === "mcp") {
    return "Guard has not loaded tools for this MCP server yet. Find the server again to list its tools.";
  }
  if (surface === "package-scripts") {
    return "Guard has not loaded scripts from package.json yet. Paste npm run, a project folder, or package.json.";
  }
  return "Guard has not loaded commands for this tool yet. Find the tool again to read its --help output.";
}

function CustomExtensionCommandRow(props: {
  command: LocalCliCommand;
  disabled: boolean;
  surface?: LocalCliSurface;
  onChange: (commandId: string, state: LocalCliCommandState) => void;
}) {
  const handleChange = useCallback((state: LocalCliCommandState) => {
    props.onChange(props.command.command_id, state);
  }, [props]);
  const depth = commandNestingDepth(props.command);
  return (
    <article
      className="guard-pattern-row px-4 py-3.5"
      data-command-id={props.command.command_id}
      style={depth > 0 ? { paddingLeft: `${1.25 + depth * 1.1}rem` } : undefined}
    >
      <div className="min-w-0 pr-3">
        <h3 className="text-sm font-semibold text-brand-dark">{props.command.name}</h3>
        {commandRowUsage(props.command.name, props.command.usage) ? (
          <p className="guard-pattern-example mt-1" title={props.command.usage}>{props.command.usage}</p>
        ) : null}
        {props.command.description ? (
          <p className="mt-1.5 text-xs leading-5 text-brand-dark/70">{props.command.description}</p>
        ) : null}
        <McpClassificationEvidence value={props.command.classification} />
        {props.surface === "mcp" && !mcpToolCanReceiveDirectAllow(props.command) ? (
          <p className="mt-1.5 text-xs leading-5 text-brand-dark/75">
            {props.command.command_id === "other"
              ? "New tools require review. You can deny tools outside this inventory."
              : "Review the actions and account inside this tool. A wrapper permission cannot allow execution."}
          </p>
        ) : null}
      </div>
      <CommandDraftControl
        label={props.command.name}
        state={props.command.state}
        disabled={props.disabled}
        mcpPolicy={props.surface === "mcp"}
        allowDisabled={props.surface === "mcp" && !mcpToolCanReceiveDirectAllow(props.command)}
        onChange={handleChange}
      />
    </article>
  );
}

function CommandDraftControl(props: {
  label: string;
  state: LocalCliCommandState;
  disabled: boolean;
  mcpPolicy?: boolean;
  allowDisabled?: boolean;
  onChange: (state: LocalCliCommandState) => void;
}) {
  const choices: Array<{ value: LocalCliCommandState; label: string; disabled?: boolean }> = [
    { value: "inherit", label: props.mcpPolicy ? "Policy" : "Recommended" },
    { value: "allow", label: "Allow", disabled: props.allowDisabled },
    ...(props.mcpPolicy ? [{ value: "review" as const, label: "Ask" }] : []),
    { value: "block", label: props.mcpPolicy ? "Deny" : "Block" },
  ];
  const tabStopIndex = extensionPolicyRadioTabStop(choices, props.state, props.disabled);
  const chooseAdjacent = (event: React.KeyboardEvent<HTMLButtonElement>, index: number) => {
    const next = nextExtensionPolicyRadioIndex(choices, index, event.key, props.disabled);
    if (next < 0) return;
    event.preventDefault();
    props.onChange(choices[next]!.value);
    event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="radio"]')[next]?.focus();
  };
  return (
    <div role="radiogroup" aria-label={`${props.label} protection setting`}
      className={props.mcpPolicy
        ? "guard-segmented !grid grid-cols-2 sm:!flex [&_[role=radio]]:!min-h-11"
        : "guard-segmented"}>
      {choices.map((choice, index) => (
        <CommandChoiceButton
          key={choice.value}
          choice={choice}
          checked={props.state === choice.value}
          tabIndex={!props.disabled && index === tabStopIndex ? 0 : -1}
          disabled={props.disabled || choice.disabled === true}
          index={index}
          onChoose={props.onChange}
          onAdjacent={chooseAdjacent}
        />
      ))}
    </div>
  );
}

function CommandChoiceButton(props: {
  choice: { value: LocalCliCommandState; label: string };
  checked: boolean;
  tabIndex: number;
  disabled: boolean;
  index: number;
  onChoose: (state: LocalCliCommandState) => void;
  onAdjacent: (event: React.KeyboardEvent<HTMLButtonElement>, index: number) => void;
}) {
  const handleClick = useCallback(() => {
    props.onChoose(props.choice.value);
  }, [props]);
  const handleKeyDown = useCallback((event: React.KeyboardEvent<HTMLButtonElement>) => {
    props.onAdjacent(event, props.index);
  }, [props]);
  return (
    <button
      type="button"
      role="radio"
      aria-checked={props.checked}
      tabIndex={props.tabIndex}
      disabled={props.disabled}
      onKeyDown={handleKeyDown}
      onClick={handleClick}
      className="disabled:cursor-not-allowed disabled:opacity-45"
    >
      {props.choice.label}
    </button>
  );
}
