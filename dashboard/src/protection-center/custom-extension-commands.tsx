import { useCallback } from "react";

import type { LocalCliCommand, LocalCliCommandState, LocalCliSurface } from "../local-cli-api";
import {
  extensionPolicyRadioTabStop,
  nextExtensionPolicyRadioIndex,
} from "../extension-policy-panel";
import { mcpToolCanReceiveDirectAllow } from "./mcp-catalog-state";
import { McpClassificationEvidence } from "./mcp-classification-evidence";
import { commandDescriptionIsCode, commandNamePrefix, commandRowUsageFor } from "./custom-extension-command-view";

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

export function emptyCommandCopy(surface: LocalCliSurface | undefined): string {
  if (surface === "mcp") {
    return "Guard has not loaded tools for this MCP server yet. Find the server again to list its tools.";
  }
  if (surface === "package-scripts") {
    return "Guard has not loaded scripts from package.json yet. Paste npm run, a project folder, or package.json.";
  }
  return "Guard has not loaded commands for this tool yet. Find the tool again to read its --help output.";
}

export function CustomExtensionCommandRow(props: {
  command: LocalCliCommand;
  disabled: boolean;
  surface?: LocalCliSurface;
  /** Set when the row renders inside a family heading; the repeated prefix is dimmed. */
  groupLabel?: string;
  changed?: boolean;
  changedLabel?: string;
  onChange: (commandId: string, state: LocalCliCommandState) => void;
}) {
  const handleChange = useCallback((state: LocalCliCommandState) => {
    props.onChange(props.command.command_id, state);
  }, [props]);
  const prefix = props.groupLabel === undefined ? "" : commandNamePrefix(props.command.name, props.groupLabel);
  const usage = commandRowUsageFor(props.command, props.surface);
  const descriptionIsCode = commandDescriptionIsCode(props.command, props.surface);
  return (
    <article
      className="guard-pattern-row px-4 py-3"
      data-command-id={props.command.command_id}
      data-changed={props.changed ? "true" : undefined}
    >
      <div className="min-w-0 pr-3">
        <div className="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-1">
          <h3 className="min-w-0 break-words text-sm font-semibold text-brand-dark">
            {prefix ? <span className="font-medium text-brand-dark/55">{prefix}</span> : null}
            {props.command.name.slice(prefix.length)}
          </h3>
          {props.changed ? (
            <span className="inline-flex items-center gap-1 text-xs font-semibold text-brand-blue">
              <span className="size-1.5 rounded-full bg-brand-blue" aria-hidden="true" />
              {props.changedLabel ?? "Unsaved"}
            </span>
          ) : null}
        </div>
        {usage ? (
          <p className="guard-pattern-example mt-1 truncate" title={props.command.usage}>{usage}</p>
        ) : null}
        {props.command.description ? (
          descriptionIsCode ? (
            <p className="guard-pattern-example mt-1 truncate" title={props.command.description}>{props.command.description}</p>
          ) : (
            <p className="mt-1 text-xs leading-5 text-brand-dark/70">{props.command.description}</p>
          )
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

export function CommandDraftControl(props: {
  label: string;
  /** "mixed" renders no checked choice, for a family whose members differ. */
  state: LocalCliCommandState | "mixed";
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
  const tabStopIndex = extensionPolicyRadioTabStop<LocalCliCommandState | "mixed">(choices, props.state, props.disabled);
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
