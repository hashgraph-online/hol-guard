import { useCallback } from "react";

import type { LocalCliCommand, LocalCliCommandState, LocalCliSurface } from "../local-cli-api";
import {
  extensionPolicyRadioTabStop,
  nextExtensionPolicyRadioIndex,
} from "../extension-policy-panel";

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

export function CustomExtensionCommandList(props: {
  commands: readonly LocalCliCommand[];
  disabled: boolean;
  surface?: LocalCliSurface;
  onChange: (commandId: string, state: LocalCliCommandState) => void;
}) {
  if (props.commands.length === 0) {
    return (
      <p className="text-sm leading-6 text-brand-dark/75">
        {props.surface === "mcp"
          ? "Guard has not loaded tools for this MCP server yet. Find the server again to list its tools."
          : "Guard has not loaded commands for this tool yet. Find the tool again to read its --help output."}
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
          onChange={props.onChange}
        />
      ))}
    </div>
  );
}

function CustomExtensionCommandRow(props: {
  command: LocalCliCommand;
  disabled: boolean;
  onChange: (commandId: string, state: LocalCliCommandState) => void;
}) {
  const handleChange = useCallback((state: LocalCliCommandState) => {
    props.onChange(props.command.command_id, state);
  }, [props]);
  return (
    <article className="guard-pattern-row" data-command-id={props.command.command_id}>
      <div className="min-w-0">
        <h3 className="text-sm font-semibold text-brand-dark">{props.command.name}</h3>
        <p className="guard-pattern-example mt-1">{props.command.usage}</p>
        {props.command.description ? (
          <p className="mt-2 text-xs leading-5 text-brand-dark/75">{props.command.description}</p>
        ) : null}
      </div>
      <CommandDraftControl
        label={props.command.name}
        state={props.command.state}
        disabled={props.disabled}
        onChange={handleChange}
      />
    </article>
  );
}

function CommandDraftControl(props: {
  label: string;
  state: LocalCliCommandState;
  disabled: boolean;
  onChange: (state: LocalCliCommandState) => void;
}) {
  const choices: Array<{ value: LocalCliCommandState; label: string }> = [
    { value: "inherit", label: "Recommended" },
    { value: "allow", label: "Allow" },
    { value: "block", label: "Block" },
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
    <div role="radiogroup" aria-label={`${props.label} protection setting`} className="guard-segmented">
      {choices.map((choice, index) => (
        <CommandChoiceButton
          key={choice.value}
          choice={choice}
          checked={props.state === choice.value}
          tabIndex={!props.disabled && index === tabStopIndex ? 0 : -1}
          disabled={props.disabled}
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
