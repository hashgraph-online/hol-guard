import { useCallback, type KeyboardEvent } from "react";

import type { LocalCliCommandState } from "../local-cli-api";
import {
  extensionPolicyRadioTabStop,
  nextExtensionPolicyRadioIndex,
} from "../extension-policy-panel";

export function BulkPolicyPicker(props: {
  value: LocalCliCommandState | "mixed";
  disabled: boolean;
  onChange: (state: LocalCliCommandState) => void;
  groupLabel?: string;
  mixedCopy?: string;
  allowLabel?: string;
  blockLabel?: string;
  mcpPolicy?: boolean;
  className?: string;
}) {
  const choices: Array<{ value: LocalCliCommandState; label: string }> = [
    { value: "inherit", label: props.mcpPolicy ? "Use policy" : "Recommended" },
    { value: "allow", label: props.allowLabel ?? "Allow all" },
    ...(props.mcpPolicy ? [{ value: "review" as const, label: "Ask listed" }] : []),
    { value: "block", label: props.blockLabel ?? "Block all" },
  ];
  const mixed = props.value === "mixed";
  const selected = mixed ? "inherit" : props.value;
  const groupLabel = props.groupLabel ?? "All tools protection setting";
  const tabStopIndex = extensionPolicyRadioTabStop(choices, selected, props.disabled);
  const chooseAdjacent = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const next = nextExtensionPolicyRadioIndex(choices, index, event.key, props.disabled);
    if (next < 0) return;
    event.preventDefault();
    props.onChange(choices[next]!.value);
    event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="radio"]')[next]?.focus();
  };
  return (
    <div className={props.className ?? "mt-4"} data-testid="custom-extension-bulk-policy">
      <div
        role="radiogroup"
        aria-label={mixed ? `${groupLabel}. Custom mix` : groupLabel}
        aria-describedby={mixed ? "bulk-policy-mixed" : undefined}
        className={props.mcpPolicy
          ? "guard-segmented w-fit !grid grid-cols-2 sm:!flex [&_[role=radio]]:!min-h-11"
          : "guard-segmented w-fit"}
      >
        {choices.map((choice, index) => (
          <BulkPolicyChoice
            key={choice.value}
            choice={choice}
            checked={props.value === choice.value}
            tabIndex={!props.disabled && index === tabStopIndex ? 0 : -1}
            disabled={props.disabled}
            index={index}
            onChoose={props.onChange}
            onAdjacent={chooseAdjacent}
          />
        ))}
      </div>
      {props.value === "mixed" ? (
        <p id="bulk-policy-mixed" className="mt-2 text-xs leading-5 text-brand-dark/70">
          {props.mixedCopy ?? `Custom mix. Pick Recommended, ${props.allowLabel ?? "Allow all"}, or Block all to reset every tool.`}
        </p>
      ) : null}
    </div>
  );
}

function BulkPolicyChoice(props: {
  choice: { value: LocalCliCommandState; label: string };
  checked: boolean;
  tabIndex: number;
  disabled: boolean;
  index: number;
  onChoose: (state: LocalCliCommandState) => void;
  onAdjacent: (event: KeyboardEvent<HTMLButtonElement>, index: number) => void;
}) {
  const handleClick = useCallback(() => {
    props.onChoose(props.choice.value);
  }, [props]);
  const handleKeyDown = useCallback((event: KeyboardEvent<HTMLButtonElement>) => {
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
      className="min-h-11 px-4 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-45"
    >
      {props.choice.label}
    </button>
  );
}
