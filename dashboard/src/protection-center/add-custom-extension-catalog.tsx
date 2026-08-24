import { useCallback, type KeyboardEvent, type ReactNode } from "react";

import type { LocalCliCommandState } from "../local-cli-api";
import {
  extensionPolicyRadioTabStop,
  nextExtensionPolicyRadioIndex,
} from "../extension-policy-panel";
import { filterCountCopy } from "./add-custom-extension-support";

export function CatalogPreview(props: {
  query: string;
  showFilterCount: boolean;
  previewNames: string[];
  visibleCount: number;
  totalCount: number;
  reviewing: boolean;
  adjustLabel: string;
  hideLabel: string;
  onOpenReview: () => void;
  onCloseReview: () => void;
  children?: ReactNode;
}) {
  return (
    <div className="mt-5">
      {props.showFilterCount && props.query.trim() !== "" ? (
        <p className="text-xs leading-5 text-brand-dark/60">{filterCountCopy(props.visibleCount, props.totalCount)}</p>
      ) : null}
      {props.previewNames.length > 0 && !props.reviewing ? (
        <ul className="mt-3 flex flex-wrap gap-2">
          {props.previewNames.map((name) => (
            <li key={name} className="rounded-full bg-slate-100 px-3 py-1.5 font-mono text-xs text-brand-dark">
              {name}
            </li>
          ))}
          {props.visibleCount > props.previewNames.length ? (
            <li className="rounded-full px-3 py-1.5 text-xs font-semibold text-brand-dark/60">
              +{props.visibleCount - props.previewNames.length} more
            </li>
          ) : null}
        </ul>
      ) : null}
      <button
        type="button"
        onClick={props.reviewing ? props.onCloseReview : props.onOpenReview}
        className="mt-4 min-h-11 text-sm font-semibold text-brand-blue"
      >
        {props.reviewing ? props.hideLabel : props.adjustLabel}
      </button>
      {props.reviewing ? props.children : null}
    </div>
  );
}

export function BulkPolicyPicker(props: {
  value: LocalCliCommandState | "mixed";
  disabled: boolean;
  onChange: (state: LocalCliCommandState) => void;
  groupLabel?: string;
  mixedCopy?: string;
}) {
  const choices: Array<{ value: LocalCliCommandState; label: string }> = [
    { value: "inherit", label: "Recommended" },
    { value: "allow", label: "Allow all" },
    { value: "block", label: "Block all" },
  ];
  const selected = props.value === "mixed" ? "inherit" : props.value;
  const tabStopIndex = extensionPolicyRadioTabStop(choices, selected, props.disabled);
  const chooseAdjacent = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const next = nextExtensionPolicyRadioIndex(choices, index, event.key, props.disabled);
    if (next < 0) return;
    event.preventDefault();
    props.onChange(choices[next]!.value);
    event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="radio"]')[next]?.focus();
  };
  return (
    <div className="mt-4" data-testid="custom-extension-bulk-policy">
      <div
        role="radiogroup"
        aria-label={props.groupLabel ?? "All tools protection setting"}
        aria-describedby={props.value === "mixed" ? "bulk-policy-mixed" : undefined}
        className="guard-segmented w-fit"
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
          {props.mixedCopy ?? "Custom mix. Pick Recommended, Allow all, or Block all to reset every tool."}
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
