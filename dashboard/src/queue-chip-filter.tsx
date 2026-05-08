import { useCallback } from "react";
import { harnessDisplayName } from "./approval-center-utils";

type ChipButtonProps = {
  label: string;
  active: boolean;
  value: string;
  onClick: (value: string) => void;
};

function ChipButton(props: ChipButtonProps) {
  const handleClick = useCallback(() => {
    props.onClick(props.value);
  }, [props.onClick, props.value]);

  return (
    <button
      type="button"
      onClick={handleClick}
      aria-pressed={props.active}
      className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors duration-150 ${
        props.active
          ? "border-brand-blue bg-brand-blue/10 text-brand-blue"
          : "border-slate-200 bg-white text-slate-600 hover:border-brand-blue/30 hover:text-brand-dark"
      }`}
    >
      {props.label}
    </button>
  );
}

type QueueChipFilterProps = {
  harnesses: string[];
  activeFilter: string;
  onFilterChange: (harness: string) => void;
};

export function QueueChipFilter(props: QueueChipFilterProps) {
  return (
    <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter by app">
      <ChipButton
        label="All"
        active={props.activeFilter === "all"}
        value="all"
        onClick={props.onFilterChange}
      />
      {props.harnesses.map((harness) => (
        <ChipButton
          key={harness}
          label={harnessDisplayName(harness)}
          active={props.activeFilter === harness}
          value={harness}
          onClick={props.onFilterChange}
        />
      ))}
    </div>
  );
}
