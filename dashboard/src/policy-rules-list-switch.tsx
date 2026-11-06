import type { PolicyActionFilter } from "./policy-rules-overview-model";

const OPTIONS: { value: PolicyActionFilter; label: string }[] = [
  { value: "all", label: "All actions" },
  { value: "allow", label: "Allow" },
  { value: "block", label: "Block" },
];

export function PolicyRulesListSwitch(props: {
  value: PolicyActionFilter;
  counts: Record<PolicyActionFilter, number>;
  onChange: (value: PolicyActionFilter) => void;
}) {
  return (
    <div className="guard-list-switch" style={{ marginTop: 0 }}>
      <div className="guard-list-switch-track" role="group" aria-label="Filter by action">
        {OPTIONS.map((option) => (
          <button
            key={option.value}
            type="button"
            aria-pressed={props.value === option.value}
            onClick={() => props.onChange(option.value)}
            className="guard-list-switch-option"
          >
            {option.label}
            <span className="guard-list-switch-count">{props.counts[option.value]}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
