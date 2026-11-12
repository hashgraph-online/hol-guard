import { useId } from "react";

type FleetAppModeSwitchProps = {
  /** Visible name of what the switch runs, such as "Guard" or "CIGAR". */
  label: string;
  /** Accessible name that also says which app, such as "Guard in Codex". */
  accessibleName: string;
  checked: boolean;
  disabled: boolean;
  /** Why the switch cannot be used, read with it and shown on hover. */
  unavailableReason?: string;
  /** Attention tone when off, for the switch whose off state lowers protection. */
  attentionWhenOff?: boolean;
  onToggle: () => void;
  testId: string;
};

/**
 * A labelled on/off switch for one app's Guard or CIGAR. The visible label
 * sits beside the track so a row reads "Guard ● CIGAR ●" at a glance.
 */
export function FleetAppModeSwitch(props: FleetAppModeSwitchProps) {
  const reasonId = useId();
  const { checked, disabled } = props;
  const track = checked
    ? "bg-brand-blue"
    : props.attentionWhenOff
      ? "bg-brand-attention/40"
      : "bg-slate-200";
  return (
    <label
      className={`inline-flex min-h-11 items-center gap-2 rounded-lg px-1 ${disabled ? "cursor-not-allowed" : "cursor-pointer"}`}
      title={props.unavailableReason}
    >
      <span className={`text-xs font-semibold ${disabled ? "text-slate-400" : "text-brand-dark"}`}>{props.label}</span>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={props.accessibleName}
        aria-describedby={props.unavailableReason ? reasonId : undefined}
        disabled={disabled}
        onClick={props.onToggle}
        data-testid={props.testId}
        className={`relative h-6 w-10 shrink-0 rounded-full transition-colors duration-200 ease-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/60 focus-visible:ring-offset-2 disabled:opacity-50 ${track}`}
      >
        <span
          aria-hidden="true"
          className={`absolute top-0.5 left-0.5 h-5 w-5 rounded-full bg-white shadow-[0_1px_2px_rgba(15,23,42,0.2)] transition-transform duration-200 ease-out ${
            checked ? "translate-x-4" : "translate-x-0"
          }`}
        />
      </button>
      {props.unavailableReason ? <span id={reasonId} className="sr-only">{props.unavailableReason}</span> : null}
    </label>
  );
}
