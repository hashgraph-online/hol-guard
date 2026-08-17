import { useCallback } from "react";
import { HiMiniKey } from "react-icons/hi2";
import { SectionLabel } from "./approval-center-primitives";
import type { ApprovalScopeChoice } from "./approval-scopes";
import type { DecisionScope } from "./guard-types";

type ReviewScopeControlsProps = {
  commonScopeOptions: ApprovalScopeChoice[];
  broaderScopeOptions: ApprovalScopeChoice[];
  advancedScopeOptions: ApprovalScopeChoice[];
  blockScopeOptions: ApprovalScopeChoice[];
  hasAllowScope: boolean;
  taskCapabilityCopy: string | null;
  exactActionPersistenceEligible: boolean;
  rememberExactAction: boolean;
  allowScope: DecisionScope;
  blockScope: DecisionScope;
  onAllowScopeChange: (scope: DecisionScope) => void;
  onBlockScopeChange: (scope: DecisionScope) => void;
  onRememberExactActionChange: (checked: boolean) => void;
};

export function ReviewScopeControls(props: ReviewScopeControlsProps) {
  return (
    <div className="mt-6 space-y-2">
      <SectionLabel>Approval scope</SectionLabel>
      {!props.hasAllowScope && (
        <p className="text-sm text-brand-attention" role="status">
          This action cannot be approved under its current Guard policy.
        </p>
      )}
      <div className="grid grid-cols-1 gap-2 md:grid-cols-2" role="radiogroup" aria-label="Allow scope selection">
        {props.commonScopeOptions.map((choice) => (
          <ScopeChoiceButton
            key={choice.value}
            choice={choice}
            checked={props.allowScope === choice.value}
            onScopeChange={props.onAllowScopeChange}
          />
        ))}
      </div>
      {props.exactActionPersistenceEligible && props.allowScope === "artifact" && (
        <ExactActionPersistenceChoice
          checked={props.rememberExactAction}
          onChange={props.onRememberExactActionChange}
        />
      )}
      {props.broaderScopeOptions.length > 0 && (
        <details className="rounded-xl border border-brand-blue/15 bg-brand-blue/[0.03] p-3">
          <summary className="cursor-pointer select-none text-xs font-semibold uppercase tracking-[0.16em] text-brand-blue">
            Save for this app
          </summary>
          <p className="mt-2 text-xs text-brand-dark/70">
            These options save the same action for this app. They do not grant unrelated actions.
          </p>
          <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-2">
            {props.broaderScopeOptions.map((choice) => (
              <ScopeChoiceButton
                key={choice.value}
                choice={choice}
                checked={props.allowScope === choice.value}
                onScopeChange={props.onAllowScopeChange}
              />
            ))}
          </div>
        </details>
      )}
      {props.advancedScopeOptions.length > 0 && (
        <details className="rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] p-3">
          <summary className="cursor-pointer select-none text-xs font-semibold uppercase tracking-[0.16em] text-brand-attention">
            Advanced: save everywhere on this machine
          </summary>
          <p className="mt-2 text-xs text-brand-dark/70">
            This saves a decision that applies across all your projects on this machine. Matching actions skip review permanently. Only use this if you fully trust this action everywhere.
          </p>
          <div className="mt-3 grid grid-cols-1 gap-2">
            {props.advancedScopeOptions.map((choice) => (
              <ScopeChoiceButton
                key={choice.value}
                choice={choice}
                checked={props.allowScope === choice.value}
                onScopeChange={props.onAllowScopeChange}
              />
            ))}
          </div>
        </details>
      )}
      {props.taskCapabilityCopy !== null && (
        <div className="flex items-start gap-2 pt-1 text-xs text-brand-dark/70">
          <HiMiniKey className="mt-0.5 h-4 w-4 shrink-0 text-brand-blue" aria-hidden="true" />
          <p>{props.taskCapabilityCopy}</p>
        </div>
      )}
      {props.blockScopeOptions.length > 0 && (
        <details className="rounded-xl border border-slate-200/70 bg-slate-50/60 p-3">
          <summary className="cursor-pointer select-none text-xs font-semibold uppercase tracking-[0.16em] text-brand-dark">
            Block matching actions
          </summary>
          <p className="mt-2 text-xs text-brand-dark/70">
            Blocking can cover a wider trusted selector without granting permission to run anything.
          </p>
          <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-2" role="radiogroup" aria-label="Block scope selection">
            {props.blockScopeOptions.map((choice) => (
              <ScopeChoiceButton
                key={choice.value}
                choice={choice}
                checked={props.blockScope === choice.value}
                onScopeChange={props.onBlockScopeChange}
              />
            ))}
          </div>
        </details>
      )}
    </div>
  );
}

function ExactActionPersistenceChoice(props: { checked: boolean; onChange: (checked: boolean) => void }) {
  const handleOnce = useCallback(() => props.onChange(false), [props.onChange]);
  const handleAlways = useCallback(() => props.onChange(true), [props.onChange]);

  return (
    <fieldset className="rounded-lg border border-brand-blue/20 bg-brand-blue/[0.03] p-3">
      <legend className="px-1 text-sm font-semibold text-brand-dark">How long should Guard allow it?</legend>
      <div className="mt-1 grid grid-cols-1 gap-2 sm:grid-cols-2">
        <label className={exactActionChoiceClassName(!props.checked)}>
          <input
            type="radio"
            name="exact-action-approval-duration"
            value="once"
            checked={!props.checked}
            onChange={handleOnce}
            className="sr-only"
          />
          <span className="block text-sm font-semibold text-brand-dark">This time</span>
          <span className="mt-0.5 block text-xs text-muted-foreground">Retry within 15 minutes.</span>
        </label>
        <label className={exactActionChoiceClassName(props.checked)}>
          <input
            type="radio"
            name="exact-action-approval-duration"
            value="always"
            checked={props.checked}
            onChange={handleAlways}
            className="sr-only"
          />
          <span className="block text-sm font-semibold text-brand-dark">Always allow exact action</span>
          <span className="mt-0.5 block text-xs text-muted-foreground">Changed commands still need review.</span>
        </label>
      </div>
    </fieldset>
  );
}

function exactActionChoiceClassName(selected: boolean): string {
  const base = "min-h-20 cursor-pointer rounded-md border px-3 py-2 text-left transition-colors focus-within:ring-2 focus-within:ring-brand-blue";
  if (selected) return `${base} border-brand-blue bg-white ring-1 ring-brand-blue/20`;
  return `${base} border-slate-200 bg-white/60 hover:border-brand-blue/40`;
}

function ScopeChoiceButton(props: {
  choice: ApprovalScopeChoice;
  checked: boolean;
  onScopeChange: (scope: DecisionScope) => void;
}) {
  const handleClick = useCallback(() => {
    props.onScopeChange(props.choice.value);
  }, [props.onScopeChange, props.choice.value]);

  return (
    <button
      type="button"
      onClick={handleClick}
      role="radio"
      aria-checked={props.checked}
      className={`rounded-xl border px-4 py-3 text-left transition-all focus:outline-none focus:ring-2 focus:ring-brand-blue/20 ${
        props.checked ? "border-brand-blue bg-brand-blue/[0.06]" : "border-slate-200/70 bg-white hover:bg-slate-50"
      }`}
    >
      <p className="text-sm font-medium text-brand-dark">{props.choice.label}</p>
      <p className="mt-0.5 text-xs text-muted-foreground">{props.choice.description}</p>
    </button>
  );
}

export function allowButtonLabel(scope: DecisionScope): string {
  if (scope === "artifact") {
    return "Allow just this once";
  }
  if (scope === "workspace") {
    return "Allow and remember for this project";
  }
  return "Approve and remember";
}

export function blockButtonLabel(scope: DecisionScope): string {
  if (scope === "artifact") {
    return "Keep blocked";
  }
  if (scope === "workspace") {
    return "Block in project";
  }
  return "Block matching actions";
}
