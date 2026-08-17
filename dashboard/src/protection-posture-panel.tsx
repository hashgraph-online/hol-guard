import { useCallback } from "react";
import type { GuardProtectionCapability } from "./guard-types";
import {
  POSTURE_OUTCOME_COLUMNS,
  PROTECTION_POSTURE_COPY,
  type ProtectionPosture,
} from "./protection-posture-copy";

const POSTURE_ORDER: ProtectionPosture[] = ["protected", "extra_careful", "watch"];

type ProtectionPosturePanelProps = {
  posture: ProtectionPosture;
  customRules: boolean;
  capabilities: GuardProtectionCapability[];
  onPostureChange: (posture: ProtectionPosture) => void;
};

export function ProtectionPosturePanel(props: ProtectionPosturePanelProps) {
  const copy = PROTECTION_POSTURE_COPY[props.posture];
  const outcomes = POSTURE_OUTCOME_COLUMNS[props.posture];

  return (
    <div className="space-y-6">
      <fieldset className="border-0 p-0">
        <legend className="sr-only">Protection</legend>
        <div className="flex flex-col gap-2 rounded-xl bg-slate-50 p-1 sm:flex-row">
          {POSTURE_ORDER.map((value) => (
            <PostureChoice
              key={value}
              value={value}
              selected={props.posture === value}
              onSelect={props.onPostureChange}
            />
          ))}
        </div>
      </fieldset>
      <p className="text-sm leading-relaxed text-slate-600">{copy.help}</p>
      {props.customRules ? (
        <p className="text-sm font-medium text-brand-dark">
          Using custom rules on top of {copy.label}
        </p>
      ) : null}
      <div className="grid gap-3 md:grid-cols-3">
        <OutcomeColumn title="Stops automatically" body={outcomes.stops} />
        <OutcomeColumn title="Asks once, then remembers" body={outcomes.asks} />
        <OutcomeColumn title="Runs quietly" body={outcomes.runs} />
      </div>
      {props.capabilities.length > 0 ? (
        <details className="rounded-xl border border-slate-200 bg-white">
          <summary className="flex min-h-11 cursor-pointer list-none items-center px-4 py-3 text-sm font-semibold text-brand-dark [&::-webkit-details-marker]:hidden">
            What this looks like in each app
          </summary>
          <ul className="space-y-3 border-t border-slate-100 px-4 py-3">
            {props.capabilities.map((capability) => (
              <li key={capability.harness}>
                <p className="text-sm font-medium text-brand-dark">{capability.display_name}</p>
                <p className="mt-0.5 text-sm text-slate-500">{capability.honesty_sentence}</p>
              </li>
            ))}
          </ul>
        </details>
      ) : null}
    </div>
  );
}

function PostureChoice(props: {
  value: ProtectionPosture;
  selected: boolean;
  onSelect: (posture: ProtectionPosture) => void;
}) {
  const handleChange = useCallback(() => {
    props.onSelect(props.value);
  }, [props.onSelect, props.value]);

  return (
    <label
      className={`flex min-h-11 flex-1 cursor-pointer items-center justify-center rounded-lg px-3 py-2 text-sm font-semibold transition-colors ${
        props.selected ? "bg-white text-brand-dark shadow-sm" : "text-slate-600 hover:text-brand-dark"
      }`}
    >
      <input
        type="radio"
        name="protection-posture"
        value={props.value}
        checked={props.selected}
        onChange={handleChange}
        className="sr-only"
      />
      {PROTECTION_POSTURE_COPY[props.value].label}
    </label>
  );
}

function OutcomeColumn(props: { title: string; body: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-400">{props.title}</p>
      <p className="mt-2 text-sm leading-relaxed text-slate-600">{props.body}</p>
    </div>
  );
}
