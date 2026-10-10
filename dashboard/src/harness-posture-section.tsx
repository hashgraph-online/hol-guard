import { useCallback, useState } from "react";
import type { GuardProtectionCapability, GuardSettings } from "./guard-types";
import {
  harnessPostureOptions,
  harnessPostureRows,
  harnessPostureSummary,
  selectHarnessPosture,
  type HarnessPostureChoice,
  type HarnessPostureRow,
} from "./harness-posture-ui";

type HarnessPostureSectionProps = {
  settings: GuardSettings;
  capabilities: GuardProtectionCapability[];
  onSettingsChange: (settings: GuardSettings) => void;
};

/** Per-app Watch/Protected control. Apps with no choice of their own follow the machine setting above. */
export function HarnessPostureSection(props: HarnessPostureSectionProps) {
  const [pendingWatch, setPendingWatch] = useState<string | null>(null);
  const rows = harnessPostureRows(props.settings, props.capabilities);
  const locked = props.settings.harness_postures_locked === true;
  const { settings, onSettingsChange } = props;

  const handleChoice = useCallback((harness: string, choice: HarnessPostureChoice) => {
    if (choice === "watch") {
      setPendingWatch(harness);
      return;
    }
    setPendingWatch(null);
    onSettingsChange(selectHarnessPosture(settings, harness, choice));
  }, [onSettingsChange, settings]);

  const handleConfirmWatch = useCallback(() => {
    if (pendingWatch === null) return;
    onSettingsChange(selectHarnessPosture(settings, pendingWatch, "watch"));
    setPendingWatch(null);
  }, [onSettingsChange, pendingWatch, settings]);

  const handleCancelWatch = useCallback(() => setPendingWatch(null), []);

  if (rows.length === 0) return null;
  const pendingRow = rows.find((row) => row.harness === pendingWatch);

  return (
    <div className="space-y-3" data-testid="harness-posture-section">
      <p className="text-sm text-slate-500" data-testid="harness-posture-summary">
        {harnessPostureSummary(rows)}
      </p>
      {locked ? (
        <p className="text-sm text-slate-500">Your organization manages protection, so Watch is unavailable here.</p>
      ) : null}
      <ul className="divide-y divide-slate-100 rounded-xl border border-slate-200 bg-white">
        {rows.map((row) => (
          <HarnessPostureRowView
            key={row.harness}
            row={row}
            settings={settings}
            locked={locked}
            onChoose={handleChoice}
          />
        ))}
      </ul>
      {pendingRow !== undefined ? (
        <div
          className="flex flex-col gap-3 rounded-xl border border-brand-attention/30 bg-brand-attention/[0.06] px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
          role="alertdialog"
          aria-label={`Switch ${pendingRow.displayName} to Watch`}
        >
          <p className="text-sm text-brand-dark">
            Guard will only record in {pendingRow.displayName}. Your other apps stay protected.
          </p>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={handleConfirmWatch}
              className="inline-flex min-h-11 items-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white"
            >
              Switch to Watch
            </button>
            <button
              type="button"
              onClick={handleCancelWatch}
              className="inline-flex min-h-11 items-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark"
            >
              Keep protection on
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function HarnessPostureRowView(props: {
  row: HarnessPostureRow;
  settings: GuardSettings;
  locked: boolean;
  onChoose: (harness: string, choice: HarnessPostureChoice) => void;
}) {
  const options = harnessPostureOptions(props.settings, props.row.harness);
  const groupName = `harness-posture-${props.row.harness}`;
  return (
    <li className="flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0">
        <p className="text-sm font-medium text-brand-dark">{props.row.displayName}</p>
        <p className="text-xs text-slate-500">{rowCaption(props.row)}</p>
      </div>
      <fieldset className="border-0 p-0">
        <legend className="sr-only">{`Protection for ${props.row.displayName}`}</legend>
        <div className="flex gap-1 rounded-xl bg-slate-50 p-1">
          {options.map((option) => (
            <HarnessPostureChoiceView
              key={option.choice}
              groupName={groupName}
              choice={option.choice}
              label={option.label}
              selected={props.row.selected === option.choice}
              disabled={props.locked && option.choice === "watch"}
              harness={props.row.harness}
              onChoose={props.onChoose}
            />
          ))}
        </div>
      </fieldset>
    </li>
  );
}

function rowCaption(row: HarnessPostureRow): string {
  if (!row.hasOverride) return "Follows the machine setting";
  return row.effective === "watch" ? "Only recording" : "Set for this app";
}

function HarnessPostureChoiceView(props: {
  groupName: string;
  choice: HarnessPostureChoice;
  label: string;
  selected: boolean;
  disabled: boolean;
  harness: string;
  onChoose: (harness: string, choice: HarnessPostureChoice) => void;
}) {
  const handleChange = useCallback(() => {
    if (props.disabled) return;
    props.onChoose(props.harness, props.choice);
  }, [props.choice, props.disabled, props.harness, props.onChoose]);

  let choiceClass = "cursor-pointer text-slate-600 hover:text-brand-dark";
  if (props.disabled) choiceClass = "cursor-not-allowed text-slate-400";
  else if (props.selected) choiceClass = "cursor-pointer bg-white text-brand-dark shadow-sm";

  return (
    <label
      className={`flex min-h-11 min-w-24 items-center justify-center rounded-lg px-3 py-2 text-sm font-semibold transition-colors focus-within:ring-2 focus-within:ring-brand-blue ${choiceClass}`}
    >
      <input
        type="radio"
        name={props.groupName}
        value={props.choice}
        checked={props.selected}
        disabled={props.disabled}
        onChange={handleChange}
        className="sr-only"
      />
      {props.label}
    </label>
  );
}
