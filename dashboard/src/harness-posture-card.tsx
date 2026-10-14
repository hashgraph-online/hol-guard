import { Fragment, useCallback, useMemo, useState, type ReactNode } from "react";
import { HiMiniEye, HiMiniMagnifyingGlass, HiMiniShieldCheck } from "react-icons/hi2";

import { ActionButton } from "./approval-center-primitives";
import type { GuardProtectionCapability, GuardSettings } from "./guard-types";
import {
  canRestartHarnessWatch,
  globalPosture,
  harnessPostureOptions,
  harnessPostureRows,
  harnessPostureSummary,
  harnessRowStatus,
  harnessRowTone,
  harnessWatchPrompt,
  joinNames,
  restartHarnessWatch,
  selectHarnessPosture,
  sortHarnessRows,
  overrideRows,
  type HarnessPostureChoice,
  type HarnessPostureRow,
} from "./harness-posture-ui";
import { PROTECTION_POSTURE_COPY } from "./protection-posture-copy";

type HarnessPostureCardProps = {
  settings: GuardSettings;
  capabilities: GuardProtectionCapability[];
  onSettingsChange: (settings: GuardSettings) => void;
  /** Switches to another settings tab, shown as the link back to the machine posture. */
  onChangeTab?: (tab: "protection") => void;
  testId?: string;
};

/**
 * Full per-app protection manager for the Apps settings tab. Rows in Watch sort
 * first, each app shows where its level comes from, and switching to Watch
 * confirms inline next to the app it affects.
 */
export function HarnessPostureManager(props: HarnessPostureCardProps) {
  const { settings, onSettingsChange } = props;
  const [pendingWatch, setPendingWatch] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const locked = settings.harness_postures_locked === true;
  const rows = useMemo(() => harnessPostureRows(settings, props.capabilities), [settings, props.capabilities]);
  const sortedRows = useMemo(() => sortHarnessRows(rows), [rows]);
  const query = search.trim().toLowerCase();
  const visibleRows = query.length === 0
    ? sortedRows
    : sortedRows.filter((row) =>
        row.displayName.toLowerCase().includes(query) || row.harness.toLowerCase().includes(query)
      );
  const machineLabel = PROTECTION_POSTURE_COPY[globalPosture(settings)].label;
  const pendingRow = pendingWatch !== null
    ? visibleRows.find((row) => row.harness === pendingWatch)
    : undefined;

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

  const handleRestartWatch = useCallback((harness: string) => {
    onSettingsChange(restartHarnessWatch(settings, harness));
  }, [onSettingsChange, settings]);

  if (rows.length === 0) return null;
  const watchingCount = rows.filter((row) => harnessRowTone(row) === "watch").length;

  return (
    <div className="space-y-3" data-testid={props.testId ?? "harness-posture-section"}>
      <div
        className={`rounded-xl border px-4 py-3 ${
          watchingCount > 0
            ? "border-brand-attention/25 bg-brand-attention/[0.05]"
            : "border-brand-green/20 bg-brand-green/[0.05]"
        }`}
        data-testid="harness-posture-status"
      >
        <p className="flex items-center gap-2 text-sm font-semibold text-brand-dark">
          <StatusDot tone={watchingCount > 0 ? "watch" : "protected"} />
          {harnessPostureSummary(rows)}
        </p>
        <p className="mt-1 text-sm text-slate-500">
          Apps start with the machine setting ({machineLabel}) and only differ when you give one its own choice.
        </p>
        {props.onChangeTab ? (
          <button
            type="button"
            onClick={() => props.onChangeTab?.("protection")}
            className="mt-2 min-h-11 text-sm font-semibold text-brand-blue underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue sm:min-h-0"
          >
            Change the machine setting
          </button>
        ) : null}
      </div>

      {locked ? (
        <p className="text-sm text-slate-500">
          Your organization manages protection for each app, so these choices can't be changed here.
        </p>
      ) : null}

      <div className="relative">
        <HiMiniMagnifyingGlass className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" aria-hidden="true" />
        <input
          type="search"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Find an app..."
          aria-label="Find an app"
          className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-4 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        />
      </div>

      <ul className="divide-y divide-slate-100 rounded-xl border border-slate-200 bg-white">
        {visibleRows.map((row) => (
          <Fragment key={row.harness}>
            <HarnessPostureRowCard
              row={row}
              settings={settings}
              locked={locked}
              capability={props.capabilities.find((item) => item.harness === row.harness) ?? null}
              onChoose={handleChoice}
              onRestartWatch={handleRestartWatch}
            />
            {pendingRow?.harness === row.harness ? (
              <li
                className="bg-brand-attention/[0.06]"
                role="alertdialog"
                aria-label={`Switch ${pendingRow.displayName} to Watch`}
              >
                <div className="flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
                  <p className="text-sm text-brand-dark">{harnessWatchPrompt(rows, pendingRow.harness)}</p>
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
              </li>
            ) : null}
          </Fragment>
        ))}
      </ul>
      {visibleRows.length === 0 ? (
        <p className="text-sm text-slate-500">No apps match your search.</p>
      ) : null}
    </div>
  );
}

function HarnessPostureRowCard(props: {
  row: HarnessPostureRow;
  settings: GuardSettings;
  locked: boolean;
  capability: GuardProtectionCapability | null;
  onChoose: (harness: string, choice: HarnessPostureChoice) => void;
  onRestartWatch: (harness: string) => void;
}) {
  const { row } = props;
  const tone = harnessRowTone(row);
  const options = harnessPostureOptions(props.settings, row.harness);
  const restartPending = props.settings.harness_watch_restart?.includes(row.harness) === true;
  const canRestart = !props.locked && canRestartHarnessWatch(props.settings, row.harness);

  return (
    <li className={tone === "watch" ? "bg-brand-attention/[0.04]" : undefined} data-harness={row.harness}>
      <div className="flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <p className="flex items-center gap-2 text-sm font-semibold text-brand-dark">
            {tone === "watch"
              ? <HiMiniEye className="h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />
              : <HiMiniShieldCheck className="h-4 w-4 shrink-0 text-brand-blue" aria-hidden="true" />}
            {row.displayName}
          </p>
          <p className="mt-0.5 text-xs text-slate-500">{harnessRowStatus(row)}</p>
          {props.capability?.limited ? (
            <p className="mt-0.5 text-xs text-slate-400" title={props.capability.honesty_sentence}>
              Limited: {props.capability.honesty_sentence}
            </p>
          ) : null}
          {canRestart && restartPending ? (
            <p className="text-xs text-slate-500">Watch timer restarts when you save.</p>
          ) : null}
          {canRestart && !restartPending ? (
            <button
              type="button"
              onClick={() => props.onRestartWatch(row.harness)}
              className="mt-1 min-h-11 text-xs font-semibold text-brand-blue underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue sm:min-h-0"
            >
              Restart Watch timer
            </button>
          ) : null}
        </div>
        <fieldset className="border-0 p-0">
          <legend className="sr-only">{`Protection for ${row.displayName}`}</legend>
          <div className="inline-flex gap-1 rounded-xl bg-slate-100 p-1">
            {options.map((option) => (
              <HarnessPostureChoiceLabel
                key={option.choice}
                groupName={`harness-posture-${row.harness}`}
                choice={option.choice}
                label={option.label}
                selected={row.selected === option.choice}
                disabled={props.locked}
                harness={row.harness}
                onChoose={props.onChoose}
              />
            ))}
          </div>
        </fieldset>
      </div>
    </li>
  );
}

export function HarnessPostureChoiceLabel(props: {
  groupName: string;
  choice: HarnessPostureChoice;
  label: string;
  selected: boolean;
  disabled: boolean;
  harness: string;
  onChoose: (harness: string, choice: HarnessPostureChoice) => void;
  /** Dense layout for inline surfaces such as the Protect screen. */
  compact?: boolean;
}) {
  const handleChange = useCallback(() => {
    if (props.disabled) return;
    props.onChoose(props.harness, props.choice);
  }, [props.choice, props.disabled, props.harness, props.onChoose]);

  const isWatch = props.choice === "watch";
  let choiceClass = "cursor-pointer text-slate-600 hover:text-brand-dark";
  if (props.disabled && props.selected) choiceClass = "cursor-not-allowed text-slate-500";
  else if (props.disabled) choiceClass = "cursor-not-allowed text-slate-400";
  else if (props.selected) {
    choiceClass = isWatch
      ? "cursor-pointer bg-brand-attention text-white shadow-sm"
      : "cursor-pointer bg-brand-blue text-white shadow-sm";
  }

  let icon: ReactNode = null;
  if (!props.compact) {
    icon = isWatch
      ? <HiMiniEye className="h-4 w-4 shrink-0" aria-hidden="true" />
      : <HiMiniShieldCheck className="h-4 w-4 shrink-0" aria-hidden="true" />;
  }

  return (
    <label
      className={`flex min-h-11 items-center justify-center rounded-lg py-2 text-sm font-semibold transition-colors focus-within:ring-2 focus-within:ring-brand-blue ${
        props.compact ? "min-w-20 px-2.5" : "min-w-24 gap-1.5 px-3"
      } ${choiceClass}`}
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
      {icon}
      {props.label}
    </label>
  );
}

function StatusDot(props: { tone: "protected" | "watch" }) {
  return (
    <span
      aria-hidden="true"
      className={`h-2 w-2 shrink-0 rounded-full ${props.tone === "watch" ? "bg-brand-attention" : "bg-brand-green"}`}
    />
  );
}

/** Compact stand-in for the full manager, shown on the Protection tab. */
export function HarnessPostureSummaryCard(props: {
  settings: GuardSettings;
  capabilities: GuardProtectionCapability[];
  onOpenApps: () => void;
}) {
  const rows = harnessPostureRows(props.settings, props.capabilities);
  if (rows.length === 0) return null;
  const overrides = overrideRows(rows);
  return (
    <div
      className="flex flex-col gap-3 py-3 sm:flex-row sm:items-center sm:justify-between"
      data-testid="harness-posture-summary-card"
    >
      <div className="min-w-0">
        <p className="flex items-center gap-2 text-sm font-medium text-brand-dark">
          <StatusDot tone={rows.some((row) => harnessRowTone(row) === "watch") ? "watch" : "protected"} />
          {harnessPostureSummary(rows)}
        </p>
        <p className="mt-0.5 text-xs text-slate-500">
          {overrides.length > 0
            ? `Your choices: ${joinNames(overrides.map((row) => row.displayName))}.`
            : "Apps follow the machine setting unless you choose Watch for one of them."}
        </p>
      </div>
      <div className="shrink-0">
        <ActionButton variant="outline" onClick={props.onOpenApps}>Choose per app</ActionButton>
      </div>
    </div>
  );
}
