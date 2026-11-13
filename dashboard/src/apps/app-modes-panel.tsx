import { harnessDisplayName } from "../approval-center-utils";
import { appModes, appModesNote } from "../fleet-app-modes";
import { useFleetAppPosture } from "../fleet-app-protection";
import type { GuardSettings } from "../guard-types";

type AppModesPanelProps = {
  harness: string;
  /** Whether Guard manages this app's hooks; the switches only exist for managed apps. */
  managed: boolean;
  /** Opens the app's setup, for an app Guard does not manage yet. */
  onSetUp: () => void;
  /** Called after a saved change so the page can refresh what it shows. */
  onChanged?: () => Promise<void> | void;
};

/** One sentence on what runs in this app now, for the panel's lead line. */
export function appModesSummary(settings: GuardSettings, harness: string): string {
  const note = appModesNote(settings, harness);
  if (note !== null) return note;
  return appModes(settings, harness).cigar
    ? "Guard and CIGAR are both on"
    : "Guard is on";
}

/**
 * The app's own Guard and CIGAR switches, the same ones as on the Protect
 * screen, so an app can be configured from its page without going back to
 * the list. Saving, confirmation, managed locks and the approval proof all
 * come from the shared posture hook.
 */
export function AppModesPanel(props: AppModesPanelProps) {
  const apps = [{ harness: props.harness, active: props.managed }];
  const posture = useFleetAppPosture({ apps, onChanged: props.onChanged });
  const displayName = harnessDisplayName(props.harness);
  const control = posture.control(props.harness);
  const settings = posture.settings;

  return (
    <section
      aria-labelledby="app-modes-heading"
      className="rounded-xl border border-slate-100 p-4 sm:p-5"
      data-testid="app-modes-panel"
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between sm:gap-6">
        <div className="min-w-0">
          <h2 id="app-modes-heading" className="text-lg font-semibold text-brand-dark">
            What runs in {displayName}
          </h2>
          {settings !== null && control !== null ? (
            <p className="mt-1 text-sm font-medium text-brand-dark" data-testid="app-modes-summary">
              {appModesSummary(settings, props.harness)}
            </p>
          ) : null}
          <p className="mt-1 max-w-[65ch] text-sm text-slate-500">
            {props.managed
              ? "Guard checks this app's actions. CIGAR adds project context so the agent reads less and spends fewer tokens."
              : `Set up Guard for ${displayName} to choose whether Guard, CIGAR or both run here.`}
          </p>
        </div>
        {control}
        {!props.managed ? (
          <button
            type="button"
            onClick={props.onSetUp}
            className="shrink-0 self-start rounded-full border border-slate-200 px-3 py-1.5 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue sm:self-auto"
          >
            Set up Guard for {displayName}
          </button>
        ) : null}
      </div>
      {posture.watchConfirm(props.harness)}
      {posture.kind === "loading" && props.managed ? (
        <div className="guard-skeleton mt-3 h-6 w-48" aria-hidden="true" />
      ) : null}
      {posture.footer}
    </section>
  );
}
