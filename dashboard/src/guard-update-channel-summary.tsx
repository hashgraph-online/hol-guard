import { HiMiniBeaker } from "react-icons/hi2";

export type GuardUpdateChannelSummaryProps = {
  version: string | null;
  useAlpha: boolean;
  busy: boolean;
  onManage: () => void;
};

// The app-wide `button { font: inherit }` reset is unlayered CSS, so it
// outranks Tailwind's layered text utilities on form controls. Buttons here
// size their label through an inner span instead (same pattern as the card's
// Open Inbox action).
export const GUARD_UPDATE_CONTROL_TEXT_CLASS = "text-[11px] font-semibold leading-4";

export const GUARD_UPDATE_CHANNEL_CONTROL_CLASS =
  "inline-flex min-h-8 shrink-0 items-center rounded-sm px-0.5 text-brand-blue transition-opacity hover:opacity-80 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 disabled:cursor-not-allowed disabled:opacity-60";

// Compact pill for panel-level actions (update, reinstall): 32px target that
// sits inline beside the status line instead of filling the card width.
export const GUARD_UPDATE_ACTION_BUTTON_CLASS =
  "inline-flex min-h-8 shrink-0 items-center justify-center gap-1 rounded-full border border-brand-blue/30 bg-white px-2.5 text-brand-blue transition-colors hover:bg-brand-blue/5 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 disabled:cursor-not-allowed disabled:opacity-60";

export function GuardUpdateChannelSummary(props: GuardUpdateChannelSummaryProps) {
  return (
    <div className="flex min-w-0 items-center justify-between gap-1.5">
      <span className="inline-flex min-w-0 items-center gap-1.5">
        {props.version ? (
          <span
            className="min-w-0 font-mono text-[10px] leading-4 text-brand-dark/70 [overflow-wrap:anywhere]"
            aria-label={`Guard version ${props.version}`}
          >
            v{props.version}
          </span>
        ) : null}
        {props.useAlpha ? (
          <span
            className="inline-flex shrink-0 items-center gap-1 rounded-full bg-brand-blue/15 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-brand-blue"
            role="status"
            aria-label="Alpha updates enabled"
          >
            <HiMiniBeaker className="h-2.5 w-2.5" aria-hidden="true" />
            Alpha
          </span>
        ) : null}
      </span>
      {props.useAlpha ? (
        <button
          type="button"
          onClick={props.onManage}
          disabled={props.busy}
          aria-label="Manage alpha updates"
          title="Manage alpha updates"
          data-testid="guard-alpha-updates-control"
          className={GUARD_UPDATE_CHANNEL_CONTROL_CLASS}
        >
          <span className={GUARD_UPDATE_CONTROL_TEXT_CLASS}>Manage</span>
        </button>
      ) : (
        <button
          type="button"
          onClick={props.onManage}
          disabled={props.busy}
          data-testid="guard-alpha-updates-control"
          className={GUARD_UPDATE_CHANNEL_CONTROL_CLASS}
        >
          <HiMiniBeaker className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span className={GUARD_UPDATE_CONTROL_TEXT_CLASS}>Try alpha updates</span>
        </button>
      )}
    </div>
  );
}
