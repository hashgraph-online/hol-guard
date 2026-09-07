import type { ReactNode } from "react";
import { HiMiniBeaker } from "react-icons/hi2";

export type GuardUpdateChannelSummaryProps = {
  version: string | null;
  useAlpha: boolean;
  busy: boolean;
  onManage: () => void;
};

// Inline channel control for the Local Guard status row: the card's 11px
// status typography with a 24px minimum hit target.
export const GUARD_UPDATE_CHANNEL_CONTROL_CLASS =
  "inline-flex min-h-6 shrink-0 items-center gap-1 rounded-sm px-0.5 text-[11px] font-semibold leading-4 text-brand-blue transition-opacity hover:opacity-80 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 disabled:cursor-not-allowed disabled:opacity-60";

// Compact pill for panel-level actions (update, reinstall): 32px target that
// sits inline beside the status line instead of filling the card width.
export const GUARD_UPDATE_ACTION_BUTTON_CLASS =
  "inline-flex min-h-8 shrink-0 items-center justify-center gap-1 rounded-full border border-brand-blue/30 bg-white px-2.5 text-[11px] font-semibold text-brand-blue transition-colors hover:bg-brand-blue/5 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 disabled:cursor-not-allowed disabled:opacity-60";

export function GuardUpdateChannelSummary(props: GuardUpdateChannelSummaryProps) {
  let channelStatus: ReactNode = null;
  if (props.useAlpha) {
    channelStatus = (
      <span
        className="inline-flex min-w-0 items-center gap-1 text-[11px] font-semibold leading-4 text-brand-blue"
        role="status"
        aria-label="Alpha updates enabled"
      >
        <HiMiniBeaker className="h-3 w-3 shrink-0" aria-hidden="true" />
        <span className="truncate">Alpha updates</span>
      </span>
    );
  }

  return (
    <div className="flex min-w-0 items-center justify-between gap-1.5">
      <span className="inline-flex min-w-0 items-center gap-1">
        {props.version ? (
          <span
            className="shrink-0 font-mono text-[10px] leading-4 text-brand-dark/70"
            aria-label={`Guard version ${props.version}`}
          >
            v{props.version}
          </span>
        ) : null}
        {channelStatus}
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
          Manage
        </button>
      ) : (
        <button
          type="button"
          onClick={props.onManage}
          disabled={props.busy}
          data-testid="guard-alpha-updates-control"
          className={GUARD_UPDATE_CHANNEL_CONTROL_CLASS}
        >
          <HiMiniBeaker className="h-3 w-3 shrink-0" aria-hidden="true" />
          Try alpha updates
        </button>
      )}
    </div>
  );
}
