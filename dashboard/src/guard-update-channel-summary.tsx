import type { ReactNode } from "react";
import { HiMiniBeaker } from "react-icons/hi2";

export type GuardUpdateChannelSummaryProps = {
  version: string | null;
  useAlpha: boolean;
  busy: boolean;
  onManage: () => void;
};

const CHANNEL_BUTTON_CLASS =
  "inline-flex min-h-11 w-full items-center justify-center gap-1.5 rounded-lg border border-brand-blue/30 bg-white px-3 py-2 text-sm font-semibold text-brand-blue transition-colors hover:bg-brand-blue/5 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 disabled:cursor-not-allowed disabled:opacity-60";

export function GuardUpdateChannelSummary(props: GuardUpdateChannelSummaryProps) {
  let versionContent: ReactNode = null;
  if (props.version) {
    versionContent = (
      <p
        className="min-w-0 truncate font-mono text-[10px] leading-4 text-brand-dark/70"
        aria-label={`Guard version ${props.version}`}
      >
        v{props.version}
      </p>
    );
  }

  let channelAction: ReactNode;
  if (props.useAlpha) {
    channelAction = (
      <div className="flex min-w-0 items-center justify-between gap-2">
        <div
          className="inline-flex min-w-0 items-center gap-1.5"
          role="status"
          aria-label="Alpha updates enabled"
        >
          <HiMiniBeaker className="h-4 w-4 shrink-0 text-brand-blue" aria-hidden="true" />
          <span className="text-sm font-semibold leading-5 text-brand-blue">Alpha updates</span>
        </div>
        <button
          type="button"
          onClick={props.onManage}
          disabled={props.busy}
          aria-label="Manage alpha updates"
          title="Manage alpha updates"
          data-testid="guard-alpha-updates-control"
          className="inline-flex min-h-11 shrink-0 items-center rounded-lg px-3 text-sm font-semibold text-brand-blue transition-colors hover:bg-brand-blue/5 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 disabled:cursor-not-allowed disabled:opacity-60"
        >
          Manage
        </button>
      </div>
    );
  } else {
    channelAction = (
      <button
        type="button"
        onClick={props.onManage}
        disabled={props.busy}
        data-testid="guard-alpha-updates-control"
        className={CHANNEL_BUTTON_CLASS}
      >
        <HiMiniBeaker className="h-4 w-4 shrink-0" aria-hidden="true" />
        Try alpha updates
      </button>
    );
  }

  return (
    <div className="space-y-1.5">
      {versionContent}
      {channelAction}
    </div>
  );
}
