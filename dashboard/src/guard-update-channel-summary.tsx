import type { ReactNode } from "react";
import { HiMiniBeaker } from "react-icons/hi2";

export type GuardUpdateChannelSummaryProps = {
  version: string | null;
  useAlpha: boolean;
  busy: boolean;
  onManage: () => void;
};

export function GuardUpdateChannelSummary(props: GuardUpdateChannelSummaryProps) {
  let versionContent: ReactNode = <span className="min-w-0 flex-1" aria-hidden="true" />;
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
      <div
        className="inline-flex min-w-0 shrink-0 items-center gap-1.5"
        role="status"
        aria-label="Alpha updates enabled"
      >
        <HiMiniBeaker className="h-3 w-3 shrink-0 text-brand-blue" aria-hidden="true" />
        <span className="text-[11px] font-semibold leading-4 text-brand-blue">Alpha updates</span>
        <button
          type="button"
          onClick={props.onManage}
          disabled={props.busy}
          aria-label="Manage alpha updates"
          title="Manage alpha updates"
          className="rounded-sm text-[11px] font-medium leading-4 text-brand-blue guard-quiet-link focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 disabled:cursor-not-allowed disabled:opacity-60"
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
        className="shrink-0 rounded-sm text-[11px] font-medium leading-4 text-brand-blue guard-quiet-link focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 disabled:cursor-not-allowed disabled:opacity-60"
      >
        Try alpha updates
      </button>
    );
  }

  return <div className="flex items-center justify-between gap-2">{versionContent}{channelAction}</div>;
}
