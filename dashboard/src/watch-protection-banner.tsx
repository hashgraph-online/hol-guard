import { useCallback, useState, type ReactNode } from "react";
import { HiMiniExclamationTriangle } from "react-icons/hi2";
import { WATCH_BANNER_COPY } from "./protection-posture-copy";
import type { WatchBannerModel } from "./harness-posture-ui";

type WatchProtectionBannerProps = {
  onTurnProtectionOn?: () => void;
  /** Names which apps are in Watch. Without it the banner describes the whole machine. */
  model?: WatchBannerModel | null;
};

const DEFAULT_CONFIRM = "Guard will start stopping dangerous actions.";

export function WatchProtectionBanner(props: WatchProtectionBannerProps) {
  const [confirming, setConfirming] = useState(false);
  const { onTurnProtectionOn } = props;
  const handleAsk = useCallback(() => setConfirming(true), []);
  const handleCancel = useCallback(() => setConfirming(false), []);
  const handleConfirm = useCallback(() => {
    setConfirming(false);
    onTurnProtectionOn?.();
  }, [onTurnProtectionOn]);

  const message = props.model?.message ?? WATCH_BANNER_COPY;
  const confirmMessage = props.model?.confirmMessage ?? DEFAULT_CONFIRM;
  const actionLabel = props.model !== undefined && props.model !== null && !props.model.globalWatch
    ? "Turn protection on for these apps"
    : "Turn protection on";

  let action: ReactNode = null;
  if (onTurnProtectionOn !== undefined && confirming) {
    action = (
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={handleConfirm}
          className="inline-flex min-h-11 items-center justify-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white"
        >
          Turn on
        </button>
        <button
          type="button"
          onClick={handleCancel}
          className="inline-flex min-h-11 items-center justify-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark"
        >
          Not now
        </button>
      </div>
    );
  } else if (onTurnProtectionOn !== undefined) {
    action = (
      <button
        type="button"
        onClick={handleAsk}
        className="inline-flex min-h-11 items-center justify-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white"
      >
        {actionLabel}
      </button>
    );
  }

  return (
    <div
      className="flex flex-col gap-3 rounded-xl border border-brand-attention/30 bg-brand-attention/[0.06] px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
      role="status"
    >
      <div className="flex items-start gap-3">
        <HiMiniExclamationTriangle className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention" aria-hidden="true" />
        <div>
          <p className="text-sm font-semibold text-brand-dark">{message}</p>
          {confirming ? <p className="mt-1 text-sm text-slate-600">{confirmMessage}</p> : null}
        </div>
      </div>
      {action}
    </div>
  );
}
