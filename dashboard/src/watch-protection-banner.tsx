import { useCallback } from "react";
import { HiMiniExclamationTriangle } from "react-icons/hi2";
import { WATCH_BANNER_COPY } from "./protection-posture-copy";

export function WatchProtectionBanner(props: { onTurnProtectionOn?: () => void }) {
  const handleTurnOn = useCallback(() => {
    props.onTurnProtectionOn?.();
  }, [props.onTurnProtectionOn]);

  return (
    <div
      className="flex flex-col gap-3 rounded-xl border border-brand-attention/30 bg-brand-attention/[0.06] px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
      role="status"
    >
      <div className="flex items-start gap-3">
        <HiMiniExclamationTriangle className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention" aria-hidden="true" />
        <p className="text-sm font-semibold text-brand-dark">{WATCH_BANNER_COPY}</p>
      </div>
      {props.onTurnProtectionOn ? (
        <button
          type="button"
          onClick={handleTurnOn}
          className="inline-flex min-h-11 items-center justify-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white"
        >
          Turn protection on
        </button>
      ) : null}
    </div>
  );
}
