import { HiMiniArrowPath } from "react-icons/hi2";

import { EXTENSION_PANEL_CLASS } from "./protection-surface";

export function ExtensionsLoadingState(props: { label: string }) {
  return (
    <div className="grid min-h-[60vh] place-items-center" aria-busy="true">
      <div className="flex flex-col items-center gap-3">
        <div className="guard-skeleton h-8 w-48" />
        <p className="text-sm text-brand-dark/70">{props.label}</p>
        <HiMiniArrowPath
          className="size-7 animate-spin text-brand-blue motion-reduce:animate-none"
          aria-hidden="true"
        />
      </div>
    </div>
  );
}

export function ExtensionsLoadError(props: {
  title: string;
  detail: string;
  reference?: string;
  onRetry: () => void;
}) {
  return (
    <div className="mx-auto max-w-4xl">
      <div className={`${EXTENSION_PANEL_CLASS} guard-extensions-tone-danger`}>
        <h1 className="text-xl font-semibold text-red-950">{props.title}</h1>
        <p role="alert" className="mt-2 text-sm text-red-800">{props.detail}</p>
        <p className="mt-3 text-xs font-medium text-red-900">Local protection continues on this device.</p>
        {props.reference ? (
          <p className="mt-2 text-xs text-red-900">
            Reference: <span className="font-mono break-all">{props.reference}</span>
          </p>
        ) : null}
        <button
          type="button"
          onClick={props.onRetry}
          className="mt-4 min-h-11 rounded-xl bg-red-800 px-4 text-sm font-semibold text-white"
        >
          Try again
        </button>
      </div>
    </div>
  );
}

export function ExtensionsNotFound(props: {
  title: string;
  detail: string;
  onBack: () => void;
}) {
  return (
    <div className="mx-auto max-w-4xl">
      <div className={`${EXTENSION_PANEL_CLASS} guard-extensions-tone-attention`}>
        <h1 className="font-semibold text-amber-950">{props.title}</h1>
        <p className="mt-2 text-sm text-amber-900">{props.detail}</p>
        <button
          type="button"
          onClick={props.onBack}
          className="mt-4 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white"
        >
          Back to Extensions
        </button>
      </div>
    </div>
  );
}
