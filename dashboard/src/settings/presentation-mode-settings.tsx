import { useId } from "react";
import { usePresentationMode } from "../presentation-mode-provider";

export function PresentationModeSettings() {
  const { mode, presentation, loading, saving, error, saved, setMode, refresh } = usePresentationMode();
  const labelId = useId();
  const descriptionId = useId();
  const technical = mode === "technical";
  return (
    <section className="space-y-5" aria-label="Experience" data-presentation-settings>
      <div>
        <h2 className="text-lg font-semibold text-brand-dark">Experience</h2>
        <p className="mt-1 text-sm text-slate-600">
          Choose how much detail Guard shows. Your protection and approval rules stay the same.
        </p>
      </div>
      <div className="rounded-xl border border-slate-200 p-4">
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <p id={labelId} className="font-medium text-brand-dark">Technical Mode</p>
            <p id={descriptionId} className="mt-1 text-sm text-slate-600">
              Off: plain-language explanations first. On: retained local details open by default.
            </p>
          </div>
          <button
            type="button" role="switch" aria-checked={technical}
            aria-labelledby={labelId} aria-describedby={descriptionId}
            disabled={loading || saving || !presentation.writable}
            onClick={() => { void setMode(technical ? "everyday" : "technical"); }}
            className="inline-flex min-h-11 min-w-14 shrink-0 items-center justify-center rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue disabled:cursor-not-allowed disabled:opacity-50"
          >
            <span aria-hidden="true" className={`relative block h-7 w-12 rounded-full ${technical ? "bg-brand-blue" : "bg-slate-300"}`}>
              <span className={`absolute top-0.5 left-0.5 h-6 w-6 rounded-full bg-white shadow-sm ${technical ? "translate-x-5" : "translate-x-0"}`} />
            </span>
          </button>
        </div>
        <p className="mt-3 text-sm text-slate-600">
          This display preference is free and saved on this device. It does not enable Cloud sync.
          You can open technical details for one action without turning on Technical Mode.
        </p>
      </div>
      <div role="status" aria-live="polite" className="text-sm text-slate-600">
        {loading ? "Reading your local display preference…" : saving ? "Saving display preference…"
          : saved && !error ? "Saved on this device." : `Current view: ${technical ? "Technical Mode" : "Everyday Mode"}.`}
      </div>
      {!loading && !presentation.writable ? (
        <p className="text-sm text-slate-600">
          {presentation.diagnostic === "presentation_not_supported_by_core"
            || presentation.diagnostic === "unsupported_presentation_schema_fell_back_to_everyday"
            ? "Update HOL Guard Core to change this preference. The current view is read-only."
            : "The local display preference is unavailable. Reconnect to Core and reload it."}
        </p>
      ) : null}
      {error ? <p role="alert" className="text-sm text-brand-attention">{error}</p> : null}
      {error || !presentation.writable ? (
        <button type="button" onClick={() => { void refresh(); }} disabled={loading || saving}
          className="min-h-11 rounded-lg border border-slate-200 px-4 text-sm font-medium text-brand-dark">
          Reload display preference
        </button>
      ) : null}
    </section>
  );
}
