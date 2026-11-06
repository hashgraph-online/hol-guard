import type { GuardActionExplanationV1 } from "./guard-types";

export function ActionExplanationSummary({ explanation }: { explanation: GuardActionExplanationV1 }) {
  return (
    <section
      className="mt-4 rounded-xl border border-slate-100 bg-slate-50/50 p-4"
      data-action-explanation
      data-action-identity={explanation.action_identity}
    >
      <p className="text-sm font-semibold text-brand-dark">{explanation.everyday.headline}</p>
      <p className="mt-1 text-sm text-slate-600">{explanation.everyday.summary}</p>
      {explanation.everyday.impact ? (
        <div className="mt-3">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">What could happen?</p>
          <p className="mt-1 text-sm text-brand-dark">{explanation.everyday.impact}</p>
        </div>
      ) : null}
      {explanation.everyday.recommendation ? (
        <div className="mt-3">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Recommended next step</p>
          <p className="mt-1 text-sm text-brand-dark">{explanation.everyday.recommendation}</p>
        </div>
      ) : null}
      <details className="mt-3">
        <summary className="cursor-pointer text-sm font-medium text-brand-blue">Show technical details</summary>
        <div className="mt-2 rounded-lg border border-slate-200 bg-white p-3 text-sm text-brand-dark">
          {explanation.technical.available && explanation.technical.command_display ? (
            <pre className="overflow-x-auto whitespace-pre-wrap break-words font-mono text-xs" data-exact-command>
              {explanation.technical.command_display}
            </pre>
          ) : (
            <p>{explanation.technical.unavailable_reason ?? "Technical details are unavailable."}</p>
          )}
        </div>
      </details>
    </section>
  );
}
