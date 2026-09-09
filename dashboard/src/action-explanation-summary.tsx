import type { GuardActionExplanationV1 } from "./guard-types";

export function ActionExplanationSummary({ explanation }: { explanation: GuardActionExplanationV1 }) {
  const { everyday, confidence, redaction } = explanation;
  return (
    <section className="mt-3 space-y-3" data-guard-action-explanation={explanation.schema_version}>
      <div>
        <h3 className="text-base font-semibold text-brand-dark">{everyday.headline}</h3>
        <p className="mt-1 break-words text-sm text-slate-600">{everyday.summary}</p>
      </div>
      {confidence === "limited" ? <p role="note" className="text-sm font-medium text-brand-attention">
        Guard could not confirm the full effect of this action. Review it carefully or stop it.
      </p> : null}
      {everyday.impact ? <p className="text-sm text-slate-600"><strong className="text-brand-dark">Possible impact: </strong>{everyday.impact}</p> : null}
      {everyday.why_guard_intervened ? <p className="text-sm text-slate-600"><strong className="text-brand-dark">Why Guard intervened: </strong>{everyday.why_guard_intervened}</p> : null}
      {everyday.consequences.length > 1 ? <ul className="list-disc space-y-1 pl-5 text-sm text-slate-600" aria-label="Possible effects">
        {everyday.consequences.map((item, index) => <li key={`${item.message_id}:${index}`}>{item.message}</li>)}
      </ul> : null}
      {everyday.recommendation ? <p className="text-sm font-medium text-brand-dark">{everyday.recommendation}</p> : null}
      {redaction.secret_like_values_removed ? <p className="text-xs text-slate-500">Secret-like values have been removed from this explanation.</p> : null}
      {redaction.truncated_fields.length > 0 ? <p className="text-xs text-slate-500">Some retained details are shortened. This explanation is not a complete copy of the action.</p> : null}
    </section>
  );
}
