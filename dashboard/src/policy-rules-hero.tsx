import type { RulesHeroModel, RulesHeroTone } from "./policy-rules-hero-model";

const PILL_TONE: Record<RulesHeroTone, "safe" | "attention" | "info"> = {
  clear: "safe",
  review: "attention",
  setup: "info",
};

/**
 * Two lines, then the list. Headline + state pill, facts as one quiet
 * line. Everything else on this page is disclosure, not decoration.
 */
export function PolicyRulesHero(props: { model: RulesHeroModel }) {
  const { model } = props;
  return (
    <section className="guard-surface-in" role="region" aria-label="Remembered rules status">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <h1 className="text-xl font-semibold tracking-tight text-brand-dark sm:text-2xl">{model.headline}</h1>
        <span className="guard-state-pill" data-tone={PILL_TONE[model.tone]}>
          <span className="guard-state-pill-dot" aria-hidden="true" />
          {model.badge}
        </span>
      </div>
      <p className="mt-1 text-sm text-slate-500">
        {model.facts.join(" · ")}
        {model.subheadline ? <span className="text-slate-400"> — {model.subheadline}</span> : null}
      </p>
    </section>
  );
}
