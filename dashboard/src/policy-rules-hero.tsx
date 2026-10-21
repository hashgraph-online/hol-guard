import type { ReactNode } from "react";
import type { RulesHeroModel, RulesHeroTone } from "./policy-rules-hero-model";

const PILL_TONE: Record<RulesHeroTone, "safe" | "attention" | "info"> = {
  clear: "safe",
  review: "attention",
  setup: "info",
};

/**
 * The rules header: a light, native surface — not the Home hero. One
 * headline that says what Guard will repeat, the state pill, and the
 * facts. No dark band, no particle stage: this page is a working list,
 * and the header stays out of its way. The widest rules live in the
 * spotlight shelf below, not duplicated here.
 */
export function PolicyRulesHero(props: {
  model: RulesHeroModel;
  cta: ReactNode;
  secondaryCta?: ReactNode;
}) {
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
      <p className="mt-1.5 max-w-2xl text-sm leading-relaxed text-slate-600">{model.subheadline}</p>

      <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-2">
        <div className="flex flex-wrap gap-2">
          {props.cta}
          {props.secondaryCta}
        </div>
        {model.facts.length > 0 ? (
          <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
            {model.facts.map((fact) => (
              <li key={fact}>{fact}</li>
            ))}
          </ul>
        ) : null}
      </div>
    </section>
  );
}
