import type { ReactNode } from "react";
import { HiMiniChevronRight } from "react-icons/hi2";
import { SectionLabel } from "./approval-center-primitives";
import { HeroParticleLogo } from "./home-hero-particle-logo";
import type { RulesHeroModel, RulesHeroTone } from "./policy-rules-hero-model";

export interface RulesHeroPreviewItem {
  id: string;
  title: string;
  meta: string;
  action: string;
}

const BADGE_TONE: Record<RulesHeroTone, string> = {
  clear: "guard-hero-badge--clear",
  review: "guard-hero-badge--review",
  setup: "",
};

export function PolicyRulesHero(props: {
  model: RulesHeroModel;
  preview: RulesHeroPreviewItem[];
  previewLabel: string;
  onOpenPreviewItem?: (id: string) => void;
  cta: ReactNode;
  secondaryCta?: ReactNode;
}) {
  const { model } = props;
  const particleMood = model.tone === "clear" ? "clear" : model.tone === "review" ? "review" : "setup";
  return (
    <section
      className="guard-hero guard-surface-in relative overflow-hidden rounded-2xl border border-white/10 p-5 text-white sm:p-6 lg:p-8"
      data-status={model.tone}
      role="region"
      aria-label="Remembered rules status"
    >
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_300px] lg:items-center">
        <div className="relative min-w-0 space-y-5">
          <div className="guard-hero-label flex flex-wrap items-center gap-2">
            <SectionLabel>Rules & exceptions</SectionLabel>
            <span className={`guard-hero-badge ${BADGE_TONE[model.tone]}`}>
              <i aria-hidden="true" />
              {model.badge}
            </span>
          </div>
          <div className="max-w-2xl">
            <h1 className="guard-hero-title text-3xl font-semibold tracking-tight text-white sm:text-4xl">{model.headline}</h1>
            <p className="mt-3 max-w-xl text-[15px] leading-relaxed text-white/75">{model.subheadline}</p>
          </div>
          {props.preview.length > 0 ? (
            <ul className="rounded-xl border border-white/15 bg-white/[0.08] p-1" aria-label={props.previewLabel}>
              {props.preview.map((item) => {
                const content = (
                  <>
                    <span
                      className={`inline-flex h-2 w-2 shrink-0 rounded-full ${item.action === "block" ? "bg-rose-300" : "bg-[#ffd58a]"}`}
                      aria-hidden="true"
                    />
                    <span className="min-w-0 flex-1 truncate text-sm text-white">{item.title}</span>
                    <span className="shrink-0 text-xs text-white/65">{item.meta}</span>
                  </>
                );
                const onOpen = props.onOpenPreviewItem;
                return (
                  <li key={item.id}>
                    {onOpen ? (
                      <button
                        type="button"
                        onClick={() => onOpen(item.id)}
                        className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left transition-colors hover:bg-white/[0.08] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/60"
                      >
                        {content}
                        <HiMiniChevronRight className="h-4 w-4 shrink-0 text-white/50" aria-hidden="true" />
                      </button>
                    ) : (
                      <div className="flex w-full items-center gap-3 rounded-lg px-3 py-2">{content}</div>
                    )}
                  </li>
                );
              })}
            </ul>
          ) : null}
          <div className="guard-hero-ctas flex flex-wrap gap-3">
            {props.cta}
            {props.secondaryCta}
          </div>
          {model.facts.length > 0 ? (
            <ul className="flex flex-wrap gap-x-6 gap-y-2 pt-1 text-sm text-white/75">
              {model.facts.map((fact) => (
                <li key={fact} className="guard-hero-fact">{fact}</li>
              ))}
            </ul>
          ) : null}
        </div>
        <div className="relative mx-auto hidden w-full max-w-[300px] md:block lg:max-w-none" aria-hidden="true">
          <HeroParticleLogo mood={particleMood} finish="white" />
          <p className="guard-hero-live">
            <i />
            <span>{model.liveLabel}</span>
          </p>
        </div>
      </div>
    </section>
  );
}
