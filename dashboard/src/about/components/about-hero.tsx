import { BrandHero, BrandHeroBadge, BrandHeroFacts, type BrandHeroTone } from "../../brand-hero";
import { TrackedExternalButton } from "./tracked-action-button";
import { MachineFigure, SYNC_STATE_LABEL, resolveSyncState } from "./machine-figure";
import { ABOUT_HERO_BODY, ABOUT_HERO_TITLE } from "../about-content";
import type { AboutRuntimeSummary } from "../about-types";

type AboutHeroState = {
  tone: BrandHeroTone;
  badge: string;
  liveLabel: string;
  facts: string[];
};

/** What the branded hero may say about this install. No runtime report means no claim. */
export function resolveAboutHeroState(runtimeSummary: AboutRuntimeSummary | null): AboutHeroState {
  if (!runtimeSummary) {
    return {
      tone: "setup",
      badge: "Not reporting",
      liveLabel: "Local-first",
      facts: ["Open source under Apache-2.0"],
    };
  }
  const pending = runtimeSummary.pendingCount;
  const version = runtimeSummary.guardVersion?.trim();
  const facts = [
    version && version.toLowerCase() !== "unknown" ? `Version ${version}` : null,
    `Cloud sync ${SYNC_STATE_LABEL[resolveSyncState(runtimeSummary)].toLowerCase()}`,
    "Open source under Apache-2.0",
  ].filter((fact): fact is string => fact !== null);
  if (pending > 0) {
    return {
      tone: "review",
      badge: `${pending} waiting for you`,
      liveLabel: `${pending} waiting`,
      facts,
    };
  }
  return { tone: "clear", badge: "Protecting this device", liveLabel: "Local-first", facts };
}

export function AboutHero({
  runtimeSummary,
}: {
  runtimeSummary: AboutRuntimeSummary | null;
}) {
  const hero = resolveAboutHeroState(runtimeSummary);
  return (
    <div className="space-y-10">
      <BrandHero tone={hero.tone} liveLabel={hero.liveLabel} labelledBy="about-hero-heading">
        <BrandHeroBadge tone={hero.tone}>{hero.badge}</BrandHeroBadge>
        <div className="max-w-2xl">
          <h1
            id="about-hero-heading"
            className="guard-hero-title text-4xl font-semibold tracking-[-0.03em] text-white sm:text-5xl"
          >
            {ABOUT_HERO_TITLE}
          </h1>
          <p className="mt-4 max-w-xl text-base leading-7 text-white/80 sm:text-lg sm:leading-8">
            {ABOUT_HERO_BODY}
          </p>
        </div>
        <div className="guard-hero-ctas flex flex-wrap gap-3">
          <TrackedExternalButton linkId="guard_docs" href="https://hol.org/guard/docs" variant="primary">
            Read Guard docs
          </TrackedExternalButton>
          <TrackedExternalButton linkId="hol_guard_source" href="https://github.com/hashgraph-online/hol-guard" variant="outline">
            View source
          </TrackedExternalButton>
        </div>
        <BrandHeroFacts facts={hero.facts} />
      </BrandHero>
      <MachineFigure runtimeSummary={runtimeSummary} />
    </div>
  );
}
