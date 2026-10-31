import { BrandHero, BrandHeroBadge, BrandHeroFacts, type BrandHeroTone } from "../../brand-hero";
import { TrackedExternalButton } from "./tracked-action-button";
import { MachineFigure, resolveSyncState } from "./machine-figure";
import { ABOUT_HERO_BODY, ABOUT_HERO_TITLE } from "../about-content";
import type { AboutRuntimeSummary } from "../about-types";

type AboutHeroState = {
  tone: BrandHeroTone;
  badge: string;
  liveLabel: string;
  facts: string[];
};

const SYNC_FACT: Record<ReturnType<typeof resolveSyncState>, string> = {
  on: "Cloud sync on",
  stalled: "Cloud sync stalled",
  pairing: "Cloud sync waiting for first upload",
  off: "Cloud sync off",
  unavailable: "Cloud sync unavailable",
};

/**
 * What the branded hero may say about this install. No runtime report means no
 * claim. The summary carries no protection health, so About says Guard is
 * running and leaves protected or not to Home.
 */
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
    SYNC_FACT[resolveSyncState(runtimeSummary)],
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
  return { tone: "setup", badge: "Running on this device", liveLabel: "Local-first", facts };
}

export function AboutHero({
  runtimeSummary,
}: {
  runtimeSummary: AboutRuntimeSummary | null;
}) {
  const hero = resolveAboutHeroState(runtimeSummary);
  return (
    <div className="space-y-10">
      {/* The surrounding SectionShell already names this region by its heading. */}
      <BrandHero tone={hero.tone} liveLabel={hero.liveLabel}>
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
