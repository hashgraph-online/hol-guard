import { BrandHero, BrandHeroBadge, BrandHeroFacts, type BrandHeroTone } from "./brand-hero";
import type { SupplyChainWorkspaceHeroState } from "./supply-chain-workspace-hero-state";

type SupplyChainWorkspaceHeroProps = {
  hero: SupplyChainWorkspaceHeroState;
};

/** Green is all clear, attention is something to fix, everything else is still settling. */
export function supplyChainBrandTone(tone: SupplyChainWorkspaceHeroState["tone"]): BrandHeroTone {
  if (tone === "green") return "clear";
  if (tone === "attention") return "review";
  return "setup";
}

/** The status at the top of the Supply chain tab, on the same branded surface Home opens with. */
export function SupplyChainWorkspaceHero({ hero }: SupplyChainWorkspaceHeroProps) {
  const tone = supplyChainBrandTone(hero.tone);
  return (
    <BrandHero
      tone={tone}
      liveLabel={hero.liveLabel}
      ariaLabel="Supply chain protection status"
      testId="supply-chain-workspace-hero"
      markOnSmall="inline"
      compact
    >
      <BrandHeroBadge tone={tone}>{hero.badge}</BrandHeroBadge>
      <div className="max-w-2xl">
        <h2 className="guard-hero-title text-2xl font-semibold tracking-tight text-white sm:text-3xl">{hero.title}</h2>
        <p className="mt-3 max-w-xl text-[15px] leading-relaxed text-white/80">{hero.detail}</p>
      </div>
      <BrandHeroFacts facts={hero.facts} />
    </BrandHero>
  );
}
