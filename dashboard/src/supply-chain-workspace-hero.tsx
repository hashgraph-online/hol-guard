import {
  HiMiniCheckCircle,
  HiMiniCloud,
  HiMiniComputerDesktop,
  HiMiniExclamationTriangle,
  HiMiniArrowPath,
} from "react-icons/hi2";
import type { SupplyChainWorkspaceHeroState } from "./supply-chain-workspace-hero-state";
import { Tag } from "./approval-center-primitives";

type SupplyChainWorkspaceHeroProps = {
  hero: SupplyChainWorkspaceHeroState;
  compact?: boolean;
};

function heroSurfaceClass(tone: SupplyChainWorkspaceHeroState["tone"]): string {
  if (tone === "green") {
    return "border-brand-green/20 bg-brand-green/[0.04]";
  }
  if (tone === "blue") {
    return "border-brand-blue/20 bg-brand-blue/[0.04]";
  }
  if (tone === "attention") {
    return "border-amber-200 bg-amber-50/70";
  }
  return "border-slate-200 bg-slate-50/80";
}

function heroIcon(hero: SupplyChainWorkspaceHeroState) {
  if (hero.protectionStatus === "protected") {
    return HiMiniCheckCircle;
  }
  if (hero.protectionStatus === "staged") {
    return HiMiniArrowPath;
  }
  if (hero.protectionStatus === "partial" || hero.protectionStatus === "unprotected") {
    return HiMiniExclamationTriangle;
  }
  return HiMiniComputerDesktop;
}

function heroIconClass(tone: SupplyChainWorkspaceHeroState["tone"]): string {
  if (tone === "green") {
    return "text-brand-green";
  }
  if (tone === "blue") {
    return "text-brand-blue";
  }
  if (tone === "attention") {
    return "text-amber-600";
  }
  return "text-slate-500";
}

function cloudTagTone(mode: SupplyChainWorkspaceHeroState["cloudMode"]): "green" | "blue" | "attention" {
  if (mode === "paired_active") {
    return "green";
  }
  if (mode === "paired_waiting") {
    return "blue";
  }
  return "attention";
}

export function SupplyChainWorkspaceHero({ hero, compact = false }: SupplyChainWorkspaceHeroProps) {
  const Icon = heroIcon(hero);
  const titleClass = hero.tone === "attention" ? "text-amber-950" : "text-brand-dark";

  return (
    <section
      className={`rounded-2xl border px-4 py-4 sm:px-5 sm:py-5 ${heroSurfaceClass(hero.tone)}`}
      aria-label="Supply chain protection status"
      data-testid="supply-chain-workspace-hero"
    >
      <div className="flex flex-wrap items-center gap-2">
        <Tag tone={cloudTagTone(hero.cloudMode)}>
          {hero.cloudMode === "local_only" ? (
            <HiMiniComputerDesktop className="mr-1 inline h-3.5 w-3.5" aria-hidden="true" />
          ) : (
            <HiMiniCloud className="mr-1 inline h-3.5 w-3.5" aria-hidden="true" />
          )}
          {hero.cloudLabel}
        </Tag>
        <span className="text-xs text-slate-500">{hero.statLine}</span>
      </div>
      {!compact ? (
        <div className="mt-3 flex items-start gap-2.5">
          <Icon className={`mt-0.5 h-5 w-5 shrink-0 ${heroIconClass(hero.tone)}`} aria-hidden="true" />
          <div className="min-w-0">
            <h2 className={`text-lg font-semibold tracking-tight ${titleClass}`}>{hero.title}</h2>
            <p className="mt-1 max-w-2xl text-sm leading-relaxed text-slate-600">{hero.detail}</p>
          </div>
        </div>
      ) : (
        <p className="mt-2 text-sm text-slate-600">{hero.detail}</p>
      )}
    </section>
  );
}
