import { useSyncExternalStore, type ReactNode } from "react";

import { BRAND_MARK } from "./brand-mark-geometry";
import { HeroParticleLogo } from "./home-hero-particle-logo";

/** Visual tone for a branded hero: the accent glow, badge tint, live dot and particle mood all follow it. */
export type BrandHeroTone = "clear" | "review" | "setup";

/** Matches Tailwind's lg breakpoint, where the particle stage shows. */
const STAGE_QUERY = "(min-width: 1024px)";

function stageVisible(): boolean {
  return typeof window !== "undefined" && window.matchMedia(STAGE_QUERY).matches;
}

function subscribeStage(callback: () => void): () => void {
  const query = window.matchMedia(STAGE_QUERY);
  query.addEventListener("change", callback);
  return () => query.removeEventListener("change", callback);
}

const MARK_CENTER = 50;
const MARK_SCALE = 42;

/** The HOL mark as a flat vector, for places too small or too dense for the particle scene. */
export function BrandMark(props: { color: string; className?: string }) {
  const at = (value: number, axis: "x" | "y") =>
    (axis === "x" ? MARK_CENTER + value * MARK_SCALE : MARK_CENTER - value * MARK_SCALE).toFixed(2);
  return (
    <span aria-hidden="true" className={`guard-brand-mark${props.className ? ` ${props.className}` : ""}`}>
      <svg viewBox="0 0 100 100" aria-hidden="true">
        {BRAND_MARK.bars.map((bar, index) => (
          <line
            key={`bar:${index}`}
            x1={at(bar.x1, "x")}
            y1={at(bar.y1, "y")}
            x2={at(bar.x2, "x")}
            y2={at(bar.y2, "y")}
            stroke={props.color}
            strokeWidth={(bar.w * MARK_SCALE).toFixed(2)}
          />
        ))}
        {BRAND_MARK.discs.map((disc, index) => (
          <circle
            key={`disc:${index}`}
            cx={at(disc.x, "x")}
            cy={at(disc.y, "y")}
            r={(disc.r * MARK_SCALE).toFixed(2)}
            fill={props.color}
          />
        ))}
      </svg>
    </span>
  );
}

export function BrandHeroBadge(props: { tone: BrandHeroTone; children: ReactNode }) {
  return (
    <span role="status" className={`guard-hero-badge guard-hero-badge--${props.tone}`}>
      <i aria-hidden="true" />
      {props.children}
    </span>
  );
}

/** One-line facts under the hero's actions, each led by a quiet dot. */
export function BrandHeroFacts(props: { facts: string[] }) {
  if (props.facts.length === 0) return null;
  return (
    <ul className="flex flex-wrap gap-x-6 gap-y-2 pt-1 text-sm text-white/75">
      {props.facts.map((fact) => (
        <li key={fact} className="guard-hero-fact">
          {fact}
        </li>
      ))}
    </ul>
  );
}

/**
 * The dark gradient surface Home opens with, carrying the HOL particle mark.
 * Pages that open on their own status (About, Supply chain) use it so every
 * first viewport reads as the same product.
 *
 * `compact` shrinks the particle stage for task pages, and
 * `markOnSmall="inline"` drops it below the lg breakpoint for a small flat
 * mark in the corner, so the work under the hero stays in the first phone
 * viewport.
 */
export function BrandHero(props: {
  tone: BrandHeroTone;
  liveLabel: string;
  children: ReactNode;
  ariaLabel?: string;
  labelledBy?: string;
  testId?: string;
  markOnSmall?: "stage" | "inline";
  /** A smaller particle stage, for task pages whose work sits under the hero. */
  compact?: boolean;
}) {
  const inline = props.markOnSmall === "inline";
  const wide = useSyncExternalStore(subscribeStage, stageVisible, () => false);
  // Inline heroes hide the stage below lg; skip its WebGL scene there instead of hiding it.
  const mountStage = !inline || wide;
  const named = Boolean(props.labelledBy || props.ariaLabel);
  const Surface = named ? "section" : "div";
  const column = props.compact ? "lg:grid-cols-[minmax(0,1fr)_260px]" : "lg:grid-cols-[minmax(0,1fr)_380px]";
  return (
    <Surface
      className="guard-hero guard-surface-in relative overflow-hidden rounded-2xl border border-white/10 p-5 text-white sm:p-6 lg:p-8"
      data-status={props.tone}
      aria-label={props.labelledBy ? undefined : props.ariaLabel}
      aria-labelledby={props.labelledBy}
      data-testid={props.testId}
    >
      {inline ? <BrandMark color="#ffffff" className="guard-hero-inline-mark lg:hidden" /> : null}
      <div className={`grid gap-6 ${column} lg:items-center`}>
        <div className="relative min-w-0 space-y-5">{props.children}</div>
        <div className={`relative mx-auto w-full max-w-[380px] lg:max-w-none${inline ? " hidden lg:block" : ""}`}>
          {mountStage ? (
            <HeroParticleLogo mood={props.tone} finish="white" className={props.compact ? "guard-hero-stage--compact" : undefined} />
          ) : null}
          <p className="guard-hero-live" aria-hidden="true">
            <i />
            <span>{props.liveLabel}</span>
          </p>
        </div>
      </div>
    </Surface>
  );
}
