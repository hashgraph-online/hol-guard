import { useRef, useEffect, useState, useCallback, type ReactNode } from "react";
import {
  HiMiniShieldCheck,
  HiMiniLockClosed,
  HiMiniDocumentText,
  HiMiniCloud,
  HiMiniArrowTopRightOnSquare,
  HiMiniCheckBadge,
} from "react-icons/hi2";
import { Badge } from "../approval-center-primitives";
import { trackAboutEvent } from "./about-analytics";
import { assertSafeAboutExternalUrl } from "./about-external-links";
import {
  ABOUT_HERO_TITLE,
  ABOUT_HERO_SUBTITLE,
  ABOUT_HERO_BODY,
  ABOUT_LOCAL_SECTION_TITLE,
  ABOUT_LOCAL_SECTION_BODY,
  ABOUT_MISSION_SECTION_TITLE,
  ABOUT_MISSION_SECTION_BODY,
  ABOUT_OPEN_SOURCE_NOTE,
  ABOUT_PARTNER_SECTION_TITLE,
  ABOUT_PARTNER_SECTION_BODY,
  ABOUT_PARTNER_CTA,
  ABOUT_PARTNER_CTA_HREF,
  ABOUT_AFFILIATE_SECTION_TITLE,
  ABOUT_AFFILIATE_SECTION_BODY,
  ABOUT_AFFILIATE_CTA,
  ABOUT_AFFILIATE_CTA_HREF,
  ABOUT_AFFILIATE_DISCLOSURE,
  ABOUT_TRUST_CARDS,
  ABOUT_PATH_CARDS,
  ABOUT_PARTNER_LEVELS,
  ABOUT_AFFILIATE_TERMS,
} from "./about-content";

function AboutSectionLabel({ children }: { children: ReactNode }) {
  return (
    <span className="text-sm font-bold tracking-widest uppercase text-brand-blue mb-3 block">
      {children}
    </span>
  );
}

function useEditorialVisibility(threshold = 0.08) {
  const ref = useRef<HTMLElement>(null);
  const [state, setState] = useState<"idle" | "hidden" | "visible">("idle");

  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") {
      setState("visible");
      return;
    }
    setState("hidden");
    const el = ref.current;
    if (!el) return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setState("visible");
          observer.disconnect();
        }
      },
      { threshold }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [threshold]);

  return { ref, state };
}

function EditorialSection({
  children,
  className = "",
  threshold = 0.08,
}: {
  children: ReactNode;
  className?: string;
  threshold?: number;
}) {
  const { ref, state } = useEditorialVisibility(threshold);

  return (
    <section
      ref={ref}
      className={[
        className,
        state === "idle"
          ? ""
          : "motion-safe:transition-[opacity,transform] transition-opacity duration-700 ease-[cubic-bezier(0.16,1,0.3,1)]",
        state === "idle" || state === "visible"
          ? "opacity-100 translate-y-0"
          : "opacity-0 motion-safe:translate-y-6",
      ].join(" ")}
    >
      {children}
    </section>
  );
}

function AboutExternalLink({
  href,
  children,
  className,
}: {
  href: string;
  children: ReactNode;
  className?: string;
}) {
  let safe: { rel: string; target: string } | null = null;
  let errorReason = "";
  try {
    safe = assertSafeAboutExternalUrl(href);
  } catch (e) {
    errorReason = e instanceof Error ? e.message : "Invalid URL";
  }

  const handleClick = useCallback(() => {
    trackAboutEvent({ type: "about_external_link_clicked", href });
  }, [href]);

  if (!safe) {
    return (
      <span
        className={[`text-slate-400 cursor-not-allowed`, className ?? ""].join(" ")}
        title={errorReason}
      >
        {children}
      </span>
    );
  }

  return (
    <a
      href={href}
      target={safe.target}
      rel={safe.rel}
      onClick={handleClick}
      className={[
        `inline-flex items-center gap-1 transition-colors hover:text-brand-blue`,
        `focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 focus-visible:ring-offset-2`,
        className ?? "",
      ].join(" ")}
    >
      {children}
      <HiMiniArrowTopRightOnSquare className="h-3.5 w-3.5 opacity-60" aria-hidden="true" />
    </a>
  );
}

function TrustPillar({
  title,
  desc,
  icon,
}: {
  title: string;
  desc: string;
  icon: ReactNode;
}) {
  return (
    <div className="border-l-4 border-brand-blue/60 pl-6 py-2">
      <div className="flex items-center gap-3 mb-2">
        <div className="shrink-0 flex h-8 w-8 items-center justify-center rounded-lg bg-brand-blue/[0.06] text-brand-blue">
          {icon}
        </div>
        <h3 className="text-base font-bold text-brand-dark">{title}</h3>
      </div>
      <p className="text-sm leading-relaxed text-slate-500">{desc}</p>
    </div>
  );
}

function PathStep({
  index,
  title,
  desc,
  ctaLabel,
  ctaHref,
}: {
  index: number;
  title: string;
  desc: string;
  ctaLabel: string;
  ctaHref: string;
}) {
  return (
    <div className="relative grid grid-cols-[48px_1fr] gap-4 sm:gap-6">
      <div className="relative z-10 flex h-12 w-12 items-center justify-center rounded-full border-2 border-brand-blue bg-white">
        <span className="font-mono text-sm font-black text-brand-blue">
          {String(index + 1).padStart(2, "0")}
        </span>
      </div>
      <div className="pt-1">
        <h4 className="text-base font-bold text-brand-dark">{title}</h4>
        <p className="mt-1.5 text-sm leading-relaxed text-slate-500">{desc}</p>
        <div className="mt-3">
          <AboutExternalLink
            href={ctaHref}
            className="text-sm font-semibold text-brand-blue hover:underline"
          >
            {ctaLabel}
          </AboutExternalLink>
        </div>
      </div>
    </div>
  );
}

function PartnerLevelRow({
  level,
  index,
}: {
  level: { name: string; description: string };
  index: number;
}) {
  return (
    <div className="border-t border-slate-100 py-5">
      <div className="flex items-baseline gap-3">
        <span className="font-mono text-xs font-black text-brand-blue/70">
          {String(index + 1).padStart(2, "0")}
        </span>
        <h3 className="text-base font-bold text-brand-dark">{level.name}</h3>
      </div>
      <p className="mt-1 ml-7 text-sm leading-relaxed text-slate-500">
        {level.description}
      </p>
    </div>
  );
}

export function AboutWorkspace() {
  return (
    <div className="space-y-20 pb-10">
      {/* Hero */}
      <EditorialSection>
        <div className="max-w-3xl">
          <h1 className="text-4xl sm:text-5xl font-black tracking-tight text-brand-dark leading-none mb-6">
            {ABOUT_HERO_TITLE}
          </h1>
          <p className="text-xl sm:text-2xl font-medium text-brand-blue mb-6">
            {ABOUT_HERO_SUBTITLE}
          </p>
          <p className="text-base leading-relaxed text-brand-dark/75 max-w-2xl">
            {ABOUT_HERO_BODY}
          </p>
        </div>
      </EditorialSection>

      {/* Local-first promise */}
      <EditorialSection>
        <div className="mb-8">
          <AboutSectionLabel>{ABOUT_LOCAL_SECTION_TITLE}</AboutSectionLabel>
          <p className="text-base leading-relaxed text-slate-500 max-w-2xl">
            {ABOUT_LOCAL_SECTION_BODY}
          </p>
        </div>
        <div className="grid sm:grid-cols-2 gap-x-12 gap-y-8">
          {ABOUT_TRUST_CARDS.map((card, i) => (
            <TrustPillar
              key={card.title}
              title={card.title}
              desc={card.description}
              icon={
                i === 0 ? (
                  <HiMiniShieldCheck className="h-4 w-4" />
                ) : i === 1 ? (
                  <HiMiniDocumentText className="h-4 w-4" />
                ) : i === 2 ? (
                  <HiMiniLockClosed className="h-4 w-4" />
                ) : (
                  <HiMiniCloud className="h-4 w-4" />
                )
              }
            />
          ))}
        </div>
      </EditorialSection>

      {/* Mission */}
      <EditorialSection>
        <div className="max-w-3xl">
          <AboutSectionLabel>{ABOUT_MISSION_SECTION_TITLE}</AboutSectionLabel>
          <p className="text-lg leading-relaxed text-brand-dark/75">
            {ABOUT_MISSION_SECTION_BODY}
          </p>
          <p className="mt-4 text-sm text-slate-400">{ABOUT_OPEN_SOURCE_NOTE}</p>
        </div>
      </EditorialSection>

      {/* Choose-your-path timeline */}
      <EditorialSection threshold={0.15}>
        <div className="mb-10">
          <AboutSectionLabel>Choose your path</AboutSectionLabel>
          <p className="text-base leading-relaxed text-slate-500 max-w-2xl">
            There are many ways to participate in the Guard ecosystem.
          </p>
        </div>
        <div className="relative">
          <div className="absolute left-[23px] top-0 bottom-0 w-[2px] bg-slate-100" />
          <div className="space-y-12">
            {ABOUT_PATH_CARDS.map((card, i) => (
              <PathStep
                key={card.title}
                index={i}
                title={card.title}
                desc={card.description}
                ctaLabel={card.ctaLabel}
                ctaHref={card.ctaHref}
              />
            ))}
          </div>
        </div>
      </EditorialSection>

      {/* Partner program */}
      <EditorialSection>
        <div className="max-w-3xl">
          <AboutSectionLabel>{ABOUT_PARTNER_SECTION_TITLE}</AboutSectionLabel>
          <p className="text-base leading-relaxed text-brand-dark/75 mb-8">
            {ABOUT_PARTNER_SECTION_BODY}
          </p>
          <div>
            {ABOUT_PARTNER_LEVELS.map((level, i) => (
              <PartnerLevelRow key={level.name} level={level} index={i} />
            ))}
          </div>
          <div className="mt-6 pt-4 border-t border-slate-100">
            <AboutExternalLink
              href={ABOUT_PARTNER_CTA_HREF}
              className="inline-flex items-center gap-1.5 rounded-lg bg-brand-blue px-4 py-2 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-brand-blue/90"
            >
              {ABOUT_PARTNER_CTA}
              <HiMiniArrowTopRightOnSquare className="h-4 w-4" aria-hidden="true" />
            </AboutExternalLink>
          </div>
        </div>
      </EditorialSection>

      {/* Affiliate starter kit */}
      <EditorialSection>
        <div className="max-w-3xl">
          <AboutSectionLabel>{ABOUT_AFFILIATE_SECTION_TITLE}</AboutSectionLabel>
          <p className="text-base leading-relaxed text-brand-dark/75 mb-8">
            {ABOUT_AFFILIATE_SECTION_BODY}
          </p>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4 mb-8">
            {[
              { label: "Commission", value: ABOUT_AFFILIATE_TERMS.commissionRate },
              { label: "Duration", value: ABOUT_AFFILIATE_TERMS.commissionDuration },
              { label: "Cookie window", value: ABOUT_AFFILIATE_TERMS.cookieWindow },
              {
                label: "Qualification",
                value: ABOUT_AFFILIATE_TERMS.qualificationNote,
              },
            ].map((metric) => (
              <div key={metric.label} className="border-t border-slate-100 pt-4">
                <p className="text-xs text-slate-400 mb-1">{metric.label}</p>
                <p className="text-lg font-bold text-brand-dark">{metric.value}</p>
              </div>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-3 pt-4 border-t border-slate-100">
            <AboutExternalLink
              href={ABOUT_AFFILIATE_CTA_HREF}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-700 transition-colors hover:bg-slate-50 hover:border-slate-300"
            >
              {ABOUT_AFFILIATE_CTA}
              <HiMiniArrowTopRightOnSquare className="h-4 w-4" aria-hidden="true" />
            </AboutExternalLink>
            <p className="text-xs text-slate-400">{ABOUT_AFFILIATE_DISCLOSURE}</p>
          </div>
        </div>
      </EditorialSection>

      {/* Trust footer */}
      <EditorialSection>
        <footer className="border-t border-slate-100 pt-8">
          <div className="flex flex-col items-start gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-2">
              <HiMiniCheckBadge className="h-5 w-5 text-brand-blue" aria-hidden="true" />
              <span className="text-sm font-semibold text-brand-dark">HOL Guard</span>
              <Badge tone="success">Local-first</Badge>
            </div>
            <p className="text-xs text-slate-400">
              Built by Hashgraph Online. Open standards for the agent internet.
            </p>
          </div>
        </footer>
      </EditorialSection>
    </div>
  );
}
