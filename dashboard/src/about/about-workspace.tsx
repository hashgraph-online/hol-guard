import { useRef, useEffect, useState, useCallback, type ReactNode } from "react";
import {
  HiMiniShieldCheck,
  HiMiniLockClosed,
  HiMiniDocumentText,
  HiMiniCloud,
  HiMiniArrowTopRightOnSquare,
  HiMiniInformationCircle,
  HiMiniCheckBadge,
} from "react-icons/hi2";
import { SectionLabel, Badge } from "../approval-center-primitives";
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

function TrustRow({
  title,
  desc,
  icon,
}: {
  title: string;
  desc: string;
  icon: ReactNode;
}) {
  return (
    <div className="flex items-start gap-4 py-5 border-b border-slate-100 last:border-b-0">
      <div className="shrink-0 flex h-9 w-9 items-center justify-center rounded-lg bg-brand-blue/[0.06] text-brand-blue">
        {icon}
      </div>
      <div>
        <h3 className="text-sm font-semibold text-brand-dark">{title}</h3>
        <p className="mt-0.5 text-sm leading-relaxed text-slate-500">{desc}</p>
      </div>
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
    <div className="relative grid grid-cols-[40px_1fr] gap-4 sm:gap-5">
      <div className="relative z-10 flex h-10 w-10 items-center justify-center rounded-full border-2 border-brand-blue bg-white">
        <span className="font-mono text-sm font-black text-brand-blue">
          {String(index + 1).padStart(2, "0")}
        </span>
      </div>
      <div className="pt-0.5">
        <h4 className="text-sm font-bold text-brand-dark">{title}</h4>
        <p className="mt-1 text-sm leading-relaxed text-slate-500">{desc}</p>
        <div className="mt-2">
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
        <h3 className="text-sm font-bold text-brand-dark">{level.name}</h3>
      </div>
      <p className="mt-1 ml-7 text-sm leading-relaxed text-slate-500">
        {level.description}
      </p>
    </div>
  );
}

export function AboutWorkspace() {
  return (
    <div className="space-y-16 pb-10">
      {/* Hero */}
      <EditorialSection className="rounded-2xl border border-brand-blue/10 bg-gradient-to-br from-brand-blue/[0.04] to-brand-dark/[0.02] p-6 sm:p-8">
        <div className="max-w-2xl">
          <h1 className="mb-2 text-2xl font-bold tracking-tight text-brand-dark sm:text-3xl">
            {ABOUT_HERO_TITLE}
          </h1>
          <p className="mb-4 text-lg font-medium text-brand-blue">
            {ABOUT_HERO_SUBTITLE}
          </p>
          <p className="text-sm leading-relaxed text-brand-dark/75">
            {ABOUT_HERO_BODY}
          </p>
        </div>
      </EditorialSection>

      {/* Local-first promise */}
      <EditorialSection>
        <div className="mb-6">
          <SectionLabel>{ABOUT_LOCAL_SECTION_TITLE}</SectionLabel>
          <p className="mt-1 text-sm leading-relaxed text-slate-500">
            {ABOUT_LOCAL_SECTION_BODY}
          </p>
        </div>
        <div className="rounded-2xl border border-slate-100 bg-white px-5 py-1 shadow-sm">
          {ABOUT_TRUST_CARDS.map((card, i) => (
            <TrustRow
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
        <div className="rounded-2xl border border-slate-100 bg-white p-6 sm:p-8 shadow-sm">
          <SectionLabel>{ABOUT_MISSION_SECTION_TITLE}</SectionLabel>
          <p className="mt-2 text-sm leading-relaxed text-brand-dark/75">
            {ABOUT_MISSION_SECTION_BODY}
          </p>
          <p className="mt-4 text-xs text-slate-400">{ABOUT_OPEN_SOURCE_NOTE}</p>
        </div>
      </EditorialSection>

      {/* Choose-your-path timeline */}
      <EditorialSection threshold={0.15}>
        <div className="mb-8">
          <SectionLabel>Choose your path</SectionLabel>
          <p className="mt-1 text-sm leading-relaxed text-slate-500">
            There are many ways to participate in the Guard ecosystem.
          </p>
        </div>
        <div className="relative">
          <div className="absolute left-[19px] top-0 bottom-0 w-[2px] bg-slate-100 sm:left-[23px]" />
          <div className="space-y-10">
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
        <div className="rounded-2xl border border-slate-100 bg-white p-6 sm:p-8 shadow-sm">
          <SectionLabel>{ABOUT_PARTNER_SECTION_TITLE}</SectionLabel>
          <p className="mt-2 text-sm leading-relaxed text-brand-dark/75">
            {ABOUT_PARTNER_SECTION_BODY}
          </p>
          <div className="mt-6">
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
        <div className="rounded-2xl border border-slate-100 bg-white p-6 sm:p-8 shadow-sm">
          <SectionLabel>{ABOUT_AFFILIATE_SECTION_TITLE}</SectionLabel>
          <p className="mt-2 mb-6 text-sm leading-relaxed text-brand-dark/75">
            {ABOUT_AFFILIATE_SECTION_BODY}
          </p>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4 mb-6">
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
        <footer className="rounded-2xl border border-slate-100 bg-white p-6 sm:p-8 shadow-sm">
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
