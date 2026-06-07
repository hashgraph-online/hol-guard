import { useCallback } from "react";
import type { ReactNode } from "react";
import {
  HiMiniShieldCheck,
  HiMiniLockClosed,
  HiMiniDocumentText,
  HiMiniCloud,
  HiMiniArrowTopRightOnSquare,
  HiMiniInformationCircle,
} from "react-icons/hi2";
import { SectionLabel, Badge, ActionButton } from "../approval-center-primitives";
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

function AboutExternalLink({
  href,
  children,
  className,
}: {
  href: string;
  children: ReactNode;
  className?: string;
}) {
  const safe = assertSafeAboutExternalUrl(href);
  const handleClick = useCallback(() => {
    trackAboutEvent({ type: "about_external_link_clicked", href });
  }, [href]);

  if (!safe.ok) {
    return (
      <span className={`text-slate-400 cursor-not-allowed ${className ?? ""}`} title={safe.reason}>
        {children}
      </span>
    );
  }

  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      onClick={handleClick}
      className={`inline-flex items-center gap-1 transition-colors hover:text-brand-blue focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 focus-visible:ring-offset-2 ${className ?? ""}`}
    >
      {children}
      <HiMiniArrowTopRightOnSquare className="h-3.5 w-3.5 opacity-60" aria-hidden="true" />
    </a>
  );
}

function TrustCard({ title, desc, icon }: { title: string; desc: string; icon: ReactNode }) {
  return (
    <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
      <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-xl bg-brand-blue/[0.06] text-brand-blue">
        {icon}
      </div>
      <h3 className="mb-1 text-sm font-semibold text-brand-dark">{title}</h3>
      <p className="text-sm leading-relaxed text-slate-500">{desc}</p>
    </div>
  );
}

function PathCard({
  title,
  desc,
  ctaLabel,
  ctaHref,
}: {
  title: string;
  desc: string;
  ctaLabel: string;
  ctaHref: string;
}) {
  return (
    <div className="flex flex-col rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
      <h3 className="mb-1 text-sm font-semibold text-brand-dark">{title}</h3>
      <p className="mb-4 flex-1 text-sm leading-relaxed text-slate-500">{desc}</p>
      <AboutExternalLink
        href={ctaHref}
        className="text-sm font-semibold text-brand-blue hover:underline"
      >
        {ctaLabel}
      </AboutExternalLink>
    </div>
  );
}

export function AboutWorkspace() {
  return (
    <div className="space-y-10">
      {/* Hero */}
      <section className="rounded-2xl border border-brand-blue/10 bg-gradient-to-br from-brand-blue/[0.04] to-brand-dark/[0.02] p-6 sm:p-8">
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
      </section>

      {/* Local-first promise */}
      <section className="space-y-4">
        <div>
          <SectionLabel>{ABOUT_LOCAL_SECTION_TITLE}</SectionLabel>
          <p className="mt-1 text-sm leading-relaxed text-slate-500">
            {ABOUT_LOCAL_SECTION_BODY}
          </p>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {ABOUT_TRUST_CARDS.map((card, i) => (
            <TrustCard
              key={i}
              title={card.title}
              desc={card.desc}
              icon={
                i === 0 ? (
                  <HiMiniShieldCheck className="h-5 w-5" />
                ) : i === 1 ? (
                  <HiMiniDocumentText className="h-5 w-5" />
                ) : i === 2 ? (
                  <HiMiniLockClosed className="h-5 w-5" />
                ) : (
                  <HiMiniCloud className="h-5 w-5" />
                )
              }
            />
          ))}
        </div>
      </section>

      {/* Mission */}
      <section className="rounded-2xl border border-slate-100 bg-white p-6 sm:p-8 shadow-sm">
        <SectionLabel>{ABOUT_MISSION_SECTION_TITLE}</SectionLabel>
        <p className="mt-2 text-sm leading-relaxed text-brand-dark/75">
          {ABOUT_MISSION_SECTION_BODY}
        </p>
        <p className="mt-4 text-xs text-slate-400">{ABOUT_OPEN_SOURCE_NOTE}</p>
      </section>

      {/* Choose-your-path grid */}
      <section className="space-y-4">
        <div>
          <SectionLabel>Choose your path</SectionLabel>
          <p className="mt-1 text-sm leading-relaxed text-slate-500">
            There are many ways to participate in the Guard ecosystem.
          </p>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {ABOUT_PATH_CARDS.map((card, i) => (
            <PathCard
              key={i}
              title={card.title}
              desc={card.desc}
              ctaLabel={card.ctaLabel}
              ctaHref={card.ctaHref}
            />
          ))}
        </div>
      </section>

      {/* Partner program */}
      <section className="rounded-2xl border border-slate-100 bg-white p-6 sm:p-8 shadow-sm">
        <SectionLabel>{ABOUT_PARTNER_SECTION_TITLE}</SectionLabel>
        <p className="mt-2 mb-6 text-sm leading-relaxed text-brand-dark/75">
          {ABOUT_PARTNER_SECTION_BODY}
        </p>
        <div className="grid gap-4 sm:grid-cols-3">
          {ABOUT_PARTNER_LEVELS.map((level, i) => (
            <div key={i} className="rounded-xl border border-slate-100 bg-slate-50/60 p-4">
              <h3 className="mb-1 text-sm font-semibold text-brand-dark">{level.name}</h3>
              <p className="text-xs leading-relaxed text-slate-500">{level.desc}</p>
            </div>
          ))}
        </div>
        <div className="mt-6">
          <AboutExternalLink
            href={ABOUT_PARTNER_CTA_HREF}
            className="inline-flex items-center gap-1.5 rounded-lg bg-brand-blue px-4 py-2 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-brand-blue/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 focus-visible:ring-offset-2"
          >
            {ABOUT_PARTNER_CTA}
            <HiMiniArrowTopRightOnSquare className="h-4 w-4" aria-hidden="true" />
          </AboutExternalLink>
        </div>
      </section>

      {/* Affiliate starter kit */}
      <section className="rounded-2xl border border-slate-100 bg-white p-6 sm:p-8 shadow-sm">
        <SectionLabel>{ABOUT_AFFILIATE_SECTION_TITLE}</SectionLabel>
        <p className="mt-2 mb-4 text-sm leading-relaxed text-brand-dark/75">
          {ABOUT_AFFILIATE_SECTION_BODY}
        </p>
        <div className="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-xl border border-slate-100 bg-slate-50/60 p-4">
            <p className="text-xs text-slate-400">Commission</p>
            <p className="text-lg font-bold text-brand-dark">{ABOUT_AFFILIATE_TERMS.commissionRate}</p>
          </div>
          <div className="rounded-xl border border-slate-100 bg-slate-50/60 p-4">
            <p className="text-xs text-slate-400">Duration</p>
            <p className="text-lg font-bold text-brand-dark">{ABOUT_AFFILIATE_TERMS.commissionDuration}</p>
          </div>
          <div className="rounded-xl border border-slate-100 bg-slate-50/60 p-4">
            <p className="text-xs text-slate-400">Cookie window</p>
            <p className="text-lg font-bold text-brand-dark">{ABOUT_AFFILIATE_TERMS.cookieWindow}</p>
          </div>
          <div className="rounded-xl border border-slate-100 bg-slate-50/60 p-4">
            <p className="text-xs text-slate-400">Qualification</p>
            <p className="text-sm font-semibold text-brand-dark">{ABOUT_AFFILIATE_TERMS.qualificationNote}</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <AboutExternalLink
            href={ABOUT_AFFILIATE_CTA_HREF}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-700 transition-colors hover:bg-slate-50 hover:border-slate-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 focus-visible:ring-offset-2"
          >
            {ABOUT_AFFILIATE_CTA}
            <HiMiniArrowTopRightOnSquare className="h-4 w-4" aria-hidden="true" />
          </AboutExternalLink>
          <p className="text-xs text-slate-400">{ABOUT_AFFILIATE_DISCLOSURE}</p>
        </div>
      </section>

      {/* Trust footer */}
      <footer className="rounded-2xl border border-slate-100 bg-white p-6 sm:p-8 shadow-sm">
        <div className="flex flex-col items-start gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <HiMiniInformationCircle className="h-5 w-5 text-brand-blue" aria-hidden="true" />
            <span className="text-sm font-semibold text-brand-dark">
              HOL Guard
            </span>
            <Badge tone="success">Local-first</Badge>
          </div>
          <p className="text-xs text-slate-400">
            Built by Hashgraph Online. Open standards for the agent internet.
          </p>
        </div>
      </footer>
    </div>
  );
}
