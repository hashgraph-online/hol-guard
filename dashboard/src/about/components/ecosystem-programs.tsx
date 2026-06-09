import { Surface, SectionLabel, Badge } from "../../approval-center-primitives";
import {
  ABOUT_PARTNER_SECTION_TITLE,
  ABOUT_PARTNER_SECTION_BODY,
  ABOUT_PARTNER_CTA,
  ABOUT_PARTNER_CTA_HREF,
  ABOUT_PARTNER_LEVELS,
  ABOUT_AFFILIATE_SECTION_TITLE,
  ABOUT_AFFILIATE_SECTION_BODY,
  ABOUT_AFFILIATE_CTA,
  ABOUT_AFFILIATE_CTA_HREF,
  ABOUT_AFFILIATE_DISCLOSURE,
  ABOUT_AFFILIATE_TERMS,
} from "../about-content";
import { AboutExternalLink } from "./about-external-link";

export function EcosystemPrograms() {
  return (
    <div className="grid gap-8 lg:grid-cols-2">
      {/* Partner program */}
      <div>
        <SectionLabel>{ABOUT_PARTNER_SECTION_TITLE}</SectionLabel>
        <p className="mt-2 text-base leading-relaxed text-brand-dark/75">
          {ABOUT_PARTNER_SECTION_BODY}
        </p>
        <div className="mt-4 space-y-0">
          {ABOUT_PARTNER_LEVELS.map((level, i) => (
            <div key={level.name} className="border-t border-slate-100 py-4">
              <div className="flex items-baseline gap-3">
                <span className="font-mono text-xs font-black text-brand-blue/70">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <h3 className="text-sm font-bold text-brand-dark">{level.name}</h3>
              </div>
              <p className="mt-1 ml-7 text-sm leading-relaxed text-slate-500">
                {level.description}
              </p>
            </div>
          ))}
        </div>
        <div className="mt-4 pt-4 border-t border-slate-100">
          <AboutExternalLink
            linkId="hol_partners"
            href={ABOUT_PARTNER_CTA_HREF}
            className="inline-flex items-center gap-1.5 rounded-lg bg-brand-blue px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-brand-blue/90"
          >
            {ABOUT_PARTNER_CTA}
          </AboutExternalLink>
        </div>
      </div>

      {/* Affiliate program */}
      <div>
        <SectionLabel>{ABOUT_AFFILIATE_SECTION_TITLE}</SectionLabel>
        <p className="mt-2 text-base leading-relaxed text-brand-dark/75">
          {ABOUT_AFFILIATE_SECTION_BODY}
        </p>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          {[
            { label: "Commission", value: ABOUT_AFFILIATE_TERMS.commissionRate },
            { label: "Duration", value: ABOUT_AFFILIATE_TERMS.commissionDuration },
            { label: "Cookie window", value: ABOUT_AFFILIATE_TERMS.cookieWindow },
            {
              label: "Qualification",
              value: ABOUT_AFFILIATE_TERMS.qualificationNote,
            },
          ].map((metric) => (
            <div key={metric.label} className="border-t border-slate-100 pt-3">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-1">
                {metric.label}
              </p>
              <p className="text-sm font-bold text-brand-dark">{metric.value}</p>
            </div>
          ))}
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-3 pt-4 border-t border-slate-100">
          <AboutExternalLink
            linkId="hol_affiliates"
            href={ABOUT_AFFILIATE_CTA_HREF}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-4 py-2.5 text-sm font-semibold text-slate-700 transition-colors hover:bg-slate-50 hover:border-slate-300"
          >
            {ABOUT_AFFILIATE_CTA}
          </AboutExternalLink>
          <p className="text-xs text-slate-400">{ABOUT_AFFILIATE_DISCLOSURE}</p>
        </div>
      </div>
    </div>
  );
}
