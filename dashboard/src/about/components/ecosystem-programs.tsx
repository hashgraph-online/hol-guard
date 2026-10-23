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
import { AboutSectionHeading } from "./about-section-heading";

export function EcosystemPrograms() {
  return (
    <div className="grid gap-8 lg:grid-cols-2">
      {/* Partner program */}
      <div>
        <AboutSectionHeading
          id="about-partner-heading"
          title={ABOUT_PARTNER_SECTION_TITLE}
          lead={ABOUT_PARTNER_SECTION_BODY}
        />
        <div className="mt-4 space-y-0">
          {ABOUT_PARTNER_LEVELS.map((level, i) => (
            <div key={level.name} className="border-t border-brand-dark/10 py-4">
              <div className="flex items-baseline gap-3">
                <span className="font-mono text-xs font-semibold tabular-nums text-brand-blue">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <h3 className="text-sm font-semibold text-brand-dark">{level.name}</h3>
              </div>
              <p className="ml-7 mt-1 text-sm leading-6 text-brand-dark/75">
                {level.description}
              </p>
            </div>
          ))}
        </div>
        <div className="mt-4 border-t border-brand-dark/10 pt-4">
          <AboutExternalLink
            linkId="hol_partners"
            href={ABOUT_PARTNER_CTA_HREF}
            className="inline-flex items-center gap-1.5 rounded-lg bg-brand-blue px-4 py-2.5 text-sm font-semibold text-white transition-colors duration-150 hover:bg-brand-blue/90 motion-reduce:transition-none"
          >
            {ABOUT_PARTNER_CTA}
          </AboutExternalLink>
        </div>
      </div>

      {/* Affiliate program */}
      <div>
        <AboutSectionHeading
          id="about-affiliate-heading"
          title={ABOUT_AFFILIATE_SECTION_TITLE}
          lead={ABOUT_AFFILIATE_SECTION_BODY}
        />
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
            <div key={metric.label} className="border-t border-brand-dark/10 pt-3">
              <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75">
                {metric.label}
              </p>
              <p className="text-sm font-semibold text-brand-dark">{metric.value}</p>
            </div>
          ))}
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-brand-dark/10 pt-4">
          <AboutExternalLink
            linkId="hol_affiliates"
            href={ABOUT_AFFILIATE_CTA_HREF}
            className="inline-flex items-center gap-1.5 rounded-lg border border-brand-dark/15 bg-white px-4 py-2.5 text-sm font-semibold text-brand-dark transition-colors duration-150 hover:border-brand-dark/25 hover:bg-surface-1 motion-reduce:transition-none"
          >
            {ABOUT_AFFILIATE_CTA}
          </AboutExternalLink>
          <p className="text-xs text-brand-dark/75">{ABOUT_AFFILIATE_DISCLOSURE}</p>
        </div>
      </div>
    </div>
  );
}
