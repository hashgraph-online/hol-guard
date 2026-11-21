import { ABOUT_PATH_CARDS } from "../about-content";
import { AboutExternalLink } from "./about-external-link";
import { AboutSectionHeading } from "./about-section-heading";
import type { AboutPathCard, AboutLinkId } from "../about-types";

const CARD_LINK_MAP: Record<AboutPathCard["id"], AboutLinkId> = {
  protect_locally: "hol_guard_install",
  sync_team: "hol_guard_cloud",
  validate_ci: "plugin_scanner_ci_docs",
  standards_partner: "hol_partners",
  affiliate_starter_kit: "hol_affiliates",
};

function PathCard({ card }: { card: AboutPathCard }) {
  return (
    <li className="flex flex-col border-t border-brand-dark/10 py-5 lg:border-l lg:border-t-0 lg:px-6 lg:py-1 lg:first:border-l-0 lg:first:pl-0">
      {/* The paths were labelled Primary / Secondary / Ecosystem, which ranks
          them for whoever built the page rather than for the reader. The
          order already says which comes first. */}
      {card.disclosureRequired ? (
        <p className="mb-2 text-[11px] font-medium text-brand-dark/75">Disclosure required</p>
      ) : null}
      <h3 className="text-base font-semibold text-brand-dark">
        {card.title}
      </h3>
      <p className="mt-1.5 flex-1 text-sm leading-6 text-brand-dark/75">{card.description}</p>
      <div className="mt-4">
        <AboutExternalLink
          linkId={CARD_LINK_MAP[card.id]}
          href={card.ctaHref}
          className="text-sm font-semibold text-brand-blue underline decoration-brand-blue/30 underline-offset-[3px] transition-colors duration-150 hover:decoration-brand-blue motion-reduce:transition-none"
        >
          {card.ctaLabel}
        </AboutExternalLink>
      </div>
    </li>
  );
}

export function PathwayGrid() {
  const primary = ABOUT_PATH_CARDS.filter((c) => c.priority === "primary");
  const secondary = ABOUT_PATH_CARDS.filter((c) => c.priority === "secondary");

  return (
    <div>
      <AboutSectionHeading
        id="about-pathways-heading"
        title="Choose your path"
        lead="There are many ways to participate in the Guard ecosystem. Local protection comes first."
      />

      {/* The tertiary cards used to sit here and repeat, word for word, the
          partner and affiliate sections immediately below. Those sections say
          it in full, so this one keeps the paths a reader can take today —
          three, which is why the first card no longer spans two of three
          columns and strands an empty row beside the third. */}
      <ul className="mt-6 grid lg:grid-cols-3">
        {primary.map((card) => (
          <PathCard key={card.id} card={card} />
        ))}
        {secondary.map((card) => (
          <PathCard key={card.id} card={card} />
        ))}
      </ul>
    </div>
  );
}
