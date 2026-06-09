import { Surface, SectionLabel, ActionButton, Badge } from "../../approval-center-primitives";
import { ABOUT_PATH_CARDS } from "../about-content";
import { AboutExternalLink } from "./about-external-link";
import type { AboutPathCard, AboutLinkId } from "../about-types";

const CARD_LINK_MAP: Record<AboutPathCard["id"], AboutLinkId> = {
  protect_locally: "hol_guard_install",
  sync_team: "hol_guard_cloud",
  validate_ci: "plugin_scanner_ci_docs",
  standards_partner: "hol_partners",
  affiliate_starter_kit: "hol_affiliates",
};

function priorityLabel(priority: AboutPathCard["priority"]): string {
  if (priority === "primary") return "Primary";
  if (priority === "secondary") return "Secondary";
  return "Ecosystem";
}

function PathCard({ card }: { card: AboutPathCard }) {
  const isPrimary = card.priority === "primary";
  const isTertiary = card.priority === "tertiary";

  return (
    <Surface
      className={`flex flex-col h-full ${isPrimary ? "sm:col-span-2 lg:col-span-2" : ""}`}
      tone={isPrimary ? "accent" : "default"}
    >
      <div className="flex items-center justify-between gap-2 mb-2">
        <Badge tone={isPrimary ? "info" : isTertiary ? "default" : "warning"}>
          {priorityLabel(card.priority)}
        </Badge>
        {card.disclosureRequired && (
          <span className="text-[10px] text-slate-400">Disclosure required</span>
        )}
      </div>
      <h3 className="text-base font-bold text-brand-dark">{card.title}</h3>
      <p className="mt-1.5 text-sm leading-relaxed text-brand-dark/70 flex-1">
        {card.description}
      </p>
      <div className="mt-4">
        <AboutExternalLink
          linkId={CARD_LINK_MAP[card.id]}
          href={card.ctaHref}
          className="text-sm font-semibold text-brand-blue hover:underline"
        >
          {card.ctaLabel}
        </AboutExternalLink>
      </div>
    </Surface>
  );
}

export function PathwayGrid() {
  const primary = ABOUT_PATH_CARDS.filter((c) => c.priority === "primary");
  const secondary = ABOUT_PATH_CARDS.filter((c) => c.priority === "secondary");
  const tertiary = ABOUT_PATH_CARDS.filter((c) => c.priority === "tertiary");

  return (
    <div>
      <SectionLabel>Choose your path</SectionLabel>
      <p className="mt-2 max-w-2xl text-base leading-relaxed text-brand-dark/75">
        There are many ways to participate in the Guard ecosystem. Local protection comes first.
      </p>

      <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {primary.map((card) => (
          <PathCard key={card.id} card={card} />
        ))}
      </div>

      <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {secondary.map((card) => (
          <PathCard key={card.id} card={card} />
        ))}
      </div>

      <div className="mt-8">
        <h3 className="text-sm font-bold text-brand-dark mb-3">Ecosystem programs</h3>
        <div className="grid gap-4 sm:grid-cols-2">
          {tertiary.map((card) => (
            <PathCard key={card.id} card={card} />
          ))}
        </div>
      </div>
    </div>
  );
}
