import { useMemo, useRef } from "react";
import { HiMiniArrowRight, HiMiniArrowTopRightOnSquare, HiMiniClock, HiMiniPlus } from "react-icons/hi2";

import type { ExtensionCatalogSummary } from "../extension-controls-api";
import { ExtensionBrandMark } from "./components/extension-brand-mark";
import { useDiscoveryMeasurement } from "./discovery-measurement";
import {
  advertiseUrl,
  featuredWindowLabel,
  sponsoredCardLabel,
  type DiscoveryFeedStatus,
  type DiscoveryOffer,
  type DiscoveryPlacement,
  type JoinedDiscoveryCard,
} from "./extensions-discover-model";
import {
  buildSpotlight,
  SHELF_SLOT_PRODUCTS,
  slotStartingPrice,
  slotState,
  spotlightHeading,
  SPOTLIGHT_CELL_COUNT,
  type SlotState,
  type SpotlightActivityCount,
  type SpotlightCard,
} from "./extensions-spotlight-model";

/**
 * The spotlight shelf at the head of Extensions.
 *
 * It has one job: show three extensions worth looking at, and say plainly why
 * each is there. Paid placements take the cells they bought and are the only
 * dark cards on the page, always labeled. Unsold cells fall through to this
 * device's busiest tools and then to a declared starter set, so the shelf is
 * never empty and never pretends an editorial list is a measurement. When no
 * cell is sold, the last one becomes the slot itself, at the exact size and
 * position a buyer would get.
 */

function SponsorLine(props: { placement: DiscoveryPlacement; featured: boolean }) {
  const brand = props.placement.creative.brandName?.trim();
  const window = featuredWindowLabel(props.placement);
  return (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
      <span className="guard-sponsor-label guard-sponsor-label-inverse" data-sponsored-label>
        {sponsoredCardLabel(props.featured)}
      </span>
      {brand ? (
        <span className="text-xs text-white/70">
          Paid for by <span className="font-semibold text-white">{brand}</span>
        </span>
      ) : null}
      {window ? (
        <span className="inline-flex items-center gap-1 text-xs text-white/70">
          <HiMiniClock className="size-3.5" aria-hidden="true" />
          {window}
        </span>
      ) : null}
    </div>
  );
}

function PaidSpotlightCard(props: {
  card: SpotlightCard;
  placement: DiscoveryPlacement;
  snapshotId: string | null;
  onOpen: (extension: ExtensionCatalogSummary) => void;
}) {
  const ref = useRef<HTMLElement | null>(null);
  const recordOpen = useDiscoveryMeasurement(
    ref,
    props.snapshotId,
    props.placement,
    props.card.featured ? "extensions_featured" : "extensions_feed",
  );
  const { catalog } = props.card;
  const headline = props.placement.creative.headline?.trim() || catalog.name;
  return (
    <article
      ref={ref}
      className="guard-spotlight-card guard-spotlight-card-paid"
      data-testid={props.card.featured ? "discovery-featured-card" : "discovery-sponsored-card"}
      data-sponsored-placement-id={props.placement.publicPlacementId}
    >
      <div className="flex items-start gap-3">
        <ExtensionBrandMark
          extension_id={catalog.extension_id}
          name={catalog.name}
          executables={catalog.executables}
          ecosystem_ids={catalog.ecosystem_ids}
          size="md"
        />
        <div className="min-w-0 flex-1">
          <SponsorLine placement={props.placement} featured={props.card.featured} />
          <h3 className="mt-2 text-balance text-lg font-semibold leading-snug tracking-tight text-white">{headline}</h3>
          <p className="mt-0.5 text-xs font-medium text-white/60">{catalog.name}</p>
        </div>
      </div>
      <p className="mt-3 line-clamp-3 text-sm leading-6 text-white/85">{props.placement.creative.body}</p>
      <div className="mt-auto pt-5">
        <button
          type="button"
          className="guard-discover-cta guard-discover-cta-inverse"
          onClick={() => {
            recordOpen();
            props.onOpen(catalog);
          }}
        >
          View extension
          <HiMiniArrowRight className="size-4" aria-hidden="true" />
        </button>
        <p className="mt-3 text-xs text-white/55">Paid placement. Your protection settings are unchanged.</p>
      </div>
    </article>
  );
}

function OrganicSpotlightCard(props: {
  card: SpotlightCard;
  onOpen: (extension: ExtensionCatalogSummary) => void;
}) {
  const { catalog, reason, basis } = props.card;
  return (
    <article className="guard-spotlight-card" data-testid="spotlight-organic-card" data-basis={basis}>
      <div className="flex items-start gap-3">
        <ExtensionBrandMark
          extension_id={catalog.extension_id}
          name={catalog.name}
          executables={catalog.executables}
          ecosystem_ids={catalog.ecosystem_ids}
          size="md"
        />
        <div className="min-w-0 flex-1">
          <h3 className="text-base font-semibold leading-snug tracking-tight text-brand-dark">{catalog.name}</h3>
          {reason ? (
            <p className="mt-1 font-mono text-xs tabular-nums text-brand-dark/55">{reason}</p>
          ) : (
            <p className="mt-1 text-xs text-brand-dark/55">Built-in coverage, ready to review</p>
          )}
        </div>
      </div>
      <p className="mt-3 line-clamp-3 text-sm leading-6 text-brand-dark/75">{catalog.description}</p>
      <div className="mt-auto pt-5">
        <button type="button" className="guard-discover-cta" onClick={() => props.onOpen(catalog)}>
          Review protection
          <HiMiniArrowRight className="size-4" aria-hidden="true" />
        </button>
      </div>
    </article>
  );
}

/**
 * The slot offered for sale, rendered at the size of a paid cell so a maker
 * sees exactly what the money buys. Shown only on an authoritative vacancy.
 */
function VacantSlotCard(props: { state: Exclude<SlotState, "hidden">; price: string | null }) {
  const soldOut = props.state === "sold-out";
  return (
    <article
      className="guard-spotlight-card guard-spotlight-slot"
      data-testid="spotlight-slot-card"
      data-state={props.state}
      aria-labelledby="spotlight-slot-heading"
    >
      <div className="flex items-start gap-3">
        <span className="guard-spotlight-slot-mark" aria-hidden="true">
          <HiMiniPlus className="size-5" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-brand-blue">
            {soldOut ? "Fully booked" : "This slot is open"}
          </p>
          <h3 id="spotlight-slot-heading" className="mt-2 text-base font-semibold leading-snug tracking-tight text-brand-dark">
            {soldOut ? "Every placement here is taken." : "Put your extension in this spot."}
          </h3>
        </div>
      </div>
      <p className="mt-3 text-sm leading-6 text-brand-dark/75">
        {soldOut
          ? "Windows free up as placements end. See the schedule to book the next one."
          : "Developers land here before they open anything else. Placements are labeled Sponsored, carry your own headline, and never change anyone’s protection."}
      </p>
      <div className="mt-auto pt-5">
        <a
          className="guard-discover-cta"
          href={advertiseUrl("extensions_feed")}
          target="_blank"
          rel="noopener noreferrer"
          referrerPolicy="no-referrer"
        >
          {soldOut ? "See the schedule" : props.price ? `Get this spot · from ${props.price}/mo` : "Get this spot"}
          <HiMiniArrowTopRightOnSquare className="size-4" aria-hidden="true" />
        </a>
        <p className="mt-3 text-xs text-brand-dark/50">
          {soldOut ? (
            "Checkout always shows the live quote before payment."
          ) : (
            <>
              Built an extension and not listed yet?{" "}
              <a
                className="font-semibold text-brand-blue hover:underline"
                href="https://github.com/hashgraph-online/hol-guard/blob/main/CONTRIBUTING.md"
                target="_blank"
                rel="noopener noreferrer"
                referrerPolicy="no-referrer"
              >
                Submit it free
              </a>
              .
            </>
          )}
        </p>
      </div>
    </article>
  );
}

function SpotlightSkeleton() {
  return (
    <div className="guard-spotlight-grid mt-5" aria-hidden="true">
      {[0, 1, 2].map((cell) => (
        <div key={cell} className="guard-spotlight-card guard-spotlight-skeleton" />
      ))}
    </div>
  );
}

export function ExtensionsSpotlight(props: {
  catalogExtensions: readonly ExtensionCatalogSummary[];
  featured: readonly JoinedDiscoveryCard[];
  sponsored: readonly JoinedDiscoveryCard[];
  activity: readonly SpotlightActivityCount[];
  offers: readonly DiscoveryOffer[];
  status: DiscoveryFeedStatus;
  snapshotId: string | null;
  settled: boolean;
  onOpenExtension: (extension: ExtensionCatalogSummary) => void;
}) {
  const spotlight = useMemo(
    () => buildSpotlight({
      featured: props.featured,
      sponsored: props.sponsored,
      activity: props.activity,
      catalog: props.catalogExtensions,
    }),
    [props.activity, props.catalogExtensions, props.featured, props.sponsored],
  );
  const slot = slotState({ status: props.status, offers: props.offers, products: SHELF_SLOT_PRODUCTS });
  const price = useMemo(() => slotStartingPrice(props.offers, SHELF_SLOT_PRODUCTS), [props.offers]);
  const heading = spotlightHeading(spotlight.lead);

  // The shelf would otherwise flip heading and contents as the feed and the
  // activity query land a moment apart; hold one skeleton until both settle.
  const waiting = !props.settled || props.status === "loading";
  // The slot replaces the weakest cell rather than adding a fourth, so the
  // row a buyer sees is the row a buyer gets. Only an authoritative "open"
  // offers it: a sold-out claim beside organic cards contradicts itself.
  const showSlot = spotlight.vacant && slot === "open";
  const cards = showSlot ? spotlight.cards.slice(0, SPOTLIGHT_CELL_COUNT - 1) : spotlight.cards;

  if (props.catalogExtensions.length === 0) return null;

  return (
    <section className="mt-6" aria-labelledby="extensions-spotlight-heading" data-testid="extensions-spotlight">
      <div className="flex flex-col gap-1">
        <h2 id="extensions-spotlight-heading" className="text-xl font-semibold tracking-tight text-brand-dark">
          {waiting ? "Extensions to look at" : heading.title}
        </h2>
        <p className="max-w-[72ch] text-sm leading-6 text-brand-dark/60" data-testid="spotlight-basis">
          {waiting ? "\u00a0" : heading.basis}
        </p>
      </div>
      {waiting ? (
        <SpotlightSkeleton />
      ) : (
        <div className="guard-spotlight-grid mt-5">
          {cards.map((card) => (
            card.placement ? (
              <PaidSpotlightCard
                key={card.catalog.extension_id}
                card={card}
                placement={card.placement}
                snapshotId={props.snapshotId}
                onOpen={props.onOpenExtension}
              />
            ) : (
              <OrganicSpotlightCard key={card.catalog.extension_id} card={card} onOpen={props.onOpenExtension} />
            )
          ))}
          {showSlot ? <VacantSlotCard state={slot} price={price} /> : null}
        </div>
      )}
      <SpotlightStatusLine status={props.status} />
    </section>
  );
}

/**
 * One quiet line about paid inventory. Unavailable, rate-limited and offline
 * all read the same on purpose: the operator learns paid content is absent
 * without a commercial error, and no state ever claims vacancy it cannot see.
 */
function SpotlightStatusLine(props: { status: DiscoveryFeedStatus }) {
  if (props.status === "loading") return null;
  if (props.status === "ready") {
    return (
      <p className="mt-4 text-xs text-brand-dark/45" data-testid="discovery-status-ready">
        Sponsored placements, when present, are labeled and never change protection.
      </p>
    );
  }
  if (props.status === "opt-out") {
    return (
      <p className="mt-4 text-xs text-brand-dark/45" data-testid="discovery-status-optout">
        Sponsored discovery is turned off for this device. Extension management is unaffected.
      </p>
    );
  }
  return (
    <p className="mt-4 text-xs text-brand-dark/45" data-testid={`discovery-status-${props.status}`}>
      Sponsored placements are not available right now.{" "}
      <a
        className="font-semibold text-brand-blue hover:underline"
        href={advertiseUrl("extensions_header")}
        target="_blank"
        rel="noopener noreferrer"
        referrerPolicy="no-referrer"
      >
        About sponsorships
      </a>
    </p>
  );
}

/**
 * The bookable row inside the catalog list. Same height and rhythm as the
 * rows around it, clearly not an extension, and only ever shown on an
 * authoritative open slot in an unfiltered list long enough that one promo
 * row cannot crowd the results out.
 */
export function CatalogSlotRow(props: { price: string | null }) {
  return (
    <div className="guard-catalog-slot-row" data-testid="catalog-slot-row">
      <span className="guard-spotlight-slot-mark" aria-hidden="true">
        <HiMiniPlus className="size-5" />
      </span>
      <div className="min-w-0 flex-[1_1_16rem]">
        <p className="text-sm font-semibold text-brand-dark">Your extension could be listed here.</p>
        <p className="mt-0.5 text-sm leading-6 text-brand-dark/65">
          A sponsored listing keeps its real protection state and its Sponsored label. Position is all it buys.
        </p>
      </div>
      <a
        className="guard-discover-cta shrink-0"
        href={advertiseUrl("extensions_feed")}
        target="_blank"
        rel="noopener noreferrer"
        referrerPolicy="no-referrer"
      >
        {props.price ? `Get a listing · from ${props.price}/mo` : "Get a listing"}
        <HiMiniArrowTopRightOnSquare className="size-4" aria-hidden="true" />
      </a>
    </div>
  );
}
