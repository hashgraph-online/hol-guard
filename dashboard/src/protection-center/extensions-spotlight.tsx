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
  allCardsActive,
  buildSpotlight,
  protectionLine,
  ruleCountLabel,
  SHELF_SLOT_PRODUCTS,
  slotInventoryLabel,
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
      <p className="line-clamp-3 text-sm leading-5 text-white/85">{props.placement.creative.body}</p>
      <div className="mt-auto">
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
        <p className="mt-2 text-xs text-white/55">Paid placement. Your protection settings are unchanged.</p>
      </div>
    </article>
  );
}

function OrganicSpotlightCard(props: {
  card: SpotlightCard;
  /** Whether this extension is already protecting the device, right now. */
  active: boolean;
  onOpen: (extension: ExtensionCatalogSummary) => void;
}) {
  const { catalog, reason, basis } = props.card;
  // Everything below comes from the catalog entry itself: what its rules look
  // at, and how many there are. No score, no ranking, no invented popularity.
  const protection = protectionLine(catalog);
  const rules = ruleCountLabel(catalog);
  return (
    <article
      className="guard-spotlight-card"
      data-testid="spotlight-organic-card"
      data-basis={basis}
      data-active={props.active ? "true" : "false"}
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
          <div className="flex items-start justify-between gap-2">
            <h3 className="text-base font-semibold leading-snug tracking-tight text-brand-dark">{catalog.name}</h3>
            <span
              className={props.active ? "guard-spotlight-state guard-spotlight-state-on" : "guard-spotlight-state"}
              data-testid="spotlight-organic-state"
            >
              {props.active ? "On" : "Off"}
            </span>
          </div>
          {reason ? (
            <p className="mt-1 font-mono text-xs tabular-nums text-brand-dark/55">{reason}</p>
          ) : rules ? (
            <p className="mt-1 text-xs text-brand-dark/55">{rules} in the built-in catalog</p>
          ) : (
            <p className="mt-1 text-xs text-brand-dark/55">Built-in coverage, ready to review</p>
          )}
        </div>
      </div>
      {protection ? (
        <p className="text-sm leading-5 text-brand-dark/85" data-testid="spotlight-organic-protection">
          {protection}
        </p>
      ) : (
        <p className="line-clamp-2 text-sm leading-5 text-brand-dark/65">{catalog.description}</p>
      )}
      <div className="mt-auto">
        <button type="button" className="guard-discover-cta guard-discover-cta-quiet" onClick={() => props.onOpen(catalog)}>
          {props.active ? "Review protection" : "Set it up"}
          <HiMiniArrowRight className="size-4" aria-hidden="true" />
        </button>
      </div>
    </article>
  );
}

/**
 * The bookable square, drawn at the size of a paid cell so a reader sees
 * exactly what the placement is. It is a standing offer: it renders whether
 * or not the server confirmed an open count, because a reader can always ask
 * for the spot. Only the numbers wait for the server.
 */
function VacantSlotCard(props: {
  state: Exclude<SlotState, "hidden" | "sold-out">;
  price: string | null;
  /** Live remaining inventory, present only when the server stated it. */
  inventory: string | null;
  /** True when the shelf kept all of its cells and the slot spans the row. */
  full?: boolean;
}) {
  return (
    <article
      className="guard-spotlight-card guard-spotlight-slot"
      data-testid="spotlight-slot-card"
      data-state={props.state}
      data-full={props.full ? "true" : undefined}
      aria-labelledby="spotlight-slot-heading"
    >
      <div className="flex items-center gap-2">
        <span className="guard-spotlight-slot-mark guard-spotlight-slot-mark-sm" aria-hidden="true">
          <HiMiniPlus className="size-4" />
        </span>
        <p className="text-xs font-semibold uppercase tracking-[0.14em] text-brand-blue">
          {props.state === "open" ? "This slot is open" : "Promote your extension"}
        </p>
      </div>
      <h3 id="spotlight-slot-heading" className="text-base font-semibold leading-snug tracking-tight text-brand-dark">
        Put your extension on this shelf.
      </h3>
      <p className="text-sm leading-5 text-brand-dark/75">
        Labeled Sponsored. Never changes anyone’s protection.
        {props.inventory ? <span className="font-semibold text-brand-dark"> {props.inventory}</span> : null}
      </p>
      <div className="mt-auto">
        <a
          className="guard-discover-cta"
          href={advertiseUrl("extensions_header")}
          target="_blank"
          rel="noopener noreferrer"
          referrerPolicy="no-referrer"
        >
          {props.price ? `Take this slot · from ${props.price}/mo` : "Take this slot"}
          <HiMiniArrowTopRightOnSquare className="size-4" aria-hidden="true" />
        </a>
        <SlotFreePath placement="extensions_header" />
      </div>
    </article>
  );
}

/**
 * The paths that cost nothing, said out loud next to the paid one. A maker
 * already in the built-in catalog claims their entry instead of buying it,
 * and a maker who is not in it yet submits the extension the usual way.
 */
function SlotFreePath(props: { placement: "extensions_feed" | "extensions_header" }) {
  return (
    <p className="mt-2 text-xs text-brand-dark/50">
      Already listed?{" "}
      <a
        className="font-semibold text-brand-blue hover:underline"
        href={advertiseUrl(props.placement, undefined, "claim")}
        target="_blank"
        rel="noopener noreferrer"
        referrerPolicy="no-referrer"
      >
        Claim it free
      </a>
      . Not listed yet?{" "}
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
    </p>
  );
}

function SpotlightSkeleton() {
  return (
    <div className="guard-spotlight-grid mt-5" aria-hidden="true">
      {[0, 1, 2].map((cell) => (
        <div key={cell} className="guard-spotlight-card guard-spotlight-skeleton min-h-40" />
      ))}
    </div>
  );
}

/**
 * Room for the slot on a shelf that is already at its cell count, taken from
 * the weakest organic cell - the last one the ranking placed. A shelf with no
 * organic cell to give up keeps every bought card and lets the slot follow
 * them; nothing a maker paid for is pushed out of view to make the ask fit.
 */
function withoutWeakestOrganic(cards: readonly SpotlightCard[]): readonly SpotlightCard[] {
  if (cards.length < SPOTLIGHT_CELL_COUNT) return cards;
  let weakest = -1;
  cards.forEach((card, index) => {
    if (!card.placement) weakest = index;
  });
  if (weakest < 0) return cards;
  return [...cards.slice(0, weakest), ...cards.slice(weakest + 1)];
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
  /** Whether an extension is protecting this device right now. */
  isExtensionActive: (extension: ExtensionCatalogSummary) => boolean;
  onOpenExtension: (extension: ExtensionCatalogSummary) => void;
}) {
  const { isExtensionActive } = props;
  const spotlight = useMemo(
    () => buildSpotlight({
      featured: props.featured,
      sponsored: props.sponsored,
      activity: props.activity,
      catalog: props.catalogExtensions,
      isActive: isExtensionActive,
    }),
    [isExtensionActive, props.activity, props.catalogExtensions, props.featured, props.sponsored],
  );
  const slot = slotState({ status: props.status, offers: props.offers, products: SHELF_SLOT_PRODUCTS });
  const price = useMemo(() => slotStartingPrice(props.offers, SHELF_SLOT_PRODUCTS), [props.offers]);
  const inventory = useMemo(() => slotInventoryLabel(props.offers, SHELF_SLOT_PRODUCTS), [props.offers]);

  // The shelf would otherwise flip heading and contents as the feed and the
  // activity query land a moment apart; hold one skeleton until both settle.
  const waiting = !props.settled || props.status === "loading";
  // The shelf carries the offer whether or not paid cards filled it, because
  // a full shelf is exactly when a reader wants the spot; only an
  // authoritative sold-out takes the offer away, since then there is nothing
  // to take. It never costs a bought cell its place: the slot takes the
  // weakest organic cell, and on a shelf that is entirely paid it simply
  // follows the three.
  const showSlot = slot === "open" || slot === "unconfirmed";
  const cards = showSlot ? withoutWeakestOrganic(spotlight.cards) : spotlight.cards;
  // Read the heading off the cards that survive that slice: a card the slot
  // pushed out of view must not decide what the shelf claims about this device.
  const heading = spotlightHeading(spotlight.lead, allCardsActive(cards, isExtensionActive));

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
              <OrganicSpotlightCard
                key={card.catalog.extension_id}
                card={card}
                active={isExtensionActive(card.catalog)}
                onOpen={props.onOpenExtension}
              />
            )
          ))}
          {showSlot ? (
            <VacantSlotCard
              state={slot === "open" ? "open" : "unconfirmed"}
              price={price}
              inventory={inventory}
              // A shelf that gave up its weakest organic cell has room for the
              // slot in the row. One that is entirely paid has none, so the
              // slot takes the whole width underneath rather than sitting as a
              // lone stub in a three-column row.
              full={cards.length >= SPOTLIGHT_CELL_COUNT}
            />
          ) : null}
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
      Paid placements could not be loaded right now.{" "}
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
 * The bookable row inside the ranked list, drawn between real rows so a
 * reader judges the placement in context. Same height and rhythm as the rows
 * around it, clearly not an extension, and shown in an unfiltered list long
 * enough that one such row cannot crowd the results out. Like the square, it
 * is a standing offer; only its numbers wait for the server.
 */
export function CatalogSlotRow(props: {
  state: Exclude<SlotState, "hidden" | "sold-out">;
  price: string | null;
  inventory: string | null;
}) {
  return (
    <div className="guard-catalog-slot-row" data-testid="catalog-slot-row" data-state={props.state}>
      <span className="guard-spotlight-slot-mark" aria-hidden="true">
        <HiMiniPlus className="size-5" />
      </span>
      <div className="min-w-0 max-w-[62ch] flex-[1_1_16rem]">
        <p className="text-sm font-semibold text-brand-dark">Put your extension in this list.</p>
        <p className="mt-0.5 text-sm leading-6 text-brand-dark/65">
          Sponsored listings sit inside the catalog, keep their real protection state and their Sponsored label.
          Position is all they buy.
          {props.inventory ? <span className="font-semibold text-brand-dark"> {props.inventory}</span> : null}
        </p>
        <SlotFreePath placement="extensions_feed" />
      </div>
      <a
        className="guard-discover-cta shrink-0 sm:ml-auto"
        href={advertiseUrl("extensions_feed")}
        target="_blank"
        rel="noopener noreferrer"
        referrerPolicy="no-referrer"
      >
        {props.price ? `Get this spot · from ${props.price}/mo` : "Get this spot"}
        <HiMiniArrowTopRightOnSquare className="size-4" aria-hidden="true" />
      </a>
    </div>
  );
}
