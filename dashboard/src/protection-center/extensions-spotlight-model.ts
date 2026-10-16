import type { ExtensionCatalogSummary } from "../extension-controls-api";
import type {
  DiscoveryFeedStatus,
  DiscoveryOffer,
  DiscoveryPlacement,
  JoinedDiscoveryCard,
} from "./extensions-discover-model";

/**
 * Selection model for the Extensions spotlight shelf.
 *
 * The shelf leads the page, so it must never be empty and must never claim
 * more than Guard can prove. Paid placements come first; the remaining cells
 * fall back to what this device actually checked, and then to a fixed starter
 * set from the built-in catalog. Every tier states its own basis, and nothing
 * here invents a metric: organic counts come from the device's own command
 * activity and the starter set is declared an editorial list, not a ranking.
 */

export const SPOTLIGHT_CELL_COUNT = 3;

/** Window used for the "busiest on this device" basis. */
export const SPOTLIGHT_ACTIVITY_DAYS = 30;

/**
 * The starter shelf for a device with no paid inventory and no recorded
 * activity yet: widely installed developer tooling the built-in catalog
 * already covers. A fixed editorial list in this order, never presented as
 * popularity, a ranking, or a measurement.
 */
export const STARTER_SPOTLIGHT_IDS: readonly string[] = [
  "command.git",
  "command.container-runtime",
  "command.cloud.aws",
  "command.package.node",
  "command.kubernetes-operations",
  "command.remote.ssh",
  "command.github",
  "command.package.python",
  "command.database.postgresql",
  "command.filesystem",
];

export type SpotlightBasis = "paid" | "activity" | "starter";

export interface SpotlightCard {
  catalog: ExtensionCatalogSummary;
  /** Present only on a paid card; organic cards never carry creative. */
  placement: DiscoveryPlacement | null;
  /** A paid card bought a featured product rather than a sponsored listing. */
  featured: boolean;
  basis: SpotlightBasis;
  /** The honest one-line reason an organic card is on the shelf. */
  reason: string | null;
}

export interface SpotlightActivityCount {
  extensionId: string;
  count: number;
}

export interface Spotlight {
  cards: SpotlightCard[];
  /** The strongest basis present, which the section heading speaks to. */
  lead: SpotlightBasis;
  /** True when no card was paid for, so the vacant cell is worth showing. */
  vacant: boolean;
}

function commandsCheckedLabel(count: number): string {
  return `${count.toLocaleString()} ${count === 1 ? "command" : "commands"} checked here`;
}

/**
 * Fills the shelf: paid placements first in server order, then the device's
 * busiest tools, then the starter set. Duplicates are dropped by canonical id
 * so one extension never takes two cells.
 */
export function buildSpotlight(input: {
  featured: readonly JoinedDiscoveryCard[];
  sponsored: readonly JoinedDiscoveryCard[];
  activity: readonly SpotlightActivityCount[];
  catalog: readonly ExtensionCatalogSummary[];
}): Spotlight {
  const cards: SpotlightCard[] = [];
  const taken = new Set<string>();
  const add = (card: SpotlightCard) => {
    if (cards.length >= SPOTLIGHT_CELL_COUNT) return;
    if (taken.has(card.catalog.extension_id)) return;
    taken.add(card.catalog.extension_id);
    cards.push(card);
  };

  for (const entry of input.featured) {
    add({ catalog: entry.catalog, placement: entry.placement, featured: true, basis: "paid", reason: null });
  }
  for (const entry of input.sponsored) {
    add({ catalog: entry.catalog, placement: entry.placement, featured: false, basis: "paid", reason: null });
  }
  const paidCount = cards.length;

  const catalogById = new Map(input.catalog.map((extension) => [extension.extension_id, extension]));
  const ranked = [...input.activity]
    .filter((bucket) => bucket.count > 0 && catalogById.has(bucket.extensionId))
    .sort((left, right) => right.count - left.count || left.extensionId.localeCompare(right.extensionId));
  for (const bucket of ranked) {
    const catalog = catalogById.get(bucket.extensionId);
    if (!catalog) continue;
    add({ catalog, placement: null, featured: false, basis: "activity", reason: commandsCheckedLabel(bucket.count) });
  }

  for (const extensionId of STARTER_SPOTLIGHT_IDS) {
    const catalog = catalogById.get(extensionId);
    if (!catalog) continue;
    add({ catalog, placement: null, featured: false, basis: "starter", reason: null });
  }
  // A catalog need not contain any starter id - a trimmed build, a future
  // rename - so the last resort is catalog order. A heading above an empty
  // grid would be exactly the dead surface this shelf exists to prevent.
  for (const catalog of input.catalog) {
    add({ catalog, placement: null, featured: false, basis: "starter", reason: null });
  }

  return {
    cards,
    lead: paidCount > 0 ? "paid" : (cards.some((card) => card.basis === "activity") ? "activity" : "starter"),
    vacant: paidCount === 0,
  };
}

export interface SpotlightHeading {
  title: string;
  basis: string;
}

/** What the shelf says it is, and on what evidence. One per lead basis. */
export function spotlightHeading(lead: SpotlightBasis): SpotlightHeading {
  if (lead === "paid") {
    return {
      title: "Featured by their makers",
      basis: "Paid placements are labeled. They change position here, never your protection.",
    };
  }
  if (lead === "activity") {
    return {
      title: "Busiest tools on this device",
      basis: `Counted from Guard's own decisions over the last ${SPOTLIGHT_ACTIVITY_DAYS} days.`,
    };
  }
  return {
    title: "Good places to start",
    basis: "A starting selection from the built-in catalog. Not a ranking or a popularity measure.",
  };
}

export type SlotState = "open" | "sold-out" | "hidden";
export type DiscoveryProduct = DiscoveryOffer["product"];

/** The products that buy the shelf cell, and the one that buys a catalog row. */
export const SHELF_SLOT_PRODUCTS: readonly DiscoveryProduct[] = ["always", "time_slot"];
export const CATALOG_SLOT_PRODUCTS: readonly DiscoveryProduct[] = ["sponsored"];

function forProducts(
  offers: readonly DiscoveryOffer[],
  products: readonly DiscoveryProduct[],
): DiscoveryOffer[] {
  return offers.filter((offer) => products.includes(offer.product));
}

/**
 * Whether to offer the placement for sale, and how. Vacancy is only ever
 * claimed on an authoritative "open" from the server; every other condition
 * - a failed feed, a device that turned discovery off, an unknown
 * availability - hides the offer rather than guessing.
 */
export function slotState(input: {
  status: DiscoveryFeedStatus;
  offers: readonly DiscoveryOffer[];
  products: readonly DiscoveryProduct[];
}): SlotState {
  if (input.status !== "ready") return "hidden";
  const known = forProducts(input.offers, input.products).filter((offer) => offer.availability !== "unknown");
  if (known.length === 0) return "hidden";
  return known.some((offer) => offer.availability === "open") ? "open" : "sold-out";
}

/**
 * The cheapest indicative monthly price among the products that actually buy
 * the placement being offered. A sponsored row never quotes a featured price.
 */
export function slotStartingPrice(
  offers: readonly DiscoveryOffer[],
  products: readonly DiscoveryProduct[],
): string | null {
  const amounts = forProducts(offers, products)
    .filter((offer) => offer.availability === "open" && offer.indicativeAmountCents !== null && offer.currency)
    .map((offer) => ({ cents: offer.indicativeAmountCents as number, currency: offer.currency as string }))
    .sort((left, right) => left.cents - right.cents);
  const cheapest = amounts[0];
  if (!cheapest) return null;
  try {
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: cheapest.currency.toUpperCase(),
      maximumFractionDigits: cheapest.cents % 100 === 0 ? 0 : 2,
    }).format(cheapest.cents / 100);
  } catch {
    return null;
  }
}

/** Reads the extension dimension of a command-activity analytics response. */
export function spotlightActivityFromDimensions(
  buckets: readonly { value: string; count: number }[],
): SpotlightActivityCount[] {
  return buckets
    .filter((bucket) => typeof bucket.value === "string" && Number.isFinite(bucket.count))
    .map((bucket) => ({ extensionId: bucket.value, count: Math.max(0, Math.trunc(bucket.count)) }));
}
