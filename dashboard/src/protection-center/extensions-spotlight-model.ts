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

/**
 * Plain English for the risk classes the catalog already declares. Every
 * phrase describes what the extension's own rules look at, so a starter card
 * can say something useful without inventing a claim or a metric. An id with
 * no entry here is skipped rather than guessed at.
 */
export const RISK_CLASS_PHRASES: Readonly<Record<string, string>> = {
  destructive_shell: "irreversible deletes and overwrites",
  network_egress: "commands that send data off this machine",
  execution: "running code that was fetched or generated",
  dynamic_execution: "code assembled at run time",
  encoded_execution: "code hidden behind encoding",
  remote_execution: "commands run on another host",
  local_secret_read: "reads of local secrets and keys",
  credential_access: "credential lookups",
  credential_exfiltration: "credentials being sent somewhere",
  security_credential_provisioning: "new credentials being issued",
  data_flow_exfiltration: "data leaving on an unexpected path",
  data_export: "bulk exports",
  database_mutation: "writes against live databases",
  supply_chain: "untrusted installs and lockfile edits",
  financial_transaction: "transfers and payments",
  permission_change: "permission and access changes",
  policy_bypass: "attempts to work around your own policy",
  destructive: "irreversible changes",
};

/**
 * What this extension watches for, in the catalog's own words. Two phrases at
 * most: the point is to help someone choose, not to recite a taxonomy.
 */
export function protectionLine(catalog: ExtensionCatalogSummary): string | null {
  const phrases: string[] = [];
  for (const riskClass of catalog.risk_classes ?? []) {
    const phrase = RISK_CLASS_PHRASES[riskClass];
    if (phrase && !phrases.includes(phrase)) phrases.push(phrase);
    if (phrases.length === 2) break;
  }
  if (phrases.length === 0) return null;
  return `Watches for ${phrases.join(" and ")}.`;
}

/** The rule count the catalog reports, stated as a count and nothing more. */
export function ruleCountLabel(catalog: ExtensionCatalogSummary): string | null {
  const count = catalog.rule_count;
  if (!Number.isFinite(count) || count <= 0) return null;
  return `${count.toLocaleString()} ${count === 1 ? "rule" : "rules"}`;
}

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
  /**
   * Whether an extension is already protecting this device. The starter tier
   * leads with what is still off, because that is the only cell a reader can
   * act on; everything else is a reassurance, not a suggestion.
   */
  isActive?: (extension: ExtensionCatalogSummary) => boolean;
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

  const isActive = input.isActive ?? (() => false);
  const starters = STARTER_SPOTLIGHT_IDS
    .map((extensionId) => catalogById.get(extensionId))
    .filter((catalog): catalog is ExtensionCatalogSummary => catalog !== undefined);
  for (const catalog of [...starters.filter((c) => !isActive(c)), ...starters.filter((c) => isActive(c))]) {
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

/**
 * True when every organic card on the shelf is already protecting this device.
 * Takes the cards that will actually render - an open slot replaces the last
 * cell, and a card nobody sees must not decide what the heading claims.
 */
export function allCardsActive(
  cards: readonly SpotlightCard[],
  isActive: (extension: ExtensionCatalogSummary) => boolean,
): boolean {
  const organic = cards.filter((card) => card.basis !== "paid");
  return organic.length > 0 && organic.every((card) => isActive(card.catalog));
}

export interface SpotlightHeading {
  title: string;
  basis: string;
}

/** What the shelf says it is, and on what evidence. One per lead basis. */
export function spotlightHeading(lead: SpotlightBasis, allActive = false): SpotlightHeading {
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
  if (allActive) {
    return {
      title: "Already covering the basics",
      basis: "These are on, and Guard checks them on every command. Not a ranking or a popularity measure.",
    };
  }
  return {
    title: "Good places to start",
    basis: "A starting selection from the built-in catalog. Not a ranking or a popularity measure.",
  };
}

export type SlotState = "open" | "sold-out" | "unconfirmed" | "hidden";
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
 * Whether to offer the placement, and what may be said about it. The offer
 * itself does not depend on the server: a reader can always ask for the spot.
 * What the server decides is the wording - "open" and "sold-out" are claimed
 * only on an authoritative availability, and every other condition (a failed
 * feed, an availability the server never checked, a server not serving the
 * feed at all) is "unconfirmed", which asks without claiming a vacancy, a
 * price or a count. Only a device that turned discovery off, or one still
 * loading it, is asked nothing.
 */
export function slotState(input: {
  status: DiscoveryFeedStatus;
  offers: readonly DiscoveryOffer[];
  products: readonly DiscoveryProduct[];
}): SlotState {
  if (input.status === "loading" || input.status === "opt-out") return "hidden";
  const known = forProducts(input.offers, input.products).filter((offer) => offer.availability !== "unknown");
  if (known.length === 0) return "unconfirmed";
  return known.some((offer) => offer.availability === "open") ? "open" : "sold-out";
}

/**
 * The one offer a buyer is actually being quoted: the cheapest product that
 * is open for sale among the products that buy this placement. Price and
 * remaining capacity are both read off it so the two numbers always describe
 * the same purchasable thing - a price for one product beside capacity summed
 * over two is a number a buyer cannot act on.
 */
export function quotedSlotOffer(
  offers: readonly DiscoveryOffer[],
  products: readonly DiscoveryProduct[],
): DiscoveryOffer | null {
  const rank = (offer: DiscoveryOffer): number => products.indexOf(offer.product);
  const priced = (offer: DiscoveryOffer): boolean => offer.indicativeAmountCents !== null && !!offer.currency;
  const candidates = forProducts(offers, products)
    .filter((offer) => offer.availability === "open")
    .sort((left, right) => {
      // A product we can name a price for leads one we cannot, then the
      // cheapest of those, then the order the placement sells them in.
      if (priced(left) !== priced(right)) return priced(left) ? -1 : 1;
      if (priced(left) && priced(right)) {
        const difference = (left.indicativeAmountCents as number) - (right.indicativeAmountCents as number);
        if (difference !== 0) return difference;
      }
      return rank(left) - rank(right);
    });
  return candidates[0] ?? null;
}

/**
 * The indicative monthly price of the quoted offer. A sponsored row never
 * quotes a featured price, and a sold-out placement quotes nothing.
 */
export function slotStartingPrice(
  offers: readonly DiscoveryOffer[],
  products: readonly DiscoveryProduct[],
): string | null {
  const quoted = quotedSlotOffer(offers, products);
  if (!quoted || quoted.indicativeAmountCents === null || !quoted.currency) return null;
  const cents = quoted.indicativeAmountCents;
  try {
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: quoted.currency.toUpperCase(),
      maximumFractionDigits: cents % 100 === 0 ? 0 : 2,
    }).format(cents / 100);
  } catch {
    return null;
  }
}

/**
 * How many of the quoted product's spots are still for sale. Capacity is
 * never summed across products: with real inventory that reads as "68 of 70
 * open" beside the price of one of the two, which tells a buyer nothing about
 * what they would be buying. When nothing is open, the one product still on
 * sale reports its own sold-out count rather than a total nobody offered.
 */
export function slotInventory(
  offers: readonly DiscoveryOffer[],
  products: readonly DiscoveryProduct[],
): { open: number; total: number } | null {
  const soldOut = forProducts(offers, products)
    .filter((offer) => offer.availability === "sold_out")
    .sort((left, right) => products.indexOf(left.product) - products.indexOf(right.product));
  const quoted = quotedSlotOffer(offers, products) ?? soldOut[0] ?? null;
  if (!quoted || quoted.openSlots === null || quoted.totalSlots === null) return null;
  if (quoted.totalSlots < 1) return null;
  return { open: quoted.openSlots, total: quoted.totalSlots };
}

/** "3 of 4 open", only when the server actually confirmed both numbers. */
export function slotInventoryLabel(
  offers: readonly DiscoveryOffer[],
  products: readonly DiscoveryProduct[],
): string | null {
  const inventory = slotInventory(offers, products);
  if (!inventory) return null;
  return `${inventory.open} of ${inventory.total} open.`;
}

/** Reads the extension dimension of a command-activity analytics response. */
export function spotlightActivityFromDimensions(
  buckets: readonly { value: string; count: number }[],
): SpotlightActivityCount[] {
  return buckets
    .filter((bucket) => typeof bucket.value === "string" && Number.isFinite(bucket.count))
    .map((bucket) => ({ extensionId: bucket.value, count: Math.max(0, Math.trunc(bucket.count)) }));
}
