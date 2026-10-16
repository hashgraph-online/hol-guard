import type { ExtensionCatalogSummary } from "../extension-controls-normalize";

/**
 * Pure selection model for the Discover view. The React layer owns fetching
 * and lifecycle; every paid-content decision (local catalog join, unknown-id
 * suppression, featured/sponsored separation, visit-stable selection, prompt
 * conditions) is computed here so the rules are directly testable and no
 * query or inventory ever leaves the device.
 */

export const GUARD_DISCOVERY_CLOUD_ORIGIN = "https://hol.org";
export const GUARD_DISCOVERY_ADVERTISE_PATH =
  "/guard/extensions/advertise?source=guard_local&intent=extension-promotion";
export const MIN_ORGANIC_ROWS_BEFORE_IN_FEED = 8;

export interface DiscoveryCreative {
  headline: string;
  body: string;
  brandName: string;
}

export interface DiscoveryPlacement {
  publicPlacementId: string;
  extensionId: string;
  product: "always" | "time_slot" | "sponsored";
  slotIndex: number;
  windowIndex: number | null;
  startsAt: string;
  endsAt: string;
  creativeVersion: string;
  creative: DiscoveryCreative;
}

export interface DiscoveryOffer {
  product: "always" | "time_slot" | "sponsored";
  availability: "open" | "sold_out" | "unknown";
  indicativeAmountCents: number | null;
  currency: string | null;
  checkedAt: string | null;
  quoteRequired: true;
  /**
   * How much of this product is still for sale, when the server says so.
   * Both numbers travel together or not at all: a count is only ever shown
   * because the server sent a consistent pair, never inferred from a
   * placement list or from availability alone.
   */
  openSlots: number | null;
  totalSlots: number | null;
}

export interface DiscoverySnapshot {
  schemaVersion: string;
  snapshotId: string;
  state: "ready" | "unavailable";
  enabled: boolean;
  reasonCode: string | null;
  generatedAt: string;
  leaseExpiresAt: string;
  placements: DiscoveryPlacement[];
  offers: DiscoveryOffer[];
}

export interface DiscoveryProjection {
  snapshot: DiscoverySnapshot;
  remainingLeaseMs: number;
  policyAllowed: boolean;
}

export type DiscoveryFeedStatus =
  | "loading"
  | "ready"
  | "unavailable"
  | "rate-limited"
  | "offline"
  | "opt-out";

export interface JoinedDiscoveryCard {
  placement: DiscoveryPlacement;
  catalog: ExtensionCatalogSummary;
}

function integerOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

/**
 * Normalizes the offers a snapshot carries. An offer the dashboard cannot read
 * is dropped rather than rendered half-known, and a slot count survives only
 * as a complete, self-consistent pair that agrees with the availability it
 * arrived with - an "open" product with nothing left, or more open than exist,
 * is a contradiction the dashboard refuses to repeat to a buyer.
 */
export function parseDiscoveryOffers(value: unknown): DiscoveryOffer[] {
  if (!Array.isArray(value)) return [];
  const offers: DiscoveryOffer[] = [];
  for (const entry of value) {
    if (typeof entry !== "object" || entry === null) continue;
    const candidate = entry as Partial<DiscoveryOffer>;
    if (candidate.product !== "always" && candidate.product !== "time_slot" && candidate.product !== "sponsored") continue;
    if (
      candidate.availability !== "open"
      && candidate.availability !== "sold_out"
      && candidate.availability !== "unknown"
    ) continue;
    if (candidate.quoteRequired !== true) continue;
    const open = integerOrNull(candidate.openSlots);
    const total = integerOrNull(candidate.totalSlots);
    const paired = open !== null && total !== null
      && total >= 1
      && open <= total
      && candidate.availability !== "unknown"
      && (candidate.availability === "open" ? open >= 1 : open === 0);
    offers.push({
      product: candidate.product,
      availability: candidate.availability,
      indicativeAmountCents:
        typeof candidate.indicativeAmountCents === "number" && Number.isFinite(candidate.indicativeAmountCents)
          ? candidate.indicativeAmountCents
          : null,
      currency: typeof candidate.currency === "string" ? candidate.currency : null,
      checkedAt: typeof candidate.checkedAt === "string" ? candidate.checkedAt : null,
      quoteRequired: true,
      openSlots: paired ? open : null,
      totalSlots: paired ? total : null,
    });
  }
  return offers;
}

export function parseDiscoveryProjection(value: unknown): DiscoveryProjection | null {
  if (typeof value !== "object" || value === null) return null;
  const record = value as Partial<DiscoveryProjection> & { snapshot?: Partial<DiscoverySnapshot> };
  const snapshot = record.snapshot;
  if (typeof record.remainingLeaseMs !== "number" || typeof record.policyAllowed !== "boolean") return null;
  if (typeof snapshot !== "object" || snapshot === null) return null;
  if (snapshot.state !== "ready" && snapshot.state !== "unavailable") return null;
  if (!Array.isArray(snapshot.placements)) return null;
  for (const placement of snapshot.placements) {
    const candidate = placement as Partial<DiscoveryPlacement>;
    if (
      typeof candidate.publicPlacementId !== "string"
      || typeof candidate.extensionId !== "string"
      || (candidate.product !== "always" && candidate.product !== "time_slot" && candidate.product !== "sponsored")
      || typeof candidate.endsAt !== "string"
      || typeof candidate.creativeVersion !== "string"
      || typeof candidate.creative?.headline !== "string"
      || typeof candidate.creative?.body !== "string"
    ) {
      return null;
    }
  }
  return {
    snapshot: {
      schemaVersion: String(snapshot.schemaVersion ?? ""),
      snapshotId: String(snapshot.snapshotId ?? ""),
      state: snapshot.state,
      enabled: snapshot.enabled === true,
      reasonCode: typeof snapshot.reasonCode === "string" ? snapshot.reasonCode : null,
      generatedAt: String(snapshot.generatedAt ?? ""),
      leaseExpiresAt: String(snapshot.leaseExpiresAt ?? ""),
      placements: snapshot.placements as DiscoveryPlacement[],
      offers: parseDiscoveryOffers(snapshot.offers),
    },
    remainingLeaseMs: record.remainingLeaseMs,
    policyAllowed: record.policyAllowed,
  };
}

export function advertiseUrl(
  placement: "extensions_feed" | "extensions_header",
  extensionId?: string,
  // "claim" is the free path for a maker whose extension is already in the
  // built-in catalog; it buys nothing and is labeled that way. It travels
  // under its own key: "intent" already carries the campaign the advertise
  // page uses to recognize Guard traffic, and overwriting it would strand
  // every one of these links outside that campaign.
  action?: "buy" | "claim",
): string {
  const url = new URL(GUARD_DISCOVERY_CLOUD_ORIGIN + GUARD_DISCOVERY_ADVERTISE_PATH);
  url.searchParams.set("placement", placement);
  if (action) {
    url.searchParams.set("action", action);
  }
  if (extensionId) {
    // Only an explicitly chosen extension id ever leaves the device.
    url.searchParams.set("extension", extensionId);
  }
  return url.toString();
}

/** Local catalog join: unknown Cloud ids never render as paid cards. */
export function joinDiscoveryPlacements(
  placements: readonly DiscoveryPlacement[],
  catalogExtensions: readonly ExtensionCatalogSummary[],
  nowMs: number,
): { featured: JoinedDiscoveryCard[]; sponsored: JoinedDiscoveryCard[] } {
  const catalogById = new Map(catalogExtensions.map((extension) => [extension.extension_id, extension]));
  const featured: JoinedDiscoveryCard[] = [];
  const sponsored: JoinedDiscoveryCard[] = [];
  for (const placement of placements) {
    if (Date.parse(placement.endsAt) <= nowMs) continue;
    const catalog = catalogById.get(placement.extensionId);
    if (!catalog) continue;
    if (placement.product === "sponsored") {
      if (!sponsored.some((entry) => entry.placement.extensionId === placement.extensionId)) {
        sponsored.push({ placement, catalog });
      }
    } else if (!featured.some((entry) => entry.placement.extensionId === placement.extensionId)) {
      featured.push({ placement, catalog });
    }
  }
  return { featured, sponsored };
}

export function sponsoredCardLabel(featured: boolean): string {
  return featured ? "Sponsored · Featured" : "Sponsored";
}

/** A time-window feature says when it ends; an all-day feature says nothing. */
export function featuredWindowLabel(placement: DiscoveryPlacement): string | null {
  if (placement.product !== "time_slot") return null;
  const ends = Date.parse(placement.endsAt);
  if (!Number.isFinite(ends)) return null;
  return `Featured until ${new Date(ends).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" })}`;
}

/** Featured extensions lead the list; everything else keeps catalog order. */
export function orderFeaturedFirst<T extends { extension_id: string }>(
  extensions: readonly T[],
  featuredIds: ReadonlySet<string>,
): T[] {
  if (featuredIds.size === 0) return [...extensions];
  return [
    ...extensions.filter((extension) => featuredIds.has(extension.extension_id)),
    ...extensions.filter((extension) => !featuredIds.has(extension.extension_id)),
  ];
}
