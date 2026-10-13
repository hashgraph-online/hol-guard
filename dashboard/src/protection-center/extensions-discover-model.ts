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
      offers: Array.isArray(snapshot.offers) ? (snapshot.offers as DiscoveryOffer[]) : [],
    },
    remainingLeaseMs: record.remainingLeaseMs,
    policyAllowed: record.policyAllowed,
  };
}

export function advertiseUrl(
  placement: "extensions_feed" | "extensions_header",
  extensionId?: string,
): string {
  const url = new URL(GUARD_DISCOVERY_CLOUD_ORIGIN + GUARD_DISCOVERY_ADVERTISE_PATH);
  url.searchParams.set("placement", placement);
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

/**
 * Visit-stable selection: keep the current card while it is still present;
 * otherwise pick deterministically from the visit seed. A valid visible card
 * is never reshuffled by polling (UX-07).
 */
export function chooseStableCard(
  entries: readonly JoinedDiscoveryCard[],
  currentId: string | null,
  visitSeed: number,
): JoinedDiscoveryCard | null {
  if (entries.length === 0) return null;
  const current = entries.find((entry) => entry.placement.publicPlacementId === currentId);
  if (current) return current;
  const index = Math.floor(visitSeed * entries.length) % entries.length;
  return entries[index];
}

export function chooseSponsoredCard(
  entries: readonly JoinedDiscoveryCard[],
  currentId: string | null,
  visitSeed: number,
  featuredExtensionId: string | null,
): JoinedDiscoveryCard | null {
  const candidates = entries.filter((entry) => entry.placement.extensionId !== featuredExtensionId);
  return chooseStableCard(candidates, currentId, visitSeed);
}

/** One compact prompt only when the feed is ready, empty, and authoritatively open. */
export function shouldShowPurchasePrompt(input: {
  status: DiscoveryFeedStatus;
  joined: { featured: JoinedDiscoveryCard[]; sponsored: JoinedDiscoveryCard[] };
  sponsoredOffer: DiscoveryOffer | null;
  organicCount: number;
}): boolean {
  return input.status === "ready"
    && input.joined.featured.length === 0
    && input.joined.sponsored.length === 0
    && input.sponsoredOffer?.availability === "open"
    && input.organicCount >= MIN_ORGANIC_ROWS_BEFORE_IN_FEED;
}

export function sponsoredCardLabel(featured: boolean): string {
  return featured ? "Sponsored · Featured" : "Sponsored";
}
