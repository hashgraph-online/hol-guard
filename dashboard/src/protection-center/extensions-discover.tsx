import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ExtensionCatalogSummary } from "../extension-controls-normalize";

/**
 * Discover: the explicitly online secondary Extensions view.
 *
 * Manage stays the default operational surface; nothing here touches
 * protection state. Paid cards join the local catalog by canonical id,
 * render at most one Featured and one post-row-8 Sponsored position, and
 * every paid card is labeled Sponsored. A valid visible card never rotates
 * on the 10-second poll; expired or revoked cards lose their paid content
 * immediately. Failure hides paid content and never affects organic rows.
 */

export const GUARD_DISCOVERY_CLOUD_ORIGIN = "https://hol.org";
export const GUARD_DISCOVERY_ADVERTISE_PATH =
  "/guard/extensions/advertise?source=guard_local&intent=extension-promotion";

const DISCOVERY_REFRESH_MS = 10_000;
const MIN_ORGANIC_ROWS_BEFORE_IN_FEED = 8;

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

function isPlacement(value: unknown): value is DiscoveryPlacement {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Partial<DiscoveryPlacement>;
  return typeof record.publicPlacementId === "string"
    && typeof record.extensionId === "string"
    && (record.product === "always" || record.product === "time_slot" || record.product === "sponsored")
    && typeof record.endsAt === "string"
    && typeof record.creativeVersion === "string"
    && typeof record.creative === "object" && record.creative !== null
    && typeof record.creative.headline === "string";
}

function parseProjection(value: unknown): DiscoveryProjection | null {
  if (typeof value !== "object" || value === null) return null;
  const record = value as Partial<DiscoveryProjection> & { snapshot?: Partial<DiscoverySnapshot> };
  const snapshot = record.snapshot;
  if (typeof record.remainingLeaseMs !== "number" || typeof record.policyAllowed !== "boolean") return null;
  if (typeof snapshot !== "object" || snapshot === null) return null;
  if (snapshot.state !== "ready" && snapshot.state !== "unavailable") return null;
  if (!Array.isArray(snapshot.placements) || !snapshot.placements.every(isPlacement)) return null;
  return {
    snapshot: {
      schemaVersion: String(snapshot.schemaVersion ?? ""),
      snapshotId: String(snapshot.snapshotId ?? ""),
      state: snapshot.state,
      enabled: snapshot.enabled === true,
      reasonCode: typeof snapshot.reasonCode === "string" ? snapshot.reasonCode : null,
      generatedAt: String(snapshot.generatedAt ?? ""),
      leaseExpiresAt: String(snapshot.leaseExpiresAt ?? ""),
      placements: snapshot.placements,
      offers: Array.isArray(snapshot.offers) ? (snapshot.offers as DiscoveryOffer[]) : [],
    },
    remainingLeaseMs: record.remainingLeaseMs,
    policyAllowed: record.policyAllowed,
  };
}

function advertiseUrl(placement: "extensions_feed" | "extensions_header", extensionId?: string): string {
  const url = new URL(GUARD_DISCOVERY_CLOUD_ORIGIN + GUARD_DISCOVERY_ADVERTISE_PATH);
  url.searchParams.set("placement", placement);
  if (extensionId) {
    // Only an explicitly chosen extension id ever leaves the device.
    url.searchParams.set("extension", extensionId);
  }
  return url.toString();
}

function SponsoredCard(props: {
  placement: DiscoveryPlacement;
  catalog: ExtensionCatalogSummary;
  featured: boolean;
  onOpen: (extension: ExtensionCatalogSummary) => void;
}) {
  return (
    <article
      data-testid={featured ? "discovery-featured-card" : "discovery-sponsored-card"}
      data-sponsored-placement-id={props.placement.publicPlacementId}
      className="flex items-start gap-3 rounded-2xl border border-brand-blue/15 bg-white px-4 py-3"
    >
      <span aria-hidden="true" className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-brand-blue/10 text-sm font-bold text-brand-blue">
        {props.catalog.name.slice(0, 1).toUpperCase()}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="truncate text-sm font-semibold text-brand-dark">{props.catalog.name}</h3>
          <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-slate-600" data-sponsored-label>
            Sponsored{featured ? " · Featured" : ""}
          </span>
        </div>
        <p className="mt-1 line-clamp-2 text-sm leading-5 text-brand-dark/70">{props.placement.creative.body}</p>
        <p className="mt-1 text-xs text-brand-dark/45">Paid placement. Your protection settings are unchanged.</p>
      </div>
      <button
        type="button"
        className="guard-extensions-chip shrink-0"
        onClick={() => props.onOpen(props.catalog)}
      >
        View extension
      </button>
    </article>
  );
}

export function ExtensionsDiscover(props: {
  active: boolean;
  catalogExtensions: readonly ExtensionCatalogSummary[];
  onOpenExtension: (extension: ExtensionCatalogSummary) => void;
  fetchPlacements: () => Promise<Response>;
}) {
  const [status, setStatus] = useState<DiscoveryFeedStatus>("loading");
  const [projection, setProjection] = useState<DiscoveryProjection | null>(null);
  const [visitSeed] = useState(() => Math.random());
  const selectedFeatured = useRef<string | null>(null);
  const selectedSponsored = useRef<string | null>(null);
  const fetchRef = useRef(props.fetchPlacements);
  fetchRef.current = props.fetchPlacements;

  const load = useCallback(async () => {
    try {
      const response = await fetchRef.current();
      if (response.status === 403) {
        setStatus("opt-out");
        return;
      }
      if (response.status === 501 || response.status === 503) {
        const body = await response.json().catch(() => null);
        const code = body && typeof body.error === "string" ? body.error : null;
        setStatus(code === "rate_limited" ? "rate-limited" : "unavailable");
        setProjection(null);
        return;
      }
      if (!response.ok) {
        setStatus("unavailable");
        setProjection(null);
        return;
      }
      const parsed = parseProjection(await response.json().catch(() => null));
      if (!parsed) {
        setStatus("unavailable");
        setProjection(null);
        return;
      }
      if (!parsed.policyAllowed) {
        setStatus("opt-out");
        setProjection(null);
        return;
      }
      if (parsed.snapshot.state !== "ready" || !parsed.snapshot.enabled) {
        setStatus("unavailable");
        setProjection(null);
        return;
      }
      setProjection(parsed);
      setStatus("ready");
    } catch {
      setStatus("offline");
      setProjection(null);
    }
  }, []);

  // Refresh on visible Discover entry, then every ten seconds; stop when the
  // view is hidden or inactive. One daemon coalesces concurrent tabs.
  useEffect(() => {
    if (!props.active) return;
    let stopped = false;
    let timer = 0;
    const tick = () => {
      if (stopped || document.hidden) return;
      void load();
    };
    const onVisibility = () => {
      if (!document.hidden) tick();
    };
    tick();
    timer = window.setInterval(tick, DISCOVERY_REFRESH_MS);
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      stopped = true;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [props.active, load]);

  const catalogById = useMemo(() => {
    const map = new Map<string, ExtensionCatalogSummary>();
    for (const extension of props.catalogExtensions) {
      map.set(extension.extension_id, extension);
    }
    return map;
  }, [props.catalogExtensions]);

  // Local catalog join: unknown Cloud ids never render as paid cards, and no
  // query or inventory ever leaves the device.
  const joined = useMemo(() => {
    if (status !== "ready" || !projection) return { featured: [], sponsored: [] };
    const now = Date.now();
    const featured: { placement: DiscoveryPlacement; catalog: ExtensionCatalogSummary }[] = [];
    const sponsored: { placement: DiscoveryPlacement; catalog: ExtensionCatalogSummary }[] = [];
    for (const placement of projection.snapshot.placements) {
      if (Date.parse(placement.endsAt) <= now) continue;
      const catalog = catalogById.get(placement.extensionId);
      if (!catalog) continue;
      if (placement.product === "sponsored") {
        sponsored.push({ placement, catalog });
      } else {
        featured.push({ placement, catalog });
      }
    }
    return { featured, sponsored };
  }, [catalogById, projection, status]);

  // Visit-stable selection: a chosen card stays until it is no longer valid
  // in the current snapshot; polls never shuffle visible cards.
  const featured = useMemo(() => {
    if (joined.featured.length === 0) {
      selectedFeatured.current = null;
      return null;
    }
    const current = joined.featured.find((entry) => entry.placement.publicPlacementId === selectedFeatured.current);
    if (current) return current;
    const index = Math.floor(visitSeed * joined.featured.length) % joined.featured.length;
    const chosen = joined.featured[index];
    selectedFeatured.current = chosen.placement.publicPlacementId;
    return chosen;
  }, [joined.featured, visitSeed]);

  const sponsored = useMemo(() => {
    if (props.catalogExtensions.length < MIN_ORGANIC_ROWS_BEFORE_IN_FEED) return null;
    const candidates = joined.sponsored.filter((entry) => entry.placement.publicPlacementId !== selectedFeatured.current);
    if (candidates.length === 0) {
      selectedSponsored.current = null;
      return null;
    }
    const current = candidates.find((entry) => entry.placement.publicPlacementId === selectedSponsored.current);
    if (current) return current;
    const index = Math.floor(visitSeed * candidates.length) % candidates.length;
    const chosen = candidates[index];
    selectedSponsored.current = chosen.placement.publicPlacementId;
    return chosen;
  }, [joined.sponsored, props.catalogExtensions.length, visitSeed]);

  const sponsoredOffer = projection?.snapshot.offers.find((offer) => offer.product === "sponsored") ?? null;
  const showPurchasePrompt = status === "ready"
    && joined.featured.length === 0
    && joined.sponsored.length === 0
    && sponsoredOffer?.availability === "open"
    && props.catalogExtensions.length >= MIN_ORGANIC_ROWS_BEFORE_IN_FEED;

  const organicRows = props.catalogExtensions;

  return (
    <div data-testid="extensions-discover" aria-label="Discover extensions">
      <p className="text-sm text-brand-dark/60">Online discovery. Sponsored placements do not change protection.</p>

      {featured ? (
        <section className="mt-4" aria-label="Featured discovery">
          <SponsoredCard
            placement={featured.placement}
            catalog={featured.catalog}
            featured
            onOpen={props.onOpenExtension}
          />
        </section>
      ) : null}

      <div className="mt-6 space-y-1">
        {organicRows.slice(0, MIN_ORGANIC_ROWS_BEFORE_IN_FEED).map((extension) => (
          <button
            key={extension.extension_id}
            type="button"
            className="flex w-full items-center justify-between gap-3 rounded-xl px-3 py-2.5 text-left transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue"
            onClick={() => props.onOpenExtension(extension)}
          >
            <span className="min-w-0">
              <span className="block truncate text-sm font-medium text-brand-dark">{extension.name}</span>
              <span className="block truncate text-xs text-brand-dark/55">{extension.extension_id}</span>
            </span>
            <span aria-hidden="true" className="text-brand-dark/30">›</span>
          </button>
        ))}
      </div>

      {sponsored ? (
        <div className="mt-2">
          <SponsoredCard
            placement={sponsored.placement}
            catalog={sponsored.catalog}
            featured={false}
            onOpen={props.onOpenExtension}
          />
        </div>
      ) : showPurchasePrompt ? (
        <aside
          data-testid="discovery-purchase-prompt"
          className="mt-2 rounded-2xl border border-dashed border-brand-blue/25 bg-brand-blue/[0.03] px-4 py-3"
        >
          <p className="text-sm font-medium text-brand-dark">This discovery space is available.</p>
          <p className="mt-1 text-xs leading-5 text-brand-dark/60">
            Promote a verified extension you own to reach developers exploring extensions here and on hol.org.
            The checkout shows the live server quote before any payment.
          </p>
          <a
            className="guard-extensions-chip mt-2 inline-flex"
            href={advertiseUrl("extensions_feed")}
            target="_blank"
            rel="noopener noreferrer"
            referrerPolicy="no-referrer"
          >
            Sponsor this placement
          </a>
        </aside>
      ) : null}

      <div className="mt-6 space-y-1">
        {organicRows.slice(MIN_ORGANIC_ROWS_BEFORE_IN_FEED).map((extension) => (
          <button
            key={extension.extension_id}
            type="button"
            className="flex w-full items-center justify-between gap-3 rounded-xl px-3 py-2.5 text-left transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue"
            onClick={() => props.onOpenExtension(extension)}
          >
            <span className="min-w-0">
              <span className="block truncate text-sm font-medium text-brand-dark">{extension.name}</span>
              <span className="block truncate text-xs text-brand-dark/55">{extension.extension_id}</span>
            </span>
            <span aria-hidden="true" className="text-brand-dark/30">›</span>
          </button>
        ))}
      </div>

      <DiscoveryStatusRow status={status} sponsoredAvailability={sponsoredOffer?.availability ?? null} />
    </div>
  );
}

function DiscoveryStatusRow(props: { status: DiscoveryFeedStatus; sponsoredAvailability: string | null }) {
  if (props.status === "ready") {
    if (props.sponsoredAvailability === "sold_out") {
      return (
        <p className="mt-6 text-xs text-brand-dark/45" data-testid="discovery-status-sold-out">
          Sponsored inventory is currently full.{" "}
          <a
            className="font-semibold text-brand-blue hover:underline"
            href={advertiseUrl("extensions_header")}
            target="_blank"
            rel="noopener noreferrer"
            referrerPolicy="no-referrer"
          >
            View availability and other placements
          </a>{" "}
          on hol.org for open windows and products.
        </p>
      );
    }
    return null;
  }
  if (props.status === "opt-out") {
    return (
      <p className="mt-6 text-xs text-brand-dark/45" data-testid="discovery-status-optout">
        Sponsored discovery is turned off for this device. Extension management is unaffected.
      </p>
    );
  }
  if (props.status === "loading") {
    return <p className="mt-6 text-xs text-brand-dark/45" role="status">Checking discovery availability…</p>;
  }
  // Unavailable, rate-limited, and offline all hide paid content without a
  // commercial error toast and never claim vacancy.
  return (
    <p className="mt-6 text-xs text-brand-dark/45" data-testid={`discovery-status-${props.status}`}>
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
