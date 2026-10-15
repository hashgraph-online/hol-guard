import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { HiMiniArrowRight, HiMiniArrowTopRightOnSquare, HiMiniClock, HiMiniSparkles } from "react-icons/hi2";
import type { ExtensionCatalogSummary } from "../extension-controls-api";
import { ExtensionBrandMark } from "./components/extension-brand-mark";
import { useDiscoveryMeasurement, type DiscoverySurface } from "./discovery-measurement";
import {
  advertiseUrl,
  chooseStableCard,
  DISCOVERY_PRODUCT_LABEL,
  featuredWindowLabel,
  formatOfferPrice,
  joinDiscoveryPlacements,
  parseDiscoveryProjection,
  shouldShowPurchasePrompt,
  sponsoredCardLabel,
  type DiscoveryFeedStatus,
  type DiscoveryOffer,
  type DiscoveryPlacement,
  type DiscoveryProjection,
  type JoinedDiscoveryCard,
} from "./extensions-discover-model";

/**
 * Discover: the online spotlight for Extensions.
 *
 * Manage stays the default operational surface; nothing here touches
 * protection state. Paid cards join the local catalog by canonical id and
 * every paid card says Sponsored, who paid for it, and that protection is
 * unchanged. A visible lead card never rotates on the 10-second poll;
 * expired or revoked cards lose their paid content immediately. Failure
 * hides paid content and never affects the catalog.
 */

const DISCOVERY_REFRESH_MS = 10_000;

export type DiscoveryFeed = { status: DiscoveryFeedStatus; projection: DiscoveryProjection | null };

/** Polls the daemon's placement projection while `active` and the page is visible. */
export function useDiscoveryFeed(active: boolean, fetchPlacements: () => Promise<Response>): DiscoveryFeed {
  const [status, setStatus] = useState<DiscoveryFeedStatus>("loading");
  const [projection, setProjection] = useState<DiscoveryProjection | null>(null);
  const requestGeneration = useRef(0);
  const fetchRef = useRef(fetchPlacements);
  fetchRef.current = fetchPlacements;

  const load = useCallback(async () => {
    const generation = requestGeneration.current + 1;
    requestGeneration.current = generation;
    const current = () => generation === requestGeneration.current;
    const fail = (next: DiscoveryFeedStatus) => {
      setStatus(next);
      setProjection(null);
    };
    try {
      const response = await fetchRef.current();
      if (!current()) return;
      if (response.status === 403) return fail("opt-out");
      if (response.status === 501 || response.status === 503 || response.status === 429) {
        const body = await response.json().catch(() => null);
        if (!current()) return;
        const code = body && typeof body.error === "string" ? body.error : null;
        return fail(code === "rate_limited" || response.status === 429 ? "rate-limited" : "unavailable");
      }
      if (!response.ok) return fail("unavailable");
      const parsed = parseDiscoveryProjection(await response.json().catch(() => null));
      if (!current()) return;
      if (!parsed) return fail("unavailable");
      if (!parsed.policyAllowed) return fail("opt-out");
      if (parsed.snapshot.state !== "ready" || !parsed.snapshot.enabled) return fail("unavailable");
      setProjection(parsed);
      setStatus("ready");
    } catch {
      if (current()) fail("offline");
    }
  }, []);

  // Refresh on entry, then every ten seconds; stop when hidden or inactive.
  // One daemon coalesces concurrent tabs.
  useEffect(() => {
    if (!active) return;
    let stopped = false;
    const tick = () => {
      if (stopped || document.hidden) return;
      void load();
    };
    const onVisibility = () => {
      if (!document.hidden) tick();
    };
    tick();
    const timer = window.setInterval(tick, DISCOVERY_REFRESH_MS);
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      stopped = true;
      requestGeneration.current += 1;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [active, load]);

  return { status, projection };
}

/** Joins the live feed to the local catalog; empty unless the feed is ready. */
export function useJoinedDiscovery(feed: DiscoveryFeed, catalogExtensions: readonly ExtensionCatalogSummary[]) {
  return useMemo(
    () => joinDiscoveryPlacements(
      feed.status === "ready" && feed.projection ? feed.projection.snapshot.placements : [],
      catalogExtensions,
      Date.now(),
    ),
    [catalogExtensions, feed.projection, feed.status],
  );
}

function SponsorLine(props: { placement: DiscoveryPlacement; featured: boolean; inverse?: boolean }) {
  const brand = props.placement.creative.brandName?.trim();
  const window = featuredWindowLabel(props.placement);
  return (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
      <span
        className={`guard-sponsor-label ${props.inverse ? "guard-sponsor-label-inverse" : ""}`}
        data-sponsored-label
      >
        {sponsoredCardLabel(props.featured)}
      </span>
      {brand ? (
        <span className={`text-xs ${props.inverse ? "text-white/70" : "text-brand-dark/60"}`}>
          Paid for by <span className={`font-semibold ${props.inverse ? "text-white" : "text-brand-dark"}`}>{brand}</span>
        </span>
      ) : null}
      {window ? (
        <span className={`inline-flex items-center gap-1 text-xs ${props.inverse ? "text-white/70" : "text-brand-dark/60"}`}>
          <HiMiniClock className="size-3.5" aria-hidden="true" />
          {window}
        </span>
      ) : null}
    </div>
  );
}

function PaidCard(props: {
  entry: JoinedDiscoveryCard;
  featured: boolean;
  variant: "hero" | "tile";
  surface: DiscoverySurface;
  snapshotId: string | null;
  onOpen: (extension: ExtensionCatalogSummary) => void;
}) {
  const ref = useRef<HTMLElement | null>(null);
  const recordOpen = useDiscoveryMeasurement(ref, props.snapshotId, props.entry.placement, props.surface);
  const { placement, catalog } = props.entry;
  const hero = props.variant === "hero";
  const headline = placement.creative.headline?.trim() || catalog.name;
  const open = () => {
    recordOpen();
    props.onOpen(catalog);
  };
  return (
    <article
      ref={ref}
      data-testid={props.featured ? "discovery-featured-card" : "discovery-sponsored-card"}
      data-sponsored-placement-id={placement.publicPlacementId}
      className={hero ? "guard-discover-hero" : "guard-discover-tile"}
    >
      <div className="flex items-start gap-3">
        <ExtensionBrandMark
          extension_id={catalog.extension_id}
          name={catalog.name}
          executables={catalog.executables}
          ecosystem_ids={catalog.ecosystem_ids}
          size={hero ? "lg" : "md"}
        />
        <div className="min-w-0 flex-1">
          <SponsorLine placement={placement} featured={props.featured} inverse={hero} />
          <h3 className={hero ? "mt-3 text-balance text-2xl font-semibold leading-tight tracking-tight text-white sm:text-[1.75rem]" : "mt-2 text-base font-semibold leading-snug text-brand-dark"}>
            {headline}
          </h3>
          <p className={hero ? "mt-1 text-sm font-medium text-white/70" : "mt-0.5 text-xs font-medium text-brand-dark/55"}>
            {catalog.name}
          </p>
        </div>
      </div>
      <p className={hero ? "mt-4 max-w-[60ch] text-[15px] leading-6 text-white/85" : "mt-3 line-clamp-3 text-sm leading-5 text-brand-dark/75"}>
        {placement.creative.body}
      </p>
      <div className={`mt-auto flex flex-wrap items-center justify-between gap-3 ${hero ? "pt-6" : "pt-4"}`}>
        <p className={`text-xs ${hero ? "text-white/60" : "text-brand-dark/50"}`}>Paid placement. Your protection settings are unchanged.</p>
        <button
          type="button"
          onClick={open}
          className={hero ? "guard-discover-cta guard-discover-cta-inverse" : "guard-discover-cta"}
        >
          View extension
          <HiMiniArrowRight className="size-4" aria-hidden="true" />
        </button>
      </div>
    </article>
  );
}

function OfferBoard(props: { offers: readonly DiscoveryOffer[]; empty: boolean }) {
  const ordered = (["always", "time_slot", "sponsored"] as const)
    .map((product) => props.offers.find((offer) => offer.product === product))
    .filter((offer): offer is DiscoveryOffer => offer !== undefined);
  return (
    <aside
      className="guard-discover-offers"
      data-testid={props.empty ? "discovery-purchase-prompt" : "discovery-offer-board"}
      aria-labelledby="discovery-offers-heading"
    >
      <div className="min-w-0">
        <p className="text-xs font-semibold uppercase tracking-[0.14em] text-brand-blue">For extension makers</p>
        <h2 id="discovery-offers-heading" className="mt-2 text-lg font-semibold tracking-tight text-brand-dark">
          {props.empty ? "This discovery space is available." : "Put your extension in this spotlight."}
        </h2>
        <p className="mt-1 max-w-[52ch] text-sm leading-6 text-brand-dark/70">
          Promote a verified extension you own to reach developers exploring extensions here and on hol.org.
          Every placement is labeled Sponsored and never changes anyone’s protection. The checkout shows the live server quote before any payment.
        </p>
      </div>
      {ordered.length ? (
        <ul className="mt-4 grid gap-2 sm:grid-cols-3" aria-label="Placement availability">
          {ordered.map((offer) => {
            const price = formatOfferPrice(offer);
            return (
              <li key={offer.product} className="guard-discover-offer" data-availability={offer.availability}>
                <span className="text-sm font-semibold text-brand-dark">{DISCOVERY_PRODUCT_LABEL[offer.product]}</span>
                <span className="text-xs text-brand-dark/60">
                  {offer.availability === "open" ? "Open now" : offer.availability === "sold_out" ? "Fully booked" : "Availability on hol.org"}
                </span>
                {price ? <span className="mt-1 font-mono text-xs font-semibold tabular-nums text-brand-dark/80">{price}</span> : null}
              </li>
            );
          })}
        </ul>
      ) : null}
      <a
        className="guard-discover-cta mt-4 self-start"
        href={advertiseUrl("extensions_feed")}
        target="_blank"
        rel="noopener noreferrer"
        referrerPolicy="no-referrer"
      >
        {props.empty ? "Sponsor this placement" : "See placements and pricing"}
        <HiMiniArrowTopRightOnSquare className="size-4" aria-hidden="true" />
      </a>
    </aside>
  );
}

export function ExtensionsDiscover(props: {
  catalogExtensions: readonly ExtensionCatalogSummary[];
  feed: DiscoveryFeed;
  onOpenExtension: (extension: ExtensionCatalogSummary) => void;
  onBrowseAll?: () => void;
}) {
  const { status, projection } = props.feed;
  const [visitSeed] = useState(() => Math.random());
  const selectedLead = useRef<string | null>(null);
  const joined = useJoinedDiscovery(props.feed, props.catalogExtensions);

  // The lead card stays put for the visit; the rest keep server order.
  const lead = useMemo(
    () => chooseStableCard(joined.featured, selectedLead.current, visitSeed),
    [joined.featured, visitSeed],
  );
  useEffect(() => {
    selectedLead.current = lead ? lead.placement.publicPlacementId : null;
  }, [lead]);
  const otherFeatured = joined.featured.filter((entry) => entry !== lead);
  const featuredIds = new Set(joined.featured.map((entry) => entry.placement.extensionId));
  const sponsored = joined.sponsored.filter((entry) => !featuredIds.has(entry.placement.extensionId));

  const offers = projection?.snapshot.offers ?? [];
  const sponsoredOffer = offers.find((offer) => offer.product === "sponsored") ?? null;
  const empty = shouldShowPurchasePrompt({ status, joined, sponsoredOffer, organicCount: props.catalogExtensions.length });
  const snapshotId = projection?.snapshot.snapshotId || null;

  return (
    <div data-testid="extensions-discover" aria-label="Discover extensions">
      <header className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.14em] text-brand-dark/55">
            <HiMiniSparkles className="size-3.5 text-brand-blue" aria-hidden="true" />
            Spotlight
          </p>
          <h2 className="mt-1 text-xl font-semibold tracking-tight text-brand-dark">Featured by their makers right now</h2>
          <p className="mt-1 text-sm text-brand-dark/60">Online discovery. Sponsored placements do not change protection.</p>
        </div>
        {props.onBrowseAll ? (
          <button type="button" className="guard-extensions-chip shrink-0" onClick={props.onBrowseAll}>
            Browse all {props.catalogExtensions.length} tools
          </button>
        ) : null}
      </header>

      {lead ? (
        <section className="mt-5" aria-label="Featured discovery">
          <PaidCard entry={lead} featured variant="hero" surface="extensions_featured" snapshotId={snapshotId} onOpen={props.onOpenExtension} />
        </section>
      ) : null}

      {otherFeatured.length || sponsored.length ? (
        <section className="mt-4 grid gap-4 md:grid-cols-2" aria-label="More sponsored extensions">
          {otherFeatured.map((entry) => (
            <PaidCard key={entry.placement.publicPlacementId} entry={entry} featured variant="tile" surface="extensions_featured" snapshotId={snapshotId} onOpen={props.onOpenExtension} />
          ))}
          {sponsored.map((entry) => (
            <PaidCard key={entry.placement.publicPlacementId} entry={entry} featured={false} variant="tile" surface="extensions_feed" snapshotId={snapshotId} onOpen={props.onOpenExtension} />
          ))}
        </section>
      ) : null}

      {status === "loading" ? <div className="guard-discover-skeleton mt-5" aria-hidden="true" /> : null}

      {status === "ready" ? (
        <div className="mt-6">
          <OfferBoard offers={offers} empty={empty || (!lead && sponsored.length === 0)} />
        </div>
      ) : null}

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
    return (
      <p className="mt-6 text-xs text-brand-dark/45" data-testid="discovery-status-ready" role="status">
        Sponsored placements, when present, are labeled and never change protection.
      </p>
    );
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
