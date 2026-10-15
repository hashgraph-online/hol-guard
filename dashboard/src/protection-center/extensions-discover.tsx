import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ExtensionCatalogSummary } from "../extension-controls-normalize";
import {
  advertiseUrl,
  chooseSponsoredCard,
  chooseStableCard,
  joinDiscoveryPlacements,
  parseDiscoveryProjection,
  shouldShowPurchasePrompt,
  sponsoredCardLabel,
  MIN_ORGANIC_ROWS_BEFORE_IN_FEED,
  type DiscoveryFeedStatus,
  type DiscoveryOffer,
  type DiscoveryPlacement,
} from "./extensions-discover-model";

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

const DISCOVERY_REFRESH_MS = 10_000;

function SponsoredCard(props: {
  placement: DiscoveryPlacement;
  catalog: ExtensionCatalogSummary;
  featured: boolean;
  onOpen: (extension: ExtensionCatalogSummary) => void;
}) {
  return (
    <article
      data-testid={props.featured ? "discovery-featured-card" : "discovery-sponsored-card"}
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
            {sponsoredCardLabel(props.featured)}
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

function OrganicRow(props: {
  extension: ExtensionCatalogSummary;
  onOpen: (extension: ExtensionCatalogSummary) => void;
}) {
  return (
    <button
      type="button"
      className="flex w-full items-center justify-between gap-3 rounded-xl px-3 py-2.5 text-left transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue"
      onClick={() => props.onOpen(props.extension)}
    >
      <span className="min-w-0">
        <span className="block truncate text-sm font-medium text-brand-dark">{props.extension.name}</span>
        <span className="block truncate text-xs text-brand-dark/55">{props.extension.extension_id}</span>
      </span>
      <span aria-hidden="true" className="text-brand-dark/30">›</span>
    </button>
  );
}

export function ExtensionsDiscover(props: {
  active: boolean;
  catalogExtensions: readonly ExtensionCatalogSummary[];
  onOpenExtension: (extension: ExtensionCatalogSummary) => void;
  fetchPlacements: () => Promise<Response>;
}) {
  const [status, setStatus] = useState<DiscoveryFeedStatus>("loading");
  const [projection, setProjection] = useState<ReturnType<typeof parseDiscoveryProjection>>(null);
  const [visitSeed] = useState(() => Math.random());
  const selectedFeatured = useRef<string | null>(null);
  const selectedSponsored = useRef<string | null>(null);
  const requestGeneration = useRef(0);
  const fetchRef = useRef(props.fetchPlacements);
  fetchRef.current = props.fetchPlacements;

  const load = useCallback(async () => {
    const generation = requestGeneration.current + 1;
    requestGeneration.current = generation;
    const current = () => generation === requestGeneration.current;
    try {
      const response = await fetchRef.current();
      if (!current()) return;
      if (response.status === 403) {
        setStatus("opt-out");
        return;
      }
      if (response.status === 501 || response.status === 503 || response.status === 429) {
        const body = await response.json().catch(() => null);
        if (!current()) return;
        const code = body && typeof body.error === "string" ? body.error : null;
        setStatus(code === "rate_limited" || response.status === 429 ? "rate-limited" : "unavailable");
        setProjection(null);
        return;
      }
      if (!response.ok) {
        setStatus("unavailable");
        setProjection(null);
        return;
      }
      const parsed = parseDiscoveryProjection(await response.json().catch(() => null));
      if (!current()) return;
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
      if (!current()) return;
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
      requestGeneration.current += 1;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [props.active, load]);

  const joined = useMemo(
    () => joinDiscoveryPlacements(
      status === "ready" && projection ? projection.snapshot.placements : [],
      props.catalogExtensions,
      Date.now(),
    ),
    [projection, props.catalogExtensions, status],
  );

  const featured = useMemo(
    () => chooseStableCard(joined.featured, selectedFeatured.current, visitSeed),
    [joined.featured, visitSeed],
  );
  useEffect(() => {
    selectedFeatured.current = featured ? featured.placement.publicPlacementId : null;
  }, [featured]);

  const sponsored = useMemo(() => {
    if (props.catalogExtensions.length < MIN_ORGANIC_ROWS_BEFORE_IN_FEED) return null;
    return chooseSponsoredCard(
      joined.sponsored,
      selectedSponsored.current,
      visitSeed,
      featured?.placement.extensionId ?? null,
    );
  }, [featured, joined.sponsored, props.catalogExtensions.length, visitSeed]);
  useEffect(() => {
    if (props.catalogExtensions.length < MIN_ORGANIC_ROWS_BEFORE_IN_FEED) return;
    selectedSponsored.current = sponsored ? sponsored.placement.publicPlacementId : null;
  }, [props.catalogExtensions.length, sponsored]);

  const sponsoredOffer: DiscoveryOffer | null = projection?.snapshot.offers.find(
    (offer) => offer.product === "sponsored",
  ) ?? null;
  const showPurchasePrompt = shouldShowPurchasePrompt({
    status,
    joined,
    sponsoredOffer,
    organicCount: props.catalogExtensions.length,
  });

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
          <OrganicRow key={extension.extension_id} extension={extension} onOpen={props.onOpenExtension} />
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
          <OrganicRow key={extension.extension_id} extension={extension} onOpen={props.onOpenExtension} />
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
