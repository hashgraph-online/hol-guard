import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ExtensionCatalogSummary } from "../extension-controls-api";
import {
  joinDiscoveryPlacements,
  parseDiscoveryProjection,
  type DiscoveryFeedStatus,
  type DiscoveryProjection,
} from "./extensions-discover-model";

/**
 * The device's view of paid placement inventory.
 *
 * Fetching and lifecycle live here; every paid-content decision stays in the
 * pure model. Failure of any kind hides paid content and never claims the
 * inventory is vacant, so a dropped network never turns into a sales pitch.
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
