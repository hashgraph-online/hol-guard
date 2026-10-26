import { useEffect, useRef, type RefObject } from "react";
import { fetchExtensionDiscoveryApi } from "../guard-api";
import type { DiscoveryPlacement } from "./extensions-discover-model";

/**
 * Privacy-bounded paid-placement measurement. The daemon only relays these
 * calls when the device has measurement turned on; any refusal (403
 * measurement_disabled, offline, rate limit) silently stops measurement for
 * the rest of the visit. Nothing about the device, the query, or the local
 * catalog is sent: only the public placement identity and a random nonce.
 */

export type DiscoverySurface = "extensions_featured" | "extensions_feed";
type DiscoveryEventKind = "served" | "viewable" | "detail_open";

const VIEWABLE_RATIO = 0.5;
const VIEWABLE_DWELL_MS = 1_000;

let measurementRefused = false;
const tokens = new Map<string, Promise<string | null>>();
const recorded = new WeakMap<Promise<string | null>, Set<DiscoveryEventKind>>();

function postJson(path: "/v1/discovery/extensions/renders" | "/v1/discovery/extensions/events", body: unknown) {
  return fetchExtensionDiscoveryApi(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function renderToken(placement: DiscoveryPlacement, surface: DiscoverySurface, snapshotId: string): Promise<string | null> {
  const key = `${placement.publicPlacementId}:${placement.creativeVersion}:${surface}`;
  const existing = tokens.get(key);
  if (existing) return existing;
  const pending = (async () => {
    if (measurementRefused || typeof crypto?.randomUUID !== "function") return null;
    try {
      const response = await postJson("/v1/discovery/extensions/renders", {
        snapshotId,
        publicPlacementId: placement.publicPlacementId,
        creativeVersion: placement.creativeVersion,
        surface,
        renderNonce: crypto.randomUUID(),
      });
      if (!response.ok) {
        measurementRefused = true;
        return null;
      }
      const body = (await response.json().catch(() => null)) as { token?: unknown } | null;
      return typeof body?.token === "string" ? body.token : null;
    } catch {
      measurementRefused = true;
      return null;
    }
  })();
  tokens.set(key, pending);
  return pending;
}

async function sendEvent(token: Promise<string | null>, kind: DiscoveryEventKind) {
  const kinds = recorded.get(token) ?? new Set<DiscoveryEventKind>();
  recorded.set(token, kinds);
  // served and viewable count once per creative per visit; every open counts.
  if (kind !== "detail_open" && kinds.has(kind)) return;
  kinds.add(kind);
  const value = await token;
  if (!value || measurementRefused) return;
  try {
    await postJson("/v1/discovery/extensions/events", { events: [{ token: value, kind }] });
  } catch {
    // Measurement never surfaces errors to the person using Guard.
  }
}

/**
 * Records served once per rendered creative, viewable after half the card
 * has been on screen for a second, and returns a click recorder for
 * detail_open.
 */
export function useDiscoveryMeasurement(
  target: RefObject<HTMLElement | null>,
  snapshotId: string | null,
  placement: DiscoveryPlacement,
  surface: DiscoverySurface,
): () => void {
  const tokenRef = useRef<Promise<string | null> | null>(null);
  const latest = useRef({ snapshotId, placement });
  latest.current = { snapshotId, placement };
  const measurable = snapshotId !== null;
  useEffect(() => {
    const { snapshotId: snapshot, placement: current } = latest.current;
    if (!snapshot) return;
    // One render token per creative and surface for the visit: polling hands
    // back fresh snapshot objects, which must not count as new impressions.
    const token = renderToken(current, surface, snapshot);
    tokenRef.current = token;
    void sendEvent(token, "served");
    const element = target.current;
    if (!element || typeof IntersectionObserver !== "function") return;
    let dwell = 0;
    const observer = new IntersectionObserver((entries) => {
      const visible = entries.some((entry) => entry.intersectionRatio >= VIEWABLE_RATIO);
      if (visible && !dwell) {
        dwell = window.setTimeout(() => {
          void sendEvent(token, "viewable");
          observer.disconnect();
        }, VIEWABLE_DWELL_MS);
      } else if (!visible && dwell) {
        window.clearTimeout(dwell);
        dwell = 0;
      }
    }, { threshold: [0, VIEWABLE_RATIO] });
    observer.observe(element);
    return () => {
      observer.disconnect();
      if (dwell) window.clearTimeout(dwell);
    };
  }, [measurable, placement.publicPlacementId, placement.creativeVersion, surface, target]);
  return () => {
    if (tokenRef.current) void sendEvent(tokenRef.current, "detail_open");
  };
}
