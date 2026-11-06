import type { SupplyChainBundle } from "./guard-types";
import type { SupplyChainBundleLoad } from "./supply-chain-intel-freshness";

/** How often a mounted view reads the cached bundle again, so a background refresh shows up. */
export const BUNDLE_REREAD_INTERVAL_MS = 60_000;

/**
 * Wraps a bundle fetch so overlapping callers share one request. Two panels
 * that mount in the same render read the bundle once between them.
 */
export function createSharedBundleReader(
  fetchBundle: () => Promise<SupplyChainBundle | null>,
): () => Promise<SupplyChainBundle | null> {
  let inflight: Promise<SupplyChainBundle | null> | null = null;
  return () => {
    if (inflight === null) {
      const request = fetchBundle();
      inflight = request;
      const clear = () => {
        if (inflight === request) inflight = null;
      };
      request.then(clear, clear);
    }
    return inflight;
  };
}

/** Turns one read into a load state. A failed read is an error, never the previous result. */
export async function readBundleLoad(
  read: () => Promise<SupplyChainBundle | null>,
): Promise<SupplyChainBundleLoad> {
  try {
    return { phase: "ready", bundle: await read() };
  } catch (error: unknown) {
    return { phase: "error", message: error instanceof Error ? error.message : "Failed to load" };
  }
}

type Scheduler = {
  start: (tick: () => void, intervalMs: number) => unknown;
  stop: (handle: unknown) => void;
};

/**
 * Tells every mounted bundle reader to read again. `refresh` is called after a
 * Sync finishes. While at least one reader is subscribed a single timer calls it
 * on an interval, skipping ticks when the page is hidden.
 */
export function createBundleRefreshBus(scheduler: Scheduler, isVisible: () => boolean) {
  const listeners = new Set<() => void>();
  let handle: unknown = null;
  let running = false;

  const refresh = () => {
    for (const listener of [...listeners]) listener();
  };

  const subscribe = (listener: () => void) => {
    listeners.add(listener);
    if (!running) {
      running = true;
      handle = scheduler.start(() => {
        if (isVisible()) refresh();
      }, BUNDLE_REREAD_INTERVAL_MS);
    }
    return () => {
      listeners.delete(listener);
      if (listeners.size === 0 && running) {
        scheduler.stop(handle);
        running = false;
        handle = null;
      }
    };
  };

  return { refresh, subscribe };
}
