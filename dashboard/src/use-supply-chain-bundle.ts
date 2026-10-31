import { useEffect, useState } from "react";
import { fetchSupplyChainBundle } from "./guard-api";
import {
  createBundleRefreshBus,
  createSharedBundleReader,
  readBundleLoad,
} from "./supply-chain-bundle-refresh";
import type { SupplyChainBundleLoad } from "./supply-chain-intel-freshness";

const readBundle = createSharedBundleReader(fetchSupplyChainBundle);

const refreshBus = createBundleRefreshBus(
  {
    start: (tick, intervalMs) => setInterval(tick, intervalMs),
    stop: (handle) => clearInterval(handle as ReturnType<typeof setInterval>),
  },
  () => typeof document === "undefined" || !document.hidden,
);

/** Call after a Sync finishes so every mounted view reads the new bundle. */
export const refreshSupplyChainBundle = refreshBus.refresh;

/**
 * Reads the signed advisory bundle Guard has cached. It reads again when
 * `refreshKey` changes, when a Sync finishes and on a slow interval, so a
 * background refresh also shows up. A successful reread keeps the previous
 * result on screen; a failed one replaces it with the error.
 */
export function useSupplyChainBundle(refreshKey = ""): SupplyChainBundleLoad {
  const [load, setLoad] = useState<SupplyChainBundleLoad>({ phase: "loading" });
  const [rereads, setRereads] = useState(0);

  useEffect(
    () => refreshBus.subscribe(() => setRereads((count) => count + 1)),
    [],
  );

  useEffect(() => {
    let cancelled = false;
    void readBundleLoad(readBundle).then((next) => {
      if (!cancelled) setLoad(next);
    });
    return () => {
      cancelled = true;
    };
  }, [refreshKey, rereads]);

  return load;
}
