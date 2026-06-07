import { useEffect, useState } from "react";
import type { GuardReceiptAnalytics } from "../guard-types";
import { fetchReceiptAnalytics } from "../guard-api";

const ANALYTICS_CACHE_TTL_MS = 60_000;

type AnalyticsCacheEntry = {
  data: GuardReceiptAnalytics;
  expiresAt: number;
};

let analyticsCache: AnalyticsCacheEntry | null = null;
let analyticsInflight: Promise<GuardReceiptAnalytics> | null = null;

export async function loadReceiptAnalyticsCached(force = false): Promise<GuardReceiptAnalytics> {
  if (!force && analyticsCache && analyticsCache.expiresAt > Date.now()) {
    return analyticsCache.data;
  }
  if (!force && analyticsInflight) {
    return analyticsInflight;
  }

  analyticsInflight = fetchReceiptAnalytics()
    .then((data) => {
      analyticsCache = { data, expiresAt: Date.now() + ANALYTICS_CACHE_TTL_MS };
      return data;
    })
    .finally(() => {
      analyticsInflight = null;
    });

  return analyticsInflight;
}

export function invalidateReceiptAnalyticsCache(): void {
  analyticsCache = null;
  analyticsInflight = null;
}

export type ReceiptAnalyticsState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ready"; data: GuardReceiptAnalytics }
  | { kind: "error"; message: string };

export function useReceiptAnalytics(enabled: boolean): ReceiptAnalyticsState {
  const [state, setState] = useState<ReceiptAnalyticsState>(() =>
    enabled ? { kind: "loading" } : { kind: "idle" },
  );

  useEffect(() => {
    if (!enabled) {
      setState({ kind: "idle" });
      return;
    }
    let cancelled = false;
    setState({ kind: "loading" });
    loadReceiptAnalyticsCached()
      .then((data) => {
        if (!cancelled) {
          setState({ kind: "ready", data });
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setState({
            kind: "error",
            message: error instanceof Error ? error.message : "Unable to load analytics.",
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [enabled]);

  return state;
}
