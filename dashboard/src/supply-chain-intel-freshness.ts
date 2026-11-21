import type { SupplyChainBundle } from "./guard-types";

export type SupplyChainBundleLoad =
  | { phase: "loading" }
  | { phase: "ready"; bundle: SupplyChainBundle | null }
  | { phase: "error"; message: string };

export type IntelFreshnessKind =
  | "loading"
  | "unavailable"
  | "sample"
  | "none"
  | "expired"
  | "current";

export type IntelFreshness = {
  kind: IntelFreshnessKind;
  label: string;
  description: string;
  tone: "green" | "attention" | "slate";
};

/** What the intel panel says when no signed advisory bundle is cached on this device. */
export function missingBundleMessage(cloudState: "local_only" | "paired_waiting" | "paired_active"): string {
  if (cloudState === "local_only") {
    return "Guard has not synced a supply chain bundle yet. Connect to Guard Cloud for live advisory data.";
  }
  return "Guard Cloud is connected, but no signed advisory bundle has synced to this device yet. Use Sync on this page to fetch it.";
}

/** Changes when a policy or cloud sync lands, which is when the cached bundle can change. */
export function bundleRefreshKey(snapshot: {
  cloud_policy_bundle_hash?: string | null;
  cloud_policy_last_ack_at?: string | null;
  cloud_sync_health?: { last_synced_at: string | null };
}): string {
  return [
    snapshot.cloud_policy_bundle_hash ?? "",
    snapshot.cloud_policy_last_ack_at ?? "",
    snapshot.cloud_sync_health?.last_synced_at ?? "",
  ].join("|");
}

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

function formatSpan(spanMs: number): string {
  if (spanMs < MINUTE_MS) return "less than a minute";
  if (spanMs < HOUR_MS) return `${Math.floor(spanMs / MINUTE_MS)}m`;
  if (spanMs < DAY_MS) return `${Math.floor(spanMs / HOUR_MS)}h`;
  return `${Math.floor(spanMs / DAY_MS)}d`;
}

/**
 * Describes a bundle expiry relative to `nowMs`: "in 3d" while it is valid and
 * "2h ago" once it has lapsed. `formatRelativeTime` only reads the past, so a
 * future expiry used to render as "just now". Returns null for a timestamp that
 * does not parse.
 */
export function formatBundleExpiry(expiresAt: string, nowMs: number): string | null {
  const expiry = Date.parse(expiresAt);
  if (Number.isNaN(expiry)) return null;
  const delta = expiry - nowMs;
  if (delta > 0) return `in ${formatSpan(delta)}`;
  const span = formatSpan(-delta);
  return span === "less than a minute" ? "just now" : `${span} ago`;
}

export function isBundleExpired(bundle: SupplyChainBundle, nowMs: number): boolean {
  const expiry = Date.parse(bundle.expiresAt);
  return !Number.isNaN(expiry) && expiry <= nowMs;
}

/**
 * Freshness of the advisory feed, read from the signed bundle Guard has cached.
 * Receipts only show that Guard was recently busy; they say nothing about how
 * current the intel behind those decisions is.
 */
export function resolveIntelFreshness(input: {
  cloudState: "local_only" | "paired_waiting" | "paired_active";
  load: SupplyChainBundleLoad;
  nowMs: number;
}): IntelFreshness {
  const { cloudState, load, nowMs } = input;
  if (cloudState === "local_only") {
    return {
      kind: "sample",
      label: "Sample data",
      description:
        "Guard checks installs against bundled sample advisories. Connect Guard Cloud for a signed live feed.",
      tone: "slate",
    };
  }
  if (load.phase === "loading") {
    return {
      kind: "loading",
      label: "Checking",
      description: "Reading the advisory bundle cached on this device.",
      tone: "slate",
    };
  }
  if (load.phase === "error") {
    return {
      kind: "unavailable",
      label: "Unavailable",
      description: `Guard could not read the advisory bundle. ${load.message}`.trim(),
      tone: "attention",
    };
  }
  const bundle = load.bundle;
  if (bundle === null) {
    return {
      kind: "none",
      label: "Not synced",
      description:
        "Guard Cloud is connected, but no signed advisory bundle is cached on this device yet. Sync from the Supply Chain tab to fetch it.",
      tone: "attention",
    };
  }
  const expiry = formatBundleExpiry(bundle.expiresAt, nowMs);
  if (isBundleExpired(bundle, nowMs)) {
    return {
      kind: "expired",
      label: "Expired",
      description: `Bundle ${bundle.bundleVersion} expired ${expiry ?? "earlier"}. Sync from the Supply Chain tab to refresh it.`,
      tone: "attention",
    };
  }
  const generated = Date.parse(bundle.generatedAt);
  const generatedText = Number.isNaN(generated)
    ? `Bundle ${bundle.bundleVersion}`
    : `Bundle ${bundle.bundleVersion} generated ${formatSpan(Math.max(0, nowMs - generated))} ago`;
  return {
    kind: "current",
    label: "Fresh",
    description: expiry === null ? `${generatedText}.` : `${generatedText}, expires ${expiry}.`,
    tone: "green",
  };
}
