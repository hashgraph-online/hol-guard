import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { renderToStaticMarkup } from "react-dom/server";

import { FeedHealthWorkspace } from "./feed-health-workspace";
import type { GuardRuntimeSnapshot, SupplyChainBundle } from "./guard-types";
import { describeFirewallFailure } from "./supply-chain-firewall-controls";
import {
  formatBundleExpiry,
  isBundleExpired,
  missingBundleMessage,
  resolveIntelFreshness,
  type SupplyChainBundleLoad,
} from "./supply-chain-intel-freshness";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const now = Date.parse("2026-10-24T12:00:00.000Z");

function bundle(overrides: Partial<SupplyChainBundle> = {}): SupplyChainBundle {
  return {
    bundleVersion: "2026.10.24-1",
    expiresAt: new Date(now + 3 * DAY).toISOString(),
    feedSnapshotHash: "hash",
    generatedAt: new Date(now - 2 * HOUR).toISOString(),
    keyId: "key",
    policyHash: "policy",
    scoringVersion: "1",
    advisories: [],
    packages: [],
    policyRules: [],
    ...overrides,
  };
}

const ready = (value: SupplyChainBundle | null): SupplyChainBundleLoad => ({ phase: "ready", bundle: value });

// A future expiry used to render as "just now" because formatRelativeTime only reads the past.
assert(formatBundleExpiry(new Date(now + 3 * DAY).toISOString(), now) === "in 3d", "a future expiry reads as in 3d");
assert(formatBundleExpiry(new Date(now + 5 * HOUR).toISOString(), now) === "in 5h", "a future expiry reads in hours");
assert(formatBundleExpiry(new Date(now + 20 * 60_000).toISOString(), now) === "in 20m", "a future expiry reads in minutes");
assert(formatBundleExpiry(new Date(now + 5_000).toISOString(), now) === "in less than a minute", "a sub-minute expiry says so");
assert(formatBundleExpiry(new Date(now - 2 * HOUR).toISOString(), now) === "2h ago", "a lapsed expiry reads as ago");
assert(formatBundleExpiry(new Date(now - 5_000).toISOString(), now) === "just now", "a just-lapsed expiry reads as just now");
assert(formatBundleExpiry("not a date", now) === null, "an unparseable expiry is reported as unknown");
assert(!isBundleExpired(bundle(), now), "a bundle with a future expiry is valid");
assert(isBundleExpired(bundle({ expiresAt: new Date(now - 1).toISOString() }), now), "a bundle past its expiry is expired");
assert(!isBundleExpired(bundle({ expiresAt: "" }), now), "a bundle without a readable expiry is not called expired");

const sample = resolveIntelFreshness({ cloudState: "local_only", load: ready(null), nowMs: now });
assert(sample.kind === "sample" && sample.label === "Sample data" && sample.tone === "slate", "local-only is sample data, never Fresh");

const loading = resolveIntelFreshness({ cloudState: "paired_active", load: { phase: "loading" }, nowMs: now });
assert(loading.kind === "loading" && loading.tone === "slate", "loading is not reported as fresh");

const failed = resolveIntelFreshness({
  cloudState: "paired_active",
  load: { phase: "error", message: "Guard daemon is unavailable." },
  nowMs: now,
});
assert(failed.kind === "unavailable" && failed.description.includes("Guard daemon is unavailable."), "a failed read is surfaced");

const none = resolveIntelFreshness({ cloudState: "paired_active", load: ready(null), nowMs: now });
assert(none.kind === "none" && none.label === "Not synced" && none.tone === "attention", "a paired device with no bundle is not Fresh");

const expired = resolveIntelFreshness({
  cloudState: "paired_waiting",
  load: ready(bundle({ expiresAt: new Date(now - 2 * HOUR).toISOString() })),
  nowMs: now,
});
assert(expired.kind === "expired" && expired.label === "Expired", "an expired bundle is not Fresh");
assert(expired.description.includes("expired 2h ago"), "the expiry age is stated");

const current = resolveIntelFreshness({ cloudState: "paired_active", load: ready(bundle()), nowMs: now });
assert(current.kind === "current" && current.label === "Fresh" && current.tone === "green", "a valid bundle is Fresh");
assert(
  current.description === "Bundle 2026.10.24-1 generated 2h ago, expires in 3d.",
  `the freshness line names the bundle and both times, got: ${current.description}`,
);

function snapshot(cloudState: GuardRuntimeSnapshot["cloud_state"]): GuardRuntimeSnapshot {
  return {
    generated_at: new Date().toISOString(),
    runtime_state: {},
    cloud_state: cloudState,
    cloud_state_label: cloudState,
    cloud_state_detail: "detail",
    cloud_sync_health: { state: "pending", label: "Pending", detail: "waiting" },
    latest_receipts: [],
  } as unknown as GuardRuntimeSnapshot;
}

// The feed page no longer calls an empty feed "Fresh": with no receipts and no bundle
// the card used to say Fresh while the banner said sample intel.
const markup = renderToStaticMarkup(<FeedHealthWorkspace snapshot={snapshot("local_only")} />);
assert(markup.includes("Sample intel only"), "local-only banner still renders");
assert(!markup.includes(">Fresh<"), "local-only feed freshness card does not claim Fresh");
assert(markup.includes("Sample data"), "local-only feed freshness card reads Sample data");

const loadingMarkup = renderToStaticMarkup(<FeedHealthWorkspace snapshot={snapshot("paired_active")} />);
assert(!loadingMarkup.includes(">Fresh<"), "a paired feed does not claim Fresh before the bundle is read");
assert(!loadingMarkup.includes("Live feed active"), "a pending bundle read does not claim the feed is active");
assert(loadingMarkup.includes("Checking the intel feed"), "a pending bundle read says it is checking");

assert(
  describeFirewallFailure({ op: "fix_all", manager: null, message: "x" }) === "Restoring protection failed",
  "Fix all failures read as a sentence, not the fix_all key",
);
assert(
  describeFirewallFailure({ op: "install", manager: "npm", message: "x" }) === "Enabling protection failed for npm",
  "manager failures name the manager",
);
assert(describeFirewallFailure({ op: "sync", manager: null, message: "x" }) === "The sync failed", "sync failure headline");
assert(describeFirewallFailure({ op: "audit", manager: null, message: "x" }) === "The audit failed", "audit failure headline");
assert(describeFirewallFailure({ op: "test", manager: "pip3", message: "x" }) === "The intercept test failed for pip3", "test failure headline");
for (const op of ["install", "repair", "test", "remove", "audit", "sync", "fix_all"] as const) {
  assert(!describeFirewallFailure({ op, manager: null, message: "x" }).includes("_"), `${op} headline hides the internal key`);
}

const here = fileURLToPath(new URL(".", import.meta.url));
const detailsSource = readFileSync(`${here}supply-chain-workspace-details.tsx`, "utf8");
assert(
  !detailsSource.includes("Older than 7 days") && !detailsSource.includes('isStale ? "attention" : "green"'),
  "the details panel no longer derives Last update from receipts",
);
assert(detailsSource.includes("resolveIntelFreshness("), "the details panel reads freshness from the bundle");
assert(detailsSource.includes("Guard Cloud connected, syncing"), "paired_waiting is not labeled live");
const bundlePanelSource = readFileSync(`${here}supply-chain-bundle-panel.tsx`, "utf8");
assert(!bundlePanelSource.includes("formatRelativeTime"), "the bundle panel does not format expiry with the past-only helper");

assert(
  missingBundleMessage("local_only").includes("Connect to Guard Cloud"),
  "a local-only device is told to connect Guard Cloud for live intel",
);
for (const cloudState of ["paired_waiting", "paired_active"] as const) {
  const message = missingBundleMessage(cloudState);
  assert(!message.includes("Connect to Guard Cloud"), `${cloudState} is not told to connect a cloud it already has`);
  assert(message.includes("Sync"), `${cloudState} is pointed at Sync to fetch the bundle`);
}
assert(
  !bundlePanelSource.includes("Connect to Guard Cloud for live advisory data"),
  "the bundle panel takes its empty-state copy from the cloud state",
);

console.log("supply-chain-intel-freshness tests passed");
