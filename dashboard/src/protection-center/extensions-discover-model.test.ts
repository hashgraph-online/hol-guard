import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

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
  type DiscoveryPlacement,
} from "./extensions-discover-model";

/**
 * Shared semantic vectors for the Discover selection model (mirrors the
 * TypeScript vectors in points-portal and the native Rust suite): local
 * catalog join with unknown-id suppression, one featured and one in-feed
 * position, visit-stable selection, prompt conditions, and the safe
 * advertise URL labels.
 */

const NOW_MS = Date.parse("2026-10-13T12:00:00.500Z");
const END = "2026-10-13T12:00:25.000Z";

function catalogExtension(id: string, name: string): ExtensionCatalogSummary {
  return {
    extension_id: id,
    name,
    kind: "command",
    trust: "reviewed",
    areas: ["developer-tools"],
    description: "A catalog extension used by the Discover model vectors.",
    commandCount: 8,
  } as unknown as ExtensionCatalogSummary;
}

function placement(overrides: Partial<DiscoveryPlacement> = {}): DiscoveryPlacement {
  return {
    publicPlacementId: "11111111-1111-4111-8111-111111111111",
    extensionId: "command.example-tool",
    product: "sponsored",
    slotIndex: 0,
    windowIndex: null,
    startsAt: "2026-10-13T12:00:00.000Z",
    endsAt: END,
    creativeVersion: "cv-1-abc12345",
    creative: {
      headline: "Explore Example Tool",
      body: "Review the supported extension and its permissions.",
      brandName: "Example Publisher",
    },
    ...overrides,
  };
}

const CATALOG = Array.from({ length: 10 }, (_, index) =>
  catalogExtension(`command.tool-${String(index).padStart(2, "0")}`, `Tool ${index}`),
);

// Unknown Cloud ids are suppressed instead of rendering as paid cards (D08).
{
  const joined = joinDiscoveryPlacements(
    [placement({ extensionId: "command.not-in-local-catalog" })],
    CATALOG,
    NOW_MS,
  );
  assert.equal(joined.featured.length, 0);
  assert.equal(joined.sponsored.length, 0);
}

// Expired placements are dropped at join time; the lease projection cannot
// revive an item whose end has passed (API-02).
{
  const joined = joinDiscoveryPlacements(
    [placement({ endsAt: "2026-10-13T11:00:00.000Z" })],
    CATALOG,
    NOW_MS,
  );
  assert.equal(joined.sponsored.length, 0);
}

// Featured and sponsored pools separate by product, deduplicate per
// extension, and the same extension cannot hold both paid positions (UX-03).
{
  const joined = joinDiscoveryPlacements(
    [
      placement({ publicPlacementId: "33333333-3333-4333-8333-333333333333", product: "always", extensionId: "command.tool-01" }),
      placement({ publicPlacementId: "44444444-4444-4444-8444-444444444444", product: "sponsored", extensionId: "command.tool-01" }),
      placement({ publicPlacementId: "55555555-5555-4555-8555-555555555555", product: "sponsored", extensionId: "command.tool-02" }),
    ],
    CATALOG,
    NOW_MS,
  );
  assert.equal(joined.featured.length, 1);
  assert.equal(joined.sponsored.length, 2);
  const featured = chooseStableCard(joined.featured, null, 0.99);
  assert.equal(featured?.placement.publicPlacementId, "33333333-3333-4333-8333-333333333333");
  const sponsored = chooseSponsoredCard(joined.sponsored, null, 0.99, featured?.placement.extensionId ?? null);
  assert.equal(sponsored?.placement.publicPlacementId, "55555555-5555-4555-8555-555555555555");
  assert.notEqual(sponsored?.placement.extensionId, featured?.placement.extensionId);
}

// Visit-stable selection: the current card survives a recompute unchanged
// and polls never shuffle a valid visible card (UX-07).
{
  const entries = joinDiscoveryPlacements(
    [
      placement({ publicPlacementId: "66666666-6666-4666-8666-666666666666", product: "always", extensionId: "command.tool-03" }),
      placement({ publicPlacementId: "77777777-7777-4777-8777-777777777777", product: "always", extensionId: "command.tool-04" }),
    ],
    CATALOG,
    NOW_MS,
  ).featured;
  const first = chooseStableCard(entries, null, 0.1);
  assert.ok(first);
  const again = chooseStableCard(entries, first.placement.publicPlacementId, 0.9);
  assert.equal(again?.placement.publicPlacementId, first.placement.publicPlacementId);
  // The selected card left the snapshot, so the next choice is the card that remains.
  const remaining = entries.filter(
    (entry) => entry.placement.publicPlacementId !== first.placement.publicPlacementId,
  );
  const afterWithdrawal = chooseStableCard(remaining, first.placement.publicPlacementId, 0.9);
  assert.equal(afterWithdrawal?.placement.publicPlacementId, remaining[0]?.placement.publicPlacementId);
  assert.notEqual(afterWithdrawal?.placement.publicPlacementId, first.placement.publicPlacementId);
}

// The purchase prompt appears only for a ready, empty, authoritatively open
// feed with at least eight organic rows (UX-05/UX-06).
{
  const openOffer = {
    product: "sponsored" as const,
    availability: "open" as const,
    indicativeAmountCents: 20000,
    currency: "usd",
    checkedAt: END,
    quoteRequired: true as const,
  };
  const empty = { featured: [], sponsored: [] };
  assert.equal(
    shouldShowPurchasePrompt({ status: "ready", joined: empty, sponsoredOffer: openOffer, organicCount: 10 }),
    true,
  );
  assert.equal(
    shouldShowPurchasePrompt({ status: "ready", joined: empty, sponsoredOffer: { ...openOffer, availability: "sold_out" }, organicCount: 10 }),
    false,
  );
  assert.equal(
    shouldShowPurchasePrompt({ status: "ready", joined: empty, sponsoredOffer: { ...openOffer, availability: "unknown" }, organicCount: 10 }),
    false,
  );
  assert.equal(
    shouldShowPurchasePrompt({ status: "ready", joined: empty, sponsoredOffer: null, organicCount: 10 }),
    false,
  );
  assert.equal(
    shouldShowPurchasePrompt({ status: "unavailable", joined: empty, sponsoredOffer: openOffer, organicCount: 10 }),
    false,
  );
  assert.equal(
    shouldShowPurchasePrompt({ status: "ready", joined: empty, sponsoredOffer: openOffer, organicCount: MIN_ORGANIC_ROWS_BEFORE_IN_FEED - 1 }),
    false,
  );
}

// Paid labels: every paid card says Sponsored; featured is Sponsored · Featured (UX-04).
assert.equal(sponsoredCardLabel(false), "Sponsored");
assert.equal(sponsoredCardLabel(true), "Sponsored · Featured");

// Purchase links carry only the allowlisted source/intent/placement labels
// and an explicitly chosen extension id — never a local URL or token (T27).
{
  const feed = advertiseUrl("extensions_feed");
  assert.ok(feed.startsWith("https://hol.org/guard/extensions/advertise?"));
  assert.ok(feed.includes("source=guard_local"));
  assert.ok(feed.includes("intent=extension-promotion"));
  assert.ok(feed.includes("placement=extensions_feed"));
  assert.ok(!feed.includes("guard-token"));
  assert.ok(!feed.includes("localhost"));
  assert.ok(!feed.includes("returnUrl"));
  const known = advertiseUrl("extensions_header", "command.tool-07");
  assert.ok(known.includes("extension=command.tool-07"));
}

// The projection parser rejects malformed shapes instead of trusting them.
{
  assert.equal(parseDiscoveryProjection(null), null);
  assert.equal(parseDiscoveryProjection({}), null);
  assert.equal(parseDiscoveryProjection({ remainingLeaseMs: 1, policyAllowed: true, snapshot: { state: "weird" } }), null);
  const valid = parseDiscoveryProjection({
    remainingLeaseMs: 25_000,
    policyAllowed: true,
    snapshot: {
      schemaVersion: "guard.extensions.discovery.v1",
      snapshotId: "22222222-2222-4222-8222-222222222222",
      state: "ready",
      enabled: true,
      reasonCode: null,
      generatedAt: "2026-10-13T12:00:00.000Z",
      leaseExpiresAt: END,
      placements: [placement()],
      offers: [],
    },
  });
  assert.ok(valid);
  assert.equal(valid.snapshot.placements.length, 1);
  assert.equal(valid.remainingLeaseMs, 25_000);
  const missingBody = placement();
  missingBody.creative = { ...missingBody.creative, body: undefined as unknown as string };
  assert.equal(parseDiscoveryProjection({
    remainingLeaseMs: 25_000,
    policyAllowed: true,
    snapshot: { ...valid.snapshot, placements: [missingBody] },
  }), null);
}

// Static markup of the model-backed labels renders the disclosure text and
// never an advertiser-supplied URL.
{
  const markup = renderToStaticMarkup(
    createElement("span", { "data-sponsored-label": sponsoredCardLabel(true) }),
  );
  assert.ok(markup.includes("Sponsored"));
  assert.ok(markup.includes("Featured"));
}

console.log("extensions-discover-model.test.ts: all assertions passed");
