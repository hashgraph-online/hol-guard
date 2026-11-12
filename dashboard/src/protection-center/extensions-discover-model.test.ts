import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import type { ExtensionCatalogSummary } from "../extension-controls-normalize";
import {
  advertiseUrl,
  joinDiscoveryPlacements,
  parseDiscoveryProjection,
  sponsoredCardLabel,
  featuredWindowLabel,
  orderCatalogRows,
  inFeedSlotIndexes,
  type DiscoveryPlacement,
} from "./extensions-discover-model";

/**
 * Shared semantic vectors for the Discover selection model (mirroring the
 * native Rust suite): local
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
  // The free path for a maker already in the catalog is the same link with a
  // declared intent; it still carries nothing about this device.
  const claim = advertiseUrl("extensions_feed", undefined, "claim");
  // The claim path travels beside the campaign tag, never over it.
  assert.ok(claim.includes("action=claim"));
  assert.ok(claim.includes("intent=extension-promotion"));
  assert.ok(claim.includes("placement=extensions_feed"));
  assert.ok(!claim.includes("extension="));
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

// Only a time-window feature names its end.
{
  assert.equal(featuredWindowLabel(placement({ product: "always" })), null);
  assert.match(featuredWindowLabel(placement({ product: "time_slot" })) ?? "", /^Featured until /);
}

// Sponsored rows lead an alphabetical catalog, then Guard's own coverage
// (built in, then trusted), then free external contributions. A free external
// extension never sorts above a paid placement or internal coverage.
{
  const ordered = orderCatalogRows(
    [
      { extension_id: "acme", trust_class: "external" as const },
      { extension_id: "aws", trust_class: "trusted-library" as const },
      { extension_id: "bolt", trust_class: "external" as const },
      { extension_id: "git", trust_class: "first-party" as const },
      { extension_id: "npm", trust_class: "trusted-library" as const },
      { extension_id: "shell", trust_class: "first-party" as const },
      { extension_id: "zeta", trust_class: "external" as const },
    ],
    new Set(["zeta"]),
  );
  assert.deepEqual(
    ordered.map((entry) => entry.extension_id),
    ["zeta", "git", "shell", "aws", "npm", "acme", "bolt"],
  );
}

// Offers are normalized, and a slot count survives only as a complete pair
// that agrees with the availability it arrived with.
{
  const parse = (offers: unknown[]) => parseDiscoveryProjection({
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
      placements: [],
      offers,
    },
  })?.snapshot.offers ?? [];

  const base = {
    product: "sponsored",
    availability: "open",
    indicativeAmountCents: 4900,
    currency: "usd",
    checkedAt: "2026-10-13T12:00:00.000Z",
    quoteRequired: true,
  };
  const counted = parse([{ ...base, openSlots: 3, totalSlots: 4 }])[0];
  assert.equal(counted?.openSlots, 3);
  assert.equal(counted?.totalSlots, 4);

  // Half a pair, a contradiction with availability, an impossible pair, and
  // counts on an unknown offer all drop the counts and keep the offer.
  for (const broken of [
    { ...base, openSlots: 3 },
    { ...base, openSlots: 0, totalSlots: 4 },
    { ...base, availability: "sold_out", openSlots: 2, totalSlots: 4 },
    { ...base, openSlots: 5, totalSlots: 4 },
    { ...base, openSlots: 1, totalSlots: 0 },
    { ...base, openSlots: 1.5, totalSlots: 4 },
    {
      ...base,
      availability: "unknown",
      indicativeAmountCents: null,
      currency: null,
      checkedAt: null,
      openSlots: 3,
      totalSlots: 4,
    },
  ]) {
    const parsed = parse([broken]);
    assert.equal(parsed.length, 1);
    assert.equal(parsed[0]?.openSlots, null);
    assert.equal(parsed[0]?.totalSlots, null);
  }

  // An offer the dashboard cannot read is dropped, not rendered half-known.
  assert.equal(parse([{ ...base, product: "banner" }]).length, 0);
  assert.equal(parse([{ ...base, availability: "maybe" }]).length, 0);
  assert.equal(parse([{ ...base, quoteRequired: false }]).length, 0);
  assert.equal(parse(["sponsored"]).length, 0);
}

// The in-feed offer recurs every ten rows and never trails the list.
assert.deepEqual(inFeedSlotIndexes(0), []);
assert.deepEqual(inFeedSlotIndexes(1), []);
assert.deepEqual(inFeedSlotIndexes(3), [2]);
assert.deepEqual(inFeedSlotIndexes(8), [6]);
assert.deepEqual(inFeedSlotIndexes(16), [6]);
assert.deepEqual(inFeedSlotIndexes(17), [6, 16]);
assert.deepEqual(inFeedSlotIndexes(45), [6, 16, 26, 36]);

console.log("extensions-discover-model.test.ts: all assertions passed");
