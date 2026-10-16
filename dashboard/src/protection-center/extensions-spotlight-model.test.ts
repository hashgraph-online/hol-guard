import assert from "node:assert/strict";

import type { ExtensionCatalogSummary } from "../extension-controls-api";
import type { DiscoveryFeedStatus, DiscoveryOffer, DiscoveryPlacement, JoinedDiscoveryCard } from "./extensions-discover-model";
import {
  buildSpotlight,
  CATALOG_SLOT_PRODUCTS,
  SHELF_SLOT_PRODUCTS,
  slotStartingPrice,
  slotState,
  spotlightActivityFromDimensions,
  spotlightHeading,
  SPOTLIGHT_CELL_COUNT,
  STARTER_SPOTLIGHT_IDS,
} from "./extensions-spotlight-model";

/**
 * The shelf must never be empty, never outrank a buyer, and never present an
 * editorial list as a measurement. These vectors pin the fallback ladder, the
 * basis copy each tier is allowed to claim, and the conditions under which a
 * slot may be offered for sale at all.
 */

function catalog(id: string): ExtensionCatalogSummary {
  return {
    extension_id: id,
    name: id.replace("command.", ""),
    description: "A catalog extension used by the spotlight vectors.",
  } as unknown as ExtensionCatalogSummary;
}

function paid(id: string, product: DiscoveryPlacement["product"]): JoinedDiscoveryCard {
  return {
    catalog: catalog(id),
    placement: {
      publicPlacementId: `placement-${id}`,
      extensionId: id,
      product,
      slotIndex: 0,
      windowIndex: null,
      startsAt: "2026-10-15T00:00:00.000Z",
      endsAt: "2026-10-16T00:00:00.000Z",
      creativeVersion: "1",
      creative: { headline: "Headline", body: "Body", brandName: "Maker" },
    },
  };
}

function offer(overrides: Partial<DiscoveryOffer> = {}): DiscoveryOffer {
  return {
    product: "sponsored",
    availability: "open",
    indicativeAmountCents: 4900,
    currency: "usd",
    checkedAt: null,
    quoteRequired: true,
    ...overrides,
  };
}

const CATALOG = [
  ...STARTER_SPOTLIGHT_IDS.map(catalog),
  catalog("command.database.redis"),
  catalog("command.secrets"),
];

// Paid placements take the cells they bought, featured before sponsored.
{
  const spotlight = buildSpotlight({
    featured: [paid("command.git", "always")],
    sponsored: [paid("command.github", "sponsored")],
    activity: [{ extensionId: "command.secrets", count: 900 }],
    catalog: CATALOG,
  });
  assert.equal(spotlight.cards.length, SPOTLIGHT_CELL_COUNT);
  assert.deepEqual(spotlight.cards.map((card) => card.basis), ["paid", "paid", "activity"]);
  assert.equal(spotlight.cards[0].featured, true);
  assert.equal(spotlight.cards[1].featured, false);
  assert.equal(spotlight.lead, "paid");
  assert.equal(spotlight.vacant, false);
}

// No paid inventory: the device's own counts fill the shelf and say so.
{
  const spotlight = buildSpotlight({
    featured: [],
    sponsored: [],
    activity: [
      { extensionId: "command.secrets", count: 12 },
      { extensionId: "command.git", count: 480 },
      { extensionId: "command.unknown-to-catalog", count: 9_000 },
    ],
    catalog: CATALOG,
  });
  assert.equal(spotlight.vacant, true);
  assert.equal(spotlight.lead, "activity");
  // Ranked by count, and an id the local catalog does not know never renders.
  assert.equal(spotlight.cards[0].catalog.extension_id, "command.git");
  assert.equal(spotlight.cards[0].reason, "480 commands checked here");
  assert.equal(spotlight.cards[1].reason, "12 commands checked here");
  assert.ok(!spotlight.cards.some((card) => card.catalog.extension_id === "command.unknown-to-catalog"));
  // The remaining cell falls through to the starter set, not to emptiness.
  assert.equal(spotlight.cards.length, SPOTLIGHT_CELL_COUNT);
  assert.equal(spotlight.cards[2].basis, "starter");
  assert.equal(spotlight.cards[2].reason, null);
}

// A brand-new device still gets a full shelf, declared as editorial.
{
  const spotlight = buildSpotlight({ featured: [], sponsored: [], activity: [], catalog: CATALOG });
  assert.equal(spotlight.lead, "starter");
  assert.equal(spotlight.vacant, true);
  assert.deepEqual(
    spotlight.cards.map((card) => card.catalog.extension_id),
    STARTER_SPOTLIGHT_IDS.slice(0, SPOTLIGHT_CELL_COUNT),
  );
  assert.ok(spotlight.cards.every((card) => card.placement === null));
}

// A zero count is not evidence of anything, and never takes a cell as one.
{
  const spotlight = buildSpotlight({
    featured: [],
    sponsored: [],
    activity: [{ extensionId: "command.secrets", count: 0 }],
    catalog: CATALOG,
  });
  assert.equal(spotlight.lead, "starter");
  assert.ok(!spotlight.cards.some((card) => card.basis === "activity"));
}

// One extension never takes two cells, however many ways it qualifies.
{
  const spotlight = buildSpotlight({
    featured: [paid("command.git", "always")],
    sponsored: [paid("command.git", "sponsored")],
    activity: [{ extensionId: "command.git", count: 500 }],
    catalog: CATALOG,
  });
  assert.equal(spotlight.cards.filter((card) => card.catalog.extension_id === "command.git").length, 1);
}

// Each basis states its own evidence; only the activity tier claims a count.
{
  assert.match(spotlightHeading("paid").basis, /Paid placements are labeled/);
  assert.match(spotlightHeading("activity").basis, /Counted from Guard's own decisions/);
  assert.match(spotlightHeading("starter").basis, /Not a ranking or a popularity measure/);
  assert.ok(!/popular/i.test(spotlightHeading("activity").title));
}

// Vacancy is claimed only on an authoritative open offer.
{
  const shelf = (offers: DiscoveryOffer[], status: DiscoveryFeedStatus = "ready") =>
    slotState({ status, offers, products: SHELF_SLOT_PRODUCTS });
  assert.equal(shelf([offer({ product: "always" })]), "open");
  assert.equal(shelf([offer({ product: "always", availability: "sold_out" })]), "sold-out");
  assert.equal(shelf([offer({ product: "always", availability: "unknown" })]), "hidden");
  assert.equal(shelf([]), "hidden");
  for (const status of ["loading", "unavailable", "rate-limited", "offline", "opt-out"] as const) {
    assert.equal(shelf([offer({ product: "always" })], status), "hidden");
  }
}

// Availability never crosses products: a sold-out sponsored listing is not
// made available by an open featured offer, and the reverse holds too.
{
  const offers = [
    offer({ product: "always", availability: "open", indicativeAmountCents: 19_900 }),
    offer({ product: "sponsored", availability: "sold_out", indicativeAmountCents: 4_900 }),
  ];
  assert.equal(slotState({ status: "ready", offers, products: CATALOG_SLOT_PRODUCTS }), "sold-out");
  assert.equal(slotState({ status: "ready", offers, products: SHELF_SLOT_PRODUCTS }), "open");
  assert.equal(slotStartingPrice(offers, CATALOG_SLOT_PRODUCTS), null);
  assert.equal(slotStartingPrice(offers, SHELF_SLOT_PRODUCTS), "$199");
}

// The advertised price is the cheapest open offer the server quoted for the
// products that actually buy the placement being advertised.
{
  assert.equal(
    slotStartingPrice(
      [
        offer({ product: "always", indicativeAmountCents: 19_900 }),
        offer({ product: "time_slot", indicativeAmountCents: 4_900 }),
      ],
      SHELF_SLOT_PRODUCTS,
    ),
    "$49",
  );
  assert.equal(slotStartingPrice([offer({ availability: "sold_out" })], CATALOG_SLOT_PRODUCTS), null);
  assert.equal(slotStartingPrice([offer({ indicativeAmountCents: null })], CATALOG_SLOT_PRODUCTS), null);
  assert.equal(slotStartingPrice([offer({ indicativeAmountCents: 4_950 })], CATALOG_SLOT_PRODUCTS), "$49.50");
  assert.equal(slotStartingPrice([], CATALOG_SLOT_PRODUCTS), null);
}

// Analytics buckets arrive from a local endpoint and are still bounded here.
{
  assert.deepEqual(
    spotlightActivityFromDimensions([
      { value: "command.git", count: 12.7 },
      { value: "command.github", count: -4 },
    ]),
    [
      { extensionId: "command.git", count: 12 },
      { extensionId: "command.github", count: 0 },
    ],
  );
}

// A catalog holding none of the starter ids still fills the shelf: a heading
// over an empty grid is the dead surface this shelf exists to prevent.
{
  const exotic = ["command.unlisted-a", "command.unlisted-b", "command.unlisted-c", "command.unlisted-d"]
    .map((extensionId) => catalog(extensionId));
  const spotlight = buildSpotlight({ featured: [], sponsored: [], activity: [], catalog: exotic });
  assert.equal(spotlight.cards.length, 3);
  assert.equal(spotlight.lead, "starter");
  assert.deepEqual(
    spotlight.cards.map((card) => card.catalog.extension_id),
    ["command.unlisted-a", "command.unlisted-b", "command.unlisted-c"],
  );
  assert.ok(spotlight.cards.every((card) => card.basis === "starter"));
}

console.log("extensions-spotlight-model tests passed");
