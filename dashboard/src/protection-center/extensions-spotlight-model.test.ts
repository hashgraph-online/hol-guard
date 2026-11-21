import assert from "node:assert/strict";

import type { ExtensionCatalogSummary } from "../extension-controls-api";
import type { DiscoveryFeedStatus, DiscoveryOffer, DiscoveryPlacement, JoinedDiscoveryCard } from "./extensions-discover-model";
import {
  buildSpotlight,
  CATALOG_SLOT_PRODUCTS,
  protectionLine,
  ruleCountLabel,
  SHELF_SLOT_PRODUCTS,
  allCardsActive,
  slotInventoryLabel,
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
    openSlots: null,
    totalSlots: null,
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

// The offer stands on its own; only the wording waits for the server. An
// authoritative availability decides "open" or "sold-out", everything the
// server never stated is "unconfirmed", and only a device that turned
// discovery off, or one still loading it, is asked nothing.
{
  const shelf = (offers: DiscoveryOffer[], status: DiscoveryFeedStatus = "ready") =>
    slotState({ status, offers, products: SHELF_SLOT_PRODUCTS });
  assert.equal(shelf([offer({ product: "always" })]), "open");
  assert.equal(shelf([offer({ product: "always", availability: "sold_out" })]), "sold-out");
  assert.equal(shelf([offer({ product: "always", availability: "unknown" })]), "unconfirmed");
  assert.equal(shelf([]), "unconfirmed");
  for (const status of ["unavailable", "rate-limited", "offline"] as const) {
    assert.equal(shelf([], status), "unconfirmed");
    // A stale open offer carried alongside a failed feed is still authoritative
    // about the product it describes.
    assert.equal(shelf([offer({ product: "always" })], status), "open");
  }
  for (const status of ["loading", "opt-out"] as const) {
    assert.equal(shelf([offer({ product: "always" })], status), "hidden");
  }
  // An unconfirmed slot quotes nothing: no price, no count.
  assert.equal(slotStartingPrice([offer({ availability: "unknown" })], SHELF_SLOT_PRODUCTS), null);
  assert.equal(slotInventoryLabel([offer({ availability: "unknown" })], SHELF_SLOT_PRODUCTS), null);
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

// Remaining inventory is only ever repeated back from the server, and it
// describes the same single product the quoted price describes.
{
  assert.equal(
    slotInventoryLabel([offer({ openSlots: 3, totalSlots: 4 })], CATALOG_SLOT_PRODUCTS),
    "3 of 4 open.",
  );
  // The count follows the price onto the cheapest open product rather than
  // summing two products a buyer cannot buy together.
  assert.equal(
    slotInventoryLabel(
      [
        offer({ product: "always", indicativeAmountCents: 19_900, openSlots: 1, totalSlots: 2 }),
        offer({ product: "time_slot", indicativeAmountCents: 4_900, openSlots: 2, totalSlots: 6 }),
      ],
      SHELF_SLOT_PRODUCTS,
    ),
    "2 of 6 open.",
  );
  // The quoted product carrying no counts says nothing, even when the other
  // product on the placement sent a complete pair.
  assert.equal(
    slotInventoryLabel(
      [
        offer({ product: "always", indicativeAmountCents: 19_900, openSlots: 1, totalSlots: 2 }),
        offer({ product: "time_slot", indicativeAmountCents: 4_900 }),
      ],
      SHELF_SLOT_PRODUCTS,
    ),
    null,
  );
  // An unknown offer contributes nothing and is not counted as inventory.
  assert.equal(
    slotInventoryLabel(
      [offer({ availability: "unknown", indicativeAmountCents: null, currency: null })],
      CATALOG_SLOT_PRODUCTS,
    ),
    null,
  );
  // An unknown product beside a quoted one neither hides nor inflates the
  // count: the quoted product still reports its own capacity.
  assert.equal(
    slotInventoryLabel(
      [
        offer({ product: "always", openSlots: 1, totalSlots: 2 }),
        offer({ product: "time_slot", availability: "unknown", indicativeAmountCents: null, currency: null }),
      ],
      SHELF_SLOT_PRODUCTS,
    ),
    "1 of 2 open.",
  );
  assert.equal(slotInventoryLabel([], CATALOG_SLOT_PRODUCTS), null);
  // A sold-out product still reports honestly rather than going silent.
  assert.equal(
    slotInventoryLabel([offer({ availability: "sold_out", openSlots: 0, totalSlots: 4 })], CATALOG_SLOT_PRODUCTS),
    "0 of 4 open.",
  );
  // Real capacity: the shelf quotes the cheapest product's own count instead
  // of adding ten always slots to sixty time-slot windows.
  assert.equal(
    slotInventoryLabel(
      [
        offer({ product: "always", indicativeAmountCents: 19_900, openSlots: 9, totalSlots: 10 }),
        offer({ product: "time_slot", indicativeAmountCents: 4_900, openSlots: 59, totalSlots: 60 }),
      ],
      SHELF_SLOT_PRODUCTS,
    ),
    "59 of 60 open.",
  );
}

// Starter copy comes from the catalog entry and stops at what it declares.
{
  const withRisk = {
    ...catalog("command.git"),
    risk_classes: ["destructive_shell", "network_egress", "execution"],
    rule_count: 1240,
  } as ExtensionCatalogSummary;
  assert.equal(
    protectionLine(withRisk),
    "Watches for irreversible deletes and overwrites and commands that send data off this machine.",
  );
  assert.equal(ruleCountLabel(withRisk), "1,240 rules");
  assert.equal(ruleCountLabel({ ...withRisk, rule_count: 1 } as ExtensionCatalogSummary), "1 rule");
  // An unmapped class is skipped rather than guessed at, and an entry that
  // declares nothing says nothing.
  assert.equal(
    protectionLine({ ...withRisk, risk_classes: ["not_a_real_class"] } as ExtensionCatalogSummary),
    null,
  );
  assert.equal(protectionLine(catalog("command.git")), null);
  assert.equal(ruleCountLabel(catalog("command.git")), null);
}

// The starter tier leads with what is still off: a shelf of cards a reader
// has already turned on is a wall, not a suggestion.
{
  const off = new Set(["command.cloud.aws"]);
  const spotlight = buildSpotlight({
    featured: [],
    sponsored: [],
    activity: [],
    catalog: CATALOG,
    isActive: (extension) => !off.has(extension.extension_id),
  });
  assert.equal(spotlight.cards[0]?.catalog.extension_id, "command.cloud.aws");
  assert.equal(allCardsActive(spotlight.cards, (extension) => !off.has(extension.extension_id)), false);
  assert.equal(
    spotlightHeading(spotlight.lead, allCardsActive(spotlight.cards, (extension) => !off.has(extension.extension_id)))
      .title,
    "Good places to start",
  );
  // The open slot drops the last cell, so the heading reads the cells that
  // are left: a card still off behind the slot never reaches the screen and
  // must not keep the shelf asking.
  const hidden = spotlight.cards[2]?.catalog.extension_id;
  const onExceptHidden = (extension: ExtensionCatalogSummary) => extension.extension_id !== hidden;
  assert.equal(allCardsActive(spotlight.cards, onExceptHidden), false);
  assert.equal(allCardsActive(spotlight.cards.slice(0, 2), onExceptHidden), true);
}

// Every starter already on: the shelf says so instead of asking again.
{
  const spotlight = buildSpotlight({
    featured: [],
    sponsored: [],
    activity: [],
    catalog: CATALOG,
    isActive: () => true,
  });
  assert.equal(allCardsActive(spotlight.cards, () => true), true);
  const heading = spotlightHeading(spotlight.lead, allCardsActive(spotlight.cards, () => true));
  assert.equal(heading.title, "Already covering the basics");
  assert.match(heading.basis, /Not a ranking/);
}

// A paid cell is never counted as coverage: the shelf still has work to do.
{
  const spotlight = buildSpotlight({
    featured: [paid("command.git", "always")],
    sponsored: [],
    activity: [],
    catalog: CATALOG,
    isActive: () => true,
  });
  assert.equal(spotlight.lead, "paid");
  assert.equal(allCardsActive(spotlight.cards, () => true), true);
  assert.equal(spotlightHeading(spotlight.lead, allCardsActive(spotlight.cards, () => true)).title, "Featured by their makers");
}

console.log("extensions-spotlight-model tests passed");
