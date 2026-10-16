import { expect, test, type Page } from "@playwright/test";

import { catalog, effective, extension, initialize, mount } from "./extension-control-fixtures";

/**
 * The Extensions surface sells placement without ever lying about inventory.
 * These scenarios pin the three states a maker and a device owner can land in:
 * nothing sold (local activity leads, the open slot is offered at the exact
 * size a buyer gets), placement sold (paid cards lead and stay labeled), and
 * the single collapsed surface that replaced the old tab pair.
 */

const STARTER_IDS = [
  "command.git",
  "command.container-runtime",
  "command.cloud.aws",
  "command.package.node",
  "command.kubernetes-operations",
  "command.remote.ssh",
  "command.github",
  "command.package.python",
  "command.database.postgresql",
  "command.filesystem",
];

/** Two starters left off, so the shelf has something to actually suggest. */
const OFF_BY_DEFAULT = ["command.cloud.aws", "command.package.python"];

function wideCatalog() {
  return { ...catalog(), extensions: STARTER_IDS.map((id) => extension(id, "")) };
}

/** Effective controls that turn the named starters off on this device. */
function withStartersOff(off: readonly string[] = OFF_BY_DEFAULT) {
  return effective({
    controls: off.map((id) => ({ target: { kind: "extension", target_id: id }, state: "disabled" })),
  });
}

function placement(id: string, product: "always" | "sponsored", brandName: string) {
  return {
    publicPlacementId: `placement-${id}`,
    extensionId: id,
    product,
    slotIndex: 0,
    windowIndex: null,
    startsAt: "2026-01-01T00:00:00Z",
    endsAt: "2099-01-01T00:00:00Z",
    creativeVersion: "1",
    creative: { headline: `${brandName} headline`, body: "Paid creative body copy.", brandName },
  };
}

type Availability = "open" | "sold_out" | "unknown";

function offer(
  product: string,
  availability: Availability,
  cents: number | null,
  slots?: { open: number; total: number } | null,
) {
  return {
    product,
    availability,
    indicativeAmountCents: cents,
    currency: "USD",
    checkedAt: "2026-01-01T00:00:00Z",
    quoteRequired: true,
    ...(slots ? { openSlots: slots.open, totalSlots: slots.total } : {}),
  };
}

function projection(options: {
  placements?: unknown[];
  shelf?: Availability;
  listing?: Availability;
  shelfSlots?: { open: number; total: number } | null;
  listingSlots?: { open: number; total: number } | null;
} = {}) {
  return {
    remainingLeaseMs: 600_000,
    policyAllowed: true,
    snapshot: {
      schemaVersion: "guard.extensions.discovery.v1",
      snapshotId: "snapshot-e2e",
      state: "ready",
      enabled: true,
      reasonCode: null,
      generatedAt: "2026-01-01T00:00:00Z",
      leaseExpiresAt: "2099-01-01T00:00:00Z",
      placements: options.placements ?? [],
      offers: [
        offer("always", options.shelf ?? "open", 19_900, options.shelfSlots),
        offer("sponsored", options.listing ?? "open", 4_900, options.listingSlots),
      ],
    },
  };
}

/** Registered after mount so it wins over the fixture's `**\/v1\/**` catch-all. */
async function routeDiscovery(page: Page, body: unknown) {
  await page.route("**/v1/discovery/extensions/**", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(body),
  }));
}

async function routeAnalytics(page: Page, buckets: { value: string; count: number }[]) {
  await page.route("**/v1/command-activity/analytics**", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      schema_version: "guard.command-activity-api.v1",
      window: { from: "2025-12-02", through: "2026-01-01", days: 30 },
      scope: { dimension: null, dimension_value: null },
      commands_checked: buckets.reduce((total, bucket) => total + bucket.count, 0),
      trend: [],
      dimensions: {
        harness: [], extension: buckets, rule: [], disposition: [],
        execution_status: [], prompt_status: [], proof_level: [], latency: [],
      },
      dimension_breakdowns_scope: "global",
      feedback: [],
      health: { status: "healthy", dropped_events: 0, persistence_errors: 0, last_error_class: null, last_error_at: null },
    }),
  }));
}

async function expectRendersAtBothSizes(page: Page, check: () => Promise<void>) {
  await page.setViewportSize({ width: 1280, height: 800 });
  await check();
  await page.setViewportSize({ width: 390, height: 844 });
  await check();
  const horizontal = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(horizontal).toBeLessThanOrEqual(1);
  await page.setViewportSize({ width: 1280, height: 800 });
}

test.describe("extensions spotlight", () => {
  test("empty paid inventory leads with local activity and offers the open slot", async ({ page }) => {
    await mount(page, { catalog: wideCatalog(), effective: withStartersOff() });
    await routeDiscovery(page, projection({
      shelfSlots: { open: 3, total: 4 },
      listingSlots: { open: 2, total: 6 },
    }));
    await routeAnalytics(page, [
      { value: "command.cloud.aws", count: 184 },
      { value: "command.git", count: 97 },
    ]);
    await initialize(page);

    const spotlight = page.getByTestId("extensions-spotlight");
    await expect(spotlight).toBeVisible();
    await expect(spotlight.getByRole("heading", { name: "Busiest tools on this device" })).toBeVisible();
    await expect(page.getByTestId("spotlight-basis")).toContainText("Counted from Guard's own decisions");
    // No sad empty state: the shelf is full, and nothing claims a popularity rank.
    await expect(page.getByTestId("spotlight-organic-card")).toHaveCount(2);
    await expect(page.getByTestId("discovery-featured-card")).toHaveCount(0);

    const slot = page.getByTestId("spotlight-slot-card");
    await expect(slot).toHaveAttribute("data-state", "open");
    await expect(slot).toContainText("This slot is open");
    // The shelf cell quotes the product that buys the shelf, not the cheaper listing.
    await expect(slot.getByRole("link", { name: /Take this slot · from \$199\/mo/ })).toBeVisible();
    // Live inventory, exactly as the server stated it for this product.
    await expect(slot).toContainText("3 of 4 open.");
    // The free path keeps the campaign tag and reports its own surface, so
    // the two asks stay apart in attribution.
    const shelfClaim = slot.getByRole("link", { name: "Claim it free" });
    await expect(shelfClaim).toBeVisible();
    await expect(shelfClaim).toHaveAttribute(
      "href",
      /intent=extension-promotion.*placement=extensions_header.*action=claim/,
    );

    // With nothing sold, the in-feed ask runs too: it is a different product
    // with its own inventory, and a maker scrolling the list must see it.
    const inFeed = page.getByTestId("catalog-slot-row");
    await expect(inFeed).toHaveCount(1);
    await expect(inFeed).toContainText("2 of 6 open.");
    await expect(inFeed.getByRole("link", { name: /Get this spot · from \$49\/mo/ })).toBeVisible();
    const feedClaim = inFeed.getByRole("link", { name: "Claim it free" });
    await expect(feedClaim).toBeVisible();
    await expect(feedClaim).toHaveAttribute(
      "href",
      /intent=extension-promotion.*placement=extensions_feed.*action=claim/,
    );

    await expectRendersAtBothSizes(page, async () => {
      await expect(spotlight).toBeVisible();
      await expect(slot).toBeVisible();
      await expect(inFeed).toBeVisible();
    });
  });

  test("a fresh device falls back to the starter set without inventing metrics", async ({ page }) => {
    await mount(page, { catalog: wideCatalog(), effective: withStartersOff() });
    await routeDiscovery(page, projection({ shelf: "unknown", listing: "unknown" }));
    await routeAnalytics(page, []);
    await initialize(page);

    await expect(page.getByRole("heading", { name: "Good places to start" })).toBeVisible();
    await expect(page.getByTestId("spotlight-basis")).toContainText("Not a ranking or a popularity measure");
    // Two starters and the slot: the shelf gives the weakest organic cell to
    // the ask rather than growing a fourth.
    await expect(page.getByTestId("spotlight-organic-card")).toHaveCount(2);
    const first = page.getByTestId("spotlight-organic-card").first();
    await expect(first).toHaveAttribute("data-basis", "starter");
    // The starter tier leads with what is still off, says what the extension
    // watches for in the catalog's own words, and offers the setup path.
    await expect(first).toHaveAttribute("data-active", "false");
    await expect(first.getByTestId("spotlight-organic-state")).toHaveText("Off");
    await expect(first.getByTestId("spotlight-organic-protection")).toContainText(
      "Watches for irreversible deletes and overwrites.",
    );
    await expect(first.getByRole("button", { name: "Set it up" })).toBeVisible();
    // Availability the server could not confirm still gets the ask - a reader
    // can always ask for the spot - but it buys no claim: no vacancy, no
    // price, no count, in either surface.
    const slot = page.getByTestId("spotlight-slot-card");
    await expect(slot).toHaveAttribute("data-state", "unconfirmed");
    await expect(slot).toContainText("Promote your extension");
    await expect(slot).not.toContainText("This slot is open");
    await expect(slot.getByRole("link", { name: "Take this slot" })).toBeVisible();
    await expect(slot).not.toContainText("$");
    const inFeed = page.getByTestId("catalog-slot-row");
    await expect(inFeed).toHaveAttribute("data-state", "unconfirmed");
    await expect(inFeed.getByRole("link", { name: "Get this spot" })).toBeVisible();
    await expect(inFeed).not.toContainText(" open.");

    await expectRendersAtBothSizes(page, async () => {
      await expect(first).toBeVisible();
    });
  });

  test("a device that already runs every starter is told so, not asked again", async ({ page }) => {
    await mount(page, { catalog: wideCatalog() });
    await routeDiscovery(page, projection({ shelf: "unknown", listing: "unknown" }));
    await routeAnalytics(page, []);
    await initialize(page);

    await expect(page.getByRole("heading", { name: "Already covering the basics" })).toBeVisible();
    await expect(page.getByTestId("spotlight-basis")).toContainText("Not a ranking or a popularity measure");
    const cards = page.getByTestId("spotlight-organic-card");
    await expect(cards).toHaveCount(2);
    // The square rides along on this heading too, not only on an empty shelf.
    await expect(page.getByTestId("spotlight-slot-card")).toHaveCount(1);
    await expect(cards.first().getByTestId("spotlight-organic-state")).toHaveText("On");
    await expect(cards.first().getByRole("button", { name: "Review protection" })).toBeVisible();
  });

  test("sold placement leads the shelf, stays labeled, and opens the in-feed ask", async ({ page }) => {
    await mount(page, { catalog: wideCatalog(), effective: withStartersOff() });
    await routeDiscovery(page, projection({
      placements: [
        placement("command.cloud.aws", "always", "Northwind Tools"),
        placement("command.github", "sponsored", "Harbor Labs"),
      ],
    }));
    await routeAnalytics(page, [{ value: "command.git", count: 41 }]);
    await initialize(page);

    const featured = page.getByTestId("discovery-featured-card");
    await expect(featured).toHaveCount(1);
    await expect(featured).toContainText("Northwind Tools");
    await expect(featured).toContainText("Paid placement. Your protection settings are unchanged.");
    await expect(page.getByTestId("discovery-sponsored-card")).toContainText("Harbor Labs");
    await expect(page.getByRole("heading", { name: "Featured by their makers" })).toBeVisible();
    // With inventory proven to exist, the one inline ask appears in the list.
    const inFeed = page.getByTestId("catalog-slot-row");
    await expect(inFeed).toHaveCount(1);
    await expect(inFeed).toContainText("Position is all they buy.");
    await expect(inFeed.getByRole("link", { name: /Get this spot · from \$49\/mo/ })).toBeVisible();
    // No counts were sent, so none are shown.
    await expect(inFeed).not.toContainText(" open.");

    await expectRendersAtBothSizes(page, async () => {
      await expect(featured).toBeVisible();
      await expect(inFeed).toBeVisible();
    });
  });

  test("a sold-out shelf is silent, and a sold-out listing never borrows an open price", async ({ page }) => {
    await mount(page, { catalog: wideCatalog(), effective: withStartersOff() });
    await routeDiscovery(page, projection({ shelf: "sold_out", listing: "sold_out", placements: [placement("command.cloud.aws", "always", "Northwind Tools")] }));
    await routeAnalytics(page, [{ value: "command.git", count: 41 }]);
    await initialize(page);

    await expect(page.getByTestId("discovery-featured-card")).toHaveCount(1);
    // An authoritative sold-out is the one answer that withdraws both asks:
    // no cell, no row, no sold-out claim sitting beside organic cards.
    await expect(page.getByTestId("spotlight-slot-card")).toHaveCount(0);
    await expect(page.getByTestId("catalog-slot-row")).toHaveCount(0);
  });

  test("a sponsored placement past the shelf still gets its labeled catalog row", async ({ page }) => {
    await mount(page, { catalog: wideCatalog(), effective: withStartersOff() });
    await routeDiscovery(page, projection({
      placements: [
        placement("command.cloud.aws", "always", "Northwind Tools"),
        placement("command.github", "always", "Harbor Labs"),
        placement("command.package.node", "always", "Tidewater"),
        placement("command.remote.ssh", "sponsored", "Fourth Buyer"),
      ],
    }));
    await routeAnalytics(page, []);
    await initialize(page);

    // The shelf holds three; the fourth buyer is disclosed in the catalog.
    await expect(page.getByTestId("discovery-featured-card")).toHaveCount(3);
    const rows = page.getByTestId("catalog-featured-row");
    await expect(rows.filter({ hasText: "Fourth Buyer" })).toHaveCount(1);
    await expect(rows.filter({ hasText: "Fourth Buyer" })).toContainText("Sponsored");
  });

  test("a sponsored row ordered ahead of the featured ones is still rendered once each", async ({ page }) => {
    await mount(page, { catalog: wideCatalog(), effective: withStartersOff() });
    await routeDiscovery(page, projection({
      placements: [
        placement("command.github", "always", "Northwind Tools"),
        placement("command.package.node", "always", "Harbor Labs"),
        placement("command.package.python", "always", "Tidewater"),
        // Sorts ahead of every featured id, which is what breaks a count-based split.
        placement("command.cloud.aws", "sponsored", "Fourth Buyer"),
      ],
    }));
    await routeAnalytics(page, []);
    await initialize(page);

    const rows = page.getByTestId("catalog-featured-row");
    await expect(rows.filter({ hasText: "Fourth Buyer" })).toHaveCount(1);
    await expect(rows.filter({ hasText: "Tidewater" })).toHaveCount(1);
    await expect(rows).toHaveCount(4);
  });

  test("one surface: no tab strip, and searching hides the shelf", async ({ page }) => {
    await mount(page, { catalog: wideCatalog(), effective: withStartersOff() });
    await routeDiscovery(page, projection());
    await routeAnalytics(page, [{ value: "command.git", count: 12 }]);
    await initialize(page);

    await expect(page.getByTestId("extensions-surface")).toBeVisible();
    await expect(page.getByRole("tablist")).toHaveCount(0);
    await expect(page.getByTestId("extensions-spotlight")).toBeVisible();

    await page.getByRole("searchbox").first().fill("github");
    await expect(page.getByTestId("extensions-spotlight")).toHaveCount(0);
    await expect(page.getByTestId("catalog-slot-row")).toHaveCount(0);
  });
});
