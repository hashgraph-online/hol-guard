import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { expect, test, type Page } from "@playwright/test";

import { catalog, effective, extension, initialize, mount } from "./extension-control-fixtures";

/**
 * The same Extensions surface, driven by projections the native runtime
 * actually produced from the Cloud placements API running against a real
 * database: real prices, real capacity (ten always slots, sixty time-slot
 * windows, four sponsored rows) and the real unknown case the sponsored
 * product falls into when its table cannot be read. Hand-written fixtures
 * used small, tidy numbers; these are the numbers a buyer will really see.
 */

function realProjection(name: string): unknown {
  const path = fileURLToPath(new URL(`./fixtures/real-discovery/${name}.json`, import.meta.url));
  return JSON.parse(readFileSync(path, "utf8"));
}

/** The catalog the real placements point at, padded past the in-feed threshold. */
const CATALOG_IDS = [
  "command.discovery-01",
  "command.discovery-03",
  "command.git",
  "command.container-runtime",
  "command.cloud.aws",
  "command.package.node",
  "command.kubernetes-operations",
  "command.remote.ssh",
  "command.github",
  "command.package.python",
];

function realCatalog() {
  return { ...catalog(), extensions: CATALOG_IDS.map((id) => extension(id, "")) };
}

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

/**
 * The recorded placements end on a real date, and the view filters them
 * against the clock. Pinning the page clock to just after the capture keeps
 * these scenarios deterministic without editing the projections.
 */
const CAPTURE_TIME = new Date("2026-10-16T09:41:00.000Z");

async function open(page: Page, fixture: string) {
  await page.clock.setFixedTime(CAPTURE_TIME);
  await mount(page, { catalog: realCatalog(), effective: effective() });
  await routeDiscovery(page, realProjection(fixture));
  await routeAnalytics(page, [{ value: "command.git", count: 41 }]);
  await initialize(page);
}

test.describe("extensions discovery, real projections", () => {
  test("nothing sold: both surfaces offer their own product at its own price and capacity", async ({ page }) => {
    await open(page, "empty-inventory");

    await expect(page.getByTestId("discovery-featured-card")).toHaveCount(0);
    await expect(page.getByTestId("discovery-sponsored-card")).toHaveCount(0);

    const slot = page.getByTestId("spotlight-slot-card");
    await expect(slot).toHaveAttribute("data-state", "open");
    // $500/mo always beside $50/mo time slot: the shelf quotes the cheaper
    // product, and the capacity beside it is that same product's sixty
    // windows - never the seventy-slot sum of two products nobody sells
    // together.
    await expect(slot.getByRole("link", { name: /Take this slot · from \$50\/mo/ })).toBeVisible();
    await expect(slot).toContainText("60 of 60 open.");
    await expect(slot).not.toContainText("70 open");

    const inFeed = page.getByTestId("catalog-slot-row");
    await expect(inFeed).toHaveCount(1);
    await expect(inFeed.getByRole("link", { name: /Get this spot · from \$200\/mo/ })).toBeVisible();
    await expect(inFeed).toContainText("4 of 4 open.");

    await expectRendersAtBothSizes(page, async () => {
      await expect(slot).toBeVisible();
      await expect(inFeed).toBeVisible();
    });
  });

  test("partial inventory: paid placements render labeled, and the in-feed count drops with the stock", async ({ page }) => {
    await open(page, "partial-inventory");

    const featured = page.getByTestId("discovery-featured-card");
    await expect(featured).toHaveCount(1);
    await expect(featured).toContainText("Explore Discovery Tool 0");
    await expect(featured).toContainText("Paid placement. Your protection settings are unchanged.");

    const sponsored = page.getByTestId("discovery-sponsored-card");
    await expect(sponsored).toHaveCount(1);
    await expect(sponsored).toContainText("Sponsored");

    // Two sold cards plus local activity would fill the shelf, and the slot
    // still takes the last cell: a shelf with paid cards on it is exactly
    // when a reader wants the spot. Each placement quotes its own product -
    // fifty-nine time-slot windows on the shelf, one sponsored row of four
    // in the list.
    const slot = page.getByTestId("spotlight-slot-card");
    await expect(slot).toHaveAttribute("data-state", "open");
    await expect(slot).toContainText("59 of 60 open.");
    await expect(slot.getByRole("link", { name: /Take this slot · from \$50\/mo/ })).toBeVisible();

    const inFeed = page.getByTestId("catalog-slot-row");
    await expect(inFeed).toHaveCount(1);
    await expect(inFeed).toContainText("1 of 4 open.");
    await expect(inFeed.getByRole("link", { name: /Get this spot · from \$200\/mo/ })).toBeVisible();

    await expectRendersAtBothSizes(page, async () => {
      await expect(featured).toBeVisible();
      await expect(inFeed).toBeVisible();
    });
  });

  test("sponsored sold out: the in-feed ask stops offering what it cannot sell", async ({ page }) => {
    await open(page, "sponsored-sold-out");

    // The placements already sold stay visible and labeled; the ask does not.
    await expect(page.getByTestId("discovery-featured-card")).toHaveCount(1);
    await expect(page.getByTestId("discovery-sponsored-card")).toHaveCount(1);
    await expect(page.getByTestId("catalog-slot-row")).toHaveCount(0);
    await expect(page.getByTestId("extensions-surface")).not.toContainText("0 of 4 open.");
  });

  test("unknown sponsored availability still offers the spot and never invents a count", async ({ page }) => {
    await open(page, "sponsored-unknown");

    // The sponsored product came back unreadable. The snapshot still projects
    // - the unknown product costs the other two nothing - the sold cards still
    // render, and the row still asks, because a reader can always ask for the
    // spot. What it will not do is claim a vacancy, a price or a count nobody
    // could read.
    await expect(page.getByTestId("discovery-featured-card")).toHaveCount(1);
    await expect(page.getByTestId("discovery-sponsored-card")).toHaveCount(1);
    const inFeed = page.getByTestId("catalog-slot-row");
    await expect(inFeed).toHaveCount(1);
    await expect(inFeed).toHaveAttribute("data-state", "unconfirmed");
    await expect(inFeed.getByRole("link", { name: "Get this spot" })).toBeVisible();
    await expect(inFeed).not.toContainText("open.");
    await expect(inFeed).not.toContainText("$");
    await expect(page.getByTestId("extensions-surface")).not.toContainText("of 4 open.");
  });
});
