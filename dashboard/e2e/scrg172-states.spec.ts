import { test, expect } from "@playwright/test";
import { resolve } from "node:path";
import {
  freeStateSnapshot,
  paidStateSnapshot,
  degradedStateSnapshot,
  emptyReceiptsPayload,
  emptyPoliciesPayload,
  emptyInventoryPayload,
  defaultSettingsPayload,
} from "./fixture-states";
import { resolveProofDir } from "./proof-dir";

const PROOF_DIR = resolveProofDir();

type FixtureState = "free" | "paid" | "degraded";

const FIXTURE_SNAPSHOTS = {
  free: freeStateSnapshot,
  paid: paidStateSnapshot,
  degraded: degradedStateSnapshot,
} as const;

const DAEMON_PARAM = "?guardDaemon=http://127.0.0.1:4175";

async function mountFixtureState(
  page: Parameters<Parameters<typeof test>[1]>[0]["page"],
  state: FixtureState,
) {
  const snapshot = FIXTURE_SNAPSHOTS[state];

  await page.route("**/v1/**", (route) => {
    const url = route.request().url();
    const path = new URL(url).pathname;

    if (path.includes("/initialize")) {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ auth_token: `e2e-token-${state}` }),
      });
    } else if (path.includes("/runtime")) {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(snapshot),
      });
    } else if (path.includes("/receipts")) {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(emptyReceiptsPayload),
      });
    } else if (path.includes("/policy")) {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(emptyPoliciesPayload),
      });
    } else if (path.includes("/settings")) {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(defaultSettingsPayload),
      });
    } else if (path.includes("/inventory")) {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(emptyInventoryPayload),
      });
    } else {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({}),
      });
    }
  });
}

test.describe("SCRG172: Dashboard renders paid/free/degraded states", () => {
  test("SCRG172-A: free state (local_only) — home view renders correctly", async ({ page }) => {
    await mountFixtureState(page, "free");
    await page.goto(`/${DAEMON_PARAM}`);
    await page.waitForLoadState("networkidle");
    await page.waitForSelector("#main-content", { state: "visible" });

    await page.screenshot({
      path: resolve(PROOF_DIR, "scrg172-free-home.png"),
      fullPage: true,
    });

    await expect(page).toHaveTitle(/Guard/i);
    await expect(page.locator("#main-content")).toBeVisible();
  });

  test("SCRG172-B: paid state (paired_active) — home view renders correctly", async ({ page }) => {
    await mountFixtureState(page, "paid");
    await page.goto(`/${DAEMON_PARAM}`);
    await page.waitForLoadState("networkidle");
    await page.waitForSelector("#main-content", { state: "visible" });

    await page.screenshot({
      path: resolve(PROOF_DIR, "scrg172-paid-home.png"),
      fullPage: true,
    });

    await expect(page).toHaveTitle(/Guard/i);
    await expect(page.locator("#main-content")).toBeVisible();
  });

  test("SCRG172-C: degraded state (paired_waiting/degraded) — home view renders correctly", async ({
    page,
  }) => {
    await mountFixtureState(page, "degraded");
    await page.goto(`/${DAEMON_PARAM}`);
    await page.waitForLoadState("networkidle");
    await page.waitForSelector("#main-content", { state: "visible" });

    await page.screenshot({
      path: resolve(PROOF_DIR, "scrg172-degraded-home.png"),
      fullPage: true,
    });

    await expect(page).toHaveTitle(/Guard/i);
    await expect(page.locator("#main-content")).toBeVisible();
  });

  test("SCRG172-D: free state — /supply-chain route renders", async ({ page }) => {
    await mountFixtureState(page, "free");
    await page.goto(`/supply-chain${DAEMON_PARAM}`);
    await page.waitForLoadState("networkidle");
    await page.waitForSelector("#main-content", { state: "visible" });

    await page.screenshot({
      path: resolve(PROOF_DIR, "scrg172-free-supply-chain.png"),
      fullPage: true,
    });

    await expect(page.locator("#main-content")).toBeVisible();
  });

  test("SCRG172-E: paid state — /audit route renders", async ({ page }) => {
    await mountFixtureState(page, "paid");
    await page.goto(`/audit${DAEMON_PARAM}`);
    await page.waitForLoadState("networkidle");
    await page.waitForSelector("#main-content", { state: "visible" });

    await page.screenshot({
      path: resolve(PROOF_DIR, "scrg172-paid-audit.png"),
      fullPage: true,
    });

    await expect(page.locator("#main-content")).toBeVisible();
  });

  test("SCRG172-F: degraded state — /feed-health route renders", async ({ page }) => {
    await mountFixtureState(page, "degraded");
    await page.goto(`/feed-health${DAEMON_PARAM}`);
    await page.waitForLoadState("networkidle");
    await page.waitForSelector("#main-content", { state: "visible" });

    await page.screenshot({
      path: resolve(PROOF_DIR, "scrg172-degraded-feed-health.png"),
      fullPage: true,
    });

    await expect(page.locator("#main-content")).toBeVisible();
  });

  test("SCRG172-G: free state — /policy route renders", async ({ page }) => {
    await mountFixtureState(page, "free");
    await page.goto(`/policy${DAEMON_PARAM}`);
    await page.waitForLoadState("networkidle");
    await page.waitForSelector("#main-content", { state: "visible" });

    await page.screenshot({
      path: resolve(PROOF_DIR, "scrg172-free-policy.png"),
      fullPage: true,
    });

    await expect(page.locator("#main-content")).toBeVisible();
  });
});
