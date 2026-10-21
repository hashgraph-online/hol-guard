import { daemonApi, expect, expectNoErrorBoundary, test } from "./fixtures";

type RuntimeFeed = {
  cloud_state: string;
  cloud_state_label: string;
  cloud_state_detail: string;
  cloud_sync_health: { label: string; detail: string };
  latest_receipts: Array<{ timestamp: string }>;
};

test.describe("Feed Health against the live daemon", () => {
  test("shows the source mode, daemon status and cloud sync health the daemon reports", async ({ page, state }) => {
    const runtime = await daemonApi<RuntimeFeed>(state, "/v1/runtime");
    await page.goto("/feed-health");
    await expect(page.getByRole("heading", { level: 1, name: "Feed Health", exact: true })).toBeVisible();
    await expectNoErrorBoundary(page);
    await expect(page.getByRole("tab", { name: "Feed Health", exact: true })).toHaveAttribute("aria-selected", "true");

    // Nothing in the integration home pairs with Guard Cloud, so the feed is
    // the bundled sample and the page says so.
    expect(runtime.cloud_state).toBe("local_only");
    await expect(page.getByText("Sample only (local-only mode)", { exact: true })).toBeVisible();
    const alert = page.getByRole("alert").filter({ hasText: "Sample intel only" });
    await expect(alert).toContainText("Guard is running in local-only mode.");

    const card = (label: string) => page.getByText(label, { exact: true }).locator("xpath=../..");
    await expect(card("Daemon status")).toContainText("Running");
    await expect(card("Daemon status")).toContainText("Guard daemon is active and processing.");
    await expect(card("Cloud sync")).toContainText(runtime.cloud_state_label);
    await expect(card("Cloud sync")).toContainText(runtime.cloud_state_detail);
    // The seeds record decisions moments ago, so the feed counts as fresh.
    expect(runtime.latest_receipts.length).toBeGreaterThan(0);
    await expect(card("Feed freshness")).toContainText("Fresh");
    await expect(card("Last activity")).toContainText("Most recent action processed by Guard.");

    await expect(page.getByText("Cloud sync health", { exact: true })).toBeVisible();
    await expect(page.getByText(runtime.cloud_sync_health.detail, { exact: true })).toBeVisible();
    await expect(page.getByText(runtime.cloud_sync_health.label, { exact: true })).toBeVisible();
  });

  test("settings shortcuts open Settings", async ({ page }) => {
    await page.goto("/feed-health");
    await expect(page.getByRole("heading", { level: 1, name: "Feed Health", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Open Settings", exact: true }).click();
    await expect.poll(() => new URL(page.url()).pathname).toBe("/settings");
    await page.goBack();
    await expect(page.getByRole("heading", { level: 1, name: "Feed Health", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Connect to cloud", exact: true }).click();
    await expect.poll(() => new URL(page.url()).pathname).toBe("/settings");
  });
});
