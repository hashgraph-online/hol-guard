import { expect, test } from "@playwright/test";

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const origin = requiredEnvironment("GUARD_INSTALLED_ORIGIN");
const session = requiredEnvironment("GUARD_INSTALLED_DASHBOARD_SESSION");
const expectedCount = Number(requiredEnvironment("GUARD_INSTALLED_ACTIVITY_COUNT"));
if (!Number.isInteger(expectedCount) || expectedCount < 1) throw new Error("GUARD_INSTALLED_ACTIVITY_COUNT must be positive");

function dashboardUrl(): string {
  const fragment = new URLSearchParams({
    "guard-token": session,
    guardDaemon: origin,
  });
  return `/evidence?view=commands#${fragment.toString()}`;
}

test("installed dashboard reconciles command analytics, filters, details, health, and feedback", async ({ page }, testInfo) => {
  const commandResponses: { path: string; status: number }[] = [];
  page.on("response", (response) => {
    const url = new URL(response.url());
    if (url.pathname.startsWith("/v1/command-activity")) {
      commandResponses.push({ path: url.pathname, status: response.status() });
    }
  });

  await page.goto(dashboardUrl());
  await expect(page.getByRole("heading", { name: "Commands" })).toBeVisible();
  const summary = page.getByLabel("Command activity summary");
  await expect(summary.getByText("Commands checked").locator("..").getByText(String(expectedCount), { exact: true })).toBeVisible();
  await expect(summary.getByText("Post-proof coverage")).toBeVisible();
  await expect(page.getByText("This view includes correlated post-execution evidence on this page.")).toBeVisible();
  await expect(page.getByText("Command activity evidence is degraded. Counts may be incomplete.")).toHaveCount(0);
  await expect(page.getByLabel("Command activity records").getByRole("row")).toHaveCount(expectedCount + 1);
  await page.screenshot({ path: testInfo.outputPath("installed-command-activity-overview.png"), fullPage: true });

  await page.getByRole("combobox", { name: "App", exact: true }).selectOption("cursor");
  await expect(page.getByText("1 records on this page", { exact: true })).toBeVisible();
  const cursorTable = page.getByLabel("Command activity records");
  await expect(cursorTable.getByRole("cell", { name: "cursor", exact: true })).toBeVisible();
  await expect(cursorTable.getByRole("cell", { name: "Prevented before execution", exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("installed-command-activity-filtered.png"), fullPage: true });

  await page.getByRole("combobox", { name: "App", exact: true }).selectOption("");
  await expect(page.getByText(`${expectedCount} records on this page`, { exact: true })).toBeVisible();
  const confirmedRow = page.getByRole("row").filter({ hasText: "Execution confirmed successful" });
  await expect(confirmedRow).toHaveCount(1);
  await confirmedRow.getByRole("button", { name: "Details" }).click();
  const detail = page.getByRole("complementary", { name: "Command activity detail" });
  await expect(detail).toBeFocused();
  await expect(detail.getByText("Execution proof").locator("..").getByText("Execution confirmed successful")).toBeVisible();
  await expect(detail.getByText("Proof source").locator("..").getByText("Post-execution proof recorded")).toBeVisible();
  await expect(detail.getByText("No review prompt recorded")).toBeVisible();
  await detail.getByRole("button", { name: "Should not have interrupted" }).click();
  await expect(detail.getByText("Feedback saved to local evidence.")).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("installed-command-activity-detail-feedback.png"), fullPage: true });

  await expect.poll(() => commandResponses.length).toBeGreaterThan(2);
  expect(commandResponses.every((response) => response.status >= 200 && response.status < 300)).toBe(true);
});
