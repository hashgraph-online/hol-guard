import { test, expect, type Page } from "@playwright/test";
import {
  freeStateSnapshot,
  paidStateSnapshot,
  connectedCloudExceptionsPayload,
  ackFailureCloudExceptionsPayload,
  pendingCloudExceptionRequestsPayload,
  emptyReceiptsPayload,
  emptyInventoryPayload,
  defaultSettingsPayload,
} from "./fixture-states";

const DAEMON_PARAM = "?guardDaemon=http://127.0.0.1:4175";

async function mountPolicyCloudRoute(
  page: Page,
  snapshot: typeof paidStateSnapshot,
  cloudExceptions: typeof connectedCloudExceptionsPayload,
) {
  await page.route("**/v1/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.includes("/initialize")) {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ auth_token: "e2e-token-policy" }),
      });
      return;
    }
    if (path.includes("/runtime")) {
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(snapshot) });
      return;
    }
    if (path.includes("/policy/cloud-exception-requests")) {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(pendingCloudExceptionRequestsPayload),
      });
      return;
    }
    if (path.includes("/policy/cloud-exceptions") || path.endsWith("/policy")) {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(cloudExceptions),
      });
      return;
    }
    if (path.includes("/receipts")) {
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(emptyReceiptsPayload) });
      return;
    }
    if (path.includes("/settings")) {
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(defaultSettingsPayload) });
      return;
    }
    if (path.includes("/inventory")) {
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(emptyInventoryPayload) });
      return;
    }
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({}) });
  });
}

test.describe("Policy cloud exceptions states", () => {
  test("connected cloud shows synced exception groups", async ({ page }) => {
    await mountPolicyCloudRoute(page, paidStateSnapshot, connectedCloudExceptionsPayload);
    await page.goto(`/policy${DAEMON_PARAM}`);
    await page.getByRole("tab", { name: "Cloud exceptions" }).click();
    await expect(page.getByText("Active on this device")).toBeVisible();
    await expect(page.getByText("codex:project:e2e-active")).toBeVisible();
  });

  test("disconnected cloud shows honest offline state", async ({ page }) => {
    await mountPolicyCloudRoute(page, freeStateSnapshot, { items: [] });
    await page.goto(`/policy${DAEMON_PARAM}`);
    await page.getByRole("tab", { name: "Cloud exceptions" }).click();
    await expect(page.getByText("Guard Cloud is not connected")).toBeVisible();
  });

  test("ack failure surfaces in exception detail", async ({ page }) => {
    await mountPolicyCloudRoute(page, paidStateSnapshot, ackFailureCloudExceptionsPayload);
    await page.goto(`/policy${DAEMON_PARAM}`);
    await page.getByRole("tab", { name: "Cloud exceptions" }).click();
    await page.getByText("codex:project:e2e-failed").click();
    await expect(page.getByText("Ack failed")).toBeVisible();
  });
});
