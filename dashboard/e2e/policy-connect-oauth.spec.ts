import { expect, test, type Page } from "@playwright/test";

import {
  defaultSettingsPayload,
  emptyInventoryPayload,
  emptyPoliciesPayload,
  emptyReceiptsPayload,
  freeStateSnapshot,
} from "./fixture-states";

const DAEMON_ORIGIN = "http://127.0.0.1:4175";

const localOnlySnapshot = {
  ...freeStateSnapshot,
  connect_url: "https://hol.org/guard/connect",
};

async function mount(page: Page) {
  await page.route("**/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path.endsWith("/initialize")) body = { auth_token: "fixture-session-token" };
    else if (path.endsWith("/runtime")) body = localOnlySnapshot;
    else if (path.endsWith("/requests")) body = { items: [], next_cursor: null, total_pending_count: 0, total_count: 0, status: "pending" };
    else if (path.endsWith("/receipts")) body = emptyReceiptsPayload;
    else if (path.endsWith("/policy")) body = emptyPoliciesPayload;
    else if (path.endsWith("/settings")) body = defaultSettingsPayload;
    else if (path.endsWith("/inventory")) body = emptyInventoryPayload;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
}

test("policy exceptions connect action starts the daemon OAuth flow", async ({ page }) => {
  await mount(page);
  let postStarts = 0;
  let connected = false;
  await page.route("**/v1/cloud/connect", async (route) => {
    if (route.request().method() === "POST") {
      postStarts += 1;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          connect_required: true,
          connect_flow: {
            state: "running",
            title: "Connect Guard Cloud",
            detail: "Complete sign-in.",
            action_label: "Connect Guard Cloud",
            connect_url: "https://hol.org/guard/connect",
            authorize_url: "https://example.test/authorize",
            browser_opened: true,
            request_id: "request-1",
            poll_after_ms: 100,
          },
        }),
      });
      return;
    }
    connected = true;
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        connect_required: false,
        connect_flow: null,
        dashboard_url: "https://hol.org/guard",
      }),
    });
  });

  await page.goto(`/policy?guardDaemon=${DAEMON_ORIGIN}`);
  await page.getByRole("tab", { name: "Cloud exceptions" }).click();
  const connectButton = page.getByRole("button", { name: "Connect Guard Cloud" });
  await expect(connectButton).toBeVisible();
  expect(await page.locator('a[href="https://hol.org/guard/connect"]').count()).toBe(0);

  await connectButton.click();
  await expect
    .poll(() => postStarts, { message: "clicking connect must POST /v1/cloud/connect" })
    .toBeGreaterThan(0);
  await expect
    .poll(() => connected, { message: "the flow must poll connection status until it lands" })
    .toBe(true);
  await expect(page.getByRole("button", { name: "Guard Cloud connected" })).toBeVisible();
});
