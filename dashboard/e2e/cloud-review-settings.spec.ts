import { expect, test, type Page } from "@playwright/test";
import { defaultSettingsPayload, emptyInventoryPayload, emptyPoliciesPayload, emptyReceiptsPayload, freeStateSnapshot } from "./fixture-states";

async function fixture(page: Page, held = 0, gatePatch: Record<string, unknown> = {}) {
  let enabled = false;
  let rejectMessage: string | null = null;
  let lastSyncedAt: string | null = null;
  const writes: Record<string, unknown>[] = [];
  const gate = {
    enabled: true, configured: true, cooldown_seconds: 0, cooldown_active: false,
    cooldown_expires_at: null, locked_until: null, fail_closed: false,
    strict_all_decisions: false, totp_enabled: true, totp_pending: false,
    ...gatePatch,
  };
  await page.route("**/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path.endsWith("/initialize")) body = { auth_token: "test-session" };
    else if (path === "/v1/runtime") body = freeStateSnapshot;
    else if (path === "/v1/requests") body = { items: [], next_cursor: null, total_pending_count: 0, total_count: 0 };
    else if (path === "/v1/receipts") body = emptyReceiptsPayload;
    else if (path === "/v1/policy") body = emptyPoliciesPayload;
    else if (path === "/v1/inventory") body = emptyInventoryPayload;
    else if (path === "/v1/settings") body = { ...defaultSettingsPayload, settings: { ...defaultSettingsPayload.settings, sync: true, approval_gate: gate } };
    else if (path === "/v1/cloud-review") {
      if (route.request().method() === "POST") {
        const input = route.request().postDataJSON();
        writes.push(input);
        if (rejectMessage) {
          await route.fulfill({ status: 403, json: { message: rejectMessage } });
          return;
        }
        enabled = input.action === "enable";
        if (input.include_held_requests) held = 0;
      }
      body = {
        enabled, connected: true, reason: enabled ? null : "cloud_review_capability_missing",
        workspace_id: "workspace-1", source: "default", pending_uploads: 0, held_events: held, isolated_events: held,
        expires_at: enabled ? "2099-01-01T00:00:00Z" : null,
        delivery_state: "healthy", last_synced_at: lastSyncedAt, approval_gate: gate,
      };
    }
    await route.fulfill({ status: 200, json: body });
  });
  await page.goto("/settings?guardDaemon=http://127.0.0.1:4175");
  return {
    writes,
    reject: () => { rejectMessage = "Authenticator code was not accepted. Try again."; },
    rejectWith: (message: string) => { rejectMessage = message; },
    updateDevice: (authorized: boolean, deliveredAt: string | null) => {
      enabled = authorized;
      lastSyncedAt = deliveredAt;
    },
  };
}

for (const viewport of [{ width: 1365, height: 900 }, { width: 390, height: 844 }]) {
  test(`Cloud Review consent survives reload at ${viewport.width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize(viewport);
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const state = await fixture(page, 527);
    const section = page.getByRole("region", { name: "Cloud Review", exact: true });
    await expect(section).toContainText("Cloud decisions still need");
    await section.getByRole("button", { name: "Enable Cloud Review" }).click();
    const dialog = page.getByRole("dialog", { name: "Authorize Cloud Review" });
    await expect(dialog.getByRole("button", { name: "Authorize this device" })).toBeDisabled();
    await expect(dialog.getByRole("checkbox")).not.toBeChecked();
    await dialog.getByRole("checkbox").check();
    await dialog.getByLabel("Authenticator code").fill("123456");
    await dialog.screenshot({ path: testInfo.outputPath(`cloud-review-consent-${viewport.width}.png`) });
    await dialog.getByRole("button", { name: "Authorize this device" }).click();
    await expect(dialog).not.toBeVisible();
    expect(state.writes).toHaveLength(1);
    expect(state.writes[0]).toMatchObject({ action: "enable", confirm: "cloud-review.enable", source: "default", workspace_id: "workspace-1", include_held_requests: true, approval_totp_code: "123456" });
    await page.reload();
    await expect(section).toContainText("Cloud Review is enabled for this device");
    await expect(section.getByRole("button", { name: "Enable Cloud Review" })).toHaveCount(0);
    await section.screenshot({ path: testInfo.outputPath(`cloud-review-enabled-${viewport.width}.png`) });
    expect(errors).toEqual([]);
  });
}

test("rejected MFA keeps recovery inline and does not claim success", async ({ page }) => {
  const state = await fixture(page);
  state.reject();
  await page.getByRole("button", { name: "Enable Cloud Review" }).click();
  const dialog = page.getByRole("dialog", { name: "Authorize Cloud Review" });
  await dialog.getByLabel("Authenticator code").fill("123456");
  await dialog.getByRole("button", { name: "Authorize this device" }).click();
  await expect(dialog.getByRole("alert")).toContainText("Authenticator code was not accepted");
  await expect(dialog.getByLabel("Authenticator code")).toHaveValue("");
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByRole("button", { name: "Enable Cloud Review" })).toBeVisible();
});

test("device authorization and delivery refresh without a reload or settings write", async ({ page }) => {
  const state = await fixture(page);
  const section = page.getByRole("region", { name: "Cloud Review", exact: true });
  await expect(section).toContainText("Confirmation needed");
  await expect(section).toContainText("Not recorded yet");
  state.updateDevice(true, "2026-09-12T15:00:00Z");
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(section).toContainText("Cloud Review is enabled for this device");
  await expect(section).not.toContainText("Not recorded yet");
  state.updateDevice(false, "2026-09-12T15:00:00Z");
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(section).toContainText("Confirmation needed");
  expect(state.writes).toEqual([]);
});

test("an older background failure cannot dismiss an open authorization dialog", async ({ page }) => {
  const state = await fixture(page);
  const section = page.getByRole("region", { name: "Cloud Review", exact: true });
  await expect(section.getByRole("button", { name: "Enable Cloud Review" })).toBeVisible();
  let release = () => {};
  const paused = new Promise<void>((resolve) => { release = resolve; });
  await page.route("**/v1/cloud-review", async (route) => {
    if (route.request().method() !== "GET") return route.fallback();
    await paused;
    await route.fulfill({ status: 503, json: { message: "Temporarily unavailable" } });
  });
  const reading = page.waitForRequest((request) => request.url().endsWith("/v1/cloud-review"));
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await reading;
  await section.getByRole("button", { name: "Enable Cloud Review" }).click();
  const dialog = page.getByRole("dialog", { name: "Authorize Cloud Review" });
  await dialog.getByLabel("Authenticator code").fill("123456");
  const finished = page.waitForResponse((response) => response.status() === 503);
  release();
  await finished;
  await expect(dialog).toBeVisible();
  await expect(dialog.getByLabel("Authenticator code")).toHaveValue("123456");
  expect(state.writes).toEqual([]);
});

test("a recent authenticator confirmation still shows the code field", async ({ page }) => {
  const state = await fixture(page, 0, { totp_recent_satisfied: true });
  state.rejectWith("TOTP code is required.");
  await page.getByRole("button", { name: "Enable Cloud Review" }).click();
  const dialog = page.getByRole("dialog", { name: "Authorize Cloud Review" });
  await expect(dialog.getByText("A new code is not needed yet")).toHaveCount(0);
  const code = dialog.getByLabel("Authenticator code");
  await expect(code).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Authorize this device" })).toBeDisabled();
  await code.fill("12345");
  await expect(dialog.getByRole("button", { name: "Authorize this device" })).toBeDisabled();
  await code.fill("654321");
  await dialog.getByRole("button", { name: "Authorize this device" }).click();
  await expect(dialog.getByRole("alert")).toHaveText("Enter the current six-digit code from your authenticator.");
  await expect(code).toBeVisible();
  await expect(code).toHaveValue("");
  expect(state.writes[0]).toMatchObject({ approval_totp_code: "654321" });
});
