import { expect, test, type Page } from "@playwright/test";

import {
  defaultSettingsPayload,
  emptyInventoryPayload,
  emptyPoliciesPayload,
  emptyReceiptsPayload,
  freeStateSnapshot,
} from "./fixture-states";

const DAEMON = "guardDaemon=http://127.0.0.1:4175";
const catalogDigest = "a".repeat(64);
const catalog = { schema_version: "1.0.0", catalog_digest: catalogDigest, extensions: [] };
const authority = (health: "tampered" | "protected" | "unenrolled") => ({
  schema_version: "1.0.0",
  health,
  revision: health === "protected" ? 0 : 4,
  catalog_digest: catalogDigest,
  global_lockdown: false,
  controls: [],
  layers: [],
  failures: health === "tampered" ? [{ code: "snapshot_missing", detail: "Authority snapshot is missing." }] : [],
});

async function mountRecoveryFixture(page: Page, setup?: {
  configured: boolean;
  enabled: boolean;
  failSettings: boolean;
}): Promise<void> {
  let repaired = false;
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path.endsWith("/settings") && setup?.failSettings) {
      await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: "unavailable" }) });
      return;
    }
    let body: unknown = {};
    if (path.endsWith("/initialize")) body = { auth_token: "e2e-extension-token" };
    else if (path.endsWith("/runtime")) body = freeStateSnapshot;
    else if (path.endsWith("/requests")) body = { items: [], next_cursor: null, total_pending_count: 0, total_count: 0, status: "pending" };
    else if (path.endsWith("/receipts")) body = emptyReceiptsPayload;
    else if (path.endsWith("/policy")) body = emptyPoliciesPayload;
    else if (path.endsWith("/settings")) body = {
      ...defaultSettingsPayload,
      settings: {
        ...defaultSettingsPayload.settings,
        approval_gate: {
          ...defaultSettingsPayload.settings.approval_gate,
          enabled: setup?.enabled ?? true,
          configured: setup?.configured ?? true,
          totp_enabled: true,
        },
      },
    };
    else if (path.endsWith("/inventory")) body = emptyInventoryPayload;
    else if (path.endsWith("/extension-controls/catalog")) body = catalog;
    else if (path.endsWith("/extension-controls/effective")) {
      const recoveryHealth = repaired ? "protected" : "tampered";
      body = authority(setup ? "unenrolled" : recoveryHealth);
    }
    else if (path.endsWith("/extension-controls/recover-authority")) {
      const payload = request.postDataJSON() as { approval_totp_code?: string };
      if (!payload.approval_totp_code) {
        await route.fulfill({ status: 403, contentType: "application/json", body: JSON.stringify({ error: "approval_gate_required" }) });
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 250));
      repaired = true;
      body = authority("protected");
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
}

for (const configured of [false, true]) {
  test(`enrollment routes ${configured ? "disabled" : "unconfigured"} approval to settings`, async ({ page }) => {
    const runtimeErrors: string[] = [];
    page.on("pageerror", (error) => runtimeErrors.push(error.message));
    await mountRecoveryFixture(page, { configured, enabled: false, failSettings: false });
    await page.goto(`/extensions?${DAEMON}`);
    await expect(page.getByRole("heading", { name: "Set up local approval before enrollment" })).toBeVisible();
    await expect(page.getByText("hol-guard command controls enroll", { exact: true })).toHaveCount(0);
    await page.getByRole("button", { name: "Set up approval", exact: true }).click();
    await expect(page).toHaveURL(/\/settings\?.*section=approval/);
    await expect(runtimeErrors).toEqual([]);
  });
}

test("enrollment waits for approval lookup and refreshes on Check again", async ({ page }) => {
  const setup = { configured: true, enabled: true, failSettings: true };
  await mountRecoveryFixture(page, setup);
  await page.goto(`/extensions?${DAEMON}`);
  await expect(page.getByRole("heading", { name: "Checking approval setup" })).toBeVisible();
  await expect(page.getByText("hol-guard command controls enroll", { exact: true })).toHaveCount(0);
  setup.failSettings = false;
  await page.getByRole("button", { name: "Check again", exact: true }).click();
  await expect(page.getByRole("button", { name: "Copy setup command", exact: true })).toBeVisible();
});

test("authenticated extension recovery shows progress and reaches protected state", async ({ page }) => {
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  await mountRecoveryFixture(page);

  await page.goto(`/extensions?${DAEMON}`);
  await page.getByRole("button", { name: "Repair now" }).click();
  await expect(page.getByRole("dialog", { name: "Repair extension controls" })).toBeVisible();
  await page.getByLabel("Authenticator code").fill("123456");
  await page.getByRole("button", { name: "Repair controls" }).click();
  await expect(
    page.getByRole("dialog", { name: "Repair extension controls" }).getByRole("button", { name: "Repairing…" }),
  ).toBeDisabled();
  await expect(page.getByText("Protected authority")).toBeVisible();
  await expect(runtimeErrors).toEqual([]);
});
