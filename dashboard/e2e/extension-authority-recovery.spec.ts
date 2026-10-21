import { expect, test, type Page } from "@playwright/test";

import {
  defaultSettingsPayload,
  emptyInventoryPayload,
  emptyPoliciesPayload,
  emptyReceiptsPayload,
  freeStateSnapshot,
} from "./fixture-states";
import { routeCatalogV2, type CatalogFixture } from "./extension-control-fixtures";

const DAEMON = "guardDaemon=http://127.0.0.1:4175";
const catalogDigest = "a".repeat(64);
const catalog = { schema_version: "1.0.0", catalog_digest: catalogDigest, extensions: [] };
const emptyLocalCliList = {
  schema_version: "guard.daemon.local-clis.v1",
  revision: 0,
  items: [],
  cloud: { sync_local_only: true, summary: "This device only." },
};
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
  failRecovery?: boolean;
  initialHealth?: "tampered" | "unenrolled";
}): Promise<{ settingsUpdates: Record<string, unknown>[] }> {
  let repaired = false;
  let configured = setup?.configured ?? true;
  let enabled = setup?.enabled ?? true;
  const settingsUpdates: Record<string, unknown>[] = [];
  await routeCatalogV2(page, () => catalog as unknown as CatalogFixture);
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path.endsWith("/settings") && setup?.failSettings) {
      await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: "unavailable" }) });
      return;
    }
    if (path.endsWith("/settings") && request.method() === "POST") {
      const update = request.postDataJSON() as { settings: { approval_gate: { enabled: boolean } } };
      settingsUpdates.push(update.settings);
      configured = true;
      enabled = update.settings.approval_gate.enabled;
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
          enabled,
          configured,
          totp_enabled: setup ? setup.configured : true,
        },
      },
    };
    else if (path.endsWith("/inventory")) body = emptyInventoryPayload;
    else if (path.endsWith("/local-clis") || path.endsWith("/local-clis/discover")) body = emptyLocalCliList;
    else if (path.endsWith("/extension-controls/catalog")) body = catalog;
    else if (path.endsWith("/extension-controls/effective")) {
      const recoveryHealth = repaired ? "protected" : "tampered";
      // Configured fixtures start unenrolled unless a failure scenario must expose tampered state.
      const initialHealth = setup?.initialHealth ?? (setup ? "unenrolled" : recoveryHealth);
      body = authority(initialHealth);
    }
    else if (path.endsWith("/extension-controls/recover-authority")) {
      const payload = request.postDataJSON() as { approval_totp_code?: string };
      if (!payload.approval_totp_code) {
        await route.fulfill({ status: 403, contentType: "application/json", body: JSON.stringify({ error: "approval_gate_required" }) });
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 250));
      if (setup?.failRecovery) {
        await route.fulfill({
          status: 503,
          contentType: "application/json",
          body: JSON.stringify({ error: "authority_recovery_failed" }),
        });
        return;
      }
      repaired = true;
      body = authority("protected");
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
  return { settingsUpdates };
}

for (const width of [1280, 390]) {
for (const configured of [false, true]) {
  test(`local approval setup completes with ${configured ? "disabled" : "unconfigured"} approval at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 800 });
    await page.emulateMedia({ reducedMotion: "reduce" });
    const runtimeErrors: string[] = [];
    page.on("pageerror", (error) => runtimeErrors.push(error.message));
    const fixture = await mountRecoveryFixture(page, { configured, enabled: false, failSettings: false });
    await page.goto(`/extensions?${DAEMON}`);
    await expect(page.getByRole("heading", { name: configured ? "Local approval is off" : "Set up local approval" })).toBeVisible();
    await expect(page.getByText(/Guard Cloud is not required/)).toBeVisible();
    await expect(page.getByRole("button", { name: "Check again", exact: true })).toHaveCount(0);
    await expect(page.getByText("hol-guard command controls enroll", { exact: true })).toHaveCount(0);
    await page.getByRole("button", { name: "Open approval settings", exact: true }).click();
    await expect(page).toHaveURL(/\/settings\?.*section=approval/);
    await expect(page.getByRole("button", { name: "Set up approval password", exact: true })).toBeInViewport();
    await expect(page.getByRole("region", { name: "Local approval setup" })).toBeFocused();
    await page.screenshot({ path: testInfo.outputPath("local-approval.png"), animations: "disabled" });
    expect(fixture.settingsUpdates).toHaveLength(0);
    await page.getByRole("button", { name: "Set up approval password", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Set your approval password" });
    await dialog.getByLabel("Password", { exact: true }).fill("synthetic-approval-password");
    await dialog.getByLabel("Confirm password", { exact: true }).fill("synthetic-approval-password");
    await dialog.getByLabel("Confirm password", { exact: true }).press("Enter");
    await expect(dialog).toBeHidden();
    expect(fixture.settingsUpdates).toHaveLength(1);
    expect(Object.keys(fixture.settingsUpdates[0])).toEqual(["approval_gate"]);
    expect(fixture.settingsUpdates[0].approval_gate).toMatchObject({ enabled: true, new_password: "synthetic-approval-password" });
    await expect(page.getByText("Local approval is ready. Return to Extensions to finish setup.")).toBeVisible();
    await page.getByRole("button", { name: "Back to Extensions", exact: true }).click();
    await expect(page).toHaveURL(/\/extensions(?:\?|$)/);
    await expect(page.getByRole("button", { name: "Copy setup command", exact: true })).toBeVisible();
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.getByRole("button", { name: "Copy setup command", exact: true }).click();
    await expect(page.getByRole("button", { name: "Command copied", exact: true })).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("hol-guard command controls enroll");
    await expect(runtimeErrors).toEqual([]);
  });
}
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

test("approval setup cancellation and unsaved changes keep a clear return path", async ({ page }) => {
  const fixture = await mountRecoveryFixture(page, { configured: false, enabled: false, failSettings: false });
  await page.goto(`/extensions?${DAEMON}`);
  await page.getByRole("button", { name: "Open approval settings", exact: true }).click();
  await page.getByRole("button", { name: "Set up approval password", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Set your approval password" });
  await dialog.getByRole("button", { name: "Go back", exact: true }).click();
  await expect(page.getByRole("button", { name: "Back to Extensions", exact: true })).toBeEnabled();
  expect(fixture.settingsUpdates).toHaveLength(0);
  await page.getByRole("checkbox", { name: "Ask for proof on allow decisions", exact: true }).check();
  await expect(page.getByRole("button", { name: "Back to Extensions", exact: true })).toBeDisabled();
  await expect(page.getByText("Save your changes before returning to Extensions.")).toBeVisible();
  await page.getByRole("checkbox", { name: "Ask for proof on allow decisions", exact: true }).uncheck();
  await page.getByRole("button", { name: "Back to Extensions", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Set up local approval", exact: true })).toBeVisible();
  expect(fixture.settingsUpdates).toHaveLength(0);
});

test("recovery routes unconfigured approval to settings instead of asking for proof", async ({ page }) => {
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  await mountRecoveryFixture(page, {
    configured: false,
    enabled: false,
    failSettings: false,
    initialHealth: "tampered",
  });
  await page.goto(`/extensions?${DAEMON}`);
  await expect(page.getByRole("heading", { name: "Protection needs repair" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Repair protection", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Set up approval", exact: true }).click();
  await expect(page).toHaveURL(/\/settings\?.*section=approval/);
  await expect(runtimeErrors).toEqual([]);
});

test("authenticated extension recovery shows progress and reaches protected state", async ({ page }) => {
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  await mountRecoveryFixture(page);

  await page.goto(`/extensions?${DAEMON}`);
  await page.getByRole("button", { name: "Repair protection" }).click();
  await expect(page.getByRole("dialog", { name: "Repair protection" })).toBeVisible();
  await page.getByLabel("Authenticator code").fill("123456");
  await page.getByRole("dialog", { name: "Repair protection" }).getByRole("button", { name: "Repair protection" }).click();
  await expect(
    page.getByRole("dialog", { name: "Repair protection" }).getByRole("button", { name: "Repairing…" }),
  ).toBeDisabled();
  await expect(page.getByText("Local protection repaired and verified.")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Protection needs repair" })).toHaveCount(0);
  await expect(runtimeErrors).toEqual([]);
});

test("authenticator Enter submits the repair approval dialog", async ({ page }) => {
  await mountRecoveryFixture(page);
  await page.goto(`/extensions?${DAEMON}`);
  await page.getByRole("button", { name: "Repair protection" }).click();
  const dialog = page.getByRole("dialog", { name: "Repair protection" });
  await dialog.getByLabel("Authenticator code").fill("123456");
  await dialog.getByLabel("Authenticator code").press("Enter");
  await expect(page.getByText("Local protection repaired and verified.")).toBeVisible();
});

test("failed extension recovery keeps the repair banner and explains the failure", async ({ page }) => {
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  await mountRecoveryFixture(page, {
    configured: true,
    enabled: true,
    failSettings: false,
    failRecovery: true,
    initialHealth: "tampered",
  });

  await page.goto(`/extensions?${DAEMON}`);
  await page.getByRole("button", { name: "Repair protection" }).click();
  const dialog = page.getByRole("dialog", { name: "Repair protection" });
  await dialog.getByLabel("Authenticator code").fill("123456");
  await dialog.getByRole("button", { name: "Repair protection" }).click();
  await expect(dialog.getByRole("button", { name: "Repairing…" })).toBeDisabled();
  await expect(dialog.getByRole("alert")).toContainText("could not verify a fully protected state");
  await expect(page.getByRole("heading", { name: "Protection needs repair" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Repair protection" })).toHaveCount(2);
  await expect(page.getByText("Local protection repaired and verified.")).toHaveCount(0);
  await expect(runtimeErrors).toEqual([]);
});
