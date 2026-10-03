import { expect, test, type Page } from "@playwright/test";

import {
  defaultSettingsPayload,
  emptyInventoryPayload,
  emptyPoliciesPayload,
  emptyReceiptsPayload,
  freeStateSnapshot,
} from "./fixture-states";

const DAEMON = "guardDaemon=http://127.0.0.1:4175";
const gatedSettingsPayload = {
  ...defaultSettingsPayload,
  settings: {
    ...defaultSettingsPayload.settings,
    approval_gate: {
      enabled: true,
      configured: true,
      cooldown_seconds: 0,
      cooldown_active: false,
      cooldown_expires_at: null,
      locked_until: null,
      fail_closed: true,
      strict_all_decisions: false,
      totp_enabled: false,
      totp_pending: false,
    },
  },
};
const unconfiguredSettingsPayload = {
  ...gatedSettingsPayload,
  settings: {
    ...gatedSettingsPayload.settings,
    approval_gate: {
      ...gatedSettingsPayload.settings.approval_gate,
      configured: false,
    },
  },
};
const disabledUnconfiguredSettingsPayload = {
  ...gatedSettingsPayload,
  settings: {
    ...gatedSettingsPayload.settings,
    approval_gate: {
      ...gatedSettingsPayload.settings.approval_gate,
      enabled: false,
      configured: false,
    },
  },
};

async function mountSettingsFixture(page: Page, settingsPayload = gatedSettingsPayload, persistWrites = false): Promise<{ settingsUpdates: Record<string, unknown>[] }> {
  const settingsUpdates: Record<string, unknown>[] = [];
  await page.route("**/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path.endsWith("/initialize")) body = { auth_token: "e2e-settings-token" };
    else if (path.endsWith("/runtime")) body = freeStateSnapshot;
    else if (path.endsWith("/requests")) {
      body = { items: [], next_cursor: null, total_pending_count: 0, total_count: 0, status: "pending" };
    } else if (path.endsWith("/receipts")) body = emptyReceiptsPayload;
    else if (path.endsWith("/policy")) body = emptyPoliciesPayload;
    else if (path.endsWith("/settings")) {
      if (route.request().method() === "POST") {
        settingsUpdates.push(JSON.parse(route.request().postData() ?? "{}") as Record<string, unknown>);
        if (persistWrites) {
          settingsPayload = { ...settingsPayload, settings: { ...settingsPayload.settings, ...settingsUpdates.at(-1)?.settings as object } };
        }
      }
      body = settingsPayload;
    }
    else if (path.endsWith("/approval-gate/totp/enroll")) {
      body = {
        ...gatedSettingsPayload,
        settings: {
          ...gatedSettingsPayload.settings,
          approval_gate: {
            ...gatedSettingsPayload.settings.approval_gate,
            totp_pending: true,
          },
        },
        enrollment: {
          manual_key: "TESTSECRET123456",
          otpauth_uri:
            "otpauth://totp/HOL%20Guard:test-device?secret=TESTSECRET123456&issuer=HOL%20Guard",
          expires_at: "2099-01-01T00:00:00Z",
        },
      };
    }
    else if (path.endsWith("/inventory")) body = emptyInventoryPayload;
    else if (path.endsWith("/diff")) body = null;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
  return { settingsUpdates };
}

for (const width of [1365, 390]) {
  test(`blocked request radio controls work at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const { settingsUpdates } = await mountSettingsFixture(page, disabledUnconfiguredSettingsPayload, true);
    await page.goto(`/settings?${DAEMON}&section=approval`);
    const safe = page.getByRole("radio", { name: /Find a safe alternative/ });
    const ask = page.getByRole("radio", { name: /Ask me for approval/ });
    await expect(safe).toBeChecked();
    await safe.focus();
    await page.keyboard.press("ArrowDown");
    await expect(ask).toBeChecked();
    await page.getByRole("button", { name: "Save settings", exact: true }).click();
    await expect.poll(() => (settingsUpdates.at(-1)?.settings as Record<string, unknown>)?.blocked_request_mode).toBe("ask");
    await page.reload();
    await expect(ask).toBeChecked();
    await safe.check();
    await page.getByRole("button", { name: "Save settings", exact: true }).click();
    await expect.poll(() => (settingsUpdates.at(-1)?.settings as Record<string, unknown>)?.blocked_request_mode).toBe("safe-alternative");
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`blocked-request-${width}.png`), fullPage: true });
  });
}

test("production Settings password proof submits with Enter without React bridge failures", async ({ page }) => {
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") runtimeErrors.push(message.text());
  });
  await mountSettingsFixture(page);

  await page.goto(`/settings?${DAEMON}&section=approval`);

  await expect(page.getByRole("tabpanel", { name: "Approval gate settings" })).toBeVisible();
  await page.getByRole("button", { name: /Approval gate/ }).click();
  await page.getByRole("button", { name: "Set up authenticator" }).click();
  await page.getByLabel("Approval password").fill("test-password");
  await page.getByLabel("Approval password").press("Enter");
  await expect(
    page.getByRole("img", { name: "Scan this QR code in Google Authenticator or another TOTP app" })
  ).toBeVisible();
  await expect(runtimeErrors).toEqual([]);
});

test("first-time approval password setup is discoverable beside the gate", async ({ page }) => {
  const fixture = await mountSettingsFixture(page, unconfiguredSettingsPayload);
  await page.goto(`/settings?${DAEMON}&section=approval`);

  await page.getByRole("tabpanel", { name: "Approval gate settings" }).waitFor();
  await expect(page.getByRole("button", { name: "Set up approval password" })).toBeVisible();
  await page.getByRole("button", { name: "Set up approval password" }).click();
  const setupDialog = page.getByRole("dialog", { name: "Set your approval password" });
  await expect(setupDialog).toBeVisible();
  await expect(setupDialog.getByRole("textbox", { name: "Password", exact: true })).toBeVisible();
  await expect(setupDialog.getByRole("textbox", { name: "Confirm password", exact: true })).toBeVisible();
  await setupDialog.getByRole("textbox", { name: "Password", exact: true }).fill("test-password");
  const confirmation = setupDialog.getByRole("textbox", { name: "Confirm password", exact: true });
  await confirmation.fill("different-password");
  await confirmation.press("Enter");
  await expect(setupDialog.getByRole("button", { name: "Save settings" })).toBeDisabled();
  expect(fixture.settingsUpdates).toHaveLength(0);
  await confirmation.fill("test-password");
  await confirmation.press("Enter");
  await expect.poll(() => fixture.settingsUpdates).toHaveLength(1);
  const updateSettings = fixture.settingsUpdates[0]?.settings as Record<string, unknown> | undefined;
  expect(updateSettings).toBeDefined();
  expect(Object.keys(updateSettings ?? {})).toEqual(["approval_gate"]);
});

test("approval password setup stays reachable while the gate is off", async ({ page }) => {
  const fixture = await mountSettingsFixture(page, disabledUnconfiguredSettingsPayload);
  await page.goto(`/settings?${DAEMON}&section=approval`);

  await page.getByRole("tabpanel", { name: "Approval gate settings" }).waitFor();
  await expect(page.getByRole("button", { name: "Set up approval password" })).toBeVisible();
  await expect(page.getByText("Authenticator app", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Set up approval password" }).click();
  const setupDialog = page.getByRole("dialog", { name: "Set your approval password" });
  await expect(setupDialog).toBeVisible();
  await setupDialog.getByRole("textbox", { name: "Password", exact: true }).fill("test-password");
  const confirmation = setupDialog.getByRole("textbox", { name: "Confirm password", exact: true });
  await confirmation.fill("test-password");
  await confirmation.press("Enter");
  await expect.poll(() => fixture.settingsUpdates).toHaveLength(1);
  const updateSettings = fixture.settingsUpdates[0]?.settings as Record<string, unknown> | undefined;
  const gateUpdate = updateSettings?.approval_gate as Record<string, unknown> | undefined;
  expect(gateUpdate?.enabled).toBe(true);
  expect(gateUpdate?.new_password).toBe("test-password");
});

test("cancelling first-time password setup restores the off gate state", async ({ page }) => {
  const fixture = await mountSettingsFixture(page, disabledUnconfiguredSettingsPayload);
  await page.goto(`/settings?${DAEMON}&section=approval`);

  await page.getByRole("tabpanel", { name: "Approval gate settings" }).waitFor();
  const gateToggle = page.locator("#settings-approval-gate");
  await expect(gateToggle).not.toBeChecked();
  await page.getByRole("button", { name: "Set up approval password" }).click();
  const setupDialog = page.getByRole("dialog", { name: "Set your approval password" });
  await expect(setupDialog).toBeVisible();
  await expect(gateToggle).toBeChecked();
  await setupDialog.getByRole("button", { name: "Go back" }).click();
  await expect(setupDialog).toBeHidden();
  await expect(gateToggle).not.toBeChecked();
  expect(fixture.settingsUpdates).toHaveLength(0);
});

test("Enter on Go back cancels password proof rather than confirming it", async ({ page }) => {
  const fixture = await mountSettingsFixture(page, unconfiguredSettingsPayload);
  await page.goto(`/settings?${DAEMON}&section=approval`);
  await page.getByRole("button", { name: "Set up approval password" }).click();
  const dialog = page.getByRole("dialog", { name: "Set your approval password" });
  await dialog.getByRole("textbox", { name: "Password", exact: true }).fill("test-password");
  await dialog.getByRole("textbox", { name: "Confirm password", exact: true }).fill("test-password");
  await expect(dialog.getByRole("button", { name: "Save settings" })).toBeEnabled();
  await dialog.getByRole("button", { name: "Go back" }).press("Enter");
  await expect(dialog).toBeHidden();
  expect(fixture.settingsUpdates).toHaveLength(0);
});

test("Authenticator proof submits once with Enter and stays guarded while pending", async ({ page }) => {
  const totpSettings = {
    ...gatedSettingsPayload,
    settings: {
      ...gatedSettingsPayload.settings,
      approval_gate: { ...gatedSettingsPayload.settings.approval_gate, totp_enabled: true },
    },
  };
  await mountSettingsFixture(page, totpSettings);
  let submissions = 0;
  let releaseRequest: () => void = () => {};
  const pendingRequest = new Promise<void>((resolve) => { releaseRequest = resolve; });
  await page.route("**/v1/settings", async (route) => {
    if (route.request().method() !== "POST") {
      await route.fallback();
      return;
    }
    submissions += 1;
    await pendingRequest;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(totpSettings) });
  });
  try {
    await page.goto(`/settings?${DAEMON}&section=approval`);
    await page.getByRole("button", { name: "Change password", exact: true }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel("New password", { exact: true }).fill("next-password");
    await dialog.getByLabel("Confirm password", { exact: true }).fill("next-password");
    const code = dialog.getByLabel("Authenticator code", { exact: true });
    await code.press("Enter");
    expect(submissions).toBe(0);
    await code.fill("123456");
    await code.press("Enter");
    await expect.poll(() => submissions).toBe(1);
    await expect(dialog.getByRole("button", { name: "Working…" })).toBeDisabled();
    await code.press("Enter");
    await dialog.locator("form").evaluate((form) => {
      form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    });
    expect(submissions).toBe(1);
    releaseRequest();
    await expect(dialog).toBeHidden();
    expect(submissions).toBe(1);
  } finally {
    releaseRequest();
  }
});
