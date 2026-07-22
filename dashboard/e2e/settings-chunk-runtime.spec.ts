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

async function mountSettingsFixture(page: Page): Promise<void> {
  await page.route("**/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path.endsWith("/initialize")) body = { auth_token: "e2e-settings-token" };
    else if (path.endsWith("/runtime")) body = freeStateSnapshot;
    else if (path.endsWith("/requests")) {
      body = { items: [], next_cursor: null, total_pending_count: 0, total_count: 0, status: "pending" };
    } else if (path.endsWith("/receipts")) body = emptyReceiptsPayload;
    else if (path.endsWith("/policy")) body = emptyPoliciesPayload;
    else if (path.endsWith("/settings")) body = gatedSettingsPayload;
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
}

test("production Settings chunk initializes without React bridge failures", async ({ page }) => {
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") runtimeErrors.push(message.text());
  });
  await mountSettingsFixture(page);

  await page.goto(`/settings?${DAEMON}`);

  await expect(page.getByRole("heading", { name: "Set how hard Guard should push back" })).toBeVisible();
  await page.getByRole("button", { name: /Approval gate/ }).click();
  await page.getByRole("button", { name: "Set up authenticator" }).click();
  await page.getByLabel("Approval password").fill("test-password");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(
    page.getByRole("img", { name: "Scan this QR code in Google Authenticator or another TOTP app" })
  ).toBeVisible();
  await expect(runtimeErrors).toEqual([]);
});
