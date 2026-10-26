import type { Page } from "@playwright/test";

import { daemonApi, expect, expectNoErrorBoundary, test, type IntegrationState } from "./fixtures";
import { settingsSeed } from "./settings-helpers";

type SettingsPayload = { settings: { approval_wait_timeout_seconds: number } };

async function daemonTimeout(state: IntegrationState): Promise<number> {
  const payload = await daemonApi<SettingsPayload>(state, "/v1/settings");
  return payload.settings.approval_wait_timeout_seconds;
}

// Edits the approval wait, saves it, and answers the save-proof dialog with the
// integration home's approval password.
async function saveTimeoutWithProof(page: Page, state: IntegrationState, seconds: number): Promise<void> {
  await page.getByRole("spinbutton", { name: "How long to wait for your answer" }).fill(String(seconds));
  await page.getByRole("region", { name: "Save settings" }).getByRole("button", { name: "Save settings" }).click();

  const proof = page.getByRole("dialog");
  await expect(proof.getByRole("heading", { name: /Confirm before saving/ })).toBeVisible();
  const confirm = proof.getByRole("button", { name: "Save settings" });
  // Nothing is saved until the password is typed.
  await expect(confirm).toBeDisabled();
  await proof.getByLabel("Approval password").fill(state.approvalPassword);
  await expect(confirm).toBeEnabled();
  await confirm.click();
  await expect(page.getByText("Settings saved successfully.")).toBeVisible();
  await expect(proof).toHaveCount(0);
}

test("saving a setting through the proof dialog persists after reload, then restores it", async ({ page, state }) => {
  const seed = settingsSeed(state);
  const timeout = page.getByRole("spinbutton", { name: "How long to wait for your answer" });
  expect(await daemonTimeout(state)).toBe(seed.approvalWaitTimeoutSeconds);

  await page.goto("/settings?section=protection");
  await expect(timeout).toHaveValue(String(seed.approvalWaitTimeoutSeconds));
  try {
    await saveTimeoutWithProof(page, state, seed.changedApprovalWaitTimeoutSeconds);

    // Guard's own state changed, and so does a fresh page load.
    expect(await daemonTimeout(state)).toBe(seed.changedApprovalWaitTimeoutSeconds);
    await page.reload();
    await expect(timeout).toHaveValue(String(seed.changedApprovalWaitTimeoutSeconds));
    await expectNoErrorBoundary(page);
  } finally {
    // Put the daemon back whatever happened above so later specs see defaults.
    await page.goto("/settings?section=protection");
    if ((await timeout.inputValue()) !== String(seed.approvalWaitTimeoutSeconds)) {
      await saveTimeoutWithProof(page, state, seed.approvalWaitTimeoutSeconds);
    }
  }

  expect(await daemonTimeout(state)).toBe(seed.approvalWaitTimeoutSeconds);
  await page.reload();
  await expect(timeout).toHaveValue(String(seed.approvalWaitTimeoutSeconds));
});
