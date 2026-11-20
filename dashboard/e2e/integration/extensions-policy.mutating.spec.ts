import type { Page } from "@playwright/test";

import { daemonApi, expect, expectNoErrorBoundary, test, type IntegrationState } from "./fixtures";

const EXTENSION_ID = "command.api-gateway";
const PERMISSION_ID = "command.api-gateway.permission.delete";
const GOVERNED_RULE_ID = "command.api-gateway.delete";
// The first save on a fresh daemon writes the control authority and recomputes
// the projection, which takes longer than the default wait.
const SAVE_TIMEOUT_MS = 60_000;

type Effective = {
  revision: number;
  health: string;
  controls: { target: { kind: string; target_id: string }; state: string }[];
  projection?: { permissions: { permission_id: string; effective_state: string }[] };
};

const readEffective = (state: IntegrationState) => daemonApi<Effective>(state, "/v1/extension-controls/effective");
const permissionControl = (effective: Effective) =>
  effective.controls.find((control) => control.target.kind === "permission" && control.target.target_id === PERMISSION_ID);

async function openPolicy(page: Page) {
  await page.goto(`/extensions/${EXTENSION_ID}?tab=policy`);
  await expectNoErrorBoundary(page);
  await expect(page.locator("#extension-policy-heading")).toHaveText("Protection settings");
  return page.locator(`[data-permission-id="${PERMISSION_ID}"]`);
}

// Waits until the daemon serves a revision newer than `previous`, which is
// the committed save, and returns it.
async function waitForCommittedRevision(state: IntegrationState, previous: number): Promise<number> {
  let committed = previous;
  await expect
    .poll(async () => (committed = (await readEffective(state)).revision), { timeout: SAVE_TIMEOUT_MS })
    .toBeGreaterThan(previous);
  return committed;
}

// The applied toast can be lost when the post-apply refresh remounts the
// panel, so the save is confirmed against the daemon. When the toast does
// show, it must name the committed revision.
async function expectToastMatches(page: Page, revision: number) {
  const toast = page.getByTestId("extension-policy-applied-toast");
  if (await toast.isVisible()) await expect(toast).toContainText(`Applied · revision ${revision}`);
}

// Reviews the one pending change, proves it with the approval password and
// returns the revision the daemon committed.
async function reviewAndApply(page: Page, state: IntegrationState, previous: number): Promise<number> {
  await expect(page.getByText("1 unsaved setting change.")).toBeVisible();
  await page.getByRole("button", { name: "Review 1 change" }).click();
  const dialog = page.getByRole("dialog", { name: "Review and apply 1 protection setting change" });
  await expect(dialog).toBeVisible({ timeout: SAVE_TIMEOUT_MS });
  await dialog.getByLabel("Approval password").fill(state.approvalPassword);
  await dialog.getByRole("button", { name: "Apply 1 reviewed change" }).click();
  await expect(dialog).toBeHidden({ timeout: SAVE_TIMEOUT_MS });
  const revision = await waitForCommittedRevision(state, previous);
  await expectToastMatches(page, revision);
  return revision;
}

test("blocking an extension permission needs the approval password, survives reload and can be restored", async ({ page, state }) => {
  test.setTimeout(180_000);
  const before = await readEffective(state);
  expect(permissionControl(before), "the permission starts on Guard's recommended setting").toBeUndefined();

  // Preview: choosing Block only drafts a change, and the daemon is untouched
  // until the reviewed change is proven and applied.
  let row = await openPolicy(page);
  await expect(row.getByRole("radio", { name: "Recommended" })).toHaveAttribute("aria-checked", "true");
  await row.getByRole("radio", { name: "Block" }).click();
  await expect(page.getByText("1 unsaved setting change.")).toBeVisible();
  expect(permissionControl(await readEffective(state))).toBeUndefined();

  await page.getByRole("button", { name: "Review 1 change" }).click();
  const review = page.getByRole("dialog", { name: "Review and apply 1 protection setting change" });
  await expect(review).toBeVisible({ timeout: SAVE_TIMEOUT_MS });
  await expect(review.getByText("Protection review", { exact: true }).first()).toBeVisible();
  await review.getByText("Developer details", { exact: true }).click();
  await expect(review.getByText(GOVERNED_RULE_ID, { exact: true })).toBeVisible();
  // Applying is gated on the approval password.
  await expect(review.getByRole("button", { name: "Apply 1 reviewed change" })).toBeDisabled();
  await review.getByLabel("Approval password").fill(state.approvalPassword);
  await review.getByRole("button", { name: "Apply 1 reviewed change" }).click();
  await expect(review).toBeHidden({ timeout: SAVE_TIMEOUT_MS });
  const blockedRevision = await waitForCommittedRevision(state, before.revision);
  await expectToastMatches(page, blockedRevision);

  // The daemon now serves the block.
  const blocked = await readEffective(state);
  expect(blocked.revision).toBe(blockedRevision);
  expect(blocked.revision).toBeGreaterThan(before.revision);
  expect(permissionControl(blocked)?.state).toBe("disabled");
  expect(blocked.projection?.permissions.find((permission) => permission.permission_id === PERMISSION_ID)?.effective_state).toBe("blocked");

  // Persistence: a fresh load still shows the block.
  row = await openPolicy(page);
  await expect(row.getByRole("radio", { name: "Block" })).toHaveAttribute("aria-checked", "true");
  await expect(row.getByRole("radio", { name: "Recommended" })).toHaveAttribute("aria-checked", "false");

  // Restore through the same reviewed flow, so later specs see the original state.
  await row.getByRole("radio", { name: "Recommended" }).click();
  const restoredRevision = await reviewAndApply(page, state, blocked.revision);
  const restored = await readEffective(state);
  expect(restored.revision).toBe(restoredRevision);
  expect(restored.revision).toBeGreaterThan(blocked.revision);
  expect(permissionControl(restored)).toBeUndefined();
  expect(restored.health).toBe("protected");

  row = await openPolicy(page);
  await expect(row.getByRole("radio", { name: "Recommended" })).toHaveAttribute("aria-checked", "true");
  await expect(row.getByRole("radio", { name: "Block" })).toHaveAttribute("aria-checked", "false");
});
