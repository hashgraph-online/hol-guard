import { expect, test } from "@playwright/test";

import { effective, initialize, mount } from "./extension-control-fixtures";

test("nested permissions tab offers quick apply and deny all drafts a block", async ({ page }) => {
  await mount(page);
  await initialize(page);
  await page.getByRole("button", { name: /^Git/ }).click();
  await expect(page.getByTestId("protection-module-detail")).toBeVisible();
  await page.getByRole("tab", { name: "Permissions" }).click();
  await expect(page.getByRole("heading", { name: "Protection settings" })).toBeVisible();

  await expect(page.getByText("Quick apply to 1 changeable setting")).toBeVisible();
  const quickApply = page.getByRole("group", { name: "Quick apply to 1 changeable settings" });
  await expect(quickApply.getByRole("button", { name: "Recommended" })).toHaveAttribute("aria-pressed", "true");

  await quickApply.getByRole("button", { name: "Deny all" }).click();
  await expect(page.getByText("1 unsaved setting change.")).toBeVisible();
  await expect(page.getByRole("radio", { name: "Block" })).toHaveAttribute("aria-checked", "true");
  await expect(quickApply.getByRole("button", { name: "Deny all" })).toHaveAttribute("aria-pressed", "true");
});

test("search console explains locked editing when protection health is not protected", async ({ page }) => {
  await mount(page, {
    effective: effective({
      health: "degraded-unacknowledged",
      failures: [{ code: "cloud_sync_stale", layer_kind: "signed-cloud" }],
    }),
  });
  await initialize(page);
  await page.getByRole("searchbox", { name: "Search command patterns" }).fill("git");

  await expect(
    page.getByRole("alert").filter({ hasText: "Settings cannot be changed until Guard verifies local settings integrity." }),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "Allow all" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Deny all" })).toBeDisabled();
});
