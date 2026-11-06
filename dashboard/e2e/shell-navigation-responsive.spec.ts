import { expect, test } from "@playwright/test";

test("shell navigation adapts continuously without a select input", async ({ page }) => {
  await page.addInitScript(() => {
    window.localStorage.removeItem("guard-sidebar-collapsed");
  });
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.goto("/", { waitUntil: "domcontentloaded" });

  const sidebar = page.getByTestId("guard-shell-sidebar");
  const mobileHeader = page.getByTestId("guard-shell-mobile-header");
  const bottomNavigation = page.getByTestId("mobile-bottom-navigation");
  const workspace = page.locator(".guard-shell-workspace");

  await expect(page.locator("#guard-mobile-navigation")).toHaveCount(0);
  await expect(sidebar).toBeVisible();
  await expect(sidebar).toHaveCSS("width", "256px");
  await expect(mobileHeader).toBeHidden();
  await expect(bottomNavigation).toBeHidden();
  const wideWorkspace = await workspace.boundingBox();
  expect(wideWorkspace).not.toBeNull();
  expect(wideWorkspace!.width).toBeLessThanOrEqual(1536.5);

  await page.setViewportSize({ width: 1024, height: 768 });
  await expect(sidebar).toBeVisible();
  await expect(sidebar).toHaveCSS("width", "76px");
  await expect(page.getByTestId("compact-navigation-trigger")).toBeVisible();
  await expect(mobileHeader).toBeHidden();
  await expect(bottomNavigation).toBeHidden();
  await expect(page.locator('[data-navigation-item="home"][data-navigation-variant="sidebar"]')).toHaveAttribute(
    "aria-current",
    "page",
  );

  await page.getByTestId("compact-navigation-trigger").click();
  const drawer = page.getByTestId("navigation-drawer");
  await expect(drawer).toBeVisible();
  await expect(drawer.locator('[role="dialog"]')).toHaveAttribute("aria-modal", "true");
  await expect(drawer.locator('[data-navigation-item="settings"]')).toBeVisible();
  await expect(page.locator(".guard-shell-content")).toHaveAttribute("inert", "");
  await page.keyboard.press("Escape");
  await expect(drawer).toHaveCount(0);
  await expect(page.getByTestId("compact-navigation-trigger")).toBeFocused();

  await page.setViewportSize({ width: 600, height: 760 });
  await expect(sidebar).toBeHidden();
  await expect(mobileHeader).toBeVisible();
  await expect(bottomNavigation).toBeVisible();
  await expect(page.getByTestId("mobile-navigation-trigger")).toBeVisible();
  await expect(page.locator('[data-navigation-item="home"][data-navigation-variant="bottom"]')).toHaveAttribute(
    "aria-current",
    "page",
  );

  await page.getByTestId("mobile-more-navigation").click();
  await expect(page.getByTestId("navigation-drawer")).toBeVisible();

  await page.setViewportSize({ width: 1024, height: 760 });
  await expect(page.getByTestId("navigation-drawer")).toHaveCount(0);
  await expect(sidebar).toBeVisible();
  await expect(sidebar).toHaveCSS("width", "76px");

  await page.setViewportSize({ width: 600, height: 760 });
  await expect(bottomNavigation).toBeVisible();
  await page.getByTestId("mobile-more-navigation").click();
  await page
    .getByTestId("navigation-drawer")
    .locator('[data-navigation-item="settings"]')
    .click();
  await expect(page).toHaveURL(/\/settings$/);
  await expect(page.getByTestId("navigation-drawer")).toHaveCount(0);
  await expect(page.getByTestId("mobile-more-navigation")).toHaveAttribute("aria-current", "page");
  await expect(mobileHeader.locator("strong")).toHaveText("Settings");

  await page.setViewportSize({ width: 375, height: 667 });
  await expect(bottomNavigation).toBeVisible();
  await page.getByTestId("mobile-more-navigation").click();
  const phoneDialog = page.getByTestId("navigation-drawer").locator('[role="dialog"]');
  await expect(phoneDialog).toBeVisible();
  const phoneBox = await phoneDialog.boundingBox();
  expect(phoneBox).not.toBeNull();
  expect(phoneBox!.width).toBeGreaterThanOrEqual(374);
  await page.getByTestId("navigation-drawer").locator('button[aria-label="Close navigation"]').last().click();
  await expect(page.getByTestId("navigation-drawer")).toHaveCount(0);
});
