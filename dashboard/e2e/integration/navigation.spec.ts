import type { Page } from "@playwright/test";

import { expect, expectNoErrorBoundary, test } from "./fixtures";

const ROUTES: ReadonlyArray<{ path: string; nav: string }> = [
  { path: "/", nav: "Home" },
  { path: "/inbox", nav: "Inbox" },
  { path: "/protect", nav: "Protect" },
  { path: "/evidence", nav: "Evidence" },
  { path: "/extensions", nav: "Extensions" },
  { path: "/policy", nav: "Rules & exceptions" },
  { path: "/supply-chain", nav: "Supply chain" },
  { path: "/settings", nav: "Settings" },
  { path: "/about", nav: "About" },
];

// The Inbox link's accessible name carries the waiting count
// ("Inbox, no Guard actions waiting"), so match its label as a prefix.
function navLink(page: Page, label: string) {
  const name = label === "Inbox" ? /^Inbox\b/ : label;
  return page.getByRole("navigation", { name: "Guard dashboard" }).getByRole("link", { name, exact: true });
}

for (const route of ROUTES) {
  test(`${route.nav} renders against the live daemon`, async ({ page }) => {
    await page.goto(route.path);
    await expect(navLink(page, route.nav)).toHaveAttribute("aria-current", "page");
    await expect(page.getByRole("main")).toBeVisible();
    await expectNoErrorBoundary(page);
    // The session must never leak into the address bar.
    expect(page.url()).not.toContain("guard-token");
  });
}

test("sidebar navigation moves between every area without a reload", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("main")).toBeVisible();
  const navigationId = await page.evaluate(() => performance.getEntriesByType("navigation").length);
  for (const route of ROUTES.slice(1)) {
    await navLink(page, route.nav).click();
    // Sidebar links keep the session in the URL fragment by design, so compare
    // only the path.
    await expect.poll(() => new URL(page.url()).pathname).toBe(route.path);
    await expectNoErrorBoundary(page);
  }
  expect(await page.evaluate(() => performance.getEntriesByType("navigation").length)).toBe(navigationId);
});
