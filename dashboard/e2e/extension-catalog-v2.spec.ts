import { expect, test, type Page } from "@playwright/test";

import {
  catalog,
  extension,
  initialize,
  mount,
  type CatalogFixture,
} from "./extension-control-fixtures";

const CATALOG_V2 = "/v2/extension-controls/catalog/";

function recordCatalogRequests(page: Page): string[] {
  const paths: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname.includes("/extension-controls/catalog")) paths.push(`${url.pathname}${url.search}`);
  });
  return paths;
}

function largeCatalog(): CatalogFixture {
  const base = extension();
  const permissions = Array.from({ length: 250 }, (_, index) => ({
    ...base.permissions[0]!,
    permission_id: `command.git.permission.bulk-${index}`,
    label: `Bulk permission ${index}`,
  }));
  return { ...catalog(), extensions: [{ ...base, permission_count: permissions.length, permissions }] };
}

test("first page reads only the bounded index; details load on the detail route", async ({ page }) => {
  const paths = recordCatalogRequests(page);
  await mount(page);
  await initialize(page);
  await expect(page.getByRole("button", { name: /^Git/ })).toBeVisible();

  expect(paths.length).toBeGreaterThan(0);
  expect(paths.every((path) => path.startsWith(`${CATALOG_V2}index?`))).toBe(true);
  expect(paths.some((path) => path.startsWith("/v1/extension-controls/catalog"))).toBe(false);

  await page.getByRole("button", { name: /^Git/ }).click();
  await expect(page.getByTestId("protection-module-detail")).toBeVisible();
  const detailPaths = paths.filter((path) => path.includes("/extensions/"));
  expect(detailPaths.length).toBeGreaterThan(0);
  expect(detailPaths.every((path) => path.startsWith(`${CATALOG_V2}extensions/command.git`))).toBe(true);
  expect(paths.some((path) => path.startsWith("/v1/extension-controls/catalog"))).toBe(false);
});

test("pattern search queries the daemon permission route", async ({ page }) => {
  const paths = recordCatalogRequests(page);
  await mount(page);
  await initialize(page);
  await page.getByRole("searchbox", { name: "Search command patterns" }).fill("hard reset");
  await expect(page.getByRole("region", { name: "Git patterns" })).toBeVisible();
  expect(paths.some((path) => path.startsWith(`${CATALOG_V2}permissions?`) && path.includes("q=hard+reset"))).toBe(true);
  expect(paths.some((path) => path.includes("/extensions/"))).toBe(false);
});

test("large permission collections traverse every page", async ({ page }) => {
  const paths = recordCatalogRequests(page);
  await mount(page, { catalog: largeCatalog() });
  await initialize(page);
  await page.getByRole("button", { name: /^Git/ }).click();
  await expect(page.getByTestId("protection-module-detail")).toBeVisible();
  const permissionPages = paths.filter((path) => path.startsWith(`${CATALOG_V2}extensions/command.git/permissions?`));
  expect(permissionPages).toHaveLength(3);
  expect(permissionPages.filter((path) => path.includes("cursor="))).toHaveLength(2);
});

test("a daemon without v2 falls back to the legacy catalog", async ({ page }) => {
  const paths = recordCatalogRequests(page);
  await mount(page, { catalogProtocol: "v1" });
  await initialize(page);
  await page.getByRole("button", { name: /^Git/ }).click();
  await expect(page.getByTestId("protection-module-detail")).toBeVisible();
  expect(paths.filter((path) => path === "/v1/extension-controls/catalog")).toHaveLength(1);
  expect(paths.some((path) => path.includes("/extensions/"))).toBe(false);
});

test("a replaced snapshot during a detail read asks for a fresh index", async ({ page }) => {
  const paths = recordCatalogRequests(page);
  await mount(page);
  // Two expiries: the client restarts a traversal once, then surfaces the stale snapshot.
  let expiries = 2;
  await page.route(`**${CATALOG_V2}extensions/command.git/rules**`, async (route) => {
    if (expiries <= 0) return route.fallback();
    expiries -= 1;
    await route.fulfill({ status: 409, contentType: "application/json", body: JSON.stringify({ error: "catalog_snapshot_expired" }) });
  });
  await initialize(page);
  await page.getByRole("button", { name: /^Git/ }).click();
  await expect(page.getByRole("heading", { name: "Extension details unavailable" })).toBeVisible();
  const indexReads = paths.filter((path) => path.startsWith(`${CATALOG_V2}index?`)).length;
  await page.getByRole("button", { name: "Try again" }).click();
  await expect(page.getByTestId("protection-module-detail")).toBeVisible();
  expect(paths.filter((path) => path.startsWith(`${CATALOG_V2}index?`)).length).toBeGreaterThan(indexReads);
});
