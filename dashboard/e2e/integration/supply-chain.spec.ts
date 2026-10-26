import { expect, expectNoErrorBoundary, test } from "./fixtures";
import { appName } from "./home-helpers";
import { expectedRows, loadPackageShims, managerCard, managerList, supplySeed } from "./supply-chain-helpers";

async function openHub(page: import("@playwright/test").Page) {
  await page.goto("/supply-chain");
  await expect(page.getByRole("heading", { level: 1, name: "Supply Chain", exact: true })).toBeVisible();
  await expectNoErrorBoundary(page);
}

test.describe("Supply chain hub against the live daemon", () => {
  test("shows the three hub tabs and leads back to Home", async ({ page }) => {
    await openHub(page);
    const tabs = page.getByRole("tablist");
    await expect(tabs.getByRole("tab", { name: "Supply Chain", exact: true })).toHaveAttribute("aria-selected", "true");
    await expect(tabs.getByRole("tab", { name: "Audit", exact: true })).toHaveAttribute("aria-selected", "false");
    await expect(tabs.getByRole("tab", { name: "Feed Health", exact: true })).toHaveAttribute("aria-selected", "false");

    await page.getByRole("button", { name: "Back to Home", exact: true }).click();
    await expect(page).toHaveURL(/\/(#.*)?$/);
    expect(new URL(page.url()).pathname).toBe("/");
    await expect(page.getByRole("region", { name: "Protection status" }).getByRole("heading", { level: 1 })).toBeVisible();
  });

  test("recovery banner counts what is wrong and lists it on demand", async ({ page }) => {
    await openHub(page);
    const recovery = page.getByRole("region", { name: "Supply-chain recovery" });
    await expect(recovery.getByRole("heading", { level: 2, name: "Restore supply-chain protection" })).toBeVisible();
    // The shim directory is not on PATH, so activation is the issue. Hosts add
    // more (unprotected tools, local-only cloud) depending on what they have.
    const summary = recovery.getByText(/\d+ issues? to resolve\./);
    await expect(summary).toBeVisible();
    expect(Number((await summary.innerText()).match(/^(\d+)/)?.[1])).toBeGreaterThanOrEqual(2);
    await expect(recovery.getByRole("button", { name: "Restore protection", exact: true })).toBeEnabled();

    const toggle = recovery.getByRole("button", { name: "View issue details", exact: true });
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await expect(recovery.getByText("Package installs are not being checked yet", { exact: true })).toHaveCount(0);
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    await expect(recovery.getByText("Package installs are not being checked yet", { exact: true })).toBeVisible();
    await expect(recovery.getByText("Guard Cloud unavailable on this device", { exact: true })).toBeVisible();
    await toggle.click();
    await expect(recovery.getByText("Package installs are not being checked yet", { exact: true })).toHaveCount(0);
  });

  test("evidence rail shows waiting states before any audit or sync", async ({ page }) => {
    await openHub(page);
    const rail = page.getByRole("region", { name: "Recent supply chain evidence" });
    await expect(rail.getByText("Last block", { exact: true })).toBeVisible();
    await expect(rail.getByText("Last audit", { exact: true })).toBeVisible();
    await expect(rail.getByText("Last sync", { exact: true })).toBeVisible();
    await expect(rail.getByText("No workspace audit yet", { exact: true })).toBeVisible();
    await expect(rail.getByText("No policy sync yet", { exact: true })).toBeVisible();
  });

  test("connected apps list the seeded app and open its shim coverage", async ({ page, state }) => {
    await openHub(page);
    const seed = supplySeed(state);
    const app = page.getByRole("button", { name: `${appName(seed.app)} Active`, exact: true });
    await expect(app).toBeVisible();
    await expect(app).toHaveAttribute("aria-expanded", "false");
    await expect(page.getByRole("button", { name: "Copilot Inactive", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Claude Code Active", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Cursor Active", exact: true })).toBeVisible();

    await app.click();
    await expect(app).toHaveAttribute("aria-expanded", "true");
    await expect(page.getByText("Shim coverage", { exact: true })).toBeVisible();
    // The shims are installed but off PATH, so nothing counts as covered yet.
    await expect(page.getByText("No package manager shims active for this app.", { exact: true })).toBeVisible();
    await app.click();
    await expect(page.getByText("Shim coverage", { exact: true })).toHaveCount(0);
  });

  test("workspace audit card opens the Audit tab", async ({ page }) => {
    await openHub(page);
    await expect(page.getByText("Workspace audit", { exact: true })).toBeVisible();
    await expect(page.getByText("Run an audit to index dependencies and surface packages that need review.")).toBeVisible();
    await page.getByRole("button", { name: "Open Audit tab", exact: true }).click();
    await expect.poll(() => new URL(page.url()).pathname).toBe("/audit");
    await expect(page.getByRole("heading", { level: 1, name: "Audit", exact: true })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Audit", exact: true })).toHaveAttribute("aria-selected", "true");
  });

  test("lists every package manager the daemon reports, with its protection status", async ({ page, state }) => {
    await openHub(page);
    const rows = expectedRows(await loadPackageShims(state));
    const seeded = supplySeed(state).shimmedManagers;
    // Installed shims always have a row, whatever the host has detected.
    for (const manager of seeded) expect(rows.map((row) => row.manager)).toContain(manager);

    const list = managerList(page);
    await expect(list.getByRole("listitem")).toHaveCount(rows.length);
    for (const row of rows) {
      const card = managerCard(page, row.manager);
      await expect(card.getByText(row.status, { exact: true })).toBeVisible();
      for (const action of row.actions) {
        await expect(card.getByRole("button", { name: action, exact: true })).toBeVisible();
      }
      if (row.detected) await expect(card.getByText("Detected", { exact: true })).toBeVisible();
    }

    // The two seeded shims are installed but the shim directory is not on PATH.
    for (const manager of seeded) {
      const card = managerCard(page, manager);
      await expect(card.getByText("PATH broken", { exact: true })).toBeVisible();
      await expect(card.getByText("Restart your shell after repair so PATH exports reload.")).toBeVisible();
      await expect(card.getByText("No protection test recorded yet")).toBeVisible();
    }
  });

  test("filter pills and search narrow the manager list", async ({ page, state }) => {
    await openHub(page);
    const rows = expectedRows(await loadPackageShims(state));
    const seeded = supplySeed(state).shimmedManagers;
    const list = managerList(page);
    const pill = (name: string) => page.getByRole("button", { name, exact: true });
    await expect(pill("All")).toHaveAttribute("aria-pressed", "true");

    await pill("Needs action").click();
    await expect(pill("Needs action")).toHaveAttribute("aria-pressed", "true");
    const needsAction = rows.filter((row) => row.tone === "attention").map((row) => row.manager);
    expect(needsAction).toEqual(expect.arrayContaining(seeded));
    await expect(list.getByRole("listitem")).toHaveCount(needsAction.length);
    for (const manager of needsAction) await expect(managerCard(page, manager)).toBeVisible();

    await pill("Unprotected").click();
    const unprotected = rows.filter((row) => row.tone !== "green").map((row) => row.manager);
    await expect(list.getByRole("listitem")).toHaveCount(unprotected.length);

    await pill("Protected").click();
    const protectedRows = rows.filter((row) => row.tone === "green");
    if (protectedRows.length === 0) {
      await expect(page.getByRole("heading", { name: "No package managers found" })).toBeVisible();
      await expect(list).toHaveCount(0);
    } else {
      await expect(list.getByRole("listitem")).toHaveCount(protectedRows.length);
    }

    await pill("All").click();
    await expect(list.getByRole("listitem")).toHaveCount(rows.length);

    const search = page.getByRole("searchbox", { name: "Filter package managers" });
    await search.fill(seeded[1]);
    const matching = rows.filter((row) => row.manager.includes(seeded[1])).map((row) => row.manager);
    await expect(list.getByRole("listitem")).toHaveCount(matching.length);
    await expect(managerCard(page, seeded[1])).toBeVisible();
    await search.fill("zzz-no-such-manager");
    await expect(page.getByRole("heading", { name: "No package managers found" })).toBeVisible();
    await search.fill("");
    await expect(list.getByRole("listitem")).toHaveCount(rows.length);
  });

  test("manager details drawer explains one manager and closes", async ({ page, state }) => {
    await openHub(page);
    const [manager] = supplySeed(state).shimmedManagers;
    await page.getByRole("button", { name: `Open ${manager} manager details`, exact: true }).click();
    const drawer = page.getByRole("dialog", { name: `${manager} manager details` });
    await expect(drawer).toBeVisible();
    const coverage = drawer.getByRole("region", { name: "Manager coverage" });
    await expect(coverage.getByText("Activation", { exact: true })).toBeVisible();
    await expect(coverage.getByText("repair_required", { exact: true })).toBeVisible();
    await expect(coverage.getByText("Integrity", { exact: true })).toBeVisible();
    await expect(coverage.getByText("ok", { exact: true })).toBeVisible();
    await expect(drawer.getByRole("region", { name: "Intercept proof" })).toContainText("No intercept proof recorded yet.");
    await expect(drawer.getByText("PATH order is broken. Repair routing, then restart your shell before testing intercepts.")).toBeVisible();
    await expect(drawer.getByRole("button", { name: "Fix PATH", exact: true })).toBeVisible();
    await expect(drawer.getByRole("button", { name: "Remove", exact: true })).toBeVisible();
    await drawer.getByRole("button", { name: "Close", exact: true }).click();
    await expect(drawer).toHaveCount(0);
  });

  test("manager details drawer closes on Escape and returns focus to its row", async ({ page, state }) => {
    await openHub(page);
    const [manager] = supplySeed(state).shimmedManagers;
    const opener = page.getByRole("button", { name: `Open ${manager} manager details`, exact: true });
    await opener.click();
    const drawer = page.getByRole("dialog", { name: `${manager} manager details` });
    await expect(drawer).toBeVisible();
    await expect(drawer.getByRole("button", { name: "Close manager details drawer" })).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(drawer).toHaveCount(0);
    await expect(opener).toBeFocused();
  });

  test("manager details drawer keeps Tab focus inside the dialog", async ({ page, state }) => {
    await openHub(page);
    const [manager] = supplySeed(state).shimmedManagers;
    await page.getByRole("button", { name: `Open ${manager} manager details`, exact: true }).click();
    const drawer = page.getByRole("dialog", { name: `${manager} manager details` });
    await expect(drawer).toBeVisible();
    for (let step = 0; step < 12; step += 1) {
      await page.keyboard.press("Tab");
      const inside = await drawer.evaluate((node) => node.contains(document.activeElement));
      expect(inside).toBe(true);
    }
  });

  test("restore protection asks for the approval password before changing anything", async ({ page, state }) => {
    await openHub(page);
    const before = await loadPackageShims(state);
    await page.getByRole("region", { name: "Supply-chain recovery" }).getByRole("button", { name: "Restore protection", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Restore package protection" });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText("Approval required", { exact: true })).toBeVisible();
    await expect(dialog.getByRole("textbox", { name: "Approval password" })).toHaveValue("");
    await expect(dialog.getByRole("button", { name: "Restore protection", exact: true })).toBeDisabled();
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(dialog).toHaveCount(0);

    // Backing out changed nothing.
    const after = await loadPackageShims(state);
    expect(after.package_shims.installed_managers).toEqual(before.package_shims.installed_managers);
    expect(after.package_shims.path_status).toBe(before.package_shims.path_status);
  });

  test("tab links reach Audit and Feed Health", async ({ page }) => {
    await openHub(page);
    await page.getByRole("tab", { name: "Feed Health", exact: true }).click();
    await expect.poll(() => new URL(page.url()).pathname).toBe("/feed-health");
    await expect(page.getByRole("heading", { level: 1, name: "Feed Health", exact: true })).toBeVisible();
    await page.getByRole("tab", { name: "Supply Chain", exact: true }).click();
    await expect.poll(() => new URL(page.url()).pathname).toBe("/supply-chain");
    await expect(page.getByRole("heading", { level: 1, name: "Supply Chain", exact: true })).toBeVisible();
  });
});
