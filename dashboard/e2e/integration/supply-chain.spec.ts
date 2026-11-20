import { expect, expectNoErrorBoundary, test } from "./fixtures";
import { appName } from "./home-helpers";
import {
  expectedRows,
  loadPackageShims,
  managerCard,
  managerList,
  openActivity,
  rosterSection,
  showAllManagers,
  supplySeed,
} from "./supply-chain-helpers";

async function openHub(page: import("@playwright/test").Page) {
  await page.goto("/supply-chain");
  await expect(page.getByRole("heading", { level: 1, name: "Supply Chain", exact: true })).toBeVisible();
  await expectNoErrorBoundary(page);
}

test.describe("Supply chain hub against the live daemon", () => {
  test("shows the hub tabs and names the page once", async ({ page }) => {
    await openHub(page);
    const tabs = page.getByRole("tablist");
    await expect(tabs.getByRole("tab", { name: "Supply Chain", exact: true })).toHaveAttribute("aria-selected", "true");
    await expect(tabs.getByRole("tab", { name: "Audit", exact: true })).toHaveAttribute("aria-selected", "false");
    await expect(tabs.getByRole("tab", { name: "Feed Health", exact: true })).toHaveAttribute("aria-selected", "false");
    // The sidebar already leads Home; the page ends without a second way back.
    await expect(page.getByRole("button", { name: "Back to Home", exact: true })).toHaveCount(0);
  });

  test("the first screen holds one primary action and folds the supporting detail", async ({ page }) => {
    await openHub(page);
    const recovery = page.getByRole("region", { name: "Supply-chain recovery" });
    await expect(recovery.locator('[data-primary="true"]')).toHaveCount(1);
    // Row actions stay quiet: nothing in the roster competes with Restore protection.
    await showAllManagers(page);
    for (const name of ["Protect", "Fix PATH"]) {
      const buttons = managerList(page).getByRole("button", { name, exact: true });
      for (const button of await buttons.all()) {
        await expect(button).not.toHaveClass(/bg-brand-blue(?![\w/-])/);
      }
    }
    // No raw shell paths on the page; they live in each manager's drawer.
    await expect(managerList(page).getByText("precedes", { exact: false })).toHaveCount(0);
    const activity = page.getByRole("button", { name: "Activity and sources", exact: true });
    await expect(activity).toHaveAttribute("aria-expanded", "false");
    await expect(page.getByRole("region", { name: "Recent supply chain evidence" })).toHaveCount(0);
    await activity.click();
    await expect(activity).toHaveAttribute("aria-expanded", "true");
    await expect(page.getByRole("region", { name: "Recent supply chain evidence" })).toBeVisible();
  });

  test("recovery banner counts what is wrong and lists it on demand", async ({ page }) => {
    await openHub(page);
    const recovery = page.getByRole("region", { name: "Supply-chain recovery" });
    await expect(recovery.getByRole("heading", { level: 2, name: "Restore supply-chain protection" })).toBeVisible();
    // The shim directory is not on PATH, so activation is the issue. Hosts add
    // more (unprotected tools, local-only cloud) depending on what they have.
    const summary = recovery.getByText(/\d+ issues? to fix\./);
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
    await openActivity(page);
    const rail = page.getByRole("region", { name: "Recent supply chain evidence" });
    await expect(rail.getByText("Last block", { exact: true })).toBeVisible();
    await expect(rail.getByText("Last audit", { exact: true })).toBeVisible();
    await expect(rail.getByText("Last sync", { exact: true })).toBeVisible();
    await expect(rail.getByText("No workspace audit yet", { exact: true })).toBeVisible();
    await expect(rail.getByText("No policy sync yet", { exact: true })).toBeVisible();
  });

  test("connected apps list the seeded app and open its shim coverage", async ({ page, state }) => {
    await openHub(page);
    await openActivity(page);
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
    await openActivity(page);
    await expect(page.getByText("Workspace audit", { exact: true })).toBeVisible();
    await expect(page.getByText("Run an audit to index dependencies and surface packages that need review.")).toBeVisible();
    await page.getByRole("button", { name: "Open Audit tab", exact: true }).click();
    await expect.poll(() => new URL(page.url()).pathname).toBe("/audit");
    await expect(page.getByRole("heading", { level: 1, name: "Audit", exact: true })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Audit", exact: true })).toHaveAttribute("aria-selected", "true");
  });

  test("groups every package manager the daemon reports by what to do next", async ({ page, state }) => {
    await openHub(page);
    const rows = expectedRows(await loadPackageShims(state));
    const seeded = supplySeed(state).shimmedManagers;
    // Installed shims always have a row, whatever the host has detected.
    for (const manager of seeded) expect(rows.map((row) => row.manager)).toContain(manager);

    await showAllManagers(page);
    const list = managerList(page);
    await expect(list.getByTestId("manager-row")).toHaveCount(rows.length);
    for (const row of rows) {
      const card = rosterSection(page, row.group).getByTestId("manager-row").filter({
        has: page.getByRole("button", { name: `Open ${row.manager} manager details`, exact: true }),
      });
      await expect(card).toHaveCount(1);
      // Only rows that need a fix repeat their state; the group heading names the rest.
      if (row.group === "Needs a fix") await expect(card.getByText(row.status, { exact: true })).toBeVisible();
      for (const action of row.actions) {
        await expect(card.getByRole("button", { name: action, exact: true })).toBeVisible();
      }
    }

    // The two seeded shims are installed, but another copy of each tool comes first on PATH.
    for (const manager of seeded) {
      const card = managerCard(page, manager);
      await expect(card.getByText("PATH broken", { exact: true })).toBeVisible();
      await expect(card.getByText(`Another ${manager} runs before Guard's shim, so installs skip Guard.`, { exact: true })).toBeVisible();
    }
  });

  test("a long not-yet-protected group folds to one line, and search finds any tool", async ({ page, state }) => {
    await openHub(page);
    const rows = expectedRows(await loadPackageShims(state));
    const seeded = supplySeed(state).shimmedManagers;
    const list = managerList(page);
    const waiting = rows.filter((row) => row.group === "Not protected yet");
    const fixes = rows.filter((row) => row.group === "Needs a fix");
    expect(fixes.map((row) => row.manager)).toEqual(expect.arrayContaining(seeded));

    const section = rosterSection(page, "Not protected yet");
    if (waiting.length > 3) {
      await expect(section.getByTestId("manager-row")).toHaveCount(0);
      await expect(section.getByText("Installs from these tools are not checked yet.", { exact: false })).toBeVisible();
      const toggle = section.getByRole("button", { name: `Show all ${waiting.length}`, exact: true });
      await expect(toggle).toHaveAttribute("aria-expanded", "false");
      await toggle.click();
      await expect(section.getByTestId("manager-row")).toHaveCount(waiting.length);
      await section.getByRole("button", { name: "Show less", exact: true }).click();
      await expect(section.getByTestId("manager-row")).toHaveCount(0);
    }
    // Tools that need a fix are never folded away.
    await expect(rosterSection(page, "Needs a fix").getByTestId("manager-row")).toHaveCount(fixes.length);

    if (rows.length > 8) {
      const search = page.getByRole("searchbox", { name: "Filter package managers" });
      await search.fill(seeded[1]);
      const matching = rows.filter((row) => row.manager.includes(seeded[1]));
      await expect(list.getByTestId("manager-row")).toHaveCount(matching.length);
      await expect(managerCard(page, seeded[1])).toBeVisible();
      await search.fill("zzz-no-such-manager");
      await expect(page.getByRole("heading", { name: "No package managers found" })).toBeVisible();
      await search.fill("");
      await expect(managerCard(page, seeded[1])).toBeVisible();
    }
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
