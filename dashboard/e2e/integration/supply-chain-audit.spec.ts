import { expect, expectNoErrorBoundary, test } from "./fixtures";
import { expectedRows, loadPackageShims, supplySeed } from "./supply-chain-helpers";

type Page = import("@playwright/test").Page;

async function openAudit(page: Page) {
  await page.goto("/audit");
  await expect(page.getByRole("heading", { level: 1, name: "Audit", exact: true })).toBeVisible();
  await expectNoErrorBoundary(page);
}

const results = (page: Page) => page.getByRole("list", { name: "Audit results" });
// A result row is the list item that holds its title button.
const resultRow = (page: Page, title: string) =>
  results(page)
    .getByRole("listitem")
    .filter({ has: page.getByRole("button", { name: new RegExp(`^${title}`) }) });

const pathRepairTitle = (manager: string) => `${manager} shim is installed but PATH still needs repair`;

test.describe("Audit tab before any audit has run", () => {
  test("offers the seeded project folder and waits for the first audit", async ({ page, state }) => {
    const seed = supplySeed(state);
    await openAudit(page);
    await expect(page.getByRole("tab", { name: "Audit", exact: true })).toHaveAttribute("aria-selected", "true");
    await expect(page.getByRole("button", { name: "Run audit", exact: true })).toBeEnabled();
    await expect(page.getByRole("heading", { level: 3, name: "No workspace audit yet" })).toBeVisible();

    // The seeded app's workspace is the project, so it is picked by default and
    // listed as a known folder next to the Guard workspace.
    await expect(page.getByRole("textbox", { name: "Project folder" })).toHaveValue(seed.project);
    const folders = page.getByRole("group", { name: "Known project folders" });
    await expect(folders.getByRole("button", { name: seed.projectName, exact: true })).toHaveAttribute("aria-pressed", "true");
    await expect(folders.getByRole("button", { name: "workspace", exact: true })).toHaveAttribute("aria-pressed", "false");
    await expect(page.getByRole("button", { name: "Choose folder", exact: true })).toBeEnabled();
  });

  test("known folder chips fill the project folder field", async ({ page, state }) => {
    const seed = supplySeed(state);
    await openAudit(page);
    const field = page.getByRole("textbox", { name: "Project folder" });
    const folders = page.getByRole("group", { name: "Known project folders" });
    await folders.getByRole("button", { name: "workspace", exact: true }).click();
    await expect(field).toHaveValue(state.workspace);
    await expect(folders.getByRole("button", { name: "workspace", exact: true })).toHaveAttribute("aria-pressed", "true");
    await folders.getByRole("button", { name: seed.projectName, exact: true }).click();
    await expect(field).toHaveValue(seed.project);
    await field.fill(`${seed.project}/typed`);
    await expect(folders.getByRole("button", { name: seed.projectName, exact: true })).toHaveAttribute("aria-pressed", "false");
  });

  test("issue list mirrors the package manager coverage the daemon reports", async ({ page, state }) => {
    const rows = expectedRows(await loadPackageShims(state));
    await openAudit(page);
    await expect(results(page)).toBeVisible();

    for (const manager of supplySeed(state).shimmedManagers) {
      const row = resultRow(page, pathRepairTitle(manager));
      await expect(row.getByText("medium", { exact: true })).toBeVisible();
      await expect(row.getByRole("button", { name: "Repair PATH", exact: true })).toBeVisible();
    }
    for (const row of rows.filter((entry) => entry.status === "Detected, not protected")) {
      const item = resultRow(page, `${row.manager} is not intercepted by Guard`);
      await expect(item.getByText("high", { exact: true })).toBeVisible();
      await expect(item.getByRole("button", { name: "Install Guard", exact: true })).toBeVisible();
    }

    // The open badge counts the rows the default Open filter lists.
    const count = await results(page).getByRole("listitem").count();
    await expect(page.getByText(`${count} open`, { exact: true })).toBeVisible();
  });

  test("search and severity filters narrow the issue list", async ({ page, state }) => {
    const [npm, pip] = supplySeed(state).shimmedManagers;
    await openAudit(page);
    const pill = (name: string) => page.getByRole("button", { name, exact: true });
    const search = page.getByRole("searchbox", { name: "Search audit issues" });

    await search.fill(pathRepairTitle(npm));
    await expect(results(page).getByRole("listitem")).toHaveCount(1);
    await expect(resultRow(page, pathRepairTitle(npm))).toBeVisible();
    await search.fill("zzz-no-such-issue");
    await expect(page.getByText("No results match your filter", { exact: true })).toBeVisible();
    await search.fill("");

    await pill("Medium").click();
    await expect(pill("Medium")).toHaveAttribute("aria-pressed", "true");
    await expect(resultRow(page, pathRepairTitle(npm))).toBeVisible();
    await expect(resultRow(page, pathRepairTitle(pip))).toBeVisible();
    await pill("High").click();
    await expect(resultRow(page, pathRepairTitle(npm))).toHaveCount(0);
    await pill("Critical").click();
    await expect(page.getByText("No results match your filter", { exact: true })).toBeVisible();
    await pill("All").first().click();
    await expect(resultRow(page, pathRepairTitle(npm))).toBeVisible();
  });

  test("marking an issue resolved moves it to the Resolved filter", async ({ page, state }) => {
    const [npm] = supplySeed(state).shimmedManagers;
    await openAudit(page);
    const title = pathRepairTitle(npm);
    const row = resultRow(page, title);
    const header = row.getByRole("button", { name: new RegExp(`^${title}`) });
    await expect(header).toHaveAttribute("aria-expanded", "false");
    const before = await results(page).getByRole("listitem").count();

    await header.click();
    await expect(header).toHaveAttribute("aria-expanded", "true");
    await expect(row.getByText(`Guard already installed the ${npm} shim on this machine.`, { exact: false })).toBeVisible();
    await row.getByRole("button", { name: "Mark as resolved", exact: true }).click();

    await expect(row).toHaveCount(0);
    await expect(results(page).getByRole("listitem")).toHaveCount(before - 1);
    await page.getByRole("button", { name: "Resolved", exact: true }).click();
    await expect(row.getByText("Resolved", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Open", exact: true }).click();

    // Resolved marks live in the page only, so a reload lists the issue again.
    await page.reload();
    await expect(resultRow(page, title)).toBeVisible();
  });

  test("repair asks for the approval password and backing out changes nothing", async ({ page, state }) => {
    const [npm] = supplySeed(state).shimmedManagers;
    const before = await loadPackageShims(state);
    await openAudit(page);
    await resultRow(page, pathRepairTitle(npm)).getByRole("button", { name: "Repair PATH", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Repair PATH" });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText("Approval required", { exact: true })).toBeVisible();
    await expect(dialog.getByRole("button", { name: "Run remediation", exact: true })).toBeDisabled();
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(dialog).toHaveCount(0);

    const after = await loadPackageShims(state);
    expect(after.package_shims.path_status).toBe(before.package_shims.path_status);
    expect(after.package_shims.path_broken_managers).toEqual(before.package_shims.path_broken_managers);
  });
});
