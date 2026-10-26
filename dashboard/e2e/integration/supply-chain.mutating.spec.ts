import { daemonApi, expect, expectNoErrorBoundary, test } from "./fixtures";
import { expectedRows, loadPackageShims, managerCard, supplySeed } from "./supply-chain-helpers";

type Receipt = {
  receipt_id: string;
  harness: string;
  artifact_id: string;
  capabilities_summary: string;
  scanner_evidence?: Array<{ operation?: string; package_inventory?: Array<{ name: string }> }>;
};

const packageFirewallReceipts = async (state: Parameters<typeof loadPackageShims>[0]) =>
  (await daemonApi<{ items: Receipt[] }>(state, "/v1/receipts?harness=package-firewall&limit=100")).items;

const auditReceipts = (receipts: Receipt[]) =>
  receipts.filter((receipt) => receipt.scanner_evidence?.some((entry) => entry.operation === "audit"));

test.describe("Supply chain actions against the live daemon", () => {
  test("workspace audit indexes the seeded project and records the result", async ({ page, state }) => {
    const seed = supplySeed(state);
    const before = auditReceipts(await packageFirewallReceipts(state));
    expect((await loadPackageShims(state)).package_shims).toMatchObject({ lastAuditProofAt: null });

    await page.goto("/audit");
    await expect(page.getByRole("heading", { level: 1, name: "Audit", exact: true })).toBeVisible();
    await expect(page.getByRole("textbox", { name: "Project folder" })).toHaveValue(seed.project);
    await page.getByRole("button", { name: "Run audit", exact: true }).click();

    // Auditing needs no approval and works against the local daemon only.
    await expect(page.getByText("Scanned 1 manifest · 1 lockfile across this workspace.")).toBeVisible();
    await expectNoErrorBoundary(page);
    await expect(page.getByRole("button", { name: "Run audit again", exact: true })).toBeEnabled();
    await expect(page.getByText("Local intel only", { exact: true })).toBeVisible();
    await expect(page.getByText(`${seed.packages.length} packages indexed`)).toBeVisible();
    await expect(page.getByText("This device is using local intel only.", { exact: false })).toBeVisible();
    await expect(page.getByRole("button", { name: `All packages ${seed.packages.length} results` })).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByRole("button", { name: "Needs review 0 results" })).toBeVisible();

    const table = page.getByRole("table", { name: "Indexed packages" });
    for (const name of seed.packages) {
      await expect(table.getByRole("button", { name: `${name} npm monitor low` })).toBeVisible();
    }
    await expect(page.getByText(`Showing ${seed.packages.length} findings`, { exact: true })).toBeVisible();

    // The daemon recorded one audit receipt listing exactly the lockfile packages.
    const after = auditReceipts(await packageFirewallReceipts(state));
    expect(after).toHaveLength(before.length + 1);
    const known = new Set(before.map((receipt) => receipt.receipt_id));
    const created = after.find((receipt) => !known.has(receipt.receipt_id));
    expect(created?.capabilities_summary).toContain(`across ${seed.packages.length} packages`);
    const inventory = created?.scanner_evidence?.find((entry) => entry.operation === "audit")?.package_inventory ?? [];
    expect(inventory.map((entry) => entry.name).sort()).toEqual([...seed.packages].sort());
    expect((await loadPackageShims(state)).package_shims).not.toMatchObject({ lastAuditProofAt: null });
  });

  test("audit results open a finding and filter by search", async ({ page, state }) => {
    const seed = supplySeed(state);
    await page.goto("/audit");
    // The finished audit is restored from the daemon, no re-run needed.
    await expect(page.getByText("Scanned 1 manifest · 1 lockfile across this workspace.")).toBeVisible();

    await page.getByRole("button", { name: "left-pad npm monitor low" }).click();
    const detail = page.getByRole("dialog", { name: "Finding detail for left-pad" });
    await expect(detail).toBeVisible();
    await expect(detail.getByText("no_cached_match", { exact: false })).toBeVisible();
    await expect(detail.getByText("Advisory aliases", { exact: true })).toBeVisible();
    await expect(detail.getByText("No linked CVE or GHSA aliases for this finding.")).toBeVisible();
    await detail.getByRole("button", { name: "Close finding detail", exact: true }).click();
    await expect(detail).toHaveCount(0);

    await page.getByRole("button", { name: "Filters", exact: true }).click();
    const filters = page.getByRole("dialog", { name: "Filter and sort package findings" });
    await expect(filters.getByRole("combobox", { name: "Ecosystem" })).toHaveValue("all");
    await filters.getByRole("searchbox", { name: "Search package findings" }).fill("left");
    await filters.getByRole("button", { name: "Show results", exact: true }).click();
    await expect(filters).toHaveCount(0);
    const table = page.getByRole("table", { name: "Indexed packages" });
    await expect(table.getByRole("button")).toHaveCount(1);
    await expect(table.getByRole("button", { name: "left-pad npm monitor low" })).toBeVisible();
    await expect(page.getByText("Showing 1 finding", { exact: true })).toBeVisible();
    // The summary still counts the whole inventory.
    await expect(page.getByRole("button", { name: `All packages ${seed.packages.length} results` })).toBeVisible();

    // An active filter adds its count to the button name.
    await page.getByRole("button", { name: "Filters 1", exact: true }).click();
    await filters.getByRole("button", { name: "Reset all", exact: true }).click();
    await filters.getByRole("button", { name: "Show results", exact: true }).click();
    await expect(table.getByRole("button")).toHaveCount(seed.packages.length);
  });

  test("hub reports the finished audit", async ({ page, state }) => {
    const seed = supplySeed(state);
    await page.goto("/supply-chain");
    await expect(page.getByRole("heading", { level: 1, name: "Supply Chain", exact: true })).toBeVisible();
    const rail = page.getByRole("region", { name: "Recent supply chain evidence" });
    await expect(rail.getByText("Workspace audit completed", { exact: true })).toBeVisible();
    await expect(
      rail.getByText(`Workspace audit completed with allow decision across ${seed.packages.length} packages.`, { exact: true }),
    ).toBeVisible();
    await expect(rail.getByText("No workspace audit yet")).toHaveCount(0);
    await expect(page.getByText(`0 packages need review across ${seed.packages.length} indexed.`, { exact: true })).toBeVisible();
    await expect(page.getByText("Last audit proof", { exact: false })).toBeVisible();
  });

  test("removing and re-protecting a manager needs the approval password and updates the daemon", async ({ page, state }) => {
    const [manager, other] = supplySeed(state).shimmedManagers;
    const detected = expectedRows(await loadPackageShims(state)).find((row) => row.manager === manager)?.detected ?? false;
    const receiptsBefore = (await packageFirewallReceipts(state)).length;

    await page.goto("/supply-chain");
    await expect(page.getByRole("heading", { level: 1, name: "Supply Chain", exact: true })).toBeVisible();
    const card = managerCard(page, manager);
    await expect(card.getByText("PATH broken", { exact: true })).toBeVisible();

    // Remove asks twice (inline confirm, then the approval password); backing out of either changes nothing.
    await card.getByRole("button", { name: "Remove", exact: true }).click();
    await card.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(card.getByRole("button", { name: "Remove", exact: true })).toBeVisible();
    await card.getByRole("button", { name: "Remove", exact: true }).click();
    await card.getByRole("button", { name: "Confirm", exact: true }).click();
    const removeDialog = page.getByRole("dialog", { name: `Remove ${manager}` });
    await expect(removeDialog.getByText("Approval required", { exact: true })).toBeVisible();
    const confirm = removeDialog.getByRole("button", { name: "Remove", exact: true });
    await expect(confirm).toBeDisabled();
    await removeDialog.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(removeDialog).toHaveCount(0);
    expect((await loadPackageShims(state)).package_shims.installed_managers).toContain(manager);

    await card.getByRole("button", { name: "Remove", exact: true }).click();
    await card.getByRole("button", { name: "Confirm", exact: true }).click();
    await removeDialog.getByRole("textbox", { name: "Approval password" }).fill(state.approvalPassword);
    await confirm.click();
    await expect(removeDialog).toHaveCount(0);

    const result = page.getByRole("status").filter({ hasText: `remove — ${manager}` });
    await expect(result.getByText("remove completed.", { exact: true })).toBeVisible();
    const receiptId = (await result.innerText()).match(/guard-receipt-[0-9a-f-]+/)?.[0];
    expect(receiptId, "result panel shows the proof receipt id").toBeTruthy();

    // The daemon dropped this manager's shim and kept the other one.
    const removed = (await loadPackageShims(state)).package_shims;
    expect(removed.installed_managers).not.toContain(manager);
    expect(removed.installed_managers).toContain(other);
    const receipts = await packageFirewallReceipts(state);
    expect(receipts.length).toBeGreaterThan(receiptsBefore);
    expect(receipts.map((receipt) => receipt.receipt_id)).toContain(receiptId);

    if (detected) {
      await expect(card.getByText("Detected, not protected", { exact: true })).toBeVisible();
    } else {
      await expect(card).toHaveCount(0);
    }
    await expect(managerCard(page, other).getByText("PATH broken", { exact: true })).toBeVisible();

    // A reload keeps the removal.
    await page.reload();
    await expect(page.getByRole("heading", { level: 1, name: "Supply Chain", exact: true })).toBeVisible();
    if (detected) await expect(managerCard(page, manager).getByText("Detected, not protected", { exact: true })).toBeVisible();
    await expect(managerCard(page, other).getByText("PATH broken", { exact: true })).toBeVisible();

    // Put it back so the machine ends in the seeded state.
    if (!detected) return;
    await managerCard(page, manager).getByRole("button", { name: "Protect", exact: true }).click();
    const installDialog = page.getByRole("dialog", { name: `Install ${manager}` });
    await expect(installDialog.getByRole("button", { name: "Install", exact: true })).toBeDisabled();
    await installDialog.getByRole("textbox", { name: "Approval password" }).fill(state.approvalPassword);
    await installDialog.getByRole("button", { name: "Install", exact: true }).click();
    await expect(installDialog).toHaveCount(0);
    await expect(page.getByRole("status").filter({ hasText: `install — ${manager}` }).getByText("install completed for 1 manager.")).toBeVisible();
    await expect(managerCard(page, manager).getByText("PATH broken", { exact: true })).toBeVisible();
    const restored = (await loadPackageShims(state)).package_shims;
    expect(restored.installed_managers).toEqual(expect.arrayContaining([manager, other]));
  });

  test("sync without Guard Cloud asks for approval to sync intel only", async ({ page }) => {
    // Sync posts a package-protection change and holds its lock, so it runs
    // with the other changes instead of beside parallel read specs.
    await page.goto("/supply-chain");
    await expectNoErrorBoundary(page);
    await page.getByRole("button", { name: "Sync", exact: true }).click();
    // A standalone sync runs no audit afterwards, so the dialog must not promise one.
    const dialog = page.getByRole("dialog", { name: "Approve supply-chain intel sync" });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole("heading", { name: "Approve supply-chain intel sync" })).toBeVisible();
    await expect(dialog.getByText("Run audit", { exact: true })).toHaveCount(0);
    await expect(dialog.getByRole("textbox", { name: "Approval password" })).toHaveValue("");
    await expect(dialog.getByRole("button", { name: "Sync supply-chain intel", exact: true })).toBeDisabled();
    await dialog.getByRole("button", { name: "Close", exact: true }).click();
    await expect(dialog).toHaveCount(0);
  });
});
