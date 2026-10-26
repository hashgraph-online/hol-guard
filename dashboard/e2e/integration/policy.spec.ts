import type { Locator } from "@playwright/test";

import { expect, expectNoErrorBoundary, test } from "./fixtures";
import { escapeRegExp } from "./inbox-helpers";
import {
  ACTION_LABEL,
  APP_LABEL,
  SCOPE_LABEL,
  cloudRow,
  localRules,
  policySeed,
  policyTab,
  rememberedRow,
} from "./policy-helpers";

test.describe("Rules & exceptions against the live daemon", () => {
  test("remembered rules list every seeded rule with its action, app and scope", async ({ page, state }) => {
    const seed = policySeed(state);
    await page.goto("/policy");
    await expect(page.getByRole("table", { name: "Remembered policy rules" })).toBeVisible();
    await expectNoErrorBoundary(page);

    for (const rule of localRules(seed)) {
      const row = rememberedRow(page, rule.title);
      await expect(row, rule.title).toHaveCount(1);
      await expect(row.getByRole("cell", { name: ACTION_LABEL[rule.action], exact: true })).toBeVisible();
      // The App cell also carries when the rule was last updated.
      const appCell = new RegExp(`^${escapeRegExp(`${APP_LABEL[rule.harness]} ${SCOPE_LABEL[rule.scope]}`)}(?: .+ ago| just now)?$`);
      await expect(row.getByRole("cell", { name: appCell })).toBeVisible();
      await expect(row.getByRole("cell", { name: "Remembered on this device" })).toBeVisible();
    }
    await expect(page.getByRole("table", { name: "Remembered policy rules" }).getByRole("row")).toHaveCount(
      // The header row plus one row per rule — local and cloud share one list.
      seed.total + 1,
    );
  });

  test("summary, tab badge and action filter counts match the seeded rules", async ({ page, state }) => {
    const seed = policySeed(state);
    await page.goto("/policy");
    await expect(policyTab(page, /^Remembered rules/)).toContainText(String(seed.total));
    const filter = page.getByRole("group", { name: "Filter by action" });
    await expect(filter.getByRole("button", { name: `All actions ${seed.total}` })).toHaveAttribute("aria-pressed", "true");
    await expect(filter.getByRole("button", { name: `Allow ${seed.allowCount}` })).toBeVisible();
    await expect(filter.getByRole("button", { name: `Block ${seed.blockCount}` })).toBeVisible();
    // Six rules live on this device, the seventh is synced from Guard Cloud.
    await expect(page.getByText(`${seed.total - 1} on this device`)).toBeVisible();
  });

  test("the broad allow is flagged and called out for a second look", async ({ page, state }) => {
    const seed = policySeed(state);
    await page.goto("/policy");
    await expect(page.getByRole("heading", { name: "1 broad allow deserves a second look", level: 1 })).toBeVisible();
    const strip = page.getByRole("status").filter({ hasText: "Broad allow:" });
    await expect(strip.getByText(seed.global_allow.title)).toBeVisible();
    await expect(rememberedRow(page, seed.global_allow.title).getByText("Broad allow")).toBeVisible();
    // A rule scoped to one project is not a broad allow.
    await expect(rememberedRow(page, seed.workspace_allow.title).getByText("Broad allow")).toHaveCount(0);
    // The global rule has no checkbox: bulk removal can never wipe global policy.
    await expect(rememberedRow(page, seed.global_allow.title).getByRole("checkbox")).toHaveCount(0);
  });

  test("rules synced from Guard Cloud are read-only", async ({ page, state }) => {
    const seed = policySeed(state);
    await page.goto("/policy");
    const row = cloudRow(page, seed.cloud_block.title);
    await expect(row).toHaveCount(1);
    await expect(row.getByRole("cell", { name: ACTION_LABEL[seed.cloud_block.action], exact: true })).toBeVisible();
    await expect(row.getByRole("cell", { name: "Synced contextual rule" })).toBeVisible();
    await expect(row.getByText("Read-only")).toBeVisible();
    await expect(row.getByRole("button", { name: "Remove rule" })).toHaveCount(0);
    await expect(row.getByRole("checkbox")).toHaveCount(0);
    await expect(page.getByText("Guard Cloud not connected")).toBeVisible();
  });

  test("filtering by action then searching narrows the table, and clearing restores it", async ({ page, state }) => {
    const seed = policySeed(state);
    await page.goto("/policy");
    const filter = page.getByRole("group", { name: "Filter by action" });
    await filter.getByRole("button", { name: `Block ${seed.blockCount}` }).click();
    await expect(filter.getByRole("button", { name: `Block ${seed.blockCount}` })).toHaveAttribute("aria-pressed", "true");
    await expect(rememberedRow(page, seed.artifact_block.title)).toBeVisible();
    await expect(rememberedRow(page, seed.harness_block.title)).toBeVisible();
    await expect(rememberedRow(page, seed.workspace_allow.title)).toHaveCount(0);
    await expect(cloudRow(page, seed.cloud_block.title)).toBeVisible();

    await page.getByRole("searchbox", { name: "Search remembered rules" }).fill("npm install");
    await expect(rememberedRow(page, seed.harness_block.title)).toBeVisible();
    await expect(rememberedRow(page, seed.artifact_block.title)).toHaveCount(0);

    await page.getByRole("searchbox", { name: "Search remembered rules" }).fill("no such rule anywhere");
    await expect(page.getByRole("heading", { name: "No rules match" })).toBeVisible();
    await page.getByRole("button", { name: "Clear search and filters" }).click();
    for (const rule of localRules(seed)) {
      await expect(rememberedRow(page, rule.title), rule.title).toBeVisible();
    }
    await expect(filter.getByRole("button", { name: `All actions ${seed.total}` })).toHaveAttribute("aria-pressed", "true");
  });

  test("the inspector shows a local rule's details and closes on Escape", async ({ page, state }) => {
    const seed = policySeed(state);
    const rule = seed.workspace_allow;
    await page.goto("/policy");
    await page.getByRole("button", { name: `Inspect rule ${rule.title}`, exact: true }).first().click();
    const dialog = page.getByRole("dialog", { name: `Rule details: ${rule.title}` });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole("heading", { name: rule.title, level: 2 })).toBeVisible();
    await expectDetail(dialog, "Source", "Remembered on this device");
    await expectDetail(dialog, "Scope", SCOPE_LABEL[rule.scope]);
    await expectDetail(dialog, "App", APP_LABEL[rule.harness]);
    await expect(dialog.getByRole("button", { name: "Remove rule" })).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    await expect(rememberedRow(page, rule.title)).toBeVisible();
  });

  test("the inspector marks a Guard Cloud rule read-only", async ({ page, state }) => {
    const rule = policySeed(state).cloud_block;
    await page.goto("/policy");
    await cloudRow(page, rule.title).getByRole("button", { name: `Inspect rule ${rule.title}`, exact: true }).click();
    const dialog = page.getByRole("dialog", { name: `Rule details: ${rule.title}` });
    await expect(dialog).toBeVisible();
    await expectDetail(dialog, "Scope", SCOPE_LABEL[rule.scope]);
    await expectDetail(dialog, "App", APP_LABEL[rule.harness]);
    await expect(dialog.getByText("Managed in Guard Cloud")).toBeVisible();
    await expect(dialog.getByText("Read-only here")).toBeVisible();
    await expect(dialog.getByRole("button", { name: "Remove rule" })).toHaveCount(0);
    await dialog.getByRole("button", { name: "Close", exact: true }).click();
    await expect(dialog).toHaveCount(0);
  });

  test("tab switching keeps the session and records the tab in the URL fragment", async ({ page, state }) => {
    const seed = policySeed(state);
    await page.goto("/policy");
    await expect(policyTab(page, /^Remembered rules/)).toHaveAttribute("aria-selected", "true");

    await policyTab(page, /^Cloud exceptions/).click();
    await expect(policyTab(page, /^Cloud exceptions/)).toHaveAttribute("aria-selected", "true");
    await expect.poll(() => new URL(page.url()).hash).toContain("policy-view=cloud-exceptions");

    await policyTab(page, /^How Guard decides/).click();
    await expect(policyTab(page, /^How Guard decides/)).toHaveAttribute("aria-selected", "true");
    await expect.poll(() => new URL(page.url()).hash).toContain("policy-view=how-guard-decides");

    // Same page, same session: no reload, no token in the query, and the daemon
    // still answers when the first tab comes back.
    expect(new URL(page.url()).pathname).toBe("/policy");
    expect(page.url()).not.toContain("?guard-token");
    await policyTab(page, /^Remembered rules/).click();
    await expect(policyTab(page, /^Remembered rules/)).toHaveAttribute("aria-selected", "true");
    await expect(rememberedRow(page, seed.workspace_allow.title)).toBeVisible();
    await expectNoErrorBoundary(page);
  });

  test("a deep link and a reload both land on the tab in the fragment", async ({ page }) => {
    await page.goto("/policy#policy-view=how-guard-decides");
    await expect(policyTab(page, /^How Guard decides/)).toHaveAttribute("aria-selected", "true");
    await page.reload();
    await expect(policyTab(page, /^How Guard decides/)).toHaveAttribute("aria-selected", "true");
    await expect(page.getByRole("heading", { name: "Policy explains. Settings configures." })).toBeVisible();
    await expectNoErrorBoundary(page);
  });

  test("the Cloud exceptions tab explains that Guard Cloud is not connected", async ({ page }) => {
    await page.goto("/policy#policy-view=cloud-exceptions");
    await expect(page.getByRole("heading", { name: "Guard Cloud is not connected" })).toBeVisible();
    await expect(page.getByText("Cloud exceptions are managed in Guard Cloud.")).toBeVisible();
    await expect(page.getByRole("button", { name: "+ Request cloud exception" })).toBeDisabled();
    await expect(page.getByText("Connect Guard Cloud to request an exception.")).toBeVisible();
    await expect(page.getByRole("button", { name: "Connect Guard Cloud" })).toBeEnabled();
    await expectNoErrorBoundary(page);
  });

  test("How Guard decides explains the evaluation order and links to protection rules", async ({ page }) => {
    await page.goto("/policy#policy-view=how-guard-decides");
    await expect(page.getByRole("heading", { name: "Policy explains. Settings configures." })).toBeVisible();
    for (const step of [
      "If a remembered local rule matches, apply it.",
      "Then apply the signed Cloud policy bundle.",
      "Matching Cloud exception allows the action.",
      "If nothing allows it, this strict config is used.",
      "Guard asks (or blocks) according to your choice.",
    ]) {
      await expect(page.getByText(step, { exact: true }), step).toBeVisible();
    }
    await expect(
      page.getByText("Evaluation order: Local remembered rule → Guard Cloud policy → Cloud exception → Strict fallback → Ask or block."),
    ).toBeVisible();
    await page.getByRole("button", { name: "Open protection rules" }).click();
    await expect.poll(() => new URL(page.url()).pathname).toBe("/settings");
    await expect(page.getByRole("region", { name: "Advanced rules" })).toBeVisible();
    await expectNoErrorBoundary(page);
  });
});

async function expectDetail(dialog: Locator, label: string, value: string): Promise<void> {
  await expect(dialog.locator("dt", { hasText: label }).locator("xpath=following-sibling::dd[1]")).toHaveText(value);
}
