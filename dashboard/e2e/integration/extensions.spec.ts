import type { Page } from "@playwright/test";

import { daemonApi, expect, expectNoErrorBoundary, test, type IntegrationState } from "./fixtures";
import { escapeRegExp } from "./inbox-helpers";

type CatalogIndex = { total_count: number; items: { extension_id: string; name: string }[] };
type CatalogRules = { total_count: number; items: { rule_id: string; title: string }[] };
type SeededExtensions = { custom_cli_id: string; custom_cli_name: string; custom_cli_example: string };

function seeded(state: IntegrationState): SeededExtensions {
  return state.seeded.extensions as unknown as SeededExtensions;
}

// The catalog loads from the bounded v2 read model, so wait for its heading
// rather than the route change.
async function openCatalog(page: Page) {
  await page.goto("/extensions");
  await expectNoErrorBoundary(page);
  await expect(page.getByRole("heading", { name: "Extensions", level: 1 })).toBeVisible();
  await expect(page.getByRole("heading", { name: "All tools" })).toBeVisible();
}

const searchBox = (page: Page) => page.getByRole("searchbox", { name: "Search command patterns" });
const filterTrigger = (page: Page) => page.getByTestId("catalog-filters").getByRole("button", { name: /^Filters/ });
const viewSwitch = (page: Page) => page.getByRole("group", { name: "Extension list" });

test("catalog lists every built-in tool the daemon's real catalog serves", async ({ page, state }) => {
  const index = await daemonApi<CatalogIndex>(state, "/v2/extension-controls/catalog/index");
  await openCatalog(page);

  const catalog = page.getByRole("region", { name: "All tools" });
  await expect(page.getByTestId("catalog-tool-count")).toHaveText(`${index.total_count.toLocaleString("en-US")} tools`);

  // The status summary splits the same total into on, always-on and off.
  const summary = await catalog.getByRole("img", { name: /^\d+ on, \d+ always on, \d+ off$/ }).getAttribute("aria-label");
  const parts = (summary ?? "").match(/\d+/g)?.map(Number) ?? [];
  expect(parts.reduce((sum, part) => sum + part, 0)).toBe(index.total_count);
  await expect(catalog.getByRole("list", { name: "Catalog status" }).getByRole("listitem")).toHaveCount(4);

  // Rows come from the catalog: the first entries the daemon serves, plus the
  // built-in API gateway extension the policy flow edits. Catalog names carry a
  // "protection" suffix the rows drop.
  for (const item of index.items.slice(0, 3)) {
    const name = item.name.replace(/ (?:command )?protection$/, "");
    await expect(catalog.getByRole("button", { name: new RegExp(`^${escapeRegExp(name)}\\b`) }).first()).toBeVisible();
  }
  await expect(catalog.getByRole("button", { name: /^API gateway\b.*HOL curated library/ })).toBeVisible();

  await expect(searchBox(page)).toBeVisible();
  await expect(page.getByRole("button", { name: "Add custom extension" })).toBeVisible();
  await expect(page.getByRole("heading", { name: /^(Protected|Finish setup|Needs repair|Protection limited|Emergency Lockdown active)$/ })).toBeVisible();
});

test("search matches command patterns across tools and recovers from no results", async ({ page }) => {
  await openCatalog(page);

  await searchBox(page).fill("kubectl");
  await expect(page.getByRole("region", { name: "Kubernetes operation protection patterns" })).toBeVisible();
  await expect(page.getByRole("group", { name: /^Quick apply to \d+ matching capabilities$/ })).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: /matching capabilities/ })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Forced Kubernetes replace", level: 3 })).toBeVisible();

  // A tool name also reaches its tool, listed apart from the patterns.
  await searchBox(page).fill("git");
  await expect(page.getByLabel("Matching tools")).toBeVisible();

  await searchBox(page).fill("zzzz-no-such-command");
  await expect(page.getByText("No command patterns or tools match this search.")).toBeVisible();
  await expect(page.getByRole("group", { name: /^Quick apply to/ })).toHaveCount(0);

  await page.getByRole("button", { name: "Clear search" }).click();
  await expect(searchBox(page)).toHaveValue("");
  await expect(page.getByRole("heading", { name: "All tools" })).toBeVisible();
});

test("trust, kind and area filters narrow the catalog and clear together", async ({ page }) => {
  await openCatalog(page);
  const total = await page.getByTestId("catalog-tool-count").innerText();
  const toolsIn = (text: string) => Number(/(\d[\d,]*) tools?/.exec(text)?.[1]?.replace(/,/g, ""));
  const keptIn = (text: string) => Number(/^(\d[\d,]*) of /.exec(text)?.[1]?.replace(/,/g, ""));

  await expect(page.getByRole("group", { name: "Trust" })).toBeHidden();
  await filterTrigger(page).click();
  await expect(filterTrigger(page)).toHaveAttribute("aria-expanded", "true");
  for (const group of ["Trust", "Kind", "Area"]) {
    await expect(page.getByRole("group", { name: group })).toBeVisible();
  }

  // Each filter button names how many tools it keeps, and the catalog agrees.
  const filters = page.getByTestId("catalog-filters");
  const external = filters.getByRole("button", { name: /^External, \d+ tools?$/ });
  const externalCount = toolsIn((await external.getAttribute("aria-label")) ?? (await external.innerText()));
  expect(externalCount).toBeGreaterThan(0);
  await external.click();
  await expect(external).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByTestId("catalog-filter-count")).toHaveText(`${externalCount} of ${toolsIn(total)} tools`);
  await expect(page.getByRole("button", { name: "Remove External trust filter" })).toBeVisible();

  // A second filter narrows further instead of replacing the first.
  const mcp = filters.getByRole("button", { name: /^MCP, \d+ tools?$/ });
  await mcp.click();
  await expect(mcp).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("button", { name: "Clear all 2 filters" })).toBeVisible();
  const both = keptIn(await page.getByTestId("catalog-filter-count").innerText());
  expect(both).toBeLessThanOrEqual(externalCount);

  await page.getByRole("button", { name: "Clear all 2 filters" }).click();
  await expect(external).toHaveAttribute("aria-pressed", "false");
  await expect(mcp).toHaveAttribute("aria-pressed", "false");
  await expect(page.getByTestId("catalog-filter-count")).toHaveText(total);
  await expect(page.getByTestId("catalog-tool-count")).toHaveText(total);
});

test("the list switch moves between built-in tools and detected custom extensions", async ({ page, state }) => {
  const { custom_cli_id: cliId, custom_cli_name: cliName } = seeded(state);
  await openCatalog(page);

  const builtIn = viewSwitch(page).getByRole("button", { name: /^All tools/ });
  const custom = viewSwitch(page).getByRole("button", { name: /^Custom extensions/ });
  await expect(builtIn).toHaveAttribute("aria-pressed", "true");
  await expect(custom).toHaveAttribute("aria-pressed", "false");
  // The seeded tool has commands Guard was not told to trust, so it needs review.
  await expect(custom).toContainText(/\d+ need review/);

  await custom.click();
  await expect(custom).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("heading", { name: "All tools" })).toHaveCount(0);
  const section = page.getByTestId("custom-extensions-section");
  await expect(section.getByRole("heading", { name: "Custom extensions" })).toBeVisible();
  const row = section.getByRole("button", { name: new RegExp(`^${escapeRegExp(cliName)}\\b`) });
  await expect(row).toContainText("Custom");
  await expect(row).toContainText("Detected");
  await expect(row).toContainText("Guard detected this tool. Review it before adding it.");
  await expect(row).toContainText("Review and add");

  await builtIn.click();
  await expect(builtIn).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("heading", { name: "All tools" })).toBeVisible();
  await expect(section).toBeHidden();

  // The row opens the connector's own page, which offers adding or forgetting
  // it. Adding needs the approval password, so the dialog is opened and closed.
  await custom.click();
  await section.getByRole("button", { name: new RegExp(`^${escapeRegExp(cliName)}\\b`) }).click();
  await expect(page).toHaveURL(new RegExp(`/extensions/local-cli/${escapeRegExp(cliId)}(?:[?#]|$)`));
  await expectNoErrorBoundary(page);
  await expect(page.getByRole("heading", { name: cliName, level: 1 })).toBeVisible();
  await expect(page.getByText(seeded(state).custom_cli_example)).toBeVisible();
  await expect(page.getByRole("button", { name: "Forget this connection" })).toBeVisible();
  await page.getByRole("button", { name: "Add custom extension" }).click();
  const dialog = page.getByRole("dialog", { name: `Save ${cliName} command settings` });
  await expect(dialog.getByRole("button", { name: "Confirm" })).toBeDisabled();
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toBeHidden();
});

test("a built-in extension opens with its permissions, rules and technical details", async ({ page, state }) => {
  const rules = await daemonApi<CatalogRules>(state, "/v2/extension-controls/catalog/extensions/command.git/rules");
  const hardReset = rules.items.find((rule) => rule.rule_id === "command.git.hard-reset");
  expect(hardReset, "the real catalog defines a Git hard reset rule").toBeDefined();

  // Reach the detail page the way a person does: from the catalog row.
  await openCatalog(page);
  await page.getByRole("region", { name: "All tools" }).getByRole("button", { name: /^API gateway\b/ }).click();
  await expect(page).toHaveURL(/\/extensions\/command\.api-gateway(?:[?#]|$)/);
  await expect(page.getByTestId("protection-module-detail")).toBeVisible();
  await expect(page.getByRole("heading", { name: /^API gateway\b/, level: 1 })).toBeVisible();
  await page.getByRole("tab", { name: "Permissions" }).click();
  const permission = page.locator('[data-permission-id="command.api-gateway.permission.delete"]');
  await expect(permission).toBeVisible();
  await expect(permission.getByRole("radio", { name: "Recommended" })).toHaveAttribute("aria-checked", "true");
  await expect(permission.getByRole("radio", { name: "Block" })).toBeEnabled();

  await page.goto("/extensions/command.git");
  await expectNoErrorBoundary(page);
  await expect(page.getByRole("heading", { name: "Git protection", level: 1 })).toBeVisible();
  await expect(page.getByRole("tablist", { name: "Extension detail sections" }).getByRole("tab")).toHaveText([
    "Overview",
    "Permissions",
    "Managed controls",
    "Activity",
    "Technical details",
  ]);
  await expect(page.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
  const ruleCount = page.locator("dt", { hasText: "Detection rules" }).locator("xpath=following-sibling::dd[1]");
  await expect(ruleCount).toHaveText(String(rules.total_count));

  await page.getByRole("tab", { name: "Technical details" }).click();
  await page.getByTestId("protection-more-detail").locator("summary").click();
  await expect(page.getByRole("heading", { name: "Detections" })).toBeVisible();
  await expect(page.getByRole("table").getByText(hardReset?.title ?? "", { exact: true })).toBeVisible();
  await expect(page.getByText("command.git.hard-reset", { exact: true })).toBeVisible();
  await expect(
    page.locator("dt", { hasText: "Extension ID" }).locator("xpath=following-sibling::dd[1]").getByText("command.git", { exact: true }),
  ).toBeVisible();

  await page.getByTestId("protection-module-detail").getByRole("button", { name: "Extensions" }).click();
  await expect(page.getByRole("heading", { name: "Extensions", level: 1 })).toBeVisible();
});

test("the Test Lab shows what Guard would decide for a command without running it", async ({ page }) => {
  await page.goto("/extensions/command.git");
  await page.getByRole("tab", { name: "Activity" }).click();
  await expect(page.getByRole("heading", { name: "Test Lab", exact: true })).toBeVisible();

  const titles = {
    allowed: "Guard would allow this",
    "ask-first": "Guard would ask first",
    blocked: "Guard would block this",
  } as const;
  // The decision depends on whether the daemon has its native command
  // evaluator (without it, Guard asks first about everything), so the check is
  // that the page reports exactly what the daemon answered.
  for (const command of ["git reset --hard HEAD~1", "git status"]) {
    await page.getByLabel("Command to check").fill(command);
    const answered = page.waitForResponse(
      (response) => new URL(response.url()).pathname === "/v1/extension-controls/test" && response.status() === 200,
    );
    await page.getByRole("button", { name: "Check safely" }).click();
    const body = await (await answered).text();
    // Checking a command never stores or echoes it.
    expect(body).not.toContain(command);
    const decision = (JSON.parse(body) as { decision: keyof typeof titles }).decision;
    expect(Object.keys(titles)).toContain(decision);
    await expect(page.getByRole("status").filter({ hasText: titles[decision] })).toBeVisible();
  }
  await expect(page.getByRole("alert")).toHaveCount(0);
});
