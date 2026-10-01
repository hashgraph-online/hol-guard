import { expect, test } from "@playwright/test";
import { initialize, mount } from "./extension-control-fixtures";

for (const width of [1280, 390]) {
  test(`large connector inventory remains reachable at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const count = 120;
    const items = Array.from({ length: count }, (_, index) => ({
      cli_id: `local-cli.fixture-${index.toString().padStart(3, "0")}`,
      name: `Fixture connector ${index.toString().padStart(3, "0")}`,
      kind: "executable", identity_hash: "b".repeat(64),
      example_label: "fixture-mcp", interpreter_name: null, observed_count: 1,
      last_seen_at: "2026-09-27T12:00:00Z", surface: "mcp", source_label: "Fixture host",
      source_path: null, help_status: "ok", state: "unset", stale: false,
      suggestable: true, grant_revision: null, authority_revision: 1,
      commands: Array.from({ length: 100 }, (_, tool) => ({
        command_id: `tool-${tool}`, name: `Tool ${tool}`, usage: `tool ${tool}`,
        description: "Synthetic tool", parent_id: null, state: "inherit",
      })),
      mcp_catalog: { complete: true, stale: false, reason: null, pages: 1,
        listed_count: 100, known_count: 100, protocol_version: "2026-07-28",
        revision: 1, updated_at: "2026-09-27T12:00:00Z", last_complete_at: "2026-09-27T12:00:00Z",
        changes: { added: [], changed: [], removed: [], stale: [] } },
    }));
    await mount(page);
    await page.route("**/v1/local-clis**", (route) => route.fulfill({ json: {
      schema_version: "guard.daemon.local-clis.v1", revision: 1, items: items.slice(0, count),
      cloud: { sync_local_only: true, summary: "Synthetic fixture." },
    } }));
    await initialize(page);
    const section = page.getByTestId("custom-extensions-section");
    const rows = section.getByRole("button").filter({ hasText: /Fixture connector \d{3}/ });
    await expect(rows).toHaveCount(8);
    await section.getByRole("button", { name: "Browse all 120 extensions", exact: true }).click();
    await expect(rows).toHaveCount(25);
    const previous = section.getByRole("button", { name: "Previous page", exact: true });
    const next = section.getByRole("button", { name: "Next page", exact: true });
    await expect(previous).toBeDisabled();
    await expect(section.getByRole("status")).toHaveText("Page 1 of 5 · Showing 1–25 of 120");
    const visited = new Set<string>();
    await next.focus();
    for (let current = 0; current < 5; current += 1) {
      for (const name of await rows.allTextContents()) visited.add(name);
      if (current < 4) await page.keyboard.press("Enter");
      await expect(next).toBeFocused();
    }
    expect(visited.size).toBe(120);
    await expect(rows).toHaveCount(20);
    await expect(next).toBeDisabled();
    await page.keyboard.press("Enter");
    await expect(next).toBeFocused();
    await expect(section.getByRole("status")).toHaveText("Page 5 of 5 · Showing 101–120 of 120");
    await previous.click();
    await expect(section.getByRole("status")).toContainText("Page 4 of 5");
    await page.screenshot({ path: testInfo.outputPath(`connector-pages-${width}.png`), animations: "disabled" });
    expect(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)).toBe(false);

    await section.getByRole("searchbox", { name: "Search custom extensions" }).fill("connector 119");
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText("Fixture connector 119");
    await expect(next).toHaveCount(0);
    await section.getByRole("searchbox", { name: "Search custom extensions" }).fill("");
    await expect(rows).toHaveCount(8);
    await section.getByRole("button", { name: "Browse all 120 extensions", exact: true }).click();
    for (let current = 0; current < 4; current += 1) await next.click();
    await section.getByRole("button", { name: "Show fewer", exact: true }).click();
    await expect(rows).toHaveCount(8);
    expect(errors).toEqual([]);
  });
}
