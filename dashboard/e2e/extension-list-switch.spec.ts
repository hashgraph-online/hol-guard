import { expect, test } from "@playwright/test";
import { catalog, extension, initialize, mount } from "./extension-control-fixtures";

function localCli(index: number, state: "unset" | "allow") {
  return {
    cli_id: `local-cli.switch-${index}`, name: `switch-connector-${index}`, kind: "executable", identity_hash: "b".repeat(64),
    example_label: "switch-mcp", interpreter_name: null, observed_count: 1, last_seen_at: "2026-09-27T12:00:00Z",
    surface: "mcp", source_label: "Fixture host", source_path: null, help_status: "ok", state, stale: false,
    suggestable: true, grant_revision: null, authority_revision: 1, commands: [],
  };
}

for (const width of [1280, 390]) {
  test(`the list switch swaps built-in and custom lists in place at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await mount(page, { catalog: { ...catalog(), extensions: [extension("command.git", "")] } });
    await page.route("**/v1/local-clis**", (route) => route.fulfill({ json: {
      schema_version: "guard.daemon.local-clis.v1", revision: 1, items: [localCli(1, "unset"), localCli(2, "allow")],
      cloud: { sync_local_only: true, summary: "Synthetic fixture." },
    } }));
    await initialize(page);

    const switcher = page.getByTestId("extension-list-switch");
    const builtin = switcher.getByRole("button", { name: /^All tools/ });
    const custom = switcher.getByRole("button", { name: /^Custom extensions/ });
    await expect(builtin).toHaveAttribute("aria-pressed", "true");
    await expect(custom).toHaveAttribute("aria-pressed", "false");
    await expect(custom).toContainText("1 need review");
    await expect(page.getByTestId("custom-extensions-section")).toBeHidden();

    await custom.click();
    await expect(custom).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByTestId("custom-extensions-section")).toBeVisible();
    await expect(page.getByRole("button", { name: /switch-connector-1/ })).toBeVisible();
    await expect(page.getByRole("button", { name: "Add custom extension", exact: true })).toHaveCount(1);

    await builtin.click();
    await expect(builtin).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByTestId("custom-extensions-section")).toBeHidden();
    await expect(page.getByRole("button", { name: "Add custom extension", exact: true })).toHaveCount(1);
    expect(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)).toBe(false);
  });
}
