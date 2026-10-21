import { expect, test } from "@playwright/test";
import { initialize, mount, showCustomExtensions } from "./extension-control-fixtures";

function project(id: string, name: string, folder: string, scripts: string[]) {
  const commands = [{ command_id: "root", name: "pnpm run", usage: "pnpm run", description: "Run pnpm run without a subcommand.", parent_id: null, state: "inherit" }];
  for (const script of scripts) {
    commands.push({ command_id: `script.${script}`, name: script, usage: `pnpm run ${script}`,
      description: `node scripts/${script.replace(/:/g, "-")}.mjs`, parent_id: null, state: "inherit" });
  }
  return {
    cli_id: `local-cli.${id}`, name, kind: "script", identity_hash: id.padEnd(64, "0").slice(0, 64),
    example_label: "pnpm run", interpreter_name: "pnpm", observed_count: 2, last_seen_at: "2026-10-16T12:00:00Z",
    surface: "package-scripts", source_label: folder, source_path: null, help_status: "ok", state: "unset",
    stale: false, suggestable: true, suggestion_score: id === "aaa" ? 200 : 100, grant_revision: null,
    authority_revision: 1, commands,
  };
}

const TYPECHECK = ["typecheck", "typecheck:ci", "typecheck:fec:ci"];
const TEST = ["test", "test:unit", "test:e2e", "test:smoke"];

for (const width of [1280, 390]) {
  test(`add flow names the project, switches in place, and groups scripts by family at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const items = [
      project("aaa", "dashboard", "web-app/dashboard", ["build", "dev", ...TYPECHECK, ...TEST]),
      project("bbb", "dashboard", "admin/dashboard", ["build", "lint"]),
      project("ccc", "docs-site", "docs-site", ["build"]),
    ];
    await mount(page);
    await page.route("**/v1/local-clis**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path.endsWith("/discover")) {
        await route.fulfill({ json: { schema_version: "guard.daemon.local-clis.v1", revision: 1, items,
          cloud: { sync_local_only: true, summary: "Synthetic fixture." } } });
        return;
      }
      await route.fulfill({ json: { schema_version: "guard.daemon.local-clis.v1", revision: 1, items,
        cloud: { sync_local_only: true, summary: "Synthetic fixture." } } });
    });
    await initialize(page);
    await showCustomExtensions(page);
    await page.getByRole("button", { name: "Add custom extension", exact: true }).first().click();

    const selected = page.getByRole("region", { name: "dashboard", exact: true });
    await expect(selected).toContainText("web-app/dashboard · 9 scripts");
    await expect(page.getByRole("textbox", { name: "Find a script" })).toHaveCount(0);

    // Nested names sit together in a family instead of a flat, oddly indented list.
    const typecheck = page.getByRole("region", { name: "typecheck scripts", exact: true });
    await expect(typecheck).toContainText("3 scripts");
    await expect(page.getByTestId("custom-extension-add-summary")).toContainText("9 scripts · 9 allowed");
    await expect(page.getByRole("button", { name: "Continue", exact: true })).toBeInViewport();
    if (process.env.HOL_GUARD_CAPTURE_PROOF === "1") {
      await page.screenshot({ path: testInfo.outputPath(`add-flow-${width}.png`), animations: "disabled" });
    }

    // Two folders share a package name; the switcher tells them apart by folder.
    await selected.getByRole("button", { name: "Change project" }).click();
    const list = page.getByRole("list", { name: "Projects on this device" });
    await expect(list.getByRole("button")).toHaveCount(4);
    await expect(list.locator('[aria-current="true"]')).toContainText("web-app/dashboard");
    if (process.env.HOL_GUARD_CAPTURE_PROOF === "1") {
      await page.screenshot({ path: testInfo.outputPath(`add-flow-switch-${width}.png`), animations: "disabled", fullPage: true });
    }
    await list.getByRole("button", { name: /admin\/dashboard/ }).click();
    await expect(selected).toContainText("admin/dashboard · 2 scripts");
    await expect(list).toHaveCount(0);
    await expect(page.getByTestId("custom-extension-add-summary")).toContainText("2 scripts");

    // A change is marked on the row and counted in the footer.
    await page.getByRole("radiogroup", { name: "lint protection setting" }).getByRole("radio", { name: "Block", exact: true }).click();
    await expect(page.locator('article[data-command-id="script.lint"]')).toContainText("Changed");
    await expect(page.getByTestId("custom-extension-add-summary")).toContainText("1 allowed · 1 blocked");

    // Another folder brings the command field back.
    await selected.getByRole("button", { name: "Change project" }).click();
    await page.getByRole("button", { name: "Use another folder or command" }).click();
    await expect(page.locator("#custom-extension-command")).toBeFocused();
    expect(errors).toEqual([]);
  });
}
