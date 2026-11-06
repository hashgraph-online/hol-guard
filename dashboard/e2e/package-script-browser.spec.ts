import { expect, test } from "@playwright/test";
import { initialize, mount, showCustomExtensions } from "./extension-control-fixtures";

const FAMILIES: Record<string, string[]> = {
  android: ["pixel", "emulator", "build", "release"],
  cap: ["android", "ios", "sync"],
  test: ["unit", "e2e", "smoke", "visual", "contract", "perf"],
  lint: ["ts", "css", "md"],
  db: ["migrate", "seed", "reset", "studio"],
  ios: ["sim", "device"],
};

function scripts() {
  const commands = [{ command_id: "root", name: "bun run", usage: "bun run", description: "Run bun run without a subcommand.", parent_id: null, state: "inherit" }];
  const add = (name: string, state: string) => commands.push({
    command_id: `script.${name}`, name, usage: `bun run ${name}`,
    description: `node scripts/${name.replace(/:/g, "-")}.mjs`, parent_id: null, state,
  });
  for (const name of ["build", "dev", "start", "preview", "format", "typecheck", "clean"]) add(name, "allow");
  for (const [family, members] of Object.entries(FAMILIES)) {
    add(family, "inherit");
    for (const member of members) add(`${family}:${member}`, family === "db" ? "block" : family === "test" ? "allow" : "inherit");
  }
  return commands;
}

for (const width of [1280, 390]) {
  test(`package scripts browse by family, filter, and bulk-apply to the shown rows at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const item = {
      cli_id: "local-cli.scripts-fixture", name: "demo-app", kind: "script",
      identity_hash: "c".repeat(64), example_label: "bun run", interpreter_name: "bun",
      observed_count: 3, last_seen_at: "2026-10-16T12:00:00Z", surface: "package-scripts",
      source_label: "demo-app", source_path: null, help_status: "ok", state: "allowed",
      stale: false, suggestable: true, grant_revision: 1, authority_revision: 1, commands: scripts(),
    };
    await mount(page);
    await page.route("**/v1/local-clis**", async (route) => {
      await route.fulfill({ json: { schema_version: "guard.daemon.local-clis.v1", revision: 1, items: [item],
        cloud: { sync_local_only: true, summary: "Synthetic fixture; this device only." } } });
    });
    await initialize(page);
    await showCustomExtensions(page);
    await page.getByRole("button", { name: /demo-app/ }).first().click();
    const detail = page.getByTestId("local-cli-detail");
    const toolbar = detail.getByTestId("custom-extension-command-toolbar");

    // The long catalog opens as a short index of families.
    await expect(detail.getByRole("button", { name: "Expand all", exact: true })).toBeVisible();
    const db = detail.getByRole("region", { name: "db scripts", exact: true });
    await expect(db).toContainText("5 scripts · 4 blocked · 1 Recommended");
    await expect(detail.getByRole("radiogroup", { name: "db:seed protection setting" })).toHaveCount(0);
    if (process.env.HOL_GUARD_CAPTURE_PROOF === "1") {
      await page.screenshot({ path: testInfo.outputPath(`scripts-index-${width}.png`), animations: "disabled", fullPage: true });
    }

    // A family choice sets every member, and the review bar counts it.
    await detail.getByRole("radiogroup", { name: "android family protection setting" })
      .getByRole("radio", { name: "Allow", exact: true }).click();
    await expect(detail.getByTestId("custom-extension-review-bar")).toContainText("5 unsaved command changes.");
    await detail.getByRole("region", { name: "android scripts", exact: true }).locator("button[aria-expanded]").click();
    await expect(detail.getByRole("radiogroup", { name: "android:pixel protection setting" })
      .getByRole("radio", { name: "Allow", exact: true })).toHaveAttribute("aria-checked", "true");

    // Search narrows across names and script bodies; bulk applies only to what is shown.
    await toolbar.getByRole("searchbox", { name: "Find a script", exact: true }).fill("cap");
    await expect(detail.getByTestId("custom-extension-bulk-scope")).toContainText("Applies to the 4 scripts shown.");
    await detail.getByTestId("custom-extension-bulk-policy").getByRole("radio", { name: "Block all", exact: true }).click();
    await expect(detail.getByTestId("custom-extension-review-bar")).toContainText("9 unsaved command changes.");
    await toolbar.getByRole("searchbox", { name: "Find a script", exact: true }).fill("");
    await toolbar.getByRole("button", { name: /^Unsaved/ }).click();
    await expect(detail.locator("article[data-command-id]")).toHaveCount(9);
    await expect(detail.locator('article[data-command-id="script.android:pixel"]')).toContainText("Unsaved");
    if (process.env.HOL_GUARD_CAPTURE_PROOF === "1") {
      await page.screenshot({ path: testInfo.outputPath(`scripts-unsaved-${width}.png`), animations: "disabled", fullPage: true });
    }

    await toolbar.getByRole("button", { name: /^Blocked/ }).click();
    // Editing a row under a setting filter keeps it in view until the view changes.
    const blockedRows = await detail.locator("article[data-command-id]").count();
    await detail.getByRole("radiogroup", { name: "db:seed protection setting" })
      .getByRole("radio", { name: "Allow", exact: true }).click();
    await expect(detail.locator("article[data-command-id]")).toHaveCount(blockedRows);
    await toolbar.getByRole("searchbox", { name: "Find a script", exact: true }).fill("no-such-script");
    await detail.getByRole("button", { name: "Clear search and filters", exact: true }).click();
    await expect(detail.getByRole("button", { name: "Expand all", exact: true })).toBeVisible();

    await detail.getByRole("button", { name: "Reset changes", exact: true }).click();
    await expect(detail.getByTestId("custom-extension-review-bar")).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
    expect(errors).toEqual([]);
  });
}
