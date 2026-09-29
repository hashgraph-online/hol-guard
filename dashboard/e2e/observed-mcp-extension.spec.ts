import { expect, test } from "@playwright/test";
import { initialize, mount } from "./extension-control-fixtures";
import { defaultSettingsPayload } from "./fixture-states";

for (const width of [1280, 390]) {
  test(`observed connector permissions remain exact at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const item = {
      cli_id: "local-cli.mcp-1234567890abcdef", name: "composio", kind: "executable",
      identity_hash: "b".repeat(64), example_label: "mcp__codex_apps__composio__",
      interpreter_name: null, observed_count: 2, last_seen_at: "2026-01-01T00:00:00Z",
      surface: "mcp", source_label: "Codex · observed tools", source_path: null,
      help_status: "ok", state: "unset", stale: false, suggestable: true, authority_revision: 0,
      commands: [
        { command_id: "tool-search", name: "composio_search_tools", usage: "mcp__codex_apps__composio__composio_search_tools",
          description: "Find available tools.", parent_id: null, state: "inherit" },
        { command_id: "tool-execute", name: "composio_execute_tool", usage: "mcp__codex_apps__composio__composio_execute_tool",
          description: "Run a selected tool.", parent_id: null, state: "inherit" },
      ],
    };
    let applied: Record<string, unknown> | null = null;
    await mount(page);
    await page.route("**/v1/local-clis**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      let body: unknown = { schema_version: "guard.daemon.local-clis.v1", revision: 0, items: [item],
        cloud: { sync_local_only: true, summary: "This device only." } };
      if (path.endsWith("/recognize")) body = { item, summary: "Detected from Codex tool activity.", revision: 0, help_status: "ok" };
      if (path.endsWith("/preview")) body = { summary: "Save these tool permissions." };
      if (path.endsWith("/apply")) { applied = route.request().postDataJSON(); body = { ok: true }; }
      await route.fulfill({ json: body });
    });
    await page.route("**/v1/settings", (route) => route.fulfill({ json: {
      ...defaultSettingsPayload,
      settings: { ...defaultSettingsPayload.settings, approval_gate: {
        ...defaultSettingsPayload.settings.approval_gate, enabled: true, configured: true, totp_enabled: true,
      } },
    } }));
    await initialize(page);
    await page.getByRole("button", { name: "Add custom extension", exact: true }).click();
    await expect(page.getByText("MCP servers and connectors", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: /composio.*2 tools/i }).click();
    await expect(page.getByRole("radio", { name: "Allow listed", exact: true })).toBeVisible();
    await page.getByRole("radiogroup", { name: "composio_search_tools protection setting" })
      .getByRole("radio", { name: "Allow", exact: true }).click();
    await page.getByRole("radiogroup", { name: "composio_execute_tool protection setting" })
      .getByRole("radio", { name: "Block", exact: true }).click();
    await page.getByLabel("Find a tool").fill("search");
    await expect(page.getByRole("heading", { name: "composio_execute_tool", exact: true })).toHaveCount(0);
    await page.getByLabel("Find a tool").fill("");
    await page.getByLabel("Find a tool").blur();
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: testInfo.outputPath(`composio-${width}.png`), fullPage: width > 600 });
    if (width < 600) {
      const continuation = page.getByRole("button", { name: "Continue", exact: true });
      await continuation.evaluate((button) => button.scrollIntoView({ block: "center", behavior: "instant" }));
      await expect(continuation).toBeInViewport();
      await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
      await page.screenshot({ path: testInfo.outputPath(`composio-tools-${width}.png`), animations: "disabled" });
    }
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.getByLabel("Authenticator code").fill("123456");
    await page.getByRole("button", { name: "Save tool permissions", exact: true }).click();
    await expect.poll(() => applied).not.toBeNull();
    expect(applied).toMatchObject({ state: "allowed", commands: [
      { command_id: "tool-search", state: "allow" }, { command_id: "tool-execute", state: "block" },
    ] });
    expect(errors).toEqual([]);
  });
}
