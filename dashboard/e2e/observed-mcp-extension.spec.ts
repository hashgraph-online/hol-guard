import { expect, test } from "@playwright/test";
import { initialize, mount } from "./extension-control-fixtures";
import { defaultSettingsPayload } from "./fixture-states";

for (const width of [1280, 390]) {
  test(`registry Codex setup stays reviewed and does not grant tools at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const requests: Record<string, unknown>[] = [];
    let discoveryCalls = 0;
    let finishApply: () => void = () => undefined;
    const applyGate = new Promise<void>((resolve) => { finishApply = resolve; });
    await mount(page);
    await page.route("**/v1/local-clis**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      const body = route.request().method() === "POST" ? route.request().postDataJSON() : {};
      if (path.endsWith("/discover")) {
        discoveryCalls += 1;
        if (width === 390) {
          await route.fulfill({ status: 503, json: { message: "Synthetic host discovery failure." } });
          return;
        }
      }
      if (path.endsWith("/refresh-job")) {
        await route.fulfill({ json: { job_id: "d".repeat(32), cli_id: "inventory:configured", state: "complete", error: null } });
        return;
      }
      if (path.endsWith("/registry-search")) {
        await route.fulfill({ json: { source: "official-mcp-registry", coverage: "search-page", more_available: false, results: [{
          name: "io.github.sample/newserver", title: "New Server", version: "1.2.3",
          description: "Synthetic remote listing.", status: "active", provenance: "official-mcp-registry",
          remote_endpoints: [{ url: "https://example.com/mcp", transport: "streamable-http" }],
          package_count: 0, package_options: [], verified_package: false, configured: false, installed: false,
        }] } });
        return;
      }
      if (path.endsWith("/registry-setup")) {
        requests.push(body);
        if (body.operation === "apply") await applyGate;
        await route.fulfill({ json: body.operation === "preview"
          ? { host: "codex", kind: "remote", registry_name: body.registry_name, version: body.version, endpoint: body.endpoint,
            setup_name: "newserver", selection_digest: "b".repeat(64),
            permissions_granted: false, host_change_applied: false }
          : { host: "codex", kind: "remote", setup_name: "newserver",
            permissions_granted: false, host_change_applied: true } });
        return;
      }
      await route.fulfill({ json: { schema_version: "guard.daemon.local-clis.v1", revision: 0, items: [],
        cloud: { sync_local_only: true, summary: "Synthetic fixture." } } });
    });
    await page.route("**/v1/settings", (route) => route.fulfill({ json: {
      ...defaultSettingsPayload,
      settings: { ...defaultSettingsPayload.settings, approval_gate: {
        ...defaultSettingsPayload.settings.approval_gate, enabled: true, configured: true, totp_enabled: true,
      } },
    } }));
    await initialize(page);
    await page.getByRole("button", { name: "Add custom extension", exact: true }).click();
    await page.getByText("Find an MCP server in the public registry", { exact: true }).click();
    const registry = page.getByRole("region", { name: "Public MCP registry search", exact: true });
    await registry.getByRole("searchbox", { name: "Server or app name", exact: true }).fill("newserver");
    await registry.getByRole("button", { name: "Search registry", exact: true }).click();
    await registry.getByRole("button", { name: "Review HTTPS setup", exact: true }).click();
    const review = registry.getByRole("region", { name: "Review Codex MCP setup", exact: true });
    await expect(review).toContainText("https://example.com/mcp");
    await expect(review.getByRole("button", { name: "Add to Codex", exact: true })).toBeDisabled();
    if (process.env.HOL_GUARD_MCP_CAPTURE_PROOF === "1") {
      await page.screenshot({ path: testInfo.outputPath(`registry-setup-${width}.png`),
        animations: "disabled", fullPage: width > 600 });
    }
    expect(requests).toHaveLength(1);
    await review.getByLabel("Authenticator code").fill("123456");
    const beforeApply = discoveryCalls;
    await review.getByRole("button", { name: "Add to Codex", exact: true }).click();
    await expect.poll(() => requests.length).toBe(2);
    await expect(registry.getByRole("status")).toContainText("Adding the reviewed connection to Codex…");
    await page.getByText("Find an MCP server in the public registry", { exact: true }).click();
    await page.getByText("Find an MCP server in the public registry", { exact: true }).click();
    await expect(review.getByRole("button", { name: "Add to Codex", exact: true })).toBeDisabled();
    finishApply();
    await expect(registry.getByRole("status")).toContainText("No tool permission was granted.");
    await expect.poll(() => discoveryCalls).toBe(beforeApply + 1);
    if (width === 390) {
      await expect(registry.getByRole("alert")).toContainText("Codex was configured, but Guard could not fully rescan host connections.");
    }
    expect(requests).toHaveLength(2);
    expect(requests[1]).toMatchObject({ operation: "apply", registry_name: "io.github.sample/newserver",
      endpoint: "https://example.com/mcp", setup_name: "newserver", selection_digest: "b".repeat(64),
      confirm_host_change: true, approval_totp_code: "123456" });
    expect(requests[1]).not.toHaveProperty("tool_permissions");
  });

  test(`pinned registry package setup shows the launch and grants no tools at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    const requests: Record<string, unknown>[] = [];
    let discoveryCalls = 0;
    await mount(page);
    await page.route("**/v1/local-clis**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path.endsWith("/discover")) discoveryCalls += 1;
      if (path.endsWith("/registry-search")) {
        await route.fulfill({ json: { source: "official-mcp-registry", coverage: "search-page", more_available: false,
          results: [{ name: "io.github.sample/package-server", title: "Package Server", version: "1.2.3",
            description: "Synthetic pinned listing.", status: "active", provenance: "official-mcp-registry",
            remote_endpoints: [], package_count: 1,
            package_options: [{ registry_type: "npm", identifier: "@sample/server", version: "2.3.4",
              command: "npx", arguments: ["-y", "@sample/server@2.3.4"], transport: "stdio", verified_package: false }],
            verified_package: false, configured: false, installed: false }] } });
        return;
      }
      if (path.endsWith("/registry-setup")) {
        const body = route.request().postDataJSON();
        requests.push(body);
        await route.fulfill({ json: body.operation === "preview"
          ? { host: "codex", kind: "package", registry_name: body.registry_name, version: body.version,
            package_identifier: body.package_identifier, package_version: body.package_version,
            setup_name: body.setup_name, command: "/synthetic/npx", arguments: ["-y", "@sample/server@2.3.4"],
            verified_package: false, selection_digest: "c".repeat(64),
            permissions_granted: false, host_change_applied: false }
          : { host: "codex", kind: "package", setup_name: body.setup_name,
            permissions_granted: false, host_change_applied: true } });
        return;
      }
      await route.fulfill({ json: { schema_version: "guard.daemon.local-clis.v1", revision: 0, items: [],
        cloud: { sync_local_only: true, summary: "Synthetic fixture." } } });
    });
    await page.route("**/v1/settings", (route) => route.fulfill({ json: {
      ...defaultSettingsPayload,
      settings: { ...defaultSettingsPayload.settings, approval_gate: {
        ...defaultSettingsPayload.settings.approval_gate, enabled: true, configured: true, totp_enabled: true,
      } },
    } }));
    await initialize(page);
    await page.getByRole("button", { name: "Add custom extension", exact: true }).click();
    await page.getByText("Find an MCP server in the public registry", { exact: true }).click();
    const registry = page.getByRole("region", { name: "Public MCP registry search", exact: true });
    await registry.getByRole("searchbox", { name: "Server or app name", exact: true }).fill("package-server");
    await registry.getByRole("button", { name: "Search registry", exact: true }).click();
    await registry.getByRole("button", { name: "Review npm package · @sample/server@2.3.4" }).click();
    const review = registry.getByRole("region", { name: "Review Codex MCP setup", exact: true });
    await expect(review).toContainText("Unverified registry package");
    await expect(review).toContainText('"/synthetic/npx" "-y" "@sample/server@2.3.4"');
    expect(requests).toHaveLength(1);
    await review.getByLabel("Authenticator code").fill("123456");
    const beforeApply = discoveryCalls;
    await review.getByRole("button", { name: "Add to Codex", exact: true }).click();
    await expect(registry.getByRole("status")).toContainText("No tool permission was granted.");
    await expect.poll(() => discoveryCalls).toBe(beforeApply + 1);
    expect(requests[1]).toMatchObject({ operation: "apply", kind: "package",
      package_identifier: "@sample/server", package_version: "2.3.4", selection_digest: "c".repeat(64),
      confirm_host_change: true, approval_totp_code: "123456" });
    expect(requests[1]).not.toHaveProperty("tool_permissions");
  });

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
    let discovered = false;
    let registryRequests = 0;
    await mount(page);
    await page.route("**/v1/local-clis**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      let body: unknown = { schema_version: "guard.daemon.local-clis.v1", revision: 0, items: discovered ? [item] : [],
        cloud: { sync_local_only: true, summary: "This device only." } };
      if (path.endsWith("/registry-search")) {
        registryRequests += 1;
        expect(route.request().postDataJSON()).toEqual({ search: "composio" });
        body = { source: "official-mcp-registry", coverage: "search-page", more_available: false, results: [{
          name: "io.github.ComposioHQ/composio", title: "Composio", version: "1.0.5", description: "Synthetic listing.",
          status: "active", remote_endpoints: [{ url: "https://connect.composio.dev/mcp", transport: "streamable-http" }],
          package_count: 0, package_options: [], provenance: "official-mcp-registry", verified_package: false,
          configured: false, installed: false,
        }] };
      }
      if (path.endsWith("/refresh-job")) {
        expect(route.request().postDataJSON()).toEqual({ operation: "configured-connections", client_job_id: expect.stringMatching(/^[a-f0-9]{32}$/) });
        discovered = true;
        body = { job_id: "d".repeat(32), cli_id: "inventory:configured", state: "complete", error: null };
      }
      if (path.endsWith("/discover")) {
        body = { ...body, discovery_issue: "configured_host_scan_failed" };
      }
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
    await expect(page.getByRole("button", { name: /composio.*Detected/i })).toBeVisible();
    expect(discovered).toBe(true);
    await page.getByRole("button", { name: "Add custom extension", exact: true }).click();
    await expect(page.getByText("MCP servers and connectors", { exact: true })).toBeVisible();
    await expect(page.getByRole("status").filter({ hasText: "could not read configured host connections" })).toBeVisible();
    await expect(page.getByRole("alert").filter({ hasText: "could not read configured host connections" })).toHaveCount(0);
    expect(registryRequests).toBe(0);
    await page.getByText("Find an MCP server in the public registry", { exact: true }).click();
    const registry = page.getByRole("region", { name: "Public MCP registry search", exact: true });
    await registry.getByRole("searchbox", { name: "Server or app name", exact: true }).fill("composio");
    await registry.getByRole("button", { name: "Search registry", exact: true }).click();
    await expect(registry).toContainText("Possible existing connection. Inspect it before adding another.");
    await expect(registry).toContainText("Packages unverified");
    expect(registryRequests).toBe(1);
    await page.getByText("Find an MCP server in the public registry", { exact: true }).click();
    await page.getByRole("button", { name: /composio.*2 tools/i }).click();
    await expect(page.getByRole("radio", { name: "Allow listed", exact: true })).toBeVisible();
    await page.getByRole("radiogroup", { name: "composio_search_tools protection setting" })
      .getByRole("radio", { name: "Allow", exact: true }).click();
    await page.getByRole("radiogroup", { name: "composio_execute_tool protection setting" })
      .getByRole("radio", { name: "Deny", exact: true }).click();
    await page.getByLabel("Find a tool").fill("search");
    await expect(page.getByRole("heading", { name: "composio_execute_tool", exact: true })).toHaveCount(0);
    await page.getByLabel("Find a tool").fill("");
    await page.getByLabel("Find a tool").blur();
    await page.evaluate(() => window.scrollTo(0, 0));
    if (process.env.HOL_GUARD_MCP_CAPTURE_PROOF === "1") {
      await page.screenshot({ path: testInfo.outputPath(`composio-${width}.png`), fullPage: width > 600 });
    }
    if (width < 600) {
      const continuation = page.getByRole("button", { name: "Continue", exact: true });
      await continuation.evaluate((button) => button.scrollIntoView({ block: "center", behavior: "instant" }));
      await expect(continuation).toBeInViewport();
      await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
      if (process.env.HOL_GUARD_MCP_CAPTURE_PROOF === "1") {
        await page.screenshot({ path: testInfo.outputPath(`composio-tools-${width}.png`), animations: "disabled" });
      }
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
