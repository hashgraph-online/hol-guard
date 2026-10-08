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
    let applied = false;
    const older = { rollback_handle: "c".repeat(64), setup_name: "older-server", kind: "remote",
      registry_name: "io.github.sample/older-server", version: "1.0.0", selection_digest: "c".repeat(64) };
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
        if (body.operation === "recent") {
          await route.fulfill({ json: { setups: [{ ...older, rollback_available: !applied },
            ...(applied ? [{ rollback_handle: "a".repeat(64), setup_name: "newserver", kind: "remote",
              registry_name: "io.github.sample/newserver", version: "1.2.3", selection_digest: "b".repeat(64) }] : [])] } });
          return;
        }
        requests.push(body);
        if (body.operation === "apply") { await applyGate; applied = true; }
        await route.fulfill({ json: body.operation === "preview"
          ? { host: "codex", kind: "remote", registry_name: body.registry_name, version: body.version, endpoint: body.endpoint,
            setup_name: "newserver", selection_digest: "b".repeat(64),
            permissions_granted: false, host_change_applied: false }
          : { host: "codex", kind: "remote", setup_name: "newserver",
            permissions_granted: false, host_change_applied: true, rollback_handle: "a".repeat(64) } });
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
    await page.getByTestId("custom-extensions-empty").getByRole("button", { name: "Add custom extension", exact: true }).click();
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
    await expect(registry.getByRole("status").filter({ hasText: "Adding the reviewed connection to Codex…" })).toBeVisible();
    await page.getByText("Find an MCP server in the public registry", { exact: true }).click();
    await page.getByText("Find an MCP server in the public registry", { exact: true }).click();
    await expect(review.getByRole("button", { name: "Add to Codex", exact: true })).toBeDisabled();
    finishApply();
    await expect(registry.getByRole("status").filter({ hasText: "No tool permission was granted." })).toBeVisible();
    await expect(registry.getByRole("button", { name: "Undo setup for older-server", exact: true })).toBeDisabled();
    await expect(registry.getByRole("button", { name: "Undo setup for newserver", exact: true })).toBeEnabled();
    await expect.poll(() => discoveryCalls).toBe(beforeApply + 1);
    if (width === 390) {
      await expect(registry.getByRole("alert")).toContainText("Codex configuration changed, but Guard could not fully rescan host connections.");
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
        if (body.operation === "recent") {
          await route.fulfill({ json: { setups: [] } });
          return;
        }
        requests.push(body);
        await route.fulfill({ json: body.operation === "preview"
          ? { host: "codex", kind: "package", registry_name: body.registry_name, version: body.version,
            package_identifier: body.package_identifier, package_version: body.package_version,
            setup_name: body.setup_name, command: "/synthetic/npx", arguments: ["-y", "@sample/server@2.3.4"],
            verified_package: false, selection_digest: "c".repeat(64),
            permissions_granted: false, host_change_applied: false }
          : { host: "codex", kind: "package", setup_name: body.setup_name,
            permissions_granted: false, host_change_applied: true, rollback_handle: "a".repeat(64) } });
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
    await page.getByTestId("custom-extensions-empty").getByRole("button", { name: "Add custom extension", exact: true }).click();
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
    await expect(registry.getByRole("status").filter({ hasText: "No tool permission was granted." })).toBeVisible();
    await expect.poll(() => discoveryCalls).toBe(beforeApply + 1);
    expect(requests[1]).toMatchObject({ operation: "apply", kind: "package",
      package_identifier: "@sample/server", package_version: "2.3.4", selection_digest: "c".repeat(64),
      confirm_host_change: true, approval_totp_code: "123456" });
    expect(requests[1]).not.toHaveProperty("tool_permissions");
  });

  test(`saved MCP setup can be reviewed and undone with fresh proof while registry is offline at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const saved = { rollback_handle: "a".repeat(64), setup_name: "saved-server", kind: "remote",
      registry_name: "io.github.sample/saved-server", version: "1.2.3", selection_digest: "b".repeat(64) };
    let historyCalls = 0;
    let present = true;
    const changes: Record<string, unknown>[] = [];
    await mount(page);
    await page.route("**/v1/local-clis**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      const body = route.request().method() === "POST" ? route.request().postDataJSON() : {};
      if (path.endsWith("/registry-search")) {
        await route.fulfill({ status: 503, json: { message: "Synthetic registry unavailable." } });
        return;
      }
      if (path.endsWith("/registry-setup")) {
        if (body.operation === "recent") {
          historyCalls += 1;
          await route.fulfill(historyCalls === 1
            ? { status: 503, json: { message: "Synthetic history unavailable." } }
            : { json: { setups: present ? [saved] : [] } });
        } else if (body.operation === "rollback-preview") {
          await route.fulfill({ json: { ...saved, host: "codex", endpoint: "https://example.com/mcp",
            permissions_granted: false, host_change_applied: false } });
        } else if (body.operation === "rollback") {
          changes.push(body);
          present = changes.length === 1;
          await route.fulfill(present
            ? { status: 401, json: { message: "Approval proof expired. Enter a fresh code." } }
            : { json: { host: "codex", kind: "remote", setup_name: saved.setup_name,
              setup_rolled_back: true, permissions_granted: false, host_change_applied: true } });
        } else {
          throw new Error(`Unexpected setup operation: ${body.operation}`);
        }
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
    await page.getByTestId("custom-extensions-empty").getByRole("button", { name: "Add custom extension", exact: true }).click();
    await page.getByText("Find an MCP server in the public registry", { exact: true }).click();
    const registry = page.getByRole("region", { name: "Public MCP registry search", exact: true });
    const history = registry.getByRole("region", { name: "Recent MCP setup", exact: true });
    await history.getByRole("button", { name: "Retry history", exact: true }).click();
    const undo = history.getByRole("button", { name: "Undo setup for saved-server", exact: true });
    await expect(undo).toBeVisible();
    await registry.getByRole("searchbox").fill("saved-server");
    await registry.getByRole("button", { name: "Search registry", exact: true }).click();
    await expect(registry.getByRole("alert")).toContainText("Synthetic registry unavailable.");
    await undo.click();
    const review = registry.getByRole("region", { name: "Review Codex MCP setup", exact: true });
    await expect(review).toContainText("does not revoke provider access or erase Guard tool choices");
    await expect(review.getByRole("button", { name: "Remove from Codex", exact: true })).toBeDisabled();
    await review.getByLabel("Authenticator code").fill("123456");
    await review.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(undo).toBeFocused();
    expect(changes).toHaveLength(0);
    await undo.click();
    await expect(review.getByLabel("Authenticator code")).toHaveValue("");
    if (process.env.HOL_GUARD_MCP_CAPTURE_PROOF === "1") {
      await page.screenshot({ path: testInfo.outputPath(`registry-undo-${width}.png`), animations: "disabled", fullPage: width > 600 });
    }
    await review.getByLabel("Authenticator code").fill("123456");
    await review.getByRole("button", { name: "Remove from Codex", exact: true }).click();
    await expect(registry.getByRole("alert")).toContainText("Approval proof expired.");
    await expect(review.getByLabel("Authenticator code")).toHaveValue("");
    await expect(review.getByRole("button", { name: "Remove from Codex", exact: true })).toBeDisabled();
    await review.getByLabel("Authenticator code").fill("654321");
    await review.getByRole("button", { name: "Remove from Codex", exact: true }).click();
    await expect(undo).toHaveCount(0);
    expect(changes).toHaveLength(2);
    expect(changes[1]).toMatchObject({ operation: "rollback", rollback_handle: saved.rollback_handle,
      setup_name: saved.setup_name, selection_digest: saved.selection_digest,
      confirm_host_change: true, approval_totp_code: "654321" });
    expect(changes[1].session_nonce).not.toBe(changes[0].session_nonce);
    expect(changes[1]).not.toHaveProperty("tool_permissions");
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    expect(errors).toEqual([]);
  });

  for (const conflictStage of ["rollback-preview", "rollback"]) {
  test(`changed Codex configuration leaves Undo unavailable during ${conflictStage} at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    const saved = { rollback_handle: "a".repeat(64), setup_name: "saved-server", kind: "remote",
      registry_name: "io.github.sample/saved-server", version: "1.2.3", selection_digest: "b".repeat(64) };
    let available = true;
    let changes = 0;
    await mount(page);
    await page.route("**/v1/local-clis**", async (route) => {
      const body = route.request().method() === "POST" ? route.request().postDataJSON() : {};
      if (new URL(route.request().url()).pathname.endsWith("/registry-setup")) {
        if (body.operation === "recent") {
          await route.fulfill({ json: { setups: [{ ...saved, rollback_available: available }] } });
        } else if (body.operation === "rollback-preview") {
          if (conflictStage === "rollback-preview") {
            available = false;
            await route.fulfill({ status: 409, json: { error: "codex_config_changed",
              message: "Codex configuration changed. Guard kept it unchanged." } });
          } else {
            await route.fulfill({ json: { ...saved, host: "codex", endpoint: "https://example.com/mcp",
              permissions_granted: false, host_change_applied: false } });
          }
        } else if (body.operation === "rollback") {
          changes += 1;
          available = false;
          await route.fulfill({ status: 409, json: { error: "codex_config_changed",
            message: "Codex configuration changed. Guard kept it unchanged." } });
        } else throw new Error(`Unexpected setup operation: ${body.operation}`);
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
    await page.getByTestId("custom-extensions-empty").getByRole("button", { name: "Add custom extension", exact: true }).click();
    await page.getByText("Find an MCP server in the public registry", { exact: true }).click();
    const registry = page.getByRole("region", { name: "Public MCP registry search", exact: true });
    const undo = registry.getByRole("button", { name: "Undo setup for saved-server", exact: true });
    await undo.click();
    const review = registry.getByRole("region", { name: "Review Codex MCP setup", exact: true });
    if (conflictStage === "rollback") {
      await review.getByLabel("Authenticator code").fill("123456");
      await review.getByRole("button", { name: "Remove from Codex", exact: true }).click();
    }
    await expect(registry.getByRole("alert")).toContainText("kept it unchanged");
    await expect(review).toHaveCount(0);
    await expect(undo).toBeDisabled();
    await expect(registry.getByRole("region", { name: "Recent MCP setup", exact: true })).toContainText("Configuration changed. Review this connection in Codex.");
    expect(changes).toBe(conflictStage === "rollback" ? 1 : 0);
  });
  }

  test(`closing the registry dismisses delayed Undo previews at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    const saved = { rollback_handle: "a".repeat(64), setup_name: "saved-server", kind: "remote",
      registry_name: "io.github.sample/saved-server", version: "1.2.3", selection_digest: "b".repeat(64) };
    let finishPreview: () => void = () => undefined;
    const previewGate = new Promise<void>((resolve) => { finishPreview = resolve; });
    let finishSecondPreview: () => void = () => undefined;
    const secondPreviewGate = new Promise<void>((resolve) => { finishSecondPreview = resolve; });
    let previewsStarted = 0;
    let previewFinished = false;
    await mount(page);
    await page.route("**/v1/local-clis**", async (route) => {
      const body = route.request().method() === "POST" ? route.request().postDataJSON() : {};
      if (new URL(route.request().url()).pathname.endsWith("/registry-setup")) {
        if (body.operation === "recent") await route.fulfill({ json: { setups: [saved] } });
        else if (body.operation === "rollback-preview") {
          const previewNumber = ++previewsStarted;
          await (previewNumber === 1 ? previewGate : secondPreviewGate);
          await route.fulfill({ json: { ...saved, host: "codex", endpoint: "https://example.com/mcp",
            permissions_granted: false, host_change_applied: false } });
          if (previewNumber === 1) previewFinished = true;
        } else throw new Error(`Unexpected setup operation: ${body.operation}`);
        return;
      }
      await route.fulfill({ json: { schema_version: "guard.daemon.local-clis.v1", revision: 0, items: [],
        cloud: { sync_local_only: true, summary: "Synthetic fixture." } } });
    });
    await initialize(page);
    await page.getByTestId("custom-extensions-empty").getByRole("button", { name: "Add custom extension", exact: true }).click();
    const toggle = page.getByText("Find an MCP server in the public registry", { exact: true });
    await toggle.click();
    const registry = page.getByRole("region", { name: "Public MCP registry search", exact: true });
    const undo = registry.getByRole("button", { name: "Undo setup for saved-server", exact: true });
    await undo.click();
    await expect.poll(() => previewsStarted).toBe(1);
    await expect(registry.getByRole("status").filter({ hasText: "Checking the saved setup" })).toBeVisible();
    await toggle.click();
    await toggle.click();
    await expect(undo).toBeEnabled();
    await undo.click();
    await expect.poll(() => previewsStarted).toBe(2);
    finishPreview();
    await expect.poll(() => previewFinished).toBe(true);
    await expect(registry.getByRole("status").filter({ hasText: "Checking the saved setup" })).toBeVisible();
    await expect(undo).toBeDisabled();
    await expect(registry.getByRole("region", { name: "Review Codex MCP setup", exact: true })).toHaveCount(0);
    finishSecondPreview();
    await expect(registry.getByRole("region", { name: "Review Codex MCP setup", exact: true })).toBeVisible();
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
