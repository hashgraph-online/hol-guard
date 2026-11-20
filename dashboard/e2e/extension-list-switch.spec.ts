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

test("a search keeps the switch, so the custom list stays one click away", async ({ page }) => {
  await mount(page, { catalog: { ...catalog(), extensions: [extension("command.git", "")] } });
  await page.route("**/v1/local-clis**", (route) => route.fulfill({ json: {
    schema_version: "guard.daemon.local-clis.v1", revision: 1, items: [localCli(1, "unset")],
    cloud: { sync_local_only: true, summary: "Synthetic fixture." },
  } }));
  await initialize(page);
  await page.getByRole("searchbox", { name: "Search command patterns" }).fill("git");
  const custom = page.getByTestId("extension-list-switch").getByRole("button", { name: /^Custom extensions/ });
  await expect(custom).toBeVisible();
  await custom.click();
  await expect(page.getByRole("button", { name: /switch-connector-1/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "Add custom extension", exact: true })).toHaveCount(1);
});

test("starting Add from All tools returns to the custom list", async ({ page }) => {
  await mount(page, { catalog: { ...catalog(), extensions: [extension("command.git", "")] } });
  await page.route("**/v1/local-clis**", (route) => route.fulfill({ json: {
    schema_version: "guard.daemon.local-clis.v1", revision: 1, items: [localCli(1, "allow")],
    cloud: { sync_local_only: true, summary: "Synthetic fixture." },
  } }));
  await initialize(page);
  const switcher = page.getByTestId("extension-list-switch");
  await expect(switcher.getByRole("button", { name: /^All tools/ })).toHaveAttribute("aria-pressed", "true");
  await page.getByRole("button", { name: "Add custom extension", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Add a custom extension", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Extensions", exact: true }).click();
  await expect(switcher.getByRole("button", { name: /^Custom extensions/ })).toHaveAttribute("aria-pressed", "true");
});

test("a failed connector scan is visible without opening the custom list", async ({ page }) => {
  await mount(page, { catalog: { ...catalog(), extensions: [extension("command.git", "")] } });
  await page.route("**/v1/local-clis**", (route) => route.fulfill({ json: {
    schema_version: "guard.daemon.local-clis.v1", revision: 1, items: [localCli(1, "allow")],
    cloud: { sync_local_only: true, summary: "Synthetic fixture." },
  } }));
  await page.route("**/v1/local-clis/refresh-job", (route) => route.fulfill({ status: 500, json: { error: "scan failed" } }));
  await initialize(page);
  const notice = page.getByRole("status").filter({ hasText: "could not check host configuration" });
  await expect(notice).toBeVisible();
  // Even the failure Guard cannot name must hand the reader a next step.
  await expect(notice).toContainText("restart Guard");
  await expect(notice.getByRole("button", { name: "Check for connectors again" })).toBeVisible();
});

/**
 * The banner used to answer every failed host scan with one sentence that
 * named no cause and no next action, because the only `.catch()` on the way
 * dropped the error. These cover both halves of that path: a scan the daemon
 * refuses to start, and a scan that starts and then fails a stage.
 */
async function routeConnectorScan(page: import("@playwright/test").Page, options: {
  configured: (clientJobId: string) => { status: number; json: Record<string, unknown> };
  poll?: (jobId: string) => { status: number; json: Record<string, unknown> };
}) {
  await page.route("**/v1/local-clis/refresh-job", (route) => {
    const payload = (route.request().postDataJSON() ?? {}) as Record<string, unknown>;
    const jobId = typeof payload.job_id === "string" ? payload.job_id : "";
    if (jobId) {
      // A cancel, or a poll on a job the test started.
      if (payload.cancel === true || !options.poll) {
        return route.fulfill({ json: { job_id: jobId, cli_id: "inventory:configured", state: "cancelled", error: null } });
      }
      const polled = options.poll(jobId);
      return route.fulfill({ status: polled.status, json: polled.json });
    }
    const clientJobId = typeof payload.client_job_id === "string" ? payload.client_job_id : "0".repeat(32);
    if (payload.operation === "configured-connections") {
      const started = options.configured(clientJobId);
      return route.fulfill({ status: started.status, json: started.json });
    }
    // The Codex app inventory is not under test here, so it completes.
    return route.fulfill({ json: { job_id: clientJobId, cli_id: "inventory:codex-host", state: "complete", error: null } });
  });
}

test("a daemon that refuses the scan says which refusal it was", async ({ page }) => {
  await mount(page, { catalog: { ...catalog(), extensions: [extension("command.git", "")] } });
  await page.route("**/v1/local-clis**", (route) => route.fulfill({ json: {
    schema_version: "guard.daemon.local-clis.v1", revision: 1, items: [localCli(1, "allow")],
    cloud: { sync_local_only: true, summary: "Synthetic fixture." },
  } }));
  await routeConnectorScan(page, {
    configured: () => ({ status: 503, json: { error: "discovery_busy", message: "Other connections are refreshing. Try again shortly." } }),
  });
  await initialize(page);

  const notice = page.getByRole("status").filter({ hasText: "already refreshing other connections" });
  await expect(notice).toBeVisible();
  await expect(notice).toContainText("Check for connectors again");
  await expect(notice.getByRole("button", { name: "Check for connectors again" })).toBeVisible();
  await expect(page.getByText("Could not check host configuration", { exact: false })).toHaveCount(0);
});

test("a scan that fails reading host configuration names what to fix", async ({ page }) => {
  await mount(page, { catalog: { ...catalog(), extensions: [extension("command.git", "")] } });
  await page.route("**/v1/local-clis**", (route) => route.fulfill({ json: {
    schema_version: "guard.daemon.local-clis.v1", revision: 1, items: [localCli(1, "allow")],
    cloud: { sync_local_only: true, summary: "Synthetic fixture." },
  } }));
  await routeConnectorScan(page, {
    configured: (clientJobId) => ({ status: 200, json: { job_id: clientJobId, cli_id: "inventory:configured", state: "running", error: null } }),
    poll: (jobId) => ({ status: 200, json: { job_id: jobId, cli_id: "inventory:configured", state: "failed", error: "configured_host_scan_failed" } }),
  });
  await initialize(page);

  const notice = page.getByRole("status").filter({ hasText: "could not read this device's configured connections" });
  await expect(notice).toBeVisible();
  await expect(notice).toContainText("MCP settings are valid");
  await expect(notice).toContainText("Known connections were kept");
  await expect(notice.getByRole("button", { name: "Check for connectors again" })).toBeVisible();
});

test("a scan that cannot save what it read never blames the reader's config", async ({ page }) => {
  await mount(page, { catalog: { ...catalog(), extensions: [extension("command.git", "")] } });
  await page.route("**/v1/local-clis**", (route) => route.fulfill({ json: {
    schema_version: "guard.daemon.local-clis.v1", revision: 1, items: [localCli(1, "allow")],
    cloud: { sync_local_only: true, summary: "Synthetic fixture." },
  } }));
  await routeConnectorScan(page, {
    configured: (clientJobId) => ({ status: 200, json: { job_id: clientJobId, cli_id: "inventory:configured", state: "running", error: null } }),
    poll: (jobId) => ({ status: 200, json: { job_id: jobId, cli_id: "inventory:configured", state: "failed", error: "configured_host_persist_failed" } }),
  });
  await initialize(page);

  const notice = page.getByRole("status").filter({ hasText: "could not save them" });
  await expect(notice).toBeVisible();
  await expect(notice).toContainText("restart Guard");
  // Saving is Guard's own failure; sending the reader to their MCP settings
  // would be an hour spent on a file that is fine.
  await expect(notice).not.toContainText("MCP settings are valid");
  await expect(notice.getByRole("button", { name: "Check for connectors again" })).toBeVisible();
});

test("a failed cleanup does not replace the reason the scan failed", async ({ page }) => {
  await mount(page, { catalog: { ...catalog(), extensions: [extension("command.git", "")] } });
  await page.route("**/v1/local-clis**", (route) => route.fulfill({ json: {
    schema_version: "guard.daemon.local-clis.v1", revision: 1, items: [localCli(1, "allow")],
    cloud: { sync_local_only: true, summary: "Synthetic fixture." },
  } }));
  // The poll fails to parse, then the cancel that cleans the job up answers
  // with a different job. The reader must still be told what actually broke.
  await page.route("**/v1/local-clis/refresh-job", (route) => {
    const payload = (route.request().postDataJSON() ?? {}) as Record<string, unknown>;
    const jobId = typeof payload.job_id === "string" ? payload.job_id : "";
    if (payload.cancel === true) {
      return route.fulfill({ json: { job_id: "b".repeat(32), cli_id: "inventory:configured", state: "cancelled", error: null } });
    }
    if (jobId) {
      return route.fulfill({ json: {} });
    }
    const clientJobId = typeof payload.client_job_id === "string" ? payload.client_job_id : "0".repeat(32);
    if (payload.operation === "configured-connections") {
      return route.fulfill({ json: { job_id: clientJobId, cli_id: "inventory:configured", state: "running", error: null } });
    }
    return route.fulfill({ json: { job_id: clientJobId, cli_id: "inventory:codex-host", state: "complete", error: null } });
  });
  await initialize(page);

  const notice = page.getByRole("status").filter({ hasText: "could not read this discovery's progress" });
  await expect(notice).toBeVisible();
  await expect(notice).toContainText("Reload this page");
  await expect(notice).not.toContainText("A different discovery replaced this one");
});
