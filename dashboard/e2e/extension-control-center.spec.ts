import { expect, test } from "@playwright/test";

import {
  DAEMON_ORIGIN,
  DIGEST,
  effective,
  initialize,
  mount,
} from "./extension-control-fixtures";
import { freeStateSnapshot } from "./fixture-states";

test("extension cards navigate through one canonical detail action", async ({ page }) => {
  await mount(page);
  await initialize(page);
  const card = page.getByRole("button", { name: /^Git/ });
  await expect(card).toBeVisible();
  await card.press("Enter");
  await expect(page).toHaveURL(/\/extensions\/command\.git$/);
  await expect(page.getByTestId("protection-module-detail")).toBeVisible();
  expect(await page.evaluate(() => (window as typeof window & { __ecc_xss?: boolean }).__ecc_xss ?? false)).toBe(false);
});

test("canonical Extension detail exposes managed authority without gating local safety", async ({ page }) => {
  await mount(page, {
    runtime: {
      ...freeStateSnapshot,
      latest_receipts: [{
        receipt_id: "receipt-git-blocked",
        harness: "codex",
        artifact_id: "artifact-git",
        artifact_hash: "c".repeat(64),
        policy_decision: "block",
        capabilities_summary: "Git command protection",
        changed_capabilities: [],
        provenance_summary: "Guard decision",
        user_override: null,
        source_scope: null,
        timestamp: "2026-08-25T12:00:00Z",
        action_envelope_json: {
          schema_version: 1,
          action_id: "action-git-blocked",
          harness: "codex",
          event_name: "tool.execute",
          action_type: "shell_command",
          workspace: null,
          workspace_hash: null,
          tool_name: "git",
          command: null,
          prompt_excerpt: null,
          target_paths: [],
          network_hosts: [],
          mcp_server: null,
          mcp_tool: null,
          package_manager: null,
          package_name: null,
          script_name: null,
          raw_payload_redacted: {},
        },
      }],
    },
    effective: effective({
      layers: [{
        schema_version: "1.0.0",
        kind: "signed-cloud",
        catalog_digest: DIGEST,
        global_lockdown: false,
        controls: [{
          target_kind: "permission",
          target_id: "command.git.permission.hard-reset",
          state: "enabled",
        }],
      }, {
        schema_version: "1.0.0",
        kind: "local-admin",
        catalog_digest: DIGEST,
        global_lockdown: false,
        controls: [{
          target_kind: "permission",
          target_id: "command.git.permission.hard-reset",
          state: "disabled",
        }],
      }],
      projection: {
        schema_version: "guard.daemon.extension-control-projection.v1",
        revision: 7,
        catalog_digest: DIGEST,
        health: "protected",
        extensions: [{
          extension_id: "command.git",
          effective_state: "allowed",
          local_state: "inherited",
          managed_state: "inherited",
          required: false,
          reason_codes: [],
        }],
        permissions: [{
          permission_id: "command.git.permission.hard-reset",
          extension_id: "command.git",
          effective_state: "blocked",
          local_state: "disabled",
          managed_state: "enabled",
          configurable: true,
          fixed_reason: null,
          reason_codes: ["control.disabled-permission"],
        }],
      },
      managed_controls: {
        control_set_id: "managed-git-safety",
        control_set_name: "Managed Git safety",
        bundle_version: 7,
        workspace_id: "workspace-managed-controls",
        authority_mode: "managed-restrictive",
        catalog_digest: DIGEST,
        acknowledgement: {
          extension_authority_revision: 3,
          effective_projection_digest: "b".repeat(64),
          status: "applied",
        },
      },
    }),
  });
  await initialize(page);
  await page.getByRole("button", { name: /^Git/ }).click();
  await expect(page.getByTestId("protection-module-detail")).toBeVisible();
  await expect(page.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByTestId("protection-module-detail").getByText("Set on this device").first()).toBeVisible();
  await expect(page.getByText("Blocked", { exact: true })).toBeVisible();
  await expect(page.getByText("Managed by workspace-managed-controls · Set on this device")).toBeVisible();
  await page.getByRole("tab", { name: "Overview" }).focus();
  await page.getByRole("tab", { name: "Overview" }).press("End");
  await expect(page.getByRole("tab", { name: "Technical details" })).toBeFocused();
  await expect(page.getByRole("tab", { name: "Technical details" })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("tab", { name: "Technical details" }).press("Home");
  await expect(page.getByRole("tab", { name: "Overview" })).toBeFocused();
  await expect(page.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("tab", { name: "Overview" }).press("ArrowRight");
  await expect(page.getByRole("tab", { name: "Permissions" })).toBeFocused();
  await expect(page.getByRole("tab", { name: "Permissions" })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("tab", { name: "Permissions" }).press("ArrowLeft");
  await expect(page.getByRole("tab", { name: "Overview" })).toBeFocused();
  await expect(page.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("tab", { name: "Activity" }).click();
  await expect(page.getByRole("heading", { name: "Recent Extension decisions" })).toBeVisible();
  await expect(page.getByText("Blocked · codex")).toBeVisible();
  await expect(page.getByRole("link", { name: "Open receipt" })).toHaveAttribute("href", /selected=receipt-git-blocked/);
  await page.getByRole("tab", { name: "Managed controls" }).click();
  await expect(page).toHaveURL(/tab=managed-controls/);
  await expect(page.getByRole("heading", { name: "Active managed control" })).toBeVisible();
  await expect(page.getByText("Managed Git safety")).toBeVisible();
  await expect(page.getByText(/cannot weaken this workspace restriction/)).toBeVisible();
  await expect(page.getByText(/Local protection and local tightening remain available/)).toBeVisible();
});

test("managed controls reports loading and unchanged refresh results", async ({ page }) => {
  await mount(page, {
    refreshEffectiveDelayMs: 50,
    runtime: { ...freeStateSnapshot, cloud_policy_sync_error: "stale" },
    runtimeRefresh: freeStateSnapshot,
    effective: effective({
      health: "degraded-unacknowledged",
      failures: [{ code: "cloud_sync_stale", layer_kind: "signed-cloud" }],
      layers: [{
        schema_version: "1.0.0",
        kind: "signed-cloud",
        catalog_digest: DIGEST,
        global_lockdown: false,
        controls: [{ target_kind: "extension", target_id: "command.git", state: "enabled" }],
      }],
    }),
  });
  await initialize(page);
  await page.getByRole("button", { name: /^Git/ }).click();
  await page.getByRole("tab", { name: "Managed controls" }).click();
  await expect(page.getByText(/Guard Cloud data is stale/)).toBeVisible();
  await page.getByRole("button", { name: "Check again", exact: true }).first().click();
  await expect(page.getByRole("status").filter({ hasText: "No change detected" }).first()).toBeVisible();
  const checkAgain = page.getByRole("button", { name: "Check again", exact: true }).last();
  await checkAgain.click();
  await expect(page.getByRole("button", { name: "Checking…", exact: true })).toBeDisabled();
  await expect(page.getByRole("status").filter({ hasText: "No change detected" })).toBeVisible();
});

test("managed controls reports a failed refresh without hiding the last state", async ({ page }) => {
  await mount(page, {
    failEffectiveRefresh: true,
    effective: effective({
      failures: [{ code: "cloud_sync_stale", layer_kind: "signed-cloud" }],
    }),
  });
  await initialize(page);
  await page.getByRole("button", { name: /^Git/ }).click();
  await page.getByRole("tab", { name: "Managed controls" }).click();
  await page.getByRole("button", { name: "Check again", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "last verified local authority remains in force" })).toBeVisible();
  await expect(page.getByText(/Guard Cloud data is stale/)).toBeVisible();
});

test("dirty permission drafts require confirmation before click or keyboard tab changes", async ({ page }) => {
  await mount(page);
  await initialize(page);
  await page.getByRole("button", { name: /^Git/ }).click();
  await page.getByRole("tab", { name: "Permissions" }).click();
  await page.getByRole("radio", { name: "Block" }).click();
  await expect(page.getByText("1 unsaved setting change.")).toBeVisible();

  page.once("dialog", async (dialog) => {
    expect(dialog.message()).toBe("Discard your unreviewed protection setting changes?");
    await dialog.dismiss();
  });
  await page.getByRole("tab", { name: "Activity" }).click();
  await expect(page.getByRole("tab", { name: "Permissions" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("radio", { name: "Block" })).toHaveAttribute("aria-checked", "true");

  await page.getByRole("tab", { name: "Permissions" }).focus();
  page.once("dialog", async (dialog) => {
    expect(dialog.message()).toBe("Discard your unreviewed protection setting changes?");
    await dialog.dismiss();
  });
  await page.getByRole("tab", { name: "Permissions" }).press("ArrowRight");
  await expect(page.getByRole("tab", { name: "Permissions" })).toBeFocused();
  await expect(page.getByRole("tab", { name: "Permissions" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("radio", { name: "Block" })).toHaveAttribute("aria-checked", "true");

  page.once("dialog", async (dialog) => {
    await dialog.accept();
  });
  await page.getByRole("tab", { name: "Activity" }).click();
  await expect(page.getByRole("tab", { name: "Activity" })).toHaveAttribute("aria-selected", "true");
});

test("managed controls starts the supported Guard Cloud connection flow", async ({ page }) => {
  let connectStarts = 0;
  await mount(page, {
    runtime: { ...freeStateSnapshot, dashboard_url: "", connect_url: "" },
  });
  await page.route("**/v1/cloud/connect", async (route) => {
    connectStarts += 1;
    expect(route.request().method()).toBe("POST");
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        connect_required: true,
        connect_flow: {
          state: "running",
          title: "Connect Guard Cloud",
          detail: "Complete sign-in.",
          action_label: "Open sign-in",
          connect_url: "https://example.test/connect",
          authorize_url: "https://example.test/authorize",
          browser_opened: false,
          request_id: "request-1",
          poll_after_ms: 1500,
        },
      }),
    });
  });
  await initialize(page);
  await page.getByRole("button", { name: /^Git/ }).click();
  await page.getByRole("tab", { name: "Managed controls" }).click();
  await page.getByRole("button", { name: "Connect Guard Cloud" }).click();
  await expect(page.getByRole("link", { name: "Open Guard Cloud sign-in" })).toHaveAttribute(
    "href",
    "https://example.test/authorize",
  );
  await expect(page.getByRole("status")).toContainText("Complete sign-in");
  expect(connectStarts).toBe(1);
});

test("alias direct loads canonicalize and preserve only supported detail state", async ({ page }) => {
  await mount(page);
  await initialize(page);
  await page.goto("/extensions/command.scm?tab=commands&risk=high&sort=risk&guard-token=should-disappear#private-fragment");
  await expect(page).toHaveURL(/\/extensions\/command\.git\?tab=commands&risk=high&sort=risk#/);
  expect(new URL(page.url()).searchParams.has("guard-token")).toBe(false);
  expect(page.url()).not.toContain("private-fragment");
  await expect(page.getByRole("tab", { name: "Permissions" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("heading", { name: "Protection settings" })).toBeVisible();
});

test("unknown and encoded invalid extension IDs fail closed", async ({ page }) => {
  await mount(page);
  await initialize(page);
  await page.goto("/extensions/command.unknown");
  await expect(page.getByRole("heading", { name: "Extension not found" })).toBeVisible();
  await page.goto("/extensions/%2Fetc%2Fpasswd");
  await expect(page.getByRole("heading", { name: "Extension not found" })).toBeVisible();
});

test("global lockdown and narrow viewport remain explicit and usable", async ({ page }) => {
  await mount(page, { effective: effective({ global_lockdown: true }) });
  await page.setViewportSize({ width: 320, height: 720 });
  await initialize(page);
  await page.getByRole("button", { name: /^Git/ }).click();
  await expect(page.getByText(/Emergency Lockdown currently controls this module/)).toBeVisible();
  await page.getByRole("tab", { name: "Permissions" }).click();
  await expect(page.getByText(/Emergency Lockdown remains dominant/)).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});

test("search results offer safe bulk actions with clear scope on desktop and mobile", async ({ page }) => {
  await mount(page);
  await initialize(page);

  await page.getByRole("searchbox", { name: "Search command patterns" }).fill("git");
  await expect(page.getByText("Quick apply to 1 matching capability")).toBeVisible();
  const quickApply = page.getByRole("group", { name: "Quick apply to 1 matching capabilities" });
  await expect(quickApply.getByRole("button", { name: "Recommended" })).toHaveAttribute("aria-pressed", "true");
  await quickApply.getByRole("button", { name: "Recommended" }).click();
  await expect(page.getByText("1 unsaved setting change.")).toHaveCount(0);

  await quickApply.getByRole("button", { name: "Deny all" }).click();
  await expect(page.getByText("1 unsaved setting change.")).toBeVisible();
  await expect(page.getByRole("radio", { name: "Block" })).toHaveAttribute("aria-checked", "true");

  await page.getByRole("searchbox", { name: "Search command patterns" }).fill("no matching capability");
  await expect(page.getByText("No command patterns or tools match this search.")).toBeVisible();
  await expect(page.getByText("1 unsaved setting change.")).toBeVisible();
  await page.getByRole("searchbox", { name: "Search command patterns" }).fill("git");

  await quickApply.getByRole("button", { name: "Recommended" }).click();
  await expect(page.getByText("1 unsaved setting change.")).toHaveCount(0);
  await quickApply.getByRole("button", { name: "Allow all" }).click();
  await expect(page.getByRole("button", { name: "Review 1 change" })).toBeVisible();

  await page.setViewportSize({ width: 320, height: 720 });
  await expect(quickApply.getByRole("button", { name: "Allow all" })).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});

test("bulk allow preserves organization blocks", async ({ page }) => {
  await mount(page, {
    effective: effective({
      layers: [{
        schema_version: "1.0.0",
        kind: "signed-cloud",
        catalog_digest: DIGEST,
        global_lockdown: false,
        controls: [{
          target_kind: "permission",
          target_id: "command.git.permission.hard-reset",
          state: "disabled",
        }],
      }],
    }),
  });
  await initialize(page);
  await page.getByRole("searchbox", { name: "Search command patterns" }).fill("git");

  await expect(page.getByText("1 organization block stays enforced.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Allow all" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Deny all" })).toBeEnabled();
});

test("malformed catalog response is rejected at the client boundary", async ({ page }) => {
  await mount(page, { malformedCatalog: true });
  await page.goto(`/extensions?guardDaemon=${DAEMON_ORIGIN}`);
  await expect(page.getByRole("heading", { name: "Extensions unavailable" })).toBeVisible();
  await expect(page.getByRole("alert")).toContainText("Invalid extension-control response");
});

// A daemon whose catalog read model and whose effective controls name different
// catalogs used to take the whole page away: the list, the policies and the
// editor were replaced by "Extensions unavailable", and its "Try again" ran the
// same unresolvable read. The daemon refuses a mutation carrying the wrong
// catalog digest on its own, so the page shows what it has and says so.
test("a catalog the daemon has not finished binding still lists every extension", async ({ page }) => {
  test.setTimeout(60_000);
  await mount(page, { effective: effective({ catalog_digest: `${"c".repeat(63)}1` }) });
  await page.goto(`/extensions?guardDaemon=${DAEMON_ORIGIN}`);
  // The loader retries across the daemon's control-refresh interval before it
  // settles for the pair it has, so this first paint is slower than a normal one.
  await expect(page.getByRole("heading", { name: "Extensions", exact: true })).toBeVisible({ timeout: 20_000 });
  await expect(page.getByTestId("protection-data-unsettled")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Extensions unavailable" })).toHaveCount(0);
  const card = page.getByRole("button", { name: /^Git/ });
  await expect(card).toBeVisible();
  await card.press("Enter");
  await expect(page.getByTestId("protection-module-detail")).toBeVisible();
});

// A frozen build extracts under a symlinked temporary prefix, so every read of
// its own installed data files failed and the daemon answered
// catalog_read_preparation_failed on every attempt. The page used to become a
// dead end: no list, no policies, and a "Try again" that re-ran the same
// unresolvable read. The legacy catalog is served from the registry the daemon
// already holds in memory, so the page falls back to it, says what is reduced
// and still edits policy.
test("a daemon that cannot prepare its catalog still lists extensions and edits policy", async ({ page }) => {
  await mount(page);
  // Registered after mount so it wins: Playwright matches the newest route first.
  await page.route("**/v2/extension-controls/catalog/index**", async (route) => {
    await route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({ error: "catalog_read_preparation_failed" }),
    });
  });
  await page.goto(`/extensions?guardDaemon=${DAEMON_ORIGIN}`);

  await expect(page.getByRole("heading", { name: "Extensions", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Extensions unavailable" })).toHaveCount(0);
  await expect(page.getByTestId("catalog-preparation-degraded")).toBeVisible();
  await expect(page.getByTestId("catalog-preparation-degraded")).toContainText("the list Guard already had");

  await page.getByRole("button", { name: /^Git/ }).click();
  await expect(page.getByTestId("protection-module-detail")).toBeVisible();
  await page.getByRole("tab", { name: "Permissions" }).click();
  const quickApply = page.getByRole("group", { name: "Quick apply to 1 changeable settings" });
  await quickApply.getByRole("button", { name: "Deny all" }).click();
  await expect(page.getByText("1 unsaved setting change.")).toBeVisible();
  await expect(page.getByRole("radio", { name: "Block" })).toHaveAttribute("aria-checked", "true");
});
